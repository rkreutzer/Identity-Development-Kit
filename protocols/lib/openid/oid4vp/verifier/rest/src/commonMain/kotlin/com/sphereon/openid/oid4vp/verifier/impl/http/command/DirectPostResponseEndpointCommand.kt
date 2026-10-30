/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.sphereon.openid.oid4vp.verifier.impl.http.command

import com.sphereon.core.api.Encoding
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFrom
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.core.api.http.command.HttpEndpointCommandAdapter
import com.sphereon.core.api.http.command.requireBody
import com.sphereon.core.api.http.describe.EndpointAuthPolicy
import com.sphereon.core.api.http.describe.HttpEndpointDescriptor
import com.sphereon.core.api.http.describe.HttpMethod
import com.sphereon.core.api.http.describe.MediaType
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.jose.tryGenerateJwkThumbprint
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.jose.jwe.DecryptJweArgs
import com.sphereon.crypto.jose.jwe.JweCompact
import com.sphereon.crypto.jose.jwe.JweService
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.verifier.config.Oid4vpVerifierInstanceIdProvider
import com.sphereon.openid.oid4vp.verifier.federation.VerifierFederationMetadata
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import kotlinx.serialization.json.JsonObject
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vp.common.clientMetadata
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.verifier.HandleDirectPostResponseArgs
import com.sphereon.openid.oid4vp.verifier.HandleDirectPostResponseCommand
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose
import com.sphereon.openid.oid4vp.verifier.config.ResponseEncryptionKeyConfig
import com.sphereon.openid.oid4vp.verifier.spi.VerifierTrustedAuthenticationRequest
import com.sphereon.openid.oid4vp.verifier.spi.VerifierTrustedAuthenticationResolver
import com.sphereon.openid.oid4vp.verifier.store.AuthorizationSessionStore
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Provider
import dev.zacsweers.metro.ContributesIntoMap
import dev.zacsweers.metro.StringKey
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Command interface for the OID4VP direct_post response endpoint.
 *
 * The wallet POSTs the VP token and presentation_submission to this endpoint
 * after the user has approved the presentation request.
 *
 * Per OpenID4VP 1.0 Section 8.4 - Response Mode: direct_post
 */
interface DirectPostResponseEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID = "oid4vp.directpost.response"

        val ENDPOINT =
            HttpEndpointDescriptor(
                method = HttpMethod.POST,
                pathPattern = "/auth/response",
                consumes = setOf(MediaType.ApplicationFormUrlEncoded),
                produces = setOf(MediaType.ApplicationJson),
                operationId = "handleDirectPostResponse",
                handlerCommandId = COMMAND_ID,
                tags = setOf("oid4vp", "direct-post"),
                summary = "Handle OID4VP direct_post authorization response from wallet",
                authPolicy = EndpointAuthPolicy.PUBLIC,
            )
    }
}

/**
 * Implementation of [DirectPostResponseEndpointCommand].
 *
 * POST /oid4vp/auth/response
 *
 * Receives the wallet's authorization response (vp_token, state, presentation_submission)
 * via application/x-www-form-urlencoded POST and delegates to [HandleDirectPostResponseCommand].
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(DirectPostResponseEndpointCommand.COMMAND_ID)
class DirectPostResponseEndpointCommandImpl(
    execution: SessionExecution,
    private val handleDirectPostCommand: HandleDirectPostResponseCommand,
    private val authorizationSessionStore: AuthorizationSessionStore,
    private val responseEncryptionKeyConfig: ResponseEncryptionKeyConfig,
    private val trustedAuthenticationResolver: Provider<VerifierTrustedAuthenticationResolver>? = null,
    private val kms: Provider<KeyManagerService>? = null,
    private val jweService: Provider<JweService>? = null,
    private val instanceIdProvider: Provider<Oid4vpVerifierInstanceIdProvider>? = null,
) : HttpEndpointCommandAdapter(
        id = DirectPostResponseEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = DirectPostResponseEndpointCommand.ENDPOINT,
    ),
    DirectPostResponseEndpointCommand {
    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> {
        val request = applyDuring(args)

        // Parse form-urlencoded body into response params
        val body = request.requireBody().getOrElse { return Err(it) }
        val responseParams = parseFormBody(body)
        if (responseParams.isEmpty()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Missing or empty request body"))
        }

        // Identify the session. Two response shapes per OID4VP §8.4:
        //   - direct_post: form has plaintext fields including `state` (the correlationId).
        //   - direct_post.jwt: form has only `response=<JWE>`. State lives INSIDE the
        //     encrypted JWT payload — we can't read it without first decrypting. To find
        //     the right decryption key without that chicken-and-egg, we use the JWE
        //     header's `kid` parameter, which the wallet MUST copy from the JWK's `kid`
        //     it selected (OID4VP §8.3). The universal command sets that kid equal to
        //     the session correlationId so a single store lookup suffices.
        val correlationId =
            responseParams["state"]?.takeIf { it.isNotBlank() }
                ?: responseParams["response"]?.let { jwe -> extractKidFromJweHeader(jwe) }
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Cannot identify session: form body lacks `state` and the JWE in `response` carries no `kid` header.",
                    ),
                )

        // Look up the authorization session to get the original request
        val session =
            authorizationSessionStore.getByCorrelationId(correlationId).getOrNull()
                ?: federationSession(responseParams["response"], correlationId)
                ?: return Err(IdkError.NOT_FOUND_ERROR(message = "Authorization session not found: $correlationId"))

        // In DC API the browser receives the response and relays only the encrypted JWT.
        // `state` is not a DC API wire parameter (OID4VP Appendix A.2); the JWE kid
        // already selected this persisted session before any private-key operation.
        if (session.authorizationRequest.responseMode == ResponseMode.DC_API_JWT.value &&
            responseParams.keys != setOf("response")) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "dc_api.jwt response must contain only the encrypted response parameter"))
        }

        // Per OID4VP §7.2 redirect_uri is OPTIONAL in the response, and this response-endpoint
        // redirect is distinct from the authorization request's `redirect_uri`: direct_post uses
        // `response_uri` for wallet submission and the two request parameters are mutually
        // exclusive, so the post-completion destination is pinned on the session instead. Unset —
        // omit it, and the wallet stays on its current screen.
        val sessionRedirectUri = session.directPostResponseRedirectUri.orEmpty()

        // A `direct_post.jwt` session decrypts under the key the server holds for its verifier
        // instance. The session carries the instance, never a key selector, so a stored session
        // cannot steer decryption at any raw alias, provider, or key id. The resolved name builds
        // the opaque `KeyInfo` handle the JARM decryption command (deeper in
        // ParseAuthorizationResponseCommandImpl → VerifyJarmResponseCommandImpl) hands the KMS for
        // the ECDH key agreement. PRIVATE expresses the intended operation; it does not request key
        // export, and no key material crosses this boundary.
        val encryptedResponse = session.authorizationRequest.responseMode in
            setOf(ResponseMode.DIRECT_POST_JWT.value, ResponseMode.DC_API_JWT.value)
        val jarmDecryptionKeyName =
            if (encryptedResponse) {
                responseEncryptionKeyConfig.resolveEncryptionKeyName(session.instanceId)
                    ?: return Err(
                        IdkError.UNKNOWN_ERROR(message = ResponseEncryptionKeyConfig.RESPONSE_ENCRYPTION_KEY_UNAVAILABLE),
                    )
            } else {
                null
            }
        val jarmDecryptionKey =
            jarmDecryptionKeyName?.let { keyName ->
                ManagedOptsKeyInfo(
                    identifier =
                        KeyInfo<Nothing>(
                            alias = keyName,
                            keyVisibility = KeyVisibility.PRIVATE,
                        ),
                )
            }

        // OID4VP §B.2.6.2 mdoc handover: when the response is encrypted (`direct_post.jwt`),
        // the SessionTranscript handover MUST embed the SHA-256 thumbprint (RFC 7638) of
        // the verifier's encryption-key JWK. We published that JWK in client_metadata.jwks
        // when creating the authorization request, so the public params are already on the
        // session — extract the same key the wallet selected (matched by `kid`, which the
        // universal command sets equal to the session correlationId) and hash it. Raw
        // 32-byte digest (the spec mandates the bytes, not the base64url encoding).
        val verifierEncryptionJwkThumbprint =
            if (encryptedResponse) {
                val jwks =
                    session.authorizationRequest.clientMetadata
                        ?.jwks
                        ?.keys
                        ?.toList()
                        .orEmpty()
                val matchingJwk = jwks.firstOrNull { it.kid == correlationId } ?: jwks.firstOrNull()
                matchingJwk?.let { jwk ->
                    tryGenerateJwkThumbprint(jwk).getOrNull()?.decodeFrom(Encoding.BASE64URL)
                }
            } else {
                null
            }

        // ISO/IEC TS 18013-7 Annex B uses a distinct mdoc handover. The mdoc-generated nonce is
        // not a request parameter; it is authenticated in the response JWE `apu` header. Extract
        // it only for the unmistakable restricted PE profile (presentation_definition without
        // dcql_query). Regular OID4VP/DCQL keeps the regular four-element handover path.
        val iso18013MdocGeneratedNonce =
            if (isIso18013AnnexBRequest(session.authorizationRequest)) {
                val jwe =
                    responseParams["response"]
                        ?: return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message = "ISO 18013-7 Annex B direct_post.jwt response is missing the response JWE",
                            ),
                        )
                val header =
                    extractJweHeader(jwe)
                        ?: return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message = "ISO 18013-7 Annex B response JWE has no decodable protected header",
                            ),
                        )
                val apu =
                    header["apu"]
                        ?.let { it as? JsonPrimitive }
                        ?.takeIf { it.isString }
                        ?.content
                        ?.let { value ->
                            runCatching { value.decodeFromBase64Url().decodeToString() }.getOrNull()
                        }
                        ?.takeIf { it.isNotBlank() }
                        ?: return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message = "ISO 18013-7 Annex B response JWE must carry a non-empty apu mdoc-generated nonce",
                            ),
                        )
                val expectedApv = session.authorizationRequest.nonce
                    ?.encodeToByteArray()
                    ?.let { it.encodeToBase64Url() }
                val actualApv =
                    header["apv"]
                        ?.let { it as? JsonPrimitive }
                        ?.takeIf { it.isString }
                        ?.content
                if (expectedApv == null || actualApv != expectedApv) {
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "ISO 18013-7 Annex B response JWE apv does not match the authorization-request nonce",
                        ),
                    )
                }
                apu
            } else {
                null
            }

        val trustRequest = VerifierTrustedAuthenticationRequest(
                        tenantId = execution.tenantId,
                        verifierInstanceId = session.instanceId,
                        verifierId = session.verifierId,
                        dcqlQueryId = session.dcqlQueryId,
                        templateId = session.templateId,
                        originalRequest = session.authorizationRequest,
                        dcqlQuery = session.dcqlQuery,
                    )
        val authenticationResolver = trustedAuthenticationResolver?.invoke()
        // Holder trust material is resolved only when a requested credential is bound in a
        // format that authenticates the holder against it (compact JWS presentations). SD-JWT and
        // mdoc bind through the credential's own key and a credential that opts out of
        // cryptographic holder binding has no holder proof, so neither needs a holder
        // attachment. A missing or empty query, or an unrecognised format, stays on the
        // fail-closed resolution path.
        val requiresHolderAuthentication = requiresHolderAuthentication(session.dcqlQuery)
        val holderAuthentications =
            if (requiresHolderAuthentication) {
                authenticationResolver
                    ?.resolveTrustedAuthentications(trustRequest)
                    ?.getOrElse { return Err(it) }
                    .orEmpty()
            } else {
                emptyList()
            }
        if (holderAuthentications.any { it.purpose != TrustedAuthenticationPurpose.HOLDER }) {
            return Err(IdkError.fromString("holder authentication resolver returned credential-issuer material", code = "TRUST_AUTHENTICATION_PURPOSE_MISMATCH"))
        }
        val issuerAuthentications = authenticationResolver
            ?.resolveTrustedCredentialIssuerAuthentications(trustRequest)
            ?.getOrElse { return Err(it) }
            .orEmpty()
        if (issuerAuthentications.any { it.purpose != TrustedAuthenticationPurpose.CREDENTIAL_ISSUER }) {
            return Err(IdkError.fromString("credential issuer authentication resolver returned holder material", code = "TRUST_AUTHENTICATION_PURPOSE_MISMATCH"))
        }
        val trustedAuthentications = holderAuthentications + issuerAuthentications
        val issuerAuthenticationLookup = authenticationResolver?.credentialIssuerAuthenticationLookup(trustRequest)

        // Build args for the direct_post handler
        val directPostArgs =
            HandleDirectPostResponseArgs(
                responseParams = responseParams,
                originalRequest = session.authorizationRequest,
                sessionCorrelationId =
                    if (session.authorizationRequest.responseMode == ResponseMode.DC_API_JWT.value) session.correlationId else null,
                dcqlQuery = session.dcqlQuery,
                redirectUri = sessionRedirectUri,
                jarmDecryptionKey = jarmDecryptionKey,
                verifierEncryptionJwkThumbprint = verifierEncryptionJwkThumbprint,
                verifierId = session.verifierId,
                dcqlQueryId = session.dcqlQueryId,
                templateId = session.templateId,
                trustedAuthentications = trustedAuthentications,
                credentialIssuerAuthenticationLookup = issuerAuthenticationLookup,
                iso18013MdocGeneratedNonce = iso18013MdocGeneratedNonce,
            )

        // Delegate to the service command
        return handleDirectPostCommand.execute(directPostArgs).map { result ->
            // Per OID4VP 1.0: response is HTTP 200 with optional redirect_uri
            // containing response_code as fragment. When no redirect is configured,
            // return empty JSON — the wallet treats HTTP 200 as success.
            val includeRedirect = sessionRedirectUri.isNotBlank()
            GenericHttpResponse(
                statusCode = 200,
                headers =
                    mapOf(
                        "Content-Type" to "application/json",
                        "Cache-Control" to "no-store",
                    ),
                body =
                    json.encodeToString(
                        kotlinx.serialization.serializer(),
                        buildJsonObject {
                            if (includeRedirect) {
                                put("redirect_uri", result.redirectUri)
                            }
                        },
                    ),
            )
        }
    }

    /**
     * Read the `kid` parameter from the JWE Protected Header without performing any
     * decryption. The header is the first segment of the compact serialization
     * (`<header>.<encryptedKey>.<iv>.<ciphertext>.<tag>`), base64url-encoded JSON.
     *
     * Used by `direct_post.jwt` session lookup — wallets per OID4VP §8.3 MUST copy the
     * selected JWK's `kid` to the JWE Protected Header, and the universal command sets
     * that kid to the session correlationId, so a single store lookup resolves the
     * session before any decryption is attempted.
     */
    /**
     * The session of a `direct_post.jwt` response under the `openid_federation:` client identifier prefix. The wallet
     * encrypts to the key published in the verifier's federation metadata, whose `kid` is the key's thumbprint rather
     * than a session id (OpenID Federation for Wallet Architectures 1.0 §6.3.1), so the response names no session.
     * When [kid] is the thumbprint of the routed instance's response-encryption key, that key decrypts the response and
     * the `state` inside names the session, which must belong to the same instance and be a federation session.
     */
    private suspend fun federationSession(jwe: String?, kid: String): AuthorizationSession? {
        if (jwe == null) return null
        val kms = kms?.invoke() ?: return null
        val jweService = jweService?.invoke() ?: return null
        val instanceId = instanceIdProvider?.invoke()?.currentInstanceId()?.trim()?.takeIf { it.isNotEmpty() } ?: return null
        val keyName = responseEncryptionKeyConfig.resolveEncryptionKeyName(instanceId) ?: return null
        val publicJwk = VerifierFederationMetadata.publicJwk(kms, keyName) ?: return null
        if (VerifierFederationMetadata.kid(publicJwk) != kid) return null
        val parsed = runCatching { JweCompact.parse(jwe) }.getOrNull() ?: return null
        val decrypted =
            jweService
                .decryptJwe(
                    DecryptJweArgs(
                        jwe = parsed,
                        decryptor = ManagedOptsKeyInfo(identifier = KeyInfo<Nothing>(alias = keyName, keyVisibility = KeyVisibility.PRIVATE)),
                    ),
                ).getOrNull() ?: return null
        val plaintext = decrypted.plaintext?.decodeToString() ?: return null
        // A signed-then-encrypted response carries a JWS; its payload is read here only to find the session. The
        // response is verified in full afterwards, as every response is.
        val payloadJson =
            plaintext.split('.').takeIf { it.size == 3 }?.let { parts ->
                runCatching { parts[1].decodeFromBase64Url().decodeToString() }.getOrNull()
            } ?: plaintext
        val payload = runCatching { json.parseToJsonElement(payloadJson) as? JsonObject }.getOrNull() ?: return null
        val state =
            (payload["state"] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotBlank() } ?: return null
        val session = authorizationSessionStore.getByCorrelationId(state).getOrNull() ?: return null
        if (session.instanceId != instanceId) return null
        if (ClientIdScheme.fromClientId(session.authorizationRequest.clientId) != ClientIdScheme.OPENID_FEDERATION) return null
        return session
    }

    private fun extractKidFromJweHeader(jwe: String): String? {
        val firstDot = jwe.indexOf('.')
        if (firstDot <= 0) return null
        val headerB64 = jwe.substring(0, firstDot)
        return try {
            val headerJson = headerB64.decodeFromBase64Url().decodeToString()
            (json.parseToJsonElement(headerJson) as? kotlinx.serialization.json.JsonObject)
                ?.get("kid")
                ?.let { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
        } catch (expected: Exception) {
            null
        }
    }

    private fun requiresHolderAuthentication(dcqlQuery: DcqlQuery?): Boolean {
        val credentials = dcqlQuery?.credentials?.takeIf { it.isNotEmpty() } ?: return true
        return credentials.any { credential ->
            if (!credential.require_cryptographic_holder_binding) return@any false
            val format = CredentialFormat.fromValue(credential.format) ?: return@any true
            format.usesTrustedHolderAuthentication
        }
    }

    private fun extractJweHeader(jwe: String): kotlinx.serialization.json.JsonObject? {
        val firstDot = jwe.indexOf('.')
        if (firstDot <= 0) return null
        return runCatching {
            val headerJson = jwe.substring(0, firstDot).decodeFromBase64Url().decodeToString()
            json.parseToJsonElement(headerJson) as? kotlinx.serialization.json.JsonObject
        }.getOrNull()
    }

    private fun isIso18013AnnexBRequest(request: com.sphereon.oauth2.common.model.AuthorizationRequest): Boolean =
        request.responseMode == ResponseMode.DIRECT_POST_JWT.value &&
            request.additionalParameters.containsKey("presentation_definition") &&
            !request.additionalParameters.containsKey("dcql_query") &&
            request.additionalParameters["client_id_scheme"]
                ?.let { it as? JsonPrimitive }
                ?.takeIf { it.isString }
                ?.content == "x509_san_dns"

    /**
     * Parse application/x-www-form-urlencoded body into a map.
     */
    private fun parseFormBody(body: String?): Map<String, String> {
        if (body.isNullOrBlank()) return emptyMap()
        return body
            .split("&")
            .mapNotNull { param ->
                val parts = param.split("=", limit = 2)
                if (parts.size == 2) {
                    urlDecode(parts[0]) to urlDecode(parts[1])
                } else {
                    null
                }
            }.toMap()
    }

    private fun urlDecode(value: String): String =
        buildString {
            var i = 0
            while (i < value.length) {
                when {
                    value[i] == '%' && i + 2 < value.length -> {
                        val hex = value.substring(i + 1, i + 3)
                        append(hex.toInt(16).toChar())
                        i += 3
                    }

                    value[i] == '+' -> {
                        append(' ')
                        i++
                    }

                    else -> {
                        append(value[i])
                        i++
                    }
                }
            }
        }
}
