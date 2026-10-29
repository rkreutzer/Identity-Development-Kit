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

package com.sphereon.oauth2.server.authorization.impl.command.clientauth

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.interop.toCertificateDto
import com.sphereon.crypto.core.interop.toJwk
import com.sphereon.crypto.core.interop.x509CertificateFromDer
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkSet
import com.sphereon.crypto.jose.jws.JwsCompact
import com.sphereon.crypto.jose.jws.JwsUtils
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.config.isRequired
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.ClientCredentials
import com.sphereon.oauth2.server.authorization.command.ClientAuthenticationEndpoint
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthentication
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationArgs
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand
import com.sphereon.oauth2.server.authorization.command.clientauth.VerifyAttestationClientAuthArgs
import com.sphereon.oauth2.server.authorization.command.clientauth.VerifyAttestationClientAuthCommand
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.command.TokenPathStage
import com.sphereon.oauth2.server.authorization.impl.command.discovery.canonicalTokenEndpointForIssuer
import com.sphereon.oauth2.server.authorization.impl.command.TokenPathStageTimings
import com.sphereon.oauth2.server.authorization.impl.resolver.ClientJwksResolver
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientType
import com.sphereon.oauth2.server.authorization.storage.ClientAssertionJtiStore
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import com.sphereon.oauth2.server.authorization.impl.storage.memory.resolveInternalRequestView
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName
import kotlin.time.Clock
import kotlin.time.Instant

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of [VerifyClientAuthenticationCommand].
 *
 * Dispatches by [ClientAuthenticationConfig] variant to verify the client identity. Basic, Post,
 * SecretJwt, PrivateKeyJwt, mTLS (PKI + self-signed), and the registered-method enforcement live
 * here. Attestation-based authentication delegates to [VerifyAttestationClientAuthCommand]: that
 * extraction keeps the 14-step draft-ietf-oauth-attestation-based-client-auth-07 path
 * independently injectable and unit-testable without booting the HTTP stack.
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifyClientAuthenticationCommandImpl", exact = true)
@ExposeImplBinding
class VerifyClientAuthenticationCommandImpl(
    execution: SessionExecution,
    private val clientRegistry: ClientRegistry,
    private val jwtService: Lazy<JwtService>,
    private val configProvider: OAuth2ServersConfigProvider,
    private val clientJwksResolver: Lazy<ClientJwksResolver>,
    private val jtiStore: Lazy<ClientAssertionJtiStore>,
    private val verifyAttestationClientAuthCommand: Lazy<VerifyAttestationClientAuthCommand>,
) : TypedServiceCommandAdapter<VerifyClientAuthenticationArgs, VerifiedClientAuthentication, IdkError>(
        commandId = VerifyClientAuthenticationCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<VerifyClientAuthenticationArgs>(),
        outputTypeToken = typeToken<VerifiedClientAuthentication>(),
    ),
    VerifyClientAuthenticationCommand {
    override val commandId: String get() = VerifyClientAuthenticationCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is VerifyClientAuthenticationArgs

    override suspend fun doExecute(
        args: VerifyClientAuthenticationArgs,
        applyDuring: (VerifyClientAuthenticationArgs) -> VerifyClientAuthenticationArgs,
    ): IdkResult<VerifiedClientAuthentication, IdkError> {
        val timings = TokenPathStageTimings(operation = "client-authentication")
        var outcome = "failed"
        return try {
            verifyClientAuthentication(args, applyDuring, timings).also { result ->
                outcome = if (result.isOk) "success" else "rejected"
            }
        } finally {
            timings.report(log, outcome)
        }
    }

    private suspend fun verifyClientAuthentication(
        args: VerifyClientAuthenticationArgs,
        applyDuring: (VerifyClientAuthenticationArgs) -> VerifyClientAuthenticationArgs,
        timings: TokenPathStageTimings,
    ): IdkResult<VerifiedClientAuthentication, IdkError> {
        val applied = applyDuring(args)

        // Attestation-based authentication is delegated end-to-end. The delegated command already
        // returns IdkResult<_, IdkError>, so route around the local AuthorizationServerError ->
        // IdkError mapping rather than unwrapping and rewrapping.
        val attestationAuth = applied.clientAuthentication as? ClientAuthenticationConfig.AttestationJwt
        if (attestationAuth != null) {
            return verifyAttestationClientAuthCommand.value.execute(
                VerifyAttestationClientAuthArgs(
                    clientId = applied.clientId,
                    attestationJwt = attestationAuth.attestation.clientAttestationJwt,
                    popJwt = attestationAuth.attestation.clientAttestationPopJwt,
                    tokenEndpointUrl = applied.tokenEndpointUrl,
                    endpoint = applied.endpoint,
                ),
            )
        }

        if (applied.endpoint in WALLET_INSTANCE_ATTESTATION_REQUIRED_ENDPOINTS &&
            configProvider.serverConfig.walletInstanceAttestation.isRequired
        ) {
            return Err(
                IdkError.fromDTO(
                    AuthorizationServerError.InvalidClient(
                        details =
                            "Wallet Instance Attestation is required at ${applied.endpoint.name.lowercase()} and must use " +
                                "attestation-based client authentication",
                    ),
                ),
            )
        }

        return executeInternal(applied, timings).mapError { IdkError.fromDTO(it) }
    }

    private suspend fun executeInternal(
        args: VerifyClientAuthenticationArgs,
        timings: TokenPathStageTimings,
    ): IdkResult<VerifiedClientAuthentication, AuthorizationServerError> {
        val auth = args.clientAuthentication
        val credentialClientId =
            when (auth) {
                is ClientAuthenticationConfig.Basic -> auth.credentials.clientId
                is ClientAuthenticationConfig.Post -> auth.credentials.clientId
                else -> null
            }
        if (credentialClientId != null && credentialClientId != args.clientId) {
            return Err(AuthorizationServerError.InvalidClient(details = "Client credentials do not match requested client"))
        }
        val requestView =
            if (auth !is ClientAuthenticationConfig.Anonymous) {
                timings
                    .record(TokenPathStage.CLIENT_REGISTRY_VIEW) {
                        clientRegistry.resolveInternalRequestView()
                    }.getOrElse { return Err(it) }
            } else {
                null
            }

        // Anonymous has no identity to enforce; every other variant must match the registered
        // token_endpoint_auth_method up front per RFC 7591 §2 + OIDF Basic-OP conformance.
        // AttestationJwt is short-circuited in [doExecute] above and never reaches this path.
        val client =
            if (auth !is ClientAuthenticationConfig.Anonymous) {
                val resolved =
                    timings
                        .record(TokenPathStage.CLIENT_LOOKUP) { requestView!!.getClient(args.clientId) }
                        .getOrElse { return Err(it) }
                if (resolved == null) {
                    return Err(AuthorizationServerError.InvalidClient(details = "Unknown client '${args.clientId}'"))
                }
                resolved?.let { enforceRegisteredAuthMethod(auth, it)?.let { error -> return Err(error) } }
                resolved
            } else {
                null
            }

        val verified: IdkResult<VerifiedClientAuthentication, AuthorizationServerError> =
            timings.record(TokenPathStage.CREDENTIAL_VERIFICATION) {
                when (auth) {
                    is ClientAuthenticationConfig.Basic -> {
                        verifyClientSecret(
                            credentials = auth.credentials,
                            method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                            clientRegistryView = requestView!!,
                        )
                    }

                    is ClientAuthenticationConfig.Post -> {
                        verifyClientSecret(
                            credentials = auth.credentials,
                            method = ClientAuthenticationMethod.CLIENT_SECRET_POST,
                            clientRegistryView = requestView!!,
                        )
                    }

                    is ClientAuthenticationConfig.SecretJwt -> {
                        verifyJwtAssertion(auth, args.clientId, args.tokenEndpointUrl, client!!, args.endpoint)
                    }

                    is ClientAuthenticationConfig.PrivateKeyJwt -> {
                        verifyJwtAssertion(auth, args.clientId, args.tokenEndpointUrl, client!!, args.endpoint)
                    }

                    is ClientAuthenticationConfig.AttestationJwt -> {
                        error("AttestationJwt is handled in doExecute and never reaches executeInternal")
                    }

                    is ClientAuthenticationConfig.None -> {
                        Ok(VerifiedClientAuthentication(clientId = args.clientId, method = ClientAuthenticationMethod.NONE))
                    }

                    ClientAuthenticationConfig.Anonymous -> {
                        Ok(VerifiedClientAuthentication(clientId = args.clientId, method = ClientAuthenticationMethod.NONE))
                    }

                    is ClientAuthenticationConfig.MutualTls -> {
                        verifyMutualTlsAuth(auth, args.clientId, client!!)
                    }
                }
            }
        return verified.flatMap { result ->
            if (client == null) {
                Ok(result)
            } else if (result.clientId != client.clientId) {
                Err(AuthorizationServerError.InvalidClient(details = "Authenticated client does not match resolved client"))
            } else {
                Ok(result.copy(clientAuthorization = client.toVerifiedClientAuthorization()))
            }
        }
    }

    /**
     * Enforce the client's registered `token_endpoint_auth_method` (RFC 7591 §2). The method the
     * client actually used on this request must equal the one registered. Additionally, `none` is
     * only permitted for public clients (OIDC Core §3.1.2.1 + OIDF Basic-OP §2).
     *
     * @return `null` when the presented method matches the registration; an `InvalidClient` error otherwise.
     */
    private fun enforceRegisteredAuthMethod(
        auth: ClientAuthenticationConfig,
        client: ClientRegistration,
    ): AuthorizationServerError.InvalidClient? {
        val presented =
            when (auth) {
                is ClientAuthenticationConfig.Basic -> {
                    ClientAuthenticationMethod.CLIENT_SECRET_BASIC
                }

                is ClientAuthenticationConfig.Post -> {
                    ClientAuthenticationMethod.CLIENT_SECRET_POST
                }

                is ClientAuthenticationConfig.SecretJwt -> {
                    ClientAuthenticationMethod.CLIENT_SECRET_JWT
                }

                is ClientAuthenticationConfig.PrivateKeyJwt -> {
                    ClientAuthenticationMethod.PRIVATE_KEY_JWT
                }

                is ClientAuthenticationConfig.None -> {
                    ClientAuthenticationMethod.NONE
                }

                // Unreachable: AttestationJwt and Anonymous were filtered out by the caller.
                is ClientAuthenticationConfig.AttestationJwt -> {
                    ClientAuthenticationMethod.ATTEST_JWT_CLIENT_AUTH
                }

                ClientAuthenticationConfig.Anonymous -> {
                    ClientAuthenticationMethod.NONE
                }

                // RFC 8705: presented method is the one registered on the client. The verifier
                // dispatches the actual PKI vs self-signed branch from the registered method.
                is ClientAuthenticationConfig.MutualTls -> {
                    if (client.tokenEndpointAuthMethod == ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH) {
                        ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH
                    } else {
                        ClientAuthenticationMethod.TLS_CLIENT_AUTH
                    }
                }
            }

        if (presented == ClientAuthenticationMethod.NONE && client.clientType != ClientType.PUBLIC) {
            return AuthorizationServerError.InvalidClient(
                details = "Client '${client.clientId}' is confidential; authentication method 'none' is only permitted for public clients",
            )
        }

        if (presented != client.tokenEndpointAuthMethod) {
            return AuthorizationServerError.InvalidClient(
                details = "Client '${client.clientId}' is registered for token_endpoint_auth_method='${client.tokenEndpointAuthMethod.value}' but presented '${presented.value}'",
            )
        }

        return null
    }

    private suspend fun verifyClientSecret(
        credentials: ClientCredentials,
        method: ClientAuthenticationMethod,
        clientRegistryView: ClientRegistry,
    ): IdkResult<VerifiedClientAuthentication, AuthorizationServerError> {
        val valid =
            clientRegistryView
                .verifyClientCredentials(credentials.clientId, credentials.clientSecret)
                .getOrElse { return Err(it) }

        if (!valid) {
            return Err(AuthorizationServerError.InvalidClient(details = "Invalid client credentials"))
        }

        return Ok(VerifiedClientAuthentication(clientId = credentials.clientId, method = method))
    }

    private suspend fun verifyJwtAssertion(
        auth: ClientAuthenticationConfig,
        clientId: String,
        tokenEndpointUrl: String,
        client: ClientRegistration,
        endpoint: ClientAuthenticationEndpoint,
    ): IdkResult<VerifiedClientAuthentication, AuthorizationServerError> {
        val assertion =
            when (auth) {
                is ClientAuthenticationConfig.SecretJwt -> auth.assertion
                is ClientAuthenticationConfig.PrivateKeyJwt -> auth.assertion
                else -> return Err(AuthorizationServerError.InvalidClient(details = "Unexpected auth type"))
            }

        // Decode the JWT header before handing the assertion to the JWT service so we can bind it
        // to the client's registered JWKS / signing algs .
        val header =
            parseJwtHeader(assertion.assertion)
                ?: return Err(AuthorizationServerError.InvalidClient(details = "JWT assertion header is not valid JSON"))

        val alg =
            header["alg"]?.let { it as? JsonPrimitive }?.takeIf { it.isString }?.content
                ?: return Err(AuthorizationServerError.InvalidClient(details = "JWT assertion header missing or invalid 'alg'"))
        if (alg == "none") {
            return Err(AuthorizationServerError.InvalidClient(details = "JWT assertion 'alg=none' is not permitted"))
        }

        // client_secret_jwt MUST use an HMAC-based algorithm; private_key_jwt MUST NOT (RFC 7518 §3.2 +
        // OIDC Core §9 — different key material per method). Enforce that independent of the
        // registered allow-list so a misconfigured `token_endpoint_auth_signing_alg` can't relax the
        // binding .
        val isHmac = alg in SUPPORTED_HS_ALGS
        if (auth is ClientAuthenticationConfig.SecretJwt && !isHmac) {
            return Err(
                AuthorizationServerError.InvalidClient(
                    details = "client_secret_jwt requires an HMAC alg (HS256/HS384/HS512); got '$alg'",
                ),
            )
        }
        if (auth is ClientAuthenticationConfig.PrivateKeyJwt && isHmac) {
            return Err(
                AuthorizationServerError.InvalidClient(
                    details = "private_key_jwt must use an asymmetric signing alg; got HMAC alg '$alg'",
                ),
            )
        }

        val expectedAlgs = resolveExpectedSigningAlgs(auth, client)
        if (alg !in expectedAlgs) {
            return Err(
                AuthorizationServerError.InvalidClient(
                    details = "JWT assertion alg '$alg' is not permitted for client '${client.clientId}' (registered: ${expectedAlgs.joinToString()})",
                ),
            )
        }

        // For private_key_jwt, require the kid to resolve inside the client's registered JWKS and
        // pin signature verification to that registered public key. Passing only the compact JWS
        // would make the generic verifier treat the header kid as a managed-KMS identifier, which
        // is the wrong trust domain for an external OAuth client.
        val trustedClientJwks =
            if (auth is ClientAuthenticationConfig.PrivateKeyJwt) {
            val kid =
                header["kid"]?.let { it as? JsonPrimitive }?.takeIf { it.isString }?.content?.takeIf { it.isNotBlank() }
                    ?: return Err(AuthorizationServerError.InvalidClient(details = "private_key_jwt assertion header missing or invalid 'kid'"))
            val jwks = clientJwksResolver.value.resolveFor(client).getOrElse { return Err(it) }
            val matched = jwks.firstOrNull { it.kid == kid }
            if (matched == null) {
                return Err(
                    AuthorizationServerError.InvalidClient(
                        details = "private_key_jwt 'kid=$kid' does not match any key in client '${client.clientId}' registered JWKS",
                    ),
                )
            }
                Json.encodeToJsonElement(JwkSet.serializer(), JwkSet(keys = arrayOf(matched))).jsonObject
            } else {
                null
            }

        // Verify JWT signature
        val verifyResult =
            jwtService.value
                .verifyJws(VerifyJwsArgs(jws = JwsCompact(assertion.assertion), trustedJwks = trustedClientJwks))
                .getOrElse {
                    return Err(
                        AuthorizationServerError.InvalidClient(
                            details = "JWT assertion signature verification failed: ${it.message.defaultMessage}",
                        ),
                    )
                }

        if (!verifyResult.isValid) {
            return Err(
                AuthorizationServerError.InvalidClient(
                    details = "JWT assertion signature invalid: ${verifyResult.errorMessages.joinToString()}",
                ),
            )
        }

        // Validate claims (already decoded during verification) per OIDC Core §9 / RFC 7523 §3
        // .
        val claimsValidation =
            validateAssertionClaims(
                claims = verifyResult.parsedPayload,
                clientId = clientId,
                tokenEndpointUrl = tokenEndpointUrl,
                requirePrivateKeyJwtIssuerAudience = auth is ClientAuthenticationConfig.PrivateKeyJwt,
                requireFederatedParIssuerAudience = auth is ClientAuthenticationConfig.PrivateKeyJwt &&
                    endpoint == ClientAuthenticationEndpoint.PAR &&
                    client.authorizationRequestProofPolicy == com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC,
                serverConfig = configProvider.serverConfig,
            )
        claimsValidation.getOrElse { return Err(it) }

        val method =
            when (auth) {
                is ClientAuthenticationConfig.SecretJwt -> ClientAuthenticationMethod.CLIENT_SECRET_JWT
                is ClientAuthenticationConfig.PrivateKeyJwt -> ClientAuthenticationMethod.PRIVATE_KEY_JWT
                else -> ClientAuthenticationMethod.NONE
            }

        return Ok(VerifiedClientAuthentication(clientId = clientId, method = method))
    }

    /**
     * Validate required assertion claims. This AS applies a selected stricter private_key_jwt
     * profile requiring the configured issuer or its canonical token endpoint as the sole audience; this is not a universal
     * RFC 7523 / OIDC Core §9 rule. client_secret_jwt retains its supported RFC 7523 audience set.
     *
     * - `iss` MUST equal `sub` AND equal `client_id` (both directions, not either-or).
     * - Federation automatic-registration PAR (Connect Federation 1.1 sections 12.1.1.2/12.1.1.2.1): only the AS Entity Identifier is allowed.
     * - Other private_key_jwt: the fixed configured AS issuer or its canonical token endpoint MUST be the sole `aud` value.
     * - client_secret_jwt: `aud` may identify the AS issuer or token endpoint; arrays retain the
     *   supported membership semantics.
     * - `exp` MUST be present and in the future.
     * - `iat`, if present, MUST be within ±5 minutes of now (5 min clock-skew window).
     * - `jti` MUST be present and MUST NOT replay within the assertion lifetime (uses [jtiStore]).
     */
    private suspend fun validateAssertionClaims(
        claims: JsonObject,
        clientId: String,
        tokenEndpointUrl: String,
        requirePrivateKeyJwtIssuerAudience: Boolean,
        requireFederatedParIssuerAudience: Boolean,
        serverConfig: OAuth2ServerInstanceConfig,
    ): IdkResult<Unit, AuthorizationServerError> {
        val issValue = claims["iss"]
        val subValue = claims["sub"]
        val iss = (issValue as? JsonPrimitive)?.takeIf { it.isString }?.content
        val sub = (subValue as? JsonPrimitive)?.takeIf { it.isString }?.content
        if (iss.isNullOrBlank() || sub.isNullOrBlank()) {
            return Err(AuthorizationServerError.InvalidClient(details = "JWT assertion missing 'iss' or 'sub'"))
        }
        if (iss != clientId || sub != clientId) {
            return Err(
                AuthorizationServerError.InvalidClient(
                    details = "JWT assertion iss/sub must both equal client_id; got iss='$iss' sub='$sub' client_id='$clientId'",
                ),
            )
        }

        val audienceValue = claims["aud"]
        val strictAudienceShapeIsValid =
            when (audienceValue) {
                is JsonPrimitive -> audienceValue.isString
                is JsonArray -> audienceValue.all { (it as? JsonPrimitive)?.isString == true }
                else -> false
            }
        val audiences =
            when (val aud = audienceValue) {
                is JsonPrimitive -> listOfNotNull(aud.takeIf { it.isString }?.content)
                is JsonArray -> aud.mapNotNull { (it as? JsonPrimitive)?.takeIf { value -> value.isString }?.content }
                else -> emptyList()
            }
        val configuredIssuer = serverConfig.issuer
        val audienceAccepted =
            if (!strictAudienceShapeIsValid) {
                false
            } else if (requireFederatedParIssuerAudience) {
                val issuer = configuredIssuer?.takeIf { it.isNotBlank() }
                issuer != null && audiences.size == 1 && audiences.single() == issuer
            } else if (requirePrivateKeyJwtIssuerAudience) {
                val issuer = configuredIssuer?.takeIf { it.isNotBlank() }
                issuer != null && audiences.size == 1 &&
                    (audiences.single() == issuer || audiences.single() == canonicalTokenEndpointForIssuer(issuer))
            } else {
                audiences.any { it == configuredIssuer || it == tokenEndpointUrl }
            }
        if (!audienceAccepted) {
            return Err(
                AuthorizationServerError.InvalidClient(
                    details =
                        if (requireFederatedParIssuerAudience) {
                            "Federated PAR private_key_jwt audience must be the configured AS Entity Identifier only"
                        } else if (requirePrivateKeyJwtIssuerAudience) {
                            "private_key_jwt audience must be one string equal to the configured AS issuer or its canonical token endpoint"
                        } else {
                            "JWT assertion audience must identify the AS issuer or token endpoint"
                        },
                ),
            )
        }

        val expValue = claims["exp"]
        val expSeconds = (expValue as? JsonPrimitive)?.takeUnless { it.isString }?.content?.toLongOrNull()
            ?: return Err(AuthorizationServerError.InvalidClient(details = "JWT assertion missing or invalid 'exp'"))
        val now = Clock.System.now()
        val exp = Instant.fromEpochSeconds(expSeconds)
        if (exp <= now) {
            return Err(AuthorizationServerError.InvalidClient(details = "JWT assertion has expired"))
        }

        val iatValue = claims["iat"]
        val iatSeconds = iatValue?.let { (it as? JsonPrimitive)?.takeUnless { primitive -> primitive.isString }?.content?.toLongOrNull() }
        if (iatValue != null && iatSeconds == null) {
            return Err(AuthorizationServerError.InvalidClient(details = "JWT assertion 'iat' is invalid"))
        }
        if (iatSeconds != null) {
            val iat = Instant.fromEpochSeconds(iatSeconds)
            val skew = now - iat
            val maxSkewSeconds = ASSERTION_IAT_SKEW_SECONDS
            if (skew.inWholeSeconds > maxSkewSeconds || (-skew.inWholeSeconds) > maxSkewSeconds) {
                return Err(
                    AuthorizationServerError.InvalidClient(
                        details = "JWT assertion 'iat' is outside the ±${maxSkewSeconds}s window",
                    ),
                )
            }
        }

        val jtiValue = claims["jti"]
        val jti = (jtiValue as? JsonPrimitive)?.takeIf { it.isString }?.content
        if (jti.isNullOrBlank()) {
            return Err(AuthorizationServerError.InvalidClient(details = "JWT assertion missing 'jti'"))
        }
        val isNewJti = jtiStore.value.recordIfNew(clientId = clientId, jti = jti, expiresAt = exp)
        if (!isNewJti) {
            return Err(AuthorizationServerError.InvalidClient(details = "JWT assertion 'jti' has already been used"))
        }

        return Ok(Unit)
    }

    /**
     * Resolve the set of signing algorithms that are acceptable for this client's JWT-based
     * authentication method. If the client explicitly registered `token_endpoint_auth_signing_alg`,
     * that allow-list is authoritative. Otherwise the per-method OIDC Core §9 defaults apply
     * (RS256 for private_key_jwt, HS256 for client_secret_jwt).
     */
    private fun resolveExpectedSigningAlgs(
        auth: ClientAuthenticationConfig,
        client: ClientRegistration,
    ): List<String> {
        val registered = client.tokenEndpointAuthSigningAlg
        if (!registered.isNullOrEmpty()) {
            return registered
        }
        return when (auth) {
            is ClientAuthenticationConfig.PrivateKeyJwt -> listOf("RS256")
            is ClientAuthenticationConfig.SecretJwt -> listOf("HS256")
            else -> emptyList()
        }
    }

    /**
     * RFC 8705 §2 client authentication: dispatches by the client's registered method to either
     * the self-signed mode (cert public key matches a registered JWK) or the PKI mode (cert
     * subject DN / SAN match a registered fixed value). The TLS handshake itself was already
     * completed by the AS edge; the cert in [ClientAuthenticationConfig.MutualTls.clientCertificateDer]
     * is the verified peer cert.
     */
    private suspend fun verifyMutualTlsAuth(
        auth: ClientAuthenticationConfig.MutualTls,
        clientId: String,
        client: ClientRegistration,
    ): IdkResult<VerifiedClientAuthentication, AuthorizationServerError> {
        if (auth.clientId != clientId) {
            return Err(
                AuthorizationServerError.InvalidClient(
                    details = "client_id mismatch between TLS auth and request body",
                ),
            )
        }

        return when (client.tokenEndpointAuthMethod) {
            ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH -> {
                verifySelfSignedTlsAuth(auth.clientCertificateDer, clientId, client)
            }

            ClientAuthenticationMethod.TLS_CLIENT_AUTH -> {
                verifyPkiTlsAuth(auth.clientCertificateDer, clientId, client)
            }

            else -> {
                Err(
                    AuthorizationServerError.InvalidClient(
                        details = "Client '$clientId' is not registered for mutual-TLS authentication",
                    ),
                )
            }
        }
    }

    /**
     * RFC 8705 §2.2: the cert's public key MUST match a JWK registered for this client (with
     * `use=sig` or unspecified). The verifier rebuilds the cert's SubjectPublicKeyInfo as a JWK
     * and compares the canonical key material against each registered key.
     */
    private suspend fun verifySelfSignedTlsAuth(
        certDer: ByteArray,
        clientId: String,
        client: ClientRegistration,
    ): IdkResult<VerifiedClientAuthentication, AuthorizationServerError> {
        val certJwk =
            try {
                val cert = x509CertificateFromDer(certDer)
                cert.tbsCertificate.subjectPublicKeyInfo.toJwk()
            } catch (expected: Exception) {
                return Err(
                    AuthorizationServerError.InvalidClient(
                        details = "TLS client certificate could not be parsed: ${expected.message}",
                    ),
                )
            }

        val registeredKeys =
            clientJwksResolver.value
                .resolveFor(client)
                .getOrElse { return Err(it) }
                .filter { it.use == null || it.use == "sig" }

        val matches = registeredKeys.any { keysShareSamePublicMaterial(it, certJwk) }
        if (!matches) {
            return Err(
                AuthorizationServerError.InvalidClient(
                    details =
                        "TLS client certificate public key does not match any JWK registered " +
                            "for client '$clientId' (self_signed_tls_client_auth)",
                ),
            )
        }

        return Ok(
            VerifiedClientAuthentication(
                clientId = clientId,
                method = ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH,
            ),
        )
    }

    /**
     * RFC 8705 §2.1: PKI mode. The cert chain is presumed validated by the TLS engine against
     * the operator-configured trust anchors; this verifier only enforces the additional
     * AS-bound subject identity match registered on the client. The registration MUST set
     * exactly one of (subject DN, dnsName SAN, email SAN, IP SAN, URI SAN); the verifier picks
     * the first non-null and compares it.
     */
    private fun verifyPkiTlsAuth(
        certDer: ByteArray,
        clientId: String,
        client: ClientRegistration,
    ): IdkResult<VerifiedClientAuthentication, AuthorizationServerError> {
        val certDto =
            try {
                x509CertificateFromDer(certDer).toCertificateDto()
            } catch (expected: Exception) {
                return Err(
                    AuthorizationServerError.InvalidClient(
                        details = "TLS client certificate could not be parsed: ${expected.message}",
                    ),
                )
            }

        // Subject DN match (RFC 8705 §2.1.2.1).
        client.tlsClientAuthSubjectDn?.let { expected ->
            val actual = certDto.subjectDN
            return if (canonicalDn(actual) == canonicalDn(expected)) {
                Ok(
                    VerifiedClientAuthentication(
                        clientId = clientId,
                        method = ClientAuthenticationMethod.TLS_CLIENT_AUTH,
                    ),
                )
            } else {
                Err(
                    AuthorizationServerError.InvalidClient(
                        details =
                            "TLS client certificate subject DN '$actual' does not match " +
                                "registered '$expected' for client '$clientId'",
                    ),
                )
            }
        }

        val sans = certDto.subjectAlternativeNames
        client.tlsClientAuthSanDns?.let { expected ->
            return matchSan(clientId, "dnsName", expected, sans?.dnsNames.orEmpty())
        }
        client.tlsClientAuthSanEmail?.let { expected ->
            return matchSan(clientId, "rfc822Name", expected, sans?.emails.orEmpty())
        }
        client.tlsClientAuthSanIp?.let { expected ->
            return matchSan(clientId, "iPAddress", expected, sans?.ipAddresses.orEmpty())
        }
        client.tlsClientAuthSanUri?.let { expected ->
            return matchSan(clientId, "uniformResourceIdentifier", expected, sans?.uris.orEmpty())
        }

        return Err(
            AuthorizationServerError.InvalidClient(
                details =
                    "Client '$clientId' is registered for tls_client_auth but no subject DN " +
                        "or SAN identifier is configured",
            ),
        )
    }

    private fun matchSan(
        clientId: String,
        sanType: String,
        expected: String,
        actuals: List<String>,
    ): IdkResult<VerifiedClientAuthentication, AuthorizationServerError> {
        if (actuals.any { it == expected }) {
            return Ok(
                VerifiedClientAuthentication(
                    clientId = clientId,
                    method = ClientAuthenticationMethod.TLS_CLIENT_AUTH,
                ),
            )
        }
        return Err(
            AuthorizationServerError.InvalidClient(
                details =
                    "TLS client certificate SAN ($sanType) does not contain registered value '$expected' " +
                        "for client '$clientId'",
            ),
        )
    }

    /**
     * RFC 4514 canonical DN comparison: normalize whitespace around `,` and `=` and lowercase
     * attribute types so equivalent encodings compare equal. Full RFC-compliant canonicalisation
     * (string-prep, attribute-type OID resolution) is deferred; this covers the common cases
     * (case differences in attribute types, spacing variation) for OIDF-style fixtures.
     */
    private fun canonicalDn(value: String): String =
        value
            .split(",")
            .joinToString(",") { rdn ->
                val parts = rdn.trim().split("=", limit = 2)
                if (parts.size == 2) {
                    "${parts[0].trim().lowercase()}=${parts[1].trim()}"
                } else {
                    rdn.trim()
                }
            }

    /**
     * Public-material comparison between two JWKs without resorting to RFC 7638 thumbprint
     * (which would require canonical JCS). For the AS use case the registered JWK and the cert's
     * recomputed JWK come from the same library, so direct field equality is sufficient.
     */
    private fun keysShareSamePublicMaterial(
        a: Jwk,
        b: Jwk,
    ): Boolean {
        if (a.kty != b.kty) {
            return false
        }
        return when (a.kty) {
            JwaKeyType.RSA -> a.n == b.n && a.e == b.e
            JwaKeyType.EC -> a.crv == b.crv && a.x == b.x && a.y == b.y
            JwaKeyType.OKP -> a.crv == b.crv && a.x == b.x
            JwaKeyType.oct -> false
        }
    }

    /**
     * Parse the header portion of a JWT without full verification.
     */
    private fun parseJwtHeader(jwt: String): JsonObject? {
        return try {
            val parts = jwt.split(".")
            if (parts.size < 2) {
                return null
            }
            JwsUtils.decodeBase64UrlToJson(parts[0])
        } catch (_: Exception) {
            null
        }
    }

    companion object {
        private val SUPPORTED_HS_ALGS = setOf("HS256", "HS384", "HS512")
        private val WALLET_INSTANCE_ATTESTATION_REQUIRED_ENDPOINTS =
            setOf(ClientAuthenticationEndpoint.PAR, ClientAuthenticationEndpoint.TOKEN)

        /** ±5 minutes, OIDC Core §9 clock-skew window applied to the assertion `iat`. */
        private const val ASSERTION_IAT_SKEW_SECONDS: Long = 300
    }
}
