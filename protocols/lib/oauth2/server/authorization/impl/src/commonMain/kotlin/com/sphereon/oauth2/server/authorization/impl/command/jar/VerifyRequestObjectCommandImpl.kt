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

@file:Suppress("ReturnCount", "TooGenericExceptionCaught", "LongMethod", "CyclomaticComplexMethod")

package com.sphereon.oauth2.server.authorization.impl.command.jar

import com.sphereon.core.api.Encoding
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFrom
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkSet
import com.sphereon.crypto.jose.jws.JwsCompact
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.crypto.resolution.AdditionalIdentifierLookup
import com.sphereon.crypto.resolution.extern.ExternalIdentifierJwksUrlOpts
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.FetchRequestUriArgs
import com.sphereon.ktor.http.client.FetchRequestUriCommand
import com.sphereon.ktor.http.client.RequestUriMethod
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.config.isEnabled
import com.sphereon.oauth2.server.authorization.command.jar.VerifiedRequestObject
import com.sphereon.oauth2.server.authorization.command.jar.VerifyRequestObjectArgs
import com.sphereon.oauth2.server.authorization.command.jar.VerifyRequestObjectCommand
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.storage.ClientAssertionJtiStore
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.time.Duration.Companion.seconds

/**
 * Server-side implementation of RFC 9101 (JAR) acceptance.
 *
 * The flow:
 *   1. Both `request` and `request_uri` present, fail with `invalid_request` per RFC 9101 §5.
 *   2. For `request_uri`, fetch the body via [FetchRequestUriCommand]; for `request`, treat the
 *      input as the JWT directly.
 *   3. Decode the JWS header without trusting it. Refuse `alg=none` (RFC 9101 §6 / RFC 8725 §2.1).
 *   4. Resolve the client by the JWT's `iss` / `client_id` claim (cross-checking against the
 *      front-channel `client_id` hint when the caller supplied one, OIDC Core §6.1).
 *   5. Select the verification key by precedence: the client's inline `jwks` (pinned-JWKS mode,
 *      resolvers disabled) when present, otherwise resolve the client's registered https
 *      `jwks_uri` (kid-pinned) via [VerifyJwsCommand]'s identifier-resolution path; fail closed
 *      when neither is configured.
 *   6. Validate `typ`, `aud`, `iss`, `exp`, `iat` per RFC 9101 §10.
 *   7. Strip JWT-only claims and merge the JAR claims onto the front-channel parameters per
 *      RFC 9101 §6.1 (signed claims win).
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<VerifyRequestObjectCommand>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifyRequestObjectCommandImpl", exact = true)
class VerifyRequestObjectCommandImpl(
    execution: SessionExecution,
    private val clientRegistry: ClientRegistry,
    private val verifyJwsCommand: VerifyJwsCommand,
    private val fetchRequestUriCommand: FetchRequestUriCommand,
    private val serversConfigProvider: OAuth2ServersConfigProvider,
    private val jtiStore: Lazy<ClientAssertionJtiStore>,
    private val actualAsSelection: com.sphereon.oauth2.common.config.OAuth2ServerInstanceIdProvider,
) : TypedServiceCommandAdapter<VerifyRequestObjectArgs, VerifiedRequestObject, IdkError>(
        commandId = VerifyRequestObjectCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<VerifyRequestObjectArgs>(),
        outputTypeToken = typeToken<VerifiedRequestObject>(),
    ),
    VerifyRequestObjectCommand {
    override val commandId: String get() = VerifyRequestObjectCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is VerifyRequestObjectArgs

    override suspend fun doExecute(
        args: VerifyRequestObjectArgs,
        applyDuring: (VerifyRequestObjectArgs) -> VerifyRequestObjectArgs,
    ): IdkResult<VerifiedRequestObject, IdkError> {
        val applied = applyDuring(args)
        return executeInternal(applied).mapError { IdkError.fromDTO(it) }
    }

    private suspend fun executeInternal(args: VerifyRequestObjectArgs): IdkResult<VerifiedRequestObject, AuthorizationServerError> {
        val serverConfig = serversConfigProvider.serverConfig
        if (!serverConfig.jar.isEnabled) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "JAR (RFC 9101) is disabled on this authorization server",
                ),
            )
        }

        if (args.requestJwt != null && args.requestUri != null) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "request and request_uri MUST NOT both be present (RFC 9101 §5)",
                ),
            )
        }

        val requestJwt = args.requestJwt
        val requestUri = args.requestUri
        val signedJwt: String =
            when {
                requestJwt != null -> {
                    requestJwt
                }

                requestUri != null -> {
                    val fetched = fetchAndExtractJwt(requestUri)
                    if (fetched.isErr) return Err(fetched.error)
                    fetched.value
                }

                else -> {
                    return Err(
                        AuthorizationServerError.InvalidRequest(
                            details = "Either request or request_uri must be supplied",
                        ),
                    )
                }
            }

        val parts = signedJwt.split(".")
        if (parts.size != JWS_PART_COUNT) {
            return Err(
                AuthorizationServerError.InvalidRequestObject(
                    details = "JAR is not a compact JWS (expected 3 parts, got ${parts.size})",
                ),
            )
        }

        val header =
            decodeBase64UrlJson(parts[0])
                ?: return Err(AuthorizationServerError.InvalidRequestObject(details = "Malformed JAR protected header"))
        val payload =
            decodeBase64UrlJson(parts[1])
                ?: return Err(AuthorizationServerError.InvalidRequestObject(details = "Malformed JAR payload"))

        val alg = header["alg"]?.jsonPrimitive?.content
        if (alg.isNullOrBlank()) {
            return Err(AuthorizationServerError.InvalidRequestObject(details = "JAR header missing 'alg'"))
        }
        if (alg.equals("none", ignoreCase = true)) {
            return Err(
                AuthorizationServerError.InvalidRequestObject(
                    details = "JAR with alg='none' is forbidden (RFC 9101 §6 / RFC 8725 §2.1)",
                ),
            )
        }

        // A present typ must be the JAR media type. An absent typ is decided once the client is known:
        // only OpenID Federation RPs may omit it (see below).
        val typ = header["typ"]?.jsonPrimitive?.content
        val typError = AuthorizationServerError.InvalidRequestObject(
            details = "JAR header 'typ' must be '${VerifyRequestObjectCommand.JAR_JWT_TYP}', got '$typ' (RFC 9101 §10.8)",
        )
        if (typ != null && typ != VerifyRequestObjectCommand.JAR_JWT_TYP) {
            return Err(typError)
        }

        // RFC 9101 §6.1 + OIDC Core §6.1: the JAR's `iss` (and inner `client_id`) MUST match the
        // front-channel `client_id` hint. The verifier resolves the client by the JWT-asserted
        // identity to fetch its keys, then enforces the cross-check.
        val jarIss = payload["iss"]?.jsonPrimitive?.content
        val jarClientId = payload["client_id"]?.jsonPrimitive?.content
        // Both claims name the same client; OpenID Federation for OpenID Connect 1.1 §12.1.1.1 requires both to be the
        // RP's Entity Identifier for Automatic Registration.
        if (jarIss != null && jarClientId != null && jarIss != jarClientId) {
            return Err(
                AuthorizationServerError.InvalidRequestObject(
                    details = "JAR 'iss' '$jarIss' and 'client_id' '$jarClientId' must name the same client",
                ),
            )
        }
        val resolvedClientId =
            jarIss ?: jarClientId
                ?: return Err(
                    AuthorizationServerError.InvalidRequestObject(
                        details = "JAR is missing both 'iss' and 'client_id' claims",
                    ),
                )

        val hint = args.clientIdHint
        if (hint != null && hint != resolvedClientId) {
            return Err(
                AuthorizationServerError.InvalidRequestObject(
                    details = "JAR 'iss' / 'client_id' '$resolvedClientId' does not match front-channel client_id '$hint'",
                ),
            )
        }

        val clientResult = clientRegistry.getClient(resolvedClientId)
        if (clientResult.isErr) {
            return Err(
                AuthorizationServerError.InvalidRequestObject(
                    details = "Failed to load client '$resolvedClientId': ${clientResult.error.message.defaultMessage}",
                ),
            )
        }
        val client =
            clientResult.value
                ?: return Err(
                    AuthorizationServerError.InvalidRequestObject(
                        details = "Unknown client '$resolvedClientId'",
                    ),
                )

        val federationProofRequired = client.authorizationRequestProofPolicy == com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC
        // OpenID Federation 1.1 §12.1.1.1 defines the Request Object without typ, and RFC 9101 §10.8 notes
        // that requiring it breaks OpenID Connect deployments. A federation RP may omit it; its Request Object
        // still has to pass every Connect check below (no sub, signed iss and client_id, aud, jti, exp).
        if (typ == null && !federationProofRequired) {
            return Err(typError)
        }
        val federationScope = if (federationProofRequired) {
            try { com.sphereon.oauth2.server.authorization.impl.command.authorization.captureFederationAuthorizationScope(execution, serversConfigProvider, actualAsSelection) }
            catch (expected: IllegalArgumentException) { return Err(AuthorizationServerError.InvalidRequestObject(details = "Federation AS scope is unavailable")) }
            catch (expected: IllegalStateException) { return Err(AuthorizationServerError.InvalidRequestObject(details = "Federation AS scope is unavailable")) }
        } else null
        if (federationScope != null && federationScope.issuer != args.issuer) {
            return Err(AuthorizationServerError.InvalidRequestObject(details = "JAR issuer scope does not match the selected AS"))
        }
        if (federationProofRequired && (payload.containsKey("request") || payload.containsKey("request_uri"))) {
            return Err(AuthorizationServerError.InvalidRequestObject(details = "Federation Request Object cannot contain request or request_uri"))
        }
        if ((client.singleUseRequestObjects || federationProofRequired) && (jarIss != resolvedClientId || jarClientId != resolvedClientId)) {
            return Err(AuthorizationServerError.InvalidRequestObject(
                details = "Federation JAR must contain both signed iss and client_id naming the RP Entity Identifier",
            ))
        }

        val pinnedAlg = client.requestObjectSigningAlg
        if (pinnedAlg != null && !pinnedAlg.equals(alg, ignoreCase = false)) {
            return Err(
                AuthorizationServerError.InvalidRequestObject(
                    details = "JAR alg '$alg' does not match client's registered request_object_signing_alg '$pinnedAlg'",
                ),
            )
        }

        val advertisedAlgs =
            serverConfig.requestObjectSigningAlgValuesSupported
                ?: serverConfig.idTokenSigningAlgValuesSupported
        if (advertisedAlgs != null && advertisedAlgs.isNotEmpty() && alg !in advertisedAlgs) {
            return Err(
                AuthorizationServerError.InvalidRequestObject(
                    details =
                        "JAR alg '$alg' is not in the AS's request_object_signing_alg_values_supported " +
                            "list (${advertisedAlgs.joinToString(", ")})",
                ),
            )
        }

        // Select the verification key source by STRICT precedence:
        //  1. inline `jwks` present -> pinned mode (resolvers disabled; inline always wins);
        //  2. else registered `jwks_uri` -> resolve via the identifier-resolution system, kid-pinned;
        //  3. else -> fail closed.
        // The two paths are mutually exclusive (exactly one of trustedJwks/identifier is passed):
        // VerifyJwsCommand only consults resolvers when trustedJwks is null.
        val inlineJwks = buildTrustedJwks(client)
        val verifyArgs =
            when {
                inlineJwks != null -> {
                    VerifyJwsArgs(jws = JwsCompact(signedJwt), trustedJwks = inlineJwks)
                }

                !client.jwksUri.isNullOrBlank() -> {
                    // SSRF / scheme-downgrade guard: only an https jwks_uri may be resolved.
                    if (!client.jwksUri!!.startsWith("https://", ignoreCase = true)) {
                        return Err(
                            AuthorizationServerError.InvalidRequestObject(
                                details = "Client '$resolvedClientId' jwks_uri must be https for JAR verification",
                            ),
                        )
                    }
                    // Require an explicit `kid` so the resolver binds to exactly that key rather than
                    // its kid-absent first()-pick, keeping the jwks_uri path as strict as pinned mode.
                    val headerKid = header["kid"]?.jsonPrimitive?.content
                    if (headerKid.isNullOrBlank()) {
                        return Err(
                            AuthorizationServerError.InvalidRequestObject(
                                details = "JAR header must carry 'kid' to select a key from the client's jwks_uri",
                            ),
                        )
                    }
                    VerifyJwsArgs(
                        jws = JwsCompact(signedJwt),
                        identifier =
                            ExternalIdentifierJwksUrlOpts(
                                identifier = client.jwksUri!!,
                                lookup = AdditionalIdentifierLookup(kid = headerKid),
                            ),
                    )
                }

                else -> {
                    return Err(
                        AuthorizationServerError.InvalidRequestObject(
                            details = "Client '$resolvedClientId' has no 'jwks' or 'jwks_uri' configured for JAR verification",
                        ),
                    )
                }
            }

        val verify = verifyJwsCommand.execute(verifyArgs)
        if (verify.isErr) {
            return Err(
                AuthorizationServerError.InvalidRequestObject(
                    details = "JAR signature verification failed: ${verify.error.message.defaultMessage}",
                ),
            )
        }
        if (!verify.value.isValid) {
            return Err(
                AuthorizationServerError.InvalidRequestObject(
                    details = "JAR signature is invalid: ${verify.value.errorMessages.joinToString("; ")}",
                ),
            )
        }

        // RFC 9101 §10.2 — `aud` MUST be the AS issuer.
        val aud = payload["aud"]
        val audMatches =
            when {
                aud is JsonPrimitive -> aud.content == args.issuer
                aud is kotlinx.serialization.json.JsonArray -> aud.any { it.jsonPrimitive.content == args.issuer }
                else -> false
            }
        if (!audMatches) {
            return Err(
                AuthorizationServerError.InvalidRequestObject(
                    details = "JAR 'aud' does not match the AS issuer '${args.issuer}'",
                ),
            )
        }

        val now = Clock.System.now()
        val skew = VerifyRequestObjectCommand.CLOCK_SKEW_SECONDS.seconds
        val exp = numericDateInstant(payload["exp"])
            ?: return Err(AuthorizationServerError.InvalidRequestObject(details = "JAR 'exp' must be a NumericDate"))
        if (now > exp + skew) {
            return Err(AuthorizationServerError.InvalidRequestObject(details = "JAR has expired"))
        }
        if (payload.containsKey("iat")) {
            val issuedAt = numericDateInstant(payload["iat"])
                ?: return Err(AuthorizationServerError.InvalidRequestObject(details = "JAR 'iat' must be a NumericDate"))
            if (issuedAt > now + skew) {
                return Err(AuthorizationServerError.InvalidRequestObject(details = "JAR 'iat' is in the future"))
            }
        }
        if (payload.containsKey("nbf")) {
            val notBefore = numericDateInstant(payload["nbf"])
                ?: return Err(AuthorizationServerError.InvalidRequestObject(details = "JAR 'nbf' must be a NumericDate"))
            if (notBefore > now + skew) {
                return Err(AuthorizationServerError.InvalidRequestObject(details = "JAR 'nbf' is in the future"))
            }
        }
        if (federationProofRequired && exp <= now) {
            return Err(AuthorizationServerError.InvalidRequestObject(details = "Federation JAR has expired"))
        }

        if (client.singleUseRequestObjects || federationProofRequired) {
            val soleAudience = (aud as? JsonPrimitive)?.content
                ?: (aud as? kotlinx.serialization.json.JsonArray)?.singleOrNull()?.jsonPrimitive?.content
            if (soleAudience != args.issuer) {
                return Err(AuthorizationServerError.InvalidRequestObject(details = "JAR 'aud' must name only this server"))
            }
            if (payload.containsKey("sub")) {
                return Err(AuthorizationServerError.InvalidRequestObject(details = "JAR must not contain 'sub'"))
            }
            val jti = payload["jti"]?.jsonPrimitive?.content?.takeIf { it.isNotBlank() }
                ?: return Err(AuthorizationServerError.InvalidRequestObject(details = "JAR is missing 'jti' claim"))
            if (!jtiStore.value.recordIfNew(resolvedClientId, REQUEST_OBJECT_JTI_PREFIX + jti, exp)) {
                return Err(AuthorizationServerError.InvalidRequestObject(details = "JAR 'jti' has already been used"))
            }
        }

        // RFC 9101 §6.1: signed claims override the front-channel parameters.
        // RFC 9101 §6.3: no unsigned query fallback for federation authorization.
        val merged = mergeParameters(if (federationProofRequired) emptyMap() else args.queryParameters, payload)
        val evidence = if (federationScope == null) null else {
            try { com.sphereon.oauth2.server.authorization.impl.command.authorization.VerifiedFederationAuthorizationEvidence.mint(federationScope, client, merged, exp) }
            catch (expected: IllegalArgumentException) { return Err(AuthorizationServerError.InvalidRequestObject(details = "Federation authorization evidence is invalid")) }
            catch (expected: IllegalStateException) { return Err(AuthorizationServerError.InvalidRequestObject(details = "Federation RP signing material is unavailable")) }
        }
        return Ok(
            VerifiedRequestObject(
                mergedParameters = merged,
                clientId = resolvedClientId,
                signingAlg = alg,
                authorizationEvidence = evidence,
            ),
        )
    }

    private suspend fun fetchAndExtractJwt(uri: String): IdkResult<String, AuthorizationServerError> {
        val fetched = fetchRequestUriCommand.execute(FetchRequestUriArgs(requestUri = uri, httpMethod = RequestUriMethod.GET))
        if (fetched.isErr) {
            return Err(
                AuthorizationServerError.InvalidRequestUri(
                    details = "Failed to fetch request_uri '$uri': ${fetched.error.message.defaultMessage}",
                ),
            )
        }
        val body = fetched.value.content.trim()
        if (body.isEmpty()) {
            return Err(
                AuthorizationServerError.InvalidRequestUri(
                    details = "request_uri '$uri' returned an empty body",
                ),
            )
        }
        return Ok(body)
    }

    /** RFC 7519 NumericDate is a finite JSON number, including a fractional second. */
    private fun numericDateInstant(value: JsonElement?): Instant? {
        val number = (value as? JsonPrimitive)?.takeUnless { it.isString }?.content
            ?.toDoubleOrNull()?.takeIf { it.isFinite() } ?: return null
        val seconds = kotlin.math.floor(number)
        if (seconds < Long.MIN_VALUE.toDouble() || seconds >= Long.MAX_VALUE.toDouble()) return null
        val wholeSeconds = seconds.toLong()
        val nanos = ((number - seconds) * 1_000_000_000).toLong()
        val instant = try { Instant.fromEpochSeconds(wholeSeconds, nanos) }
            catch (expected: IllegalArgumentException) { return null }
        // Do not accept an out-of-range value if the time implementation saturates it.
        return instant.takeIf { it.epochSeconds == wholeSeconds && it.nanosecondsOfSecond.toLong() == nanos }
    }

    private fun buildTrustedJwks(client: ClientRegistration): JsonObject? {
        val keys = client.jwks ?: return null
        if (keys.isEmpty()) return null
        val set = JwkSet(keys = keys.toTypedArray())
        return Json.encodeToJsonElement(JwkSet.serializer(), set).jsonObject
    }

    private fun decodeBase64UrlJson(encoded: String): JsonObject? =
        try {
            val bytes = encoded.decodeFrom(Encoding.BASE64URL)
            Json.parseToJsonElement(bytes.decodeToString()) as? JsonObject
        } catch (expected: Exception) {
            null
        }

    private fun mergeParameters(
        front: Map<String, String>,
        payload: JsonObject,
    ): Map<String, String> {
        val merged = front.toMutableMap()
        payload.forEach { (key, value) ->
            if (key in JWT_ENVELOPE_CLAIMS) return@forEach
            merged[key] = jsonElementToParameterValue(value)
        }
        return merged
    }

    private fun jsonElementToParameterValue(element: JsonElement): String =
        when (element) {
            is JsonPrimitive -> if (element.isString) element.content else element.toString()
            else -> element.toString()
        }

    companion object {
        private const val JWS_PART_COUNT = 3
        private const val REQUEST_OBJECT_JTI_PREFIX = "request-object:"

        /** RFC 9101 §6.1: JWT-envelope claims to strip before merging. */
        private val JWT_ENVELOPE_CLAIMS: Set<String> = setOf("iss", "aud", "exp", "iat", "jti", "nbf", "typ", "alg")
    }
}
