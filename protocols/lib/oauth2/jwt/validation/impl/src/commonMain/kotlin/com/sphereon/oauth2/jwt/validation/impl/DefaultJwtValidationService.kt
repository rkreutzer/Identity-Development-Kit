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
 *
 */

package com.sphereon.oauth2.jwt.validation.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.log.Log
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.jwt.validation.AccessTokenValidationOptions
import com.sphereon.oauth2.jwt.validation.AsIssuerTrustMaterial
import com.sphereon.oauth2.jwt.validation.IdTokenValidationOptions
import com.sphereon.oauth2.jwt.validation.IdpConfig
import com.sphereon.oauth2.jwt.validation.IdpRegistry
import com.sphereon.oauth2.jwt.validation.IdpType
import com.sphereon.oauth2.jwt.validation.JwtArtifactContext
import com.sphereon.oauth2.jwt.validation.JwtValidationError
import com.sphereon.oauth2.jwt.validation.JwtValidationService
import com.sphereon.oauth2.jwt.validation.OidcDiscoveryService
import com.sphereon.oauth2.jwt.validation.TokenClaims
import com.sphereon.oauth2.jwt.validation.ValidatedAccessToken
import com.sphereon.oauth2.jwt.validation.ValidatedIdToken
import com.sphereon.oauth2.server.resource.command.VerifyJwtArgs
import com.sphereon.oauth2.server.resource.command.VerifyJwtCommand
import com.sphereon.oauth2.server.resource.command.StandardJwtArtifactContext
import com.sphereon.oauth2.server.resource.model.TokenPayload
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject

/**
 * Default implementation of JwtValidationService.
 *
 * Wraps IDK's VerifyJwtCommand for JWT signature verification,
 * with support for multi-IdP environments.
 *
 * Key flow:
 * 1. Parse JWT to extract issuer (without verification)
 * 2. Look up IdP configuration based on issuer or tenant hint
 * 3. Delegate to VerifyJwtCommand for full verification
 * 4. Map result to ValidatedAccessToken
 *
 * Tenant resolution is intentionally NOT performed here. The authentication
 * pipeline (IdentityResolutionPipeline, typically wired by the Ktor/Spring
 * adapters) is the single source of truth for tenant resolution, and exposes
 * the resolved tenant through [com.sphereon.di.session.SessionContext] after
 * successful signature and claim validation. [ValidatedAccessToken] and
 * [ValidatedIdToken] no longer carry a tenant field.
 *
 * Stays in [SessionScope] because its transitive dependency
 * [VerifyJwtCommand] is SessionScope. The underlying [IdpRegistry] is
 * AppScope-cached, so IdP configuration is loaded once app-wide and
 * persisted across sessions even though this service is rebuilt per session.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<JwtValidationService>())
class DefaultJwtValidationService(
    private val verifyJwtCommand: VerifyJwtCommand,
    private val idpRegistry: IdpRegistry,
    private val oidcDiscoveryService: OidcDiscoveryService,
) : JwtValidationService {
    override suspend fun validateAsIssuedArtifact(
        compactJwt: String,
        trustMaterial: AsIssuerTrustMaterial,
        artifactContext: JwtArtifactContext,
    ): IdkResult<TokenClaims, JwtValidationError> {
        if (!trustMaterial.admits(artifactContext)) {
            return Err(
                JwtValidationError.validationError(
                    "AS trust material does not admit artifact context ${artifactContext.name}",
                ),
            )
        }

        val trustedIdentifier = trustMaterial.trustedIdentifier
            ?: return Err(
                JwtValidationError.idpConfigurationError(
                    "AS trust material has no caller-established signing identifier",
                ),
            )

        val claimsResult = extractClaims(compactJwt)
        if (claimsResult is Err) {
            return claimsResult
        }
        val claims = (claimsResult as Ok).value
        if (claims.issuer != trustMaterial.canonicalIssuer.value) {
            return Err(
                JwtValidationError.untrustedIssuer(
                    issuer = claims.issuer ?: "",
                    trustedIssuers = listOf(trustMaterial.canonicalIssuer.value),
                ),
            )
        }

        val idpConfig =
            IdpConfig(
                id = "as-trust",
                type = IdpType.CUSTOM,
                issuer = trustMaterial.canonicalIssuer.value,
            )
        val verifyArgs =
            VerifyJwtArgs(
                    jwt = compactJwt,
                    authorizationServer = trustMaterial.canonicalIssuer.value,
                    expectedAudience = null,
                    jwksUri = null,
                    trustedIdentifier = trustedIdentifier,
                )
        val verifyResult: IdkResult<Unit, IdkError> =
            when (artifactContext) {
                JwtArtifactContext.ACCESS_TOKEN -> verifyJwtCommand.execute(verifyArgs).map { Unit }
                JwtArtifactContext.ID_TOKEN ->
                    verifyJwtCommand.verifyStandardArtifact(verifyArgs, StandardJwtArtifactContext.ID_TOKEN).map { Unit }
                JwtArtifactContext.JARM_RESPONSE ->
                    verifyJwtCommand.verifyStandardArtifact(verifyArgs, StandardJwtArtifactContext.JARM_RESPONSE).map { Unit }
                JwtArtifactContext.LOGOUT_TOKEN ->
                    verifyJwtCommand.verifyStandardArtifact(verifyArgs, StandardJwtArtifactContext.LOGOUT_TOKEN).map { Unit }
            }

        return verifyResult.fold(
            success = {
                if (claims.issuer != trustMaterial.canonicalIssuer.value) {
                    return Err(
                        JwtValidationError.untrustedIssuer(
                            issuer = claims.issuer.orEmpty(),
                            trustedIssuers = listOf(trustMaterial.canonicalIssuer.value),
                        ),
                    )
                }
                when (artifactContext) {
                JwtArtifactContext.ID_TOKEN,
                    JwtArtifactContext.JARM_RESPONSE -> if (claims.audiences.isEmpty()) {
                        return Err(JwtValidationError.missingClaim("aud"))
                    }

                    JwtArtifactContext.LOGOUT_TOKEN ->
                        if (claims.payload["events"] !is JsonObject) {
                            return Err(JwtValidationError.missingClaim("events"))
                        }

                    JwtArtifactContext.ACCESS_TOKEN -> Unit
                }
                Ok(claims)
            },
            failure = { error ->
                Err(mapVerifyJwtError(error, idpConfig, expectedAudience = null))
            },
        )
    }

    override suspend fun validateAccessToken(
        token: String,
        options: AccessTokenValidationOptions,
    ): IdkResult<ValidatedAccessToken, JwtValidationError> {
        val trustedIssuer = options.trustedIssuer?.trim()
        val trustedJwksUri = options.trustedJwksUri?.trim()
        val hasPerCallTrust = options.trustedIssuer != null || options.trustedJwksUri != null
        if (hasPerCallTrust &&
            (trustedIssuer.isNullOrEmpty() || trustedJwksUri.isNullOrEmpty() ||
                options.idpId != null || options.tenantHint != null || options.trustedIdentifier != null)
        ) {
            return Err(
                JwtValidationError.idpConfigurationError(
                    "Per-call issuer/JWKS trust must be complete and cannot be combined with IdP selection or identifier options",
                ),
            )
        }

        // Validate token format
        val parts = token.split(".")
        if (parts.size != 3) {
            return Err(JwtValidationError.invalidFormat("JWT must have 3 parts, got ${parts.size}"))
        }

        val (idpConfig, jwksUri) = when {
            hasPerCallTrust -> {
                IdpConfig(
                    id = PER_CALL_TRUSTED_IDP_ID,
                    type = IdpType.CUSTOM,
                    issuer = trustedIssuer!!,
                    jwksUri = trustedJwksUri,
                ) to trustedJwksUri!!
            }

            else -> {
                val idpResult = resolveIdpConfig(token, options)
                if (idpResult is Err) {
                    return idpResult
                }
                val resolvedIdp = (idpResult as Ok).value
                val resolvedJwks = if (options.trustedIdentifier == null) {
                    val jwksResult = resolveJwksUri(resolvedIdp)
                    if (jwksResult is Err) {
                        return Err(jwksResult.error)
                    }
                    (jwksResult as Ok).value
                } else {
                    null
                }
                resolvedIdp to resolvedJwks
            }
        }

        if (hasPerCallTrust) {
            val claims = extractClaims(token)
            if (claims is Err) {
                return claims
            }
            val tokenIssuer = (claims as Ok).value.issuer
            if (tokenIssuer != trustedIssuer) {
                return Err(
                    JwtValidationError.untrustedIssuer(
                        issuer = tokenIssuer ?: "",
                        trustedIssuers = listOf(trustedIssuer!!),
                    ),
                )
            }
        }

        // Per-call issuer/JWKS inputs bypass registry lookup and discovery.
        val expectedAudience = options.expectedAudience ?: idpConfig.audience

        // Verify the JWT using IDK's command
        val verifyResult =
            verifyJwtCommand.execute(
                VerifyJwtArgs(
                    jwt = token,
                    authorizationServer = idpConfig.issuer,
                    expectedAudience = expectedAudience,
                    jwksUri = jwksUri,
                    trustedIdentifier = options.trustedIdentifier,
                ),
            )

        return verifyResult.fold(
            success = { jwtPayload ->
                // Full-fidelity claim view (object/array + custom claims like tenant_id/roles preserved).
                val claims = buildClaims(jwtPayload)

                // Check required scopes
                if (options.requiredScopes.isNotEmpty()) {
                    val tokenScopes = jwtPayload.scope?.split(" ")?.toSet() ?: emptySet()
                    val missingScopes = options.requiredScopes - tokenScopes
                    if (missingScopes.isNotEmpty()) {
                        return Err(JwtValidationError.missingClaim("scope: ${missingScopes.joinToString(", ")}"))
                    }
                }

                // Check required claims against the full payload (so non-stringly/custom claims count).
                for (claim in options.requiredClaims) {
                    if (!claims.containsKey(claim)) {
                        return Err(JwtValidationError.missingClaim(claim))
                    }
                }

                // Tenant is resolved by the authentication pipeline, not by this service.
                // See class-level KDoc.
                Ok(
                    ValidatedAccessToken(
                        subject = jwtPayload.sub,
                        issuer = jwtPayload.iss,
                        audiences = jwtPayload.aud ?: emptyList(),
                        expiresAt = jwtPayload.exp.epochSeconds,
                        issuedAt = jwtPayload.iat.epochSeconds,
                        notBefore = null, // TokenPayload.Jwt doesn't include nbf
                        scopes = jwtPayload.scope?.split(" ")?.toSet() ?: emptySet(),
                        clientId = jwtPayload.clientId,
                        jwtId = jwtPayload.jti,
                        rawToken = token,
                        claims = claims,
                        idpId = idpConfig.id,
                    ),
                )
            },
            failure = { error ->
                val code = error.code.takeIf { it.matches(Regex("[A-Za-z0-9_.:-]{1,160}")) } ?: "unavailable"
                Log.app().withTag("DefaultJwtValidationService")
                    .warn("JWT_VALIDATION_REFUSED stage=access-token-verification code=$code")
                Err(mapVerifyJwtError(error, idpConfig, expectedAudience))
            },
        )
    }

    override suspend fun validateIdToken(
        token: String,
        options: IdTokenValidationOptions,
    ): IdkResult<ValidatedIdToken, JwtValidationError> {
        // Validate token format
        val parts = token.split(".")
        if (parts.size != 3) {
            return Err(JwtValidationError.invalidFormat("JWT must have 3 parts, got ${parts.size}"))
        }

        // Find the IdP configuration to use
        val accessOptions =
            AccessTokenValidationOptions(
                expectedAudience = options.expectedAudience,
                idpId = options.idpId,
                tenantHint = options.tenantHint,
            )
        val idpResult = resolveIdpConfig(token, accessOptions)
        if (idpResult is Err) {
            return Err(idpResult.error)
        }

        val idpConfig = (idpResult as Ok).value

        val jwksResult = resolveJwksUri(idpConfig)
        if (jwksResult is Err) {
            return Err(jwksResult.error)
        }
        val jwksUri = (jwksResult as Ok).value

        // Verify the JWT
        val verifyResult =
            verifyJwtCommand.verifyStandardArtifact(
                VerifyJwtArgs(
                    jwt = token,
                    authorizationServer = idpConfig.issuer,
                    expectedAudience = options.expectedAudience ?: idpConfig.audience,
                    jwksUri = jwksUri,
                ),
                StandardJwtArtifactContext.ID_TOKEN,
            )

        return verifyResult.fold(
            success = { jwtPayload ->
                val subject = readString(jwtPayload, "sub")
                    ?: return Err(JwtValidationError.missingClaim("sub"))
                val issuer = readString(jwtPayload, "iss")
                    ?: return Err(JwtValidationError.missingClaim("iss"))
                val expiresAt = readLong(jwtPayload, "exp")
                    ?: return Err(JwtValidationError.missingClaim("exp"))
                val issuedAt = readLong(jwtPayload, "iat")
                    ?: return Err(JwtValidationError.missingClaim("iat"))
                // Validate nonce if required
                if (options.expectedNonce != null) {
                    val tokenNonce = jwtPayload["nonce"].asString()
                    if (tokenNonce != options.expectedNonce) {
                        return Err(
                            JwtValidationError.validationError(
                                "Nonce mismatch: expected ${options.expectedNonce}, got $tokenNonce",
                            ),
                        )
                    }
                }

                // Tenant is resolved by the authentication pipeline, not by this service.
                // See class-level KDoc.
                Ok(
                    ValidatedIdToken(
                        subject = subject,
                        issuer = issuer,
                        audiences = readAudiences(jwtPayload),
                        expiresAt = expiresAt,
                        issuedAt = issuedAt,
                        authTime =
                            jwtPayload["auth_time"]
                                .asString()
                                ?.toDoubleOrNull()
                                ?.toLong(),
                        nonce = jwtPayload["nonce"].asString(),
                        name = jwtPayload["name"].asString(),
                        email = jwtPayload["email"].asString(),
                        emailVerified = jwtPayload["email_verified"].asString()?.toBooleanStrictOrNull(),
                        preferredUsername = jwtPayload["preferred_username"].asString(),
                        givenName = jwtPayload["given_name"].asString(),
                        familyName = jwtPayload["family_name"].asString(),
                        rawToken = token,
                        claims = jwtPayload.toMap(),
                        idpId = idpConfig.id,
                    ),
                )
            },
            failure = { error ->
                Err(mapVerifyJwtError(error, idpConfig, options.expectedAudience ?: idpConfig.audience))
            },
        )
    }

    override suspend fun extractClaims(token: String): IdkResult<TokenClaims, JwtValidationError> {
        val parts = token.split(".")
        if (parts.size != 3) {
            return Err(JwtValidationError.invalidFormat("JWT must have 3 parts, got ${parts.size}"))
        }

        val headerJson =
            decodeBase64Url(parts[0]).ifEmpty {
                return Err(JwtValidationError.invalidFormat("Cannot decode JWT header"))
            }
        val payloadJson =
            decodeBase64Url(parts[1]).ifEmpty {
                return Err(JwtValidationError.invalidFormat("Cannot decode JWT payload"))
            }

        val header =
            runCatching { JSON.parseToJsonElement(headerJson).jsonObject }
                .getOrElse {
                    return Err(
                        JwtValidationError.invalidFormat(
                            "JWT header is not a JSON object: ${it.message}",
                        ),
                    )
                }

        val payload =
            runCatching { JSON.parseToJsonElement(payloadJson).jsonObject }
                .getOrElse {
                    return Err(
                        JwtValidationError.invalidFormat(
                            "JWT payload is not a JSON object: ${it.message}",
                        ),
                    )
                }

        return Ok(
            TokenClaims(
                header = header.toMap(),
                payload = payload.toMap(),
                issuer = readString(payload, "iss"),
                subject = readString(payload, "sub"),
                audiences = readAudiences(payload),
                expiresAt = readLong(payload, "exp"),
                issuedAt = readLong(payload, "iat"),
            ),
        )
    }

    private suspend fun resolveIdpConfig(
        token: String,
        options: AccessTokenValidationOptions,
    ): IdkResult<IdpConfig, JwtValidationError> {
        // Priority 1: Explicit IdP ID
        val explicitIdpId = options.idpId
        if (explicitIdpId != null) {
            return idpRegistry.getIdpById(explicitIdpId)
        }

        // Priority 2: Tenant hint
        val tenantHint = options.tenantHint
        if (tenantHint != null) {
            val tenantIdp = idpRegistry.getIdpForTenant(tenantHint)
            if (tenantIdp is Ok) {
                return tenantIdp
            }
        }

        // Priority 3: Extract issuer from token and look up
        val claims = extractClaims(token)
        if (claims is Ok) {
            val issuer = claims.value.issuer
            if (issuer != null) {
                return idpRegistry.getIdpByIssuer(issuer)
            }
        }

        // Priority 4: Default IdP
        return idpRegistry.getDefaultIdp()
    }

    /**
     * Resolve the JWKS endpoint promised by [IdpConfig]. An explicit endpoint is
     * authoritative. Every discovery-capable IdP type resolves a missing endpoint
     * through OIDC metadata; CUSTOM configurations must provide one themselves.
     *
     * Returning a concrete endpoint is important: [VerifyJwtCommand] interprets a
     * null identifier as a managed/KMS key lookup. A remote OIDC token's `kid` is
     * not a local KMS alias, so passing null would silently select the wrong trust
     * mechanism instead of performing the documented OIDC discovery flow.
     */
    private suspend fun resolveJwksUri(idpConfig: IdpConfig): IdkResult<String, JwtValidationError> {
        idpConfig.jwksUri?.trim()?.takeIf(String::isNotEmpty)?.let { return Ok(it) }

        if (idpConfig.type == IdpType.CUSTOM) {
            return Err(
                JwtValidationError.idpConfigurationError(
                    "Custom IdP '${idpConfig.id}' must configure a JWKS URI",
                ),
            )
        }

        val discovered = oidcDiscoveryService.getMetadata(idpConfig.issuer)
        if (discovered is Err) {
            return Err(discovered.error)
        }
        val metadata = (discovered as Ok).value
        return if (metadata.issuer != idpConfig.issuer) {
            Err(
                JwtValidationError.discoveryFailed(
                    issuer = idpConfig.issuer,
                    cause = "Discovered issuer '${metadata.issuer}' does not match the configured issuer",
                ),
            )
        } else {
            val jwksUri = metadata.jwksUri.trim()
            if (jwksUri.isEmpty()) {
                Err(
                    JwtValidationError.discoveryFailed(
                        issuer = idpConfig.issuer,
                        cause = "Discovered metadata contains an empty JWKS URI",
                    ),
                )
            } else {
                Ok(jwksUri)
            }
        }
    }

    /**
     * The verified token's full claim view: the registered claims surfaced via the typed
     * [TokenPayload.Jwt] fields plus EVERY non-registered claim from [TokenPayload.Jwt.additionalClaims]
     * with full fidelity — object/array claims like `roles` and custom claims like `tenant_id` are
     * `JsonElement`, not flattened. This is the authoritative claim view consumers read off
     * [ValidatedAccessToken.claims] / [ValidatedIdToken.claims], so they never re-parse the raw token.
     */
    private fun buildClaims(jwtPayload: TokenPayload.Jwt): Map<String, JsonElement> =
        buildMap {
            put("sub", JsonPrimitive(jwtPayload.sub))
            put("iss", JsonPrimitive(jwtPayload.iss))
            jwtPayload.aud?.let { auds -> put("aud", JsonArray(auds.map { JsonPrimitive(it) })) }
            put("exp", JsonPrimitive(jwtPayload.exp.epochSeconds))
            put("iat", JsonPrimitive(jwtPayload.iat.epochSeconds))
            jwtPayload.scope?.let { put("scope", JsonPrimitive(it)) }
            jwtPayload.clientId?.let { put("client_id", JsonPrimitive(it)) }
            jwtPayload.jti?.let { put("jti", JsonPrimitive(it)) }
            putAll(jwtPayload.additionalClaims)
        }

    /** Read a claim as a plain string (or null when absent / not a JSON primitive). */
    private fun JsonElement?.asString(): String? = (this as? JsonPrimitive)?.contentOrNull

    private fun decodeBase64Url(input: String): String =
        try {
            input.decodeFromBase64Url().decodeToString()
        } catch (_: Exception) {
            ""
        }

    /**
     * Map a [VerifyJwtCommand] failure to a typed [JwtValidationError].
     *
     * Classification is driven entirely by the stable [IdkError.code] values
     * emitted by the discriminated
     * [com.sphereon.oauth2.server.resource.error.ResourceServerError.InvalidToken]
     * subtypes in
     * [com.sphereon.oauth2.server.resource.impl.command.VerifyJwtCommandImpl]
     * (and [com.sphereon.oauth2.server.resource.error.ResourceServerError.AudienceMismatch]).
     * Supporting context (expiry timestamp, issuer, audience lists) is read
     * from the structured [IdkError.meta] map. No `startsWith`-style matching
     * on [IdkError.message] is performed; codes are the primary dispatch.
     *
     * Unknown codes fall through to a generic [JwtValidationError.validationError]
     * with the original default message and `reason` meta preserved as cause.
     */
    private fun mapVerifyJwtError(
        error: IdkError,
        idpConfig: IdpConfig,
        expectedAudience: String?,
    ): JwtValidationError {
        val defaultMessage = error.message.defaultMessage
        val reason = (error.meta["reason"] as? String) ?: defaultMessage

        return when (error.code) {
            AUDIENCE_MISMATCH_CODE -> {
                val actual = (error.meta["actual"] as? List<*>)?.filterIsInstance<String>().orEmpty()
                JwtValidationError.invalidAudience(
                    tokenAudience = actual,
                    expectedAudience = expectedAudience ?: (error.meta["expected"] as? String).orEmpty(),
                )
            }

            TOKEN_EXPIRED_CODE -> {
                val expiresAt = (error.meta["expires_at"] as? Long) ?: 0L
                JwtValidationError.expired(expiresAt)
            }

            ISSUER_MISMATCH_CODE -> {
                val expected =
                    (error.meta["expected"] as? String) ?: idpConfig.issuer
                JwtValidationError.untrustedIssuer(
                    issuer = expected,
                    trustedIssuers = listOf(idpConfig.issuer),
                )
            }

            SIGNATURE_INVALID_CODE -> {
                JwtValidationError.signatureInvalid(idpConfig.issuer, cause = reason)
            }

            MISSING_KID_CODE -> {
                JwtValidationError.keyNotFound(kid = "", issuer = idpConfig.issuer)
            }

            UNSUPPORTED_ALGORITHM_CODE -> {
                val algorithm = (error.meta["algorithm"] as? String).orEmpty()
                JwtValidationError.algorithmNotAllowed(
                    algorithm = algorithm,
                    allowedAlgorithms = emptyList(),
                )
            }

            TOKEN_MALFORMED_CODE, PARSE_FAILURE_CODE -> {
                JwtValidationError.invalidFormat(reason)
            }

            // Generic, non-JWT-specific `invalid_token` failures (e.g. introspection
            // paths, bearer/DPoP scheme mismatches) continue to surface as a
            // validation error so callers still see the underlying reason.
            INVALID_TOKEN_CODE -> {
                JwtValidationError.validationError(message = reason, cause = reason)
            }

            else -> {
                JwtValidationError.validationError(message = defaultMessage, cause = reason)
            }
        }
    }

    private fun readString(
        payload: JsonObject,
        key: String,
    ): String? = (payload[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

    private fun readLong(
        payload: JsonObject,
        key: String,
    ): Long? = (payload[key] as? JsonPrimitive)?.content?.toDoubleOrNull()?.toLong()

    private fun readAudiences(payload: JsonObject): List<String> =
        when (val aud = payload["aud"]) {
            null -> {
                emptyList()
            }

            is JsonPrimitive -> {
                if (aud.isString) listOf(aud.content) else emptyList()
            }

            is JsonArray -> {
                aud.mapNotNull { element ->
                    (element as? JsonPrimitive)?.takeIf { it.isString }?.content
                }
            }

            else -> {
                emptyList()
            }
        }

    private companion object {
        private const val PER_CALL_TRUSTED_IDP_ID = "per-call-trusted-issuer"
        private val JSON =
            Json {
                ignoreUnknownKeys = true
                isLenient = true
            }

        // RFC 6750 Bearer-token error codes emitted by VerifyJwtCommandImpl via the
        // discriminated ResourceServerError.InvalidToken subtypes.
        private const val INVALID_TOKEN_CODE = "invalid_token"
        private const val AUDIENCE_MISMATCH_CODE = "audience_mismatch"
        private const val TOKEN_EXPIRED_CODE = "token_expired"
        private const val ISSUER_MISMATCH_CODE = "issuer_mismatch"
        private const val SIGNATURE_INVALID_CODE = "signature_invalid"
        private const val TOKEN_MALFORMED_CODE = "token_malformed"
        private const val MISSING_KID_CODE = "missing_kid"
        private const val UNSUPPORTED_ALGORITHM_CODE = "unsupported_algorithm"
        private const val PARSE_FAILURE_CODE = "parse_failure"
    }
}
