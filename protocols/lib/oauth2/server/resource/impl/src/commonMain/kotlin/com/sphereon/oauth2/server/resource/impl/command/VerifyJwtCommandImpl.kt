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

package com.sphereon.oauth2.server.resource.impl.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.conf.ConfigLevel
import com.sphereon.core.api.conf.ConfigService
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.jose.jws.JwsCompact
import com.sphereon.crypto.jose.jws.JwsUtils
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.resolution.AdditionalIdentifierLookup
import com.sphereon.crypto.resolution.IdentifierOptsOrResult
import com.sphereon.crypto.resolution.extern.ExternalIdentifierJwksUrlOpts
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.server.resource.command.VerifyJwtArgs
import com.sphereon.oauth2.server.resource.command.VerifyJwtCommand
import com.sphereon.oauth2.server.resource.command.StandardJwtArtifactContext
import com.sphereon.oauth2.server.resource.error.ResourceServerError
import com.sphereon.oauth2.server.resource.model.TokenPayload
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName
import kotlin.time.Clock
import kotlin.time.Instant

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of VerifyJwtCommand
 *
 * Verifies JWT access tokens according to RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens).
 *
 * **Verification flow**:
 * 1. Verify JWT signature using JwtService
 * 2. Parse and validate the claims required by the selected context
 * 3. Require the RFC 9068 typ only for resource-server access-token execution
 * 4. Extract DPoP binding (cnf.jkt) if present
 * 5. Return TokenPayload.Jwt
 *
 * **Note**: Relies on JwtService for signature verification and uses JwsUtils
 * for proper base64url decoding.
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifyJwtCommandImpl", exact = true)
@ExposeImplBinding
class VerifyJwtCommandImpl(
    execution: SessionExecution,
    private val jwtService: JwtService,
) : TypedServiceCommandAdapter<VerifyJwtArgs, TokenPayload.Jwt, IdkError>(
        commandId = VerifyJwtCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<VerifyJwtArgs>(),
        outputTypeToken = typeToken<TokenPayload.Jwt>(),
    ),
    VerifyJwtCommand {
    override val commandId: String get() = VerifyJwtCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is VerifyJwtArgs

    // Cached at session scope: VerifyJwtCommandImpl is @SingleIn(SessionScope), so the config
    // resolution runs at most once per session and subsequent resource-server requests reuse
    // the resolved value. Per-request overrides still flow through args.clockSkewSeconds.
    private val configuredClockSkewSeconds: Long by lazy { resolveClockSkewFromConfig() }

    override suspend fun doExecute(
        args: VerifyJwtArgs,
        applyDuring: (VerifyJwtArgs) -> VerifyJwtArgs,
    ): IdkResult<TokenPayload.Jwt, IdkError> {
        val applied = applyDuring(args)
        return executeInternal(
            jwt = applied.jwt,
            authorizationServer = applied.authorizationServer,
            expectedAudience = applied.expectedAudience,
            jwksUri = applied.jwksUri,
            trustedIdentifier = applied.trustedIdentifier,
            clockSkewSeconds = applied.clockSkewSeconds ?: configuredClockSkewSeconds,
            standardArtifactContext = null,
        ).map { it.toTokenPayload(applied.authorizationServer) }
            .mapError { IdkError.fromDTO(it) }
    }

    override suspend fun verifyStandardArtifact(
        args: VerifyJwtArgs,
        context: StandardJwtArtifactContext,
    ): IdkResult<JsonObject, IdkError> =
        executeInternal(
            jwt = args.jwt,
            authorizationServer = args.authorizationServer,
            expectedAudience = args.expectedAudience,
            jwksUri = args.jwksUri,
            trustedIdentifier = args.trustedIdentifier,
            clockSkewSeconds = args.clockSkewSeconds ?: configuredClockSkewSeconds,
            standardArtifactContext = context,
        ).map { it.claims }
            .mapError { IdkError.fromDTO(it) }

    private fun resolveClockSkewFromConfig(): Long {
        val configured =
            runCatching {
                val configService = execution.conf.conf(ConfigLevel.PRINCIPAL) as? ConfigService
                configService?.getPropertyAsString(VerifyJwtArgs.CONFIG_KEY_CLOCK_SKEW, null)?.toLongOrNull()
            }.getOrNull()
        return configured ?: VerifyJwtArgs.DEFAULT_CLOCK_SKEW_SECONDS
    }

    private suspend fun executeInternal(
        jwt: String,
        authorizationServer: String,
        expectedAudience: String?,
        jwksUri: String? = null,
        trustedIdentifier: IdentifierOptsOrResult? = null,
        clockSkewSeconds: Long = VerifyJwtArgs.DEFAULT_CLOCK_SKEW_SECONDS,
        standardArtifactContext: StandardJwtArtifactContext?,
    ): IdkResult<VerifiedJwtPayload, ResourceServerError> {
        if (jwksUri != null && trustedIdentifier != null) {
            return Err(
                ResourceServerError.InvalidToken.Malformed(
                    reason = "jwksUri and trustedIdentifier are mutually exclusive verification anchors",
                ),
            )
        }
        // Parse the header once up front — used for kid-scoped JWKS lookup below, then reused
        // after signature verification for typ validation (avoids the second decode).
        val parts = jwt.split(".")
        if (parts.size != 3) {
            return Err(ResourceServerError.InvalidToken.Malformed(reason = "JWT must have 3 parts"))
        }
        val protectedHeader =
            try {
                JwsUtils.decodeBase64UrlToJson(parts[0])
            } catch (expected: Exception) {
                return Err(
                    ResourceServerError.InvalidToken.ParseFailure(
                        reason = "Failed to parse JWT header: ${expected.message}",
                    ),
                )
            }

        val identifier =
            if (trustedIdentifier != null) {
                trustedIdentifier
            } else if (jwksUri != null) {
                val kid = protectedHeader["kid"]?.jsonPrimitive?.content
                ExternalIdentifierJwksUrlOpts(
                    identifier = jwksUri,
                    lookup = AdditionalIdentifierLookup(kid = kid),
                )
            } else {
                null
            }

        val verifyArgs = VerifyJwsArgs(jws = JwsCompact(jwt), identifier = identifier)
        val verificationResult = jwtService.verifyJws(verifyArgs)

        if (verificationResult.isErr) {
            val code = verificationResult.error.code.takeIf { it.matches(Regex("[A-Za-z0-9_.:-]{1,160}")) } ?: "unavailable"
            log.warn("JWT resource verification refused command=$commandId stage=jws-result-error code=$code")
            return Err(
                ResourceServerError.InvalidToken.SignatureInvalid(
                    details = verificationResult.error.message.defaultMessage,
                ),
            )
        }

        val validationResult = verificationResult.value
        if (!validationResult.isValid) {
            log.warn("JWT resource verification refused command=$commandId stage=jws-signature-invalid")
            return Err(
                ResourceServerError.InvalidToken.SignatureInvalid(
                    details = validationResult.errorMessages.joinToString(", "),
                ),
            )
        }

        val jwsGeneral = validationResult.jws
        if (jwsGeneral.signatures.isEmpty()) {
            return Err(ResourceServerError.InvalidToken.Malformed(reason = "JWT has no signatures"))
        }

        val payloadJson =
            try {
                JwsUtils.decodeBase64UrlToJson(jwsGeneral.payload)
            } catch (expected: Exception) {
                return Err(
                    ResourceServerError.InvalidToken.ParseFailure(
                        reason = "Failed to parse JWT payload: ${expected.message}",
                    ),
                )
            }

        // RFC 9068 §4 requires the access-token media type. Reject absent and non-string typ
        // values safely; jsonPrimitive would throw for malformed object/array headers.
        if (standardArtifactContext == null && !hasSupportedAccessTokenTyp(protectedHeader)) {
            log.warn("JWT resource verification refused command=$commandId stage=access-token-type")
            return Err(
                ResourceServerError.InvalidToken.Malformed(
                    reason = "JWT typ must be 'at+jwt' or 'application/at+jwt'",
                ),
            )
        }
        if (standardArtifactContext != null) {
            val artifactTyp = protectedHeader["typ"]
            if (artifactTyp != null) {
                val typ = artifactTyp as? JsonPrimitive
                val isCompatible = typ != null && typ.isString && isArtifactTypCompatible(standardArtifactContext, typ.content)
                if (!isCompatible) {
                    return Err(
                        ResourceServerError.InvalidToken.Malformed(
                            reason = "JWT typ is not valid for $standardArtifactContext",
                        ),
                    )
                }
            }
        }

        // 4. Extract and validate required claims
        val iss = payloadJson["iss"]?.let { value -> (value as? JsonPrimitive)?.takeIf { it.isString }?.content }
        if (iss != authorizationServer) {
            return Err(
                ResourceServerError.InvalidToken.IssuerMismatch(
                    expected = authorizationServer,
                    actual = iss,
                ),
            )
        }

        val subValue = payloadJson["sub"]
        val sub = subValue?.let { value -> (value as? JsonPrimitive)?.takeIf { it.isString }?.content }
        if ((standardArtifactContext == null || standardArtifactContext == StandardJwtArtifactContext.ID_TOKEN) && sub == null) {
            return Err(ResourceServerError.InvalidToken.Malformed(reason = "Missing sub claim"))
        }
        if (standardArtifactContext == StandardJwtArtifactContext.LOGOUT_TOKEN && subValue != null && sub.isNullOrBlank()) {
            return Err(ResourceServerError.InvalidToken.Malformed(reason = "Invalid sub claim"))
        }

        val exp =
            payloadJson["exp"]
                ?.let { it as? JsonPrimitive }
                ?.content
                ?.toDoubleOrNull()
                ?.toLong()
                ?: return Err(
                    ResourceServerError.InvalidToken.Malformed(reason = "Missing or invalid exp claim"),
                )

        val iatValue = payloadJson["iat"]
        val iat = iatValue?.let { value -> (value as? JsonPrimitive)?.content?.toDoubleOrNull()?.toLong() }
        if ((standardArtifactContext != StandardJwtArtifactContext.JARM_RESPONSE && iat == null) ||
            (iatValue != null && iat == null)
        ) {
            return Err(ResourceServerError.InvalidToken.Malformed(reason = "Missing or invalid iat claim"))
        }

        // 5. Validate expiration (with skew tolerance)
        val now = Clock.System.now()
        if (now.epochSeconds > exp + clockSkewSeconds) {
            return Err(ResourceServerError.InvalidToken.Expired(expiresAt = exp))
        }

        // 5b. Validate `nbf` (not before) if present — skew-tolerant.
        // Per RFC 7519 §4.1.5 a token used before `nbf` must be rejected. The RFC allows small
        // clock-skew tolerance which we honour so honest clients don't get spurious failures.
        val nbfValue = payloadJson["nbf"]
        val nbf = nbfValue?.let { (it as? JsonPrimitive)?.content?.toDoubleOrNull()?.toLong() }
        if (nbfValue != null && nbf == null) {
            return Err(ResourceServerError.InvalidToken.Malformed(reason = "Invalid nbf claim"))
        }
        if (nbf != null && now.epochSeconds + clockSkewSeconds < nbf) {
            return Err(
                ResourceServerError.InvalidToken.Malformed(
                    reason = "Token is not yet valid (nbf=$nbf, now=${now.epochSeconds})",
                ),
            )
        }

        // Audience — RFC 9068 requires `aud` to include the resource server when
        // `expectedAudience` is supplied.
        val audValue = payloadJson["aud"]
        val audiences =
            if (audValue == null) {
                null
            } else {
                parseAudClaim(audValue) ?: return Err(
                    ResourceServerError.InvalidToken.Malformed(reason = "Invalid aud claim format"),
                )
            }
        if (expectedAudience != null && audiences?.contains(expectedAudience) != true) {
            return Err(
                ResourceServerError.AudienceMismatch(
                    expected = expectedAudience,
                    actual = audiences.orEmpty(),
                ),
            )
        }

        if (standardArtifactContext != null && audiences.isNullOrEmpty()) {
            return Err(ResourceServerError.InvalidToken.Malformed(reason = "Missing or invalid aud claim"))
        }
        if (standardArtifactContext == StandardJwtArtifactContext.LOGOUT_TOKEN) {
            val events = payloadJson["events"] as? JsonObject
            val event = events?.get(BACKCHANNEL_LOGOUT_EVENT)
            val logoutEventIsObject = events?.keys == setOf(BACKCHANNEL_LOGOUT_EVENT) && event is JsonObject && event.isEmpty()
            val sidValue = payloadJson["sid"]
            val sid = sidValue?.let { value -> (value as? JsonPrimitive)?.takeIf { it.isString }?.content }
            val hasSubjectOrSession = !sub.isNullOrBlank() || !sid.isNullOrBlank()
            val jti = payloadJson["jti"]?.let { value -> (value as? JsonPrimitive)?.takeIf { it.isString }?.content }
            if ((sidValue != null && sid.isNullOrBlank()) || !logoutEventIsObject || !hasSubjectOrSession || jti.isNullOrBlank() || "nonce" in payloadJson) {
                return Err(ResourceServerError.InvalidToken.Malformed(reason = "Invalid OpenID back-channel Logout Token claims"))
            }
        }

        if (standardArtifactContext == StandardJwtArtifactContext.JARM_RESPONSE && !hasSupportedAuthorizationResponse(payloadJson)) {
            return Err(ResourceServerError.InvalidToken.Malformed(reason = "JARM response is missing a supported authorization response field"))
        }

        // 7. Extract optional claims
        return Ok(VerifiedJwtPayload(payloadJson, audiences, sub, exp, iat))
    }

    private fun VerifiedJwtPayload.toTokenPayload(authorizationServer: String): TokenPayload.Jwt {
        val scope = claims["scope"]?.jsonPrimitive?.content
        val clientId = claims["client_id"]?.jsonPrimitive?.content
        val jti = claims["jti"]?.jsonPrimitive?.content
        val cnf = claims["cnf"]?.jsonObject
        return TokenPayload.Jwt(
            sub = subject ?: error("Verified resource access token is missing sub"),
            iss = claims["iss"]?.jsonPrimitive?.content ?: authorizationServer,
            aud = audiences,
            exp = Instant.fromEpochSeconds(exp),
            iat = Instant.fromEpochSeconds(iat ?: error("Verified resource access token is missing iat")),
            scope = scope,
            clientId = clientId,
            dpopJkt = cnf?.get("jkt")?.jsonPrimitive?.content,
            certificateThumbprintS256 = cnf?.get("x5t#S256")?.jsonPrimitive?.content,
            jti = jti,
            additionalClaims = claims.filterKeys { it !in JWT_REGISTERED_CLAIMS },
        )
    }

    /**
     * Decode the JWT `aud` claim into a list. Accepts both string (single-audience) and array
     * (multi-audience) shapes per RFC 7519 §4.1.3. Returns `null` for unparseable input so the
     * caller can map to `InvalidToken.Malformed`.
     */
    private fun parseAudClaim(audValue: JsonElement?): List<String>? =
        when (audValue) {
            null -> emptyList()
            is JsonPrimitive -> if (audValue.isString) listOf(audValue.content) else null
            is JsonObject -> null
            else ->
                runCatching {
                    val elements = audValue.jsonArray
                    if (elements.all { element -> (element as? JsonPrimitive)?.isString == true }) {
                        elements.map { (it as JsonPrimitive).content }
                    } else {
                        null
                    }
                }.getOrNull()
        }

    private companion object {
        /**
         * Registered/standard claims surfaced via the typed [TokenPayload.Jwt] fields; excluded from
         * `additionalClaims` so it carries only the non-standard remainder.
         */
        val JWT_REGISTERED_CLAIMS =
            setOf("sub", "iss", "aud", "exp", "iat", "nbf", "scope", "client_id", "jti", "cnf")
    }
}

private data class VerifiedJwtPayload(
    val claims: JsonObject,
    val audiences: List<String>?,
    val subject: String?,
    val exp: Long,
    val iat: Long?,
)

private const val BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
private fun isArtifactTypCompatible(context: StandardJwtArtifactContext, typ: String): Boolean =
    when (context) {
        StandardJwtArtifactContext.ID_TOKEN -> typ in setOf("JWT", "id+jwt", "application/id+jwt")
        StandardJwtArtifactContext.JARM_RESPONSE -> typ in setOf("JWT", "oauth-authz-resp+jwt", "application/oauth-authz-resp+jwt")
        StandardJwtArtifactContext.LOGOUT_TOKEN -> typ in setOf("JWT", "logout+jwt", "application/logout+jwt")
    }

private fun hasSupportedAuthorizationResponse(claims: JsonObject): Boolean =
    listOf("code", "error", "access_token", "id_token").any { key ->
        (claims[key] as? JsonPrimitive)?.let { it.isString && it.content.isNotBlank() } == true
    }

internal fun hasSupportedAccessTokenTyp(protectedHeader: JsonObject): Boolean {
    val typ = protectedHeader["typ"] as? JsonPrimitive ?: return false
    return typ.isString && (typ.content == "at+jwt" || typ.content == "application/at+jwt")
}
