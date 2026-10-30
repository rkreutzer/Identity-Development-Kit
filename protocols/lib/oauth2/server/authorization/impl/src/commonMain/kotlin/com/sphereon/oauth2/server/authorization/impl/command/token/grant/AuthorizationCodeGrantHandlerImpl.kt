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

package com.sphereon.oauth2.server.authorization.impl.command.token.grant

import com.sphereon.oauth2.server.authorization.impl.command.token.logTokenRefusal

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.isEnabled
import com.sphereon.oauth2.common.config.isRequired
import com.sphereon.oauth2.common.model.TokenResponse
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreateIdTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateIdTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreateRefreshTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreateTokenResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreateTokenResponseCommand
import com.sphereon.oauth2.server.authorization.command.GrantParameters
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthorization
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantArgs
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantCommand
import com.sphereon.oauth2.server.authorization.command.token.GrantContext
import com.sphereon.oauth2.server.authorization.command.token.GrantHandler
import com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys
import com.sphereon.oauth2.server.authorization.impl.command.token.executeWithTrustedClientAuthorization
import com.sphereon.oauth2.server.authorization.impl.command.token.issueForVerifiedAuthorizationCode
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.oidc.OidcScopeClaimsMapper
import com.sphereon.oauth2.server.authorization.impl.command.putClaims
import com.sphereon.oauth2.server.authorization.model.FederationTokenMetadata
import com.sphereon.oauth2.server.authorization.provider.CredentialIssuerAudienceResolver
import com.sphereon.oauth2.server.authorization.model.SESSION_KEY_OIDC_CLAIMS_ID_TOKEN
import com.sphereon.oauth2.server.authorization.model.SESSION_KEY_OIDC_CLAIMS_USERINFO
import com.sphereon.oauth2.server.authorization.wallet.accessTokenClaims
import dev.zacsweers.metro.ContributesIntoMap
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.StringKey
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.putJsonArray
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * RFC 6749 §4.1.3 / OIDC Core 1.0 §3.1.3.3 / OID4VCI 1.1 §7.2 authorization-code grant handler.
 *
 * Verifies the code through [com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantCommand],
 * then mints the access / refresh / id-token triple and assembles the [TokenResponse], including
 * an OID4VCI `authorization_details` array when the original authorization request carried
 * `credential_configuration_ids`. Enforces RFC 9449 §10.1 `dpop_jkt` continuity between the
 * authorization request and the token request, and OIDC scope-filtered id_token claim emission.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<GrantHandler>())
@StringKey(GrantHandlerKeys.AUTHORIZATION_CODE)
class AuthorizationCodeGrantHandlerImpl(
    private val authorizationCodeStorage: com.sphereon.oauth2.server.authorization.storage.AuthorizationCodeStorage,
    private val verifyAuthorizationCodeGrant: VerifyAuthorizationCodeGrantCommand,
    private val createAccessToken: CreateAccessTokenCommand,
    private val createRefreshToken: Lazy<CreateRefreshTokenCommand>,
    private val createIdToken: Lazy<CreateIdTokenCommand>,
    private val createTokenResponse: CreateTokenResponseCommand,
    private val credentialIssuerAudienceResolver: CredentialIssuerAudienceResolver,
    private val log: SessionLogService,
    private val scopeClaimsMapper: OidcScopeClaimsMapper? = null,
) : GrantHandler {
    override val grantType: String = GrantHandlerKeys.AUTHORIZATION_CODE

    override fun supports(params: GrantParameters): Boolean = params is GrantParameters.AuthorizationCode

    override suspend fun handle(
        params: GrantParameters,
        context: GrantContext,
    ): IdkResult<TokenResponse, IdkError> = handleInternal(params, context, null)

    internal suspend fun handleTrusted(
        params: GrantParameters,
        context: GrantContext,
        clientAuthorization: VerifiedClientAuthorization?,
    ): IdkResult<TokenResponse, IdkError> = handleInternal(params, context, clientAuthorization)

    private suspend fun handleInternal(
        params: GrantParameters,
        context: GrantContext,
        clientAuthorization: VerifiedClientAuthorization?,
    ): IdkResult<TokenResponse, IdkError> {
        val authParams = params as GrantParameters.AuthorizationCode
        val tokenRequest = context.tokenRequest
        val applied = context.applied
        val proofJkt = context.proofJkt
        val certThumbprint = context.certThumbprintS256

        val verified =
            verifyAuthorizationCodeGrant
                .executeWithTrustedClientAuthorization(
                    VerifyAuthorizationCodeGrantArgs(
                        code = authParams.code,
                        redirectUri = authParams.redirectUri,
                        clientId = tokenRequest.clientId,
                        codeVerifier = authParams.codeVerifier,
                        requestedResource = authParams.resource,
                    ),
                    clientAuthorization,
                ).getOrElse { error ->
                    val code = error.code.takeIf { it.matches(Regex("[A-Za-z0-9_.:-]{1,160}")) } ?: "unavailable"
                    logTokenRefusal(log, "Authorization code grant refused stage=code-verification code=$code")
                    return Err(error)
                }

        // RFC 9449 §10.1 / FAPI2-SP §5.3.2.1 holder-of-key requirement: when the auth request
        // committed a `dpop_jkt` (either explicitly or via a DPoP proof at PAR), the auth code
        // is sender-constrained and the /token redemption MUST present a DPoP proof bound to
        // the same key. Reject when the proof is missing or the thumbprint differs — silently
        // issuing a non-DPoP token in either case downgrades the binding the wallet committed
        // to and lets a stolen auth code be redeemed without proof of possession.
        //
        // Server-level DPoP REQUIRED (FAPI2 / HAIP) widens the same gate: if policy mandates
        // DPoP-bound access tokens, an auth-code redemption that arrives without a proof MUST
        // be refused even when the front channel did not stamp a `dpop_jkt` onto the code (the
        // OIDF `EnsureHolderOfKeyRequired` test exercises this — wallets that present neither
        // a DPoP header nor a `dpop_jkt` form parameter at PAR previously got an unbound token
        // back). RFC 9449 §11.1 lets us answer with `invalid_dpop_proof`, but RFC 6749 §5.2's
        // `invalid_grant` is what every FAPI2 condition (`CheckTokenEndpointReturnedInvalidClient
        // GrantOrRequestError`, the holder-of-key block) accepts in common, so we emit that and
        // keep the per-grant error semantics consistent across grant types.
        val committedJkt = verified.dpopJkt
        val dpopRequired = context.serverConfig.dpop.isRequired
        if (proofJkt == null && (committedJkt != null || dpopRequired)) {
            logTokenRefusal(log, "Authorization code grant refused stage=dpop-proof-missing code_bound=${committedJkt != null} server_required=$dpopRequired")
            val reason =
                if (committedJkt != null) {
                    "Authorization code is DPoP-bound but the token request did not present a DPoP proof"
                } else {
                    "Server policy requires DPoP-bound access tokens but the token request did not present a DPoP proof"
                }
            return errOf(AuthorizationServerError.InvalidGrant(details = reason))
        }
        if (committedJkt != null && proofJkt != null && committedJkt != proofJkt) {
            logTokenRefusal(log, "Authorization code grant refused stage=dpop-key-binding")
            return invalidDpopProof("DPoP proof thumbprint does not match dpop_jkt committed at /authorize")
        }
        val boundJkt = proofJkt ?: committedJkt

        val credentialConfigurationIds =
            (verified.additionalData["credential_configuration_ids"] as? List<*>)
                ?.filterIsInstance<String>()
                ?.ifEmpty { null }
        val issuerState =
            (verified.additionalData["issuer_state"] as? String)
                ?.takeIf(String::isNotBlank)
        val authCodeAuthorizationDetails =
            buildAuthorizationCodeCredentialAuthorizationDetails(
                credentialConfigurationIds = credentialConfigurationIds,
                issuanceSessionId = issuerState,
            )

        // Access token: no identity claims (RFC 9068). The OIDC `claims` request parameter
        // (§5.5) carries through `additionalData` so /userinfo can union the requested per-
        // claim names with the scope-derived set. We pass them via additionalClaims; the
        // create-access-token command filters internal `oidc.*` keys out of the JWT payload
        // (would otherwise leak the userinfo-claim wishlist to RPs reading the JWT) but
        // keeps them on the stored token for the userinfo endpoint to read.
        val federationClaims = FederationTokenMetadata.fromUserClaims(buildJsonObject {
            putClaims(verified.userClaims)
        })
        val accessTokenAdditional =
            buildMap<String, Any> {
                federationClaims?.let { put(FederationTokenMetadata.KEY, it) }
                (verified.codeData.additionalData[SESSION_KEY_OIDC_CLAIMS_USERINFO] as? List<*>)
                    ?.filterIsInstance<String>()
                    ?.takeIf { it.isNotEmpty() }
                    ?.let { put(SESSION_KEY_OIDC_CLAIMS_USERINFO, it) }

                // RFC 9068 §2.2.3.1 authorization claims: `roles` is a REGISTERED claim for
                // JWT access tokens (sourced from RFC 7643 §4.1.2), unlike the identity
                // claims this token deliberately omits. When the authenticated user carries
                // a `roles` string collection (the local user provider surfaces it via
                // UserInfo.attributes -> userClaims; federated providers may surface it as a
                // JsonArray of string primitives), embed it so resource servers can make
                // role-based authorization decisions from the bearer token alone.
                val roles =
                    when (val raw = verified.userClaims[ROLES_CLAIM]) {
                        is JsonArray -> raw.mapNotNull { element -> (element as? JsonPrimitive)?.takeIf { it.isString }?.content }
                        is Collection<*> -> raw.filterIsInstance<String>()
                        else -> emptyList()
                    }
                if (roles.isNotEmpty()) {
                    put(ROLES_CLAIM, roles)
                }

                context.walletInstanceAttestation?.let { putAll(it.accessTokenClaims()) }
                authCodeAuthorizationDetails?.let { put("authorization_details", it) }
                // Internal AS -> credential-issuer correlation for scope-based OID4VCI
                // authorization requests. Stored token metadata retains this value for
                // introspection while the access-token JWT excludes the internal namespace.
                issuerState?.let { put(INTERNAL_OID4VCI_ISSUER_STATE_CLAIM, it) }
            }
        val accessToken =
            createAccessToken
                .execute(
                    CreateAccessTokenArgs(
                        subject = verified.subject,
                        clientId = tokenRequest.clientId,
                        scope = verified.scope,
                        audience =
                            verified.codeData.admittedAudiences
                                ?: verified.resource
                                .ifEmpty { listOfNotNull(verified.defaultAccessTokenAudience) }
                                .ifEmpty { credentialIssuerAudienceResolver.boundCredentialIssuers().map { it.audience } },
                        dpopJkt = boundJkt,
                        certificateThumbprintS256 = certThumbprint,
                        authTime = verified.codeData.authTime,
                        acr = verified.codeData.acr,
                        amr = verified.codeData.amr,
                        additionalClaims = accessTokenAdditional,
                        baseUrlOverride = applied.baseUrlOverride,
                    ),
                ).getOrElse { error -> return Err(error) }

        // OIDC Core 1.0 §12: persist the original authentication context on the
        // refresh-token row so a future refresh-grant can reissue an id_token with
        // auth_time / acr / amr / nonce / sid pinned to the original authentication.
        val refreshToken =
            createRefreshToken.value
                .issueForVerifiedAuthorizationCode(verified, context, clientAuthorization)
                .getOrElse { error -> return Err(error) }

        // RFC 6749 §10.5: stash the freshly-minted tokens on the (now consumed) auth-code
        // entry so a replay of the same code can fetch them and revoke. Best-effort — a
        // storage failure here is logged inside the storage impl and does not roll back the
        // tokens we've just issued; the worst case is a missed SHOULD-level revocation.
        authorizationCodeStorage.recordIssuedTokensForCode(
            code = authParams.code,
            accessToken = accessToken.value,
            refreshToken = refreshToken.value,
        )

        // Issue ID token when OIDC is enabled and openid scope is granted
        val grantedScopes = verified.scope?.split(" ")?.toSet() ?: emptySet()
        val oidcEnabled = context.serverConfig.oidc.isEnabled
        val idToken =
            if (oidcEnabled && "openid" in grantedScopes) {
                // Scope-based claim filtering for id_token:
                // Standard OIDC claims are scope-filtered; custom claims pass through
                val idTokenClaims =
                    if (scopeClaimsMapper != null && verified.userClaims.isNotEmpty()) {
                        val scopeFiltered = scopeClaimsMapper.filterClaims(verified.userClaims, grantedScopes)
                        val standardClaimKeys = scopeClaimsMapper.allStandardClaimKeys()
                        val customClaims = verified.userClaims.filterKeys { it !in standardClaimKeys }
                        scopeFiltered + customClaims
                    } else {
                        verified.userClaims
                    }

                // OIDC Core §5.5 — explicit `claims.id_token` request parameter. The
                // RP can ask the AS to embed specific claim names directly into the
                // id_token even when the auth-code flow's default would route them
                // through /userinfo (§5.4). The session bag captured the requested
                // names at /authorize time as a List<String> under
                // SESSION_KEY_OIDC_CLAIMS_ID_TOKEN; we look up the corresponding
                // values from the projected userClaims and feed them through
                // CreateIdTokenArgs.additionalClaims, which CreateIdTokenCommandImpl
                // unconditionally embeds into the id_token (regardless of the
                // server-level `embed-userinfo-claims-in-id-token` knob).
                val requestedIdTokenClaims =
                    (verified.codeData.additionalData[SESSION_KEY_OIDC_CLAIMS_ID_TOKEN] as? List<*>)
                        ?.filterIsInstance<String>()
                        ?.toSet()
                        ?: emptySet()
                val explicitIdTokenClaims =
                    if (requestedIdTokenClaims.isNotEmpty() && verified.userClaims.isNotEmpty()) {
                        verified.userClaims.filterKeys { it in requestedIdTokenClaims }
                    } else {
                        emptyMap()
                    }

                createIdToken.value
                    .execute(
                        CreateIdTokenArgs(
                            subject = verified.subject,
                            clientId = tokenRequest.clientId,
                            nonce = verified.codeData.nonce,
                            authTime = verified.codeData.authTime,
                            acr = verified.codeData.acr,
                            amr = verified.codeData.amr,
                            accessToken = accessToken.value,
                            authorizationCode = authParams.code,
                            userClaims = idTokenClaims,
                            additionalClaims = explicitIdTokenClaims,
                            sessionId = verified.codeData.sessionId,
                            baseUrlOverride = applied.baseUrlOverride,
                        ),
                    ).getOrElse { error -> return Err(error) }
                    .value
            } else {
                null
            }

        // OID4VCI 1.1 Section 7.2: include authorization_details with credential_identifiers
        // when the auth-code grant carried credential configuration IDs (e.g. from authorization_details
        // in the original authorization request), so the wallet knows which credentials to request.
        return createTokenResponse.execute(
            CreateTokenResponseArgs(
                accessToken = accessToken.value,
                tokenType = tokenTypeFor(boundJkt),
                refreshToken = refreshToken.value,
                scope = verified.scope,
                idToken = idToken,
                authorizationDetails = authCodeAuthorizationDetails,
            ),
        )
    }

    private companion object {
        /** RFC 9068 §2.2.3.1 / RFC 7643 §4.1.2 authorization claim name. */
        private const val ROLES_CLAIM = "roles"
        private const val INTERNAL_OID4VCI_ISSUER_STATE_CLAIM = "oid4vci.internal.issuer_state"
    }
}

@OptIn(ExperimentalUuidApi::class)
internal fun buildAuthorizationCodeCredentialAuthorizationDetails(
    credentialConfigurationIds: List<String>?,
    issuanceSessionId: String? = null,
    credentialIdentifierProvider: ((String) -> String)? = null,
): JsonArray? =
    credentialConfigurationIds?.takeIf { it.isNotEmpty() }?.let { configIds ->
        JsonArray(
            configIds.map { configId ->
                val identifier =
                    credentialIdentifierProvider?.invoke(configId)
                        ?: buildString {
                            append("urn:vdx:oid4vci:credential:")
                            issuanceSessionId?.takeIf(String::isNotBlank)?.let {
                                append(it)
                                append(':')
                            }
                            append(Uuid.random())
                        }
                buildJsonObject {
                    put("type", JsonPrimitive("openid_credential"))
                    put("credential_configuration_id", JsonPrimitive(configId))
                    // This is an authorization handle for one Credential Dataset, not the
                    // credential_configuration_id and not an OAuth scope value.
                    putJsonArray("credential_identifiers") {
                        add(JsonPrimitive(identifier))
                    }
                }
            },
        )
    }
