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

package com.sphereon.oauth2.server.authorization.command

import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.ServiceCommand
import com.sphereon.core.api.service.StringResult
import com.sphereon.oauth2.common.model.ActorClaim
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.model.TokenResponse
import com.sphereon.oauth2.server.authorization.model.AuthorizationCodeData
import kotlinx.serialization.json.JsonElement

// ============================================================================
// ParseTokenRequestCommand
// ============================================================================

/**
 * Arguments for parsing a token request.
 *
 * [httpUrl] is the absolute URL of the token endpoint (`scheme://host/path`, no query / fragment).
 * Used for DPoP `htu` binding per RFC 9449 §4.2; supplied by the HTTP shell from `Host` +
 * `X-Forwarded-Proto` so proofs verify behind a proxy.
 */
data class ParseTokenRequestArgs(
    val requestBody: Map<String, List<String>>,
    val requestHeaders: Map<String, String> = emptyMap(),
    val httpUrl: String = "",
    /**
     * Leaf TLS client certificate (DER bytes) extracted at the HTTP shell when the token
     * endpoint accepts mTLS (RFC 8705 §2). `null` when the request did not arrive over mTLS.
     * Used by [extractClientAuthentication] to promote a `client_id`-only request to a
     * [com.sphereon.oauth2.common.model.ClientAuthenticationConfig.MutualTls] auth.
     */
    val clientCertificateDer: ByteArray? = null,
)

/**
 * Parse token request command
 *
 * RFC 6749 Section 4.1.3: Token Request
 *
 * Parses and validates the incoming token request from the client.
 * Extracts grant type and grant-specific parameters.
 */
interface ParseTokenRequestCommand : ServiceCommand<ParseTokenRequestArgs, TokenRequestData, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.token.parse"
    }
}

// ============================================================================
// VerifyAuthorizationCodeGrantCommand
// ============================================================================

/**
 * Arguments for verifying an authorization code grant
 */
data class VerifyAuthorizationCodeGrantArgs(
    val code: String,
    val redirectUri: String,
    val clientId: String,
    val codeVerifier: String? = null,
    val requestedResource: List<String> = emptyList(),
)

/**
 * Verify authorization code grant command
 *
 * RFC 6749 Section 4.1.3: Authorization Code Grant
 *
 * Verifies an authorization code grant token request:
 * - Validates authorization code
 * - Verifies redirect_uri matches
 * - Validates PKCE (if used)
 * - Ensures code hasn't been used
 * - Verifies client authentication
 */
interface VerifyAuthorizationCodeGrantCommand : ServiceCommand<VerifyAuthorizationCodeGrantArgs, VerifiedAuthorizationCodeGrant, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.authcode.verify"
    }
}

// ============================================================================
// VerifyRefreshTokenGrantCommand
// ============================================================================

/**
 * Arguments for verifying a refresh token grant
 */
data class VerifyRefreshTokenGrantArgs(
    val refreshToken: String,
    val clientId: String,
    val clientInstanceKeyJkt: String? = null,
    val requestedScope: String? = null,
    val requestedResource: List<String> = emptyList(),
    val clientAuthorization: VerifiedClientAuthorization? = null,
)

/**
 * Verify refresh token grant command
 *
 * RFC 6749 Section 6: Refreshing an Access Token
 *
 * Verifies a refresh token grant:
 * - Validates refresh token
 * - Ensures token not expired/revoked
 * - Verifies client authentication
 * - Validates requested scope (must be subset of original)
 */
interface VerifyRefreshTokenGrantCommand : ServiceCommand<VerifyRefreshTokenGrantArgs, VerifiedRefreshTokenGrant, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.refresh.verify"
    }
}

// ============================================================================
// VerifyClientCredentialsGrantCommand
// ============================================================================

/**
 * Arguments for verifying a client credentials grant
 */
data class VerifyClientCredentialsGrantArgs(
    val clientId: String,
    val requestedScope: String? = null,
    val requestedAudience: List<String> = emptyList(),
)

/**
 * Verify client credentials grant command
 *
 * RFC 6749 Section 4.4: Client Credentials Grant
 *
 * Verifies a client credentials grant:
 * - Validates client authentication
 * - Verifies client is authorized for this grant type
 * - Validates requested scope
 */
interface VerifyClientCredentialsGrantCommand : ServiceCommand<VerifyClientCredentialsGrantArgs, VerifiedClientCredentialsGrant, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.clientcreds.verify"
    }
}

// ============================================================================
// CreateAccessTokenCommand
// ============================================================================

/**
 * Arguments for creating an access token.
 *
 * [baseUrlOverride] carries the per-request base URL (resolved from `Host` + `X-Forwarded-Proto`
 * by the HTTP layer) so the issued `iss` claim matches what discovery emits when the AS is
 * reached via a proxy/tunnel and `serverConfig.issuer` is unset. Resolution order at issuance:
 * `serverConfig.issuer` (configured wins), else this override. When neither is available the
 * command fails. Mirrors `BuildServerMetadataCommandImpl` so OIDF conformance holds.
 */
data class CreateAccessTokenArgs(
    val subject: String,
    val clientId: String,
    val scope: String? = null,
    val audience: List<String> = emptyList(),
    val expiresInSeconds: Int = 3600,
    /** Explicit configured server key for trusted in-process callers without an HTTP host route. */
    val serverId: String? = null,
    val dpopJkt: String? = null,
    val clientInstanceKeyJkt: String? = null,
    /** Authentication time from the end-user authentication event, in epoch seconds. */
    val authTime: Long? = null,
    /** Authentication Context Class Reference achieved for this end-user token. */
    val acr: String? = null,
    /** Authentication Methods References achieved for this end-user token. */
    val amr: List<String>? = null,
    val additionalClaims: Map<String, Any> = emptyMap(),
    val baseUrlOverride: String? = null,
    /**
     * RFC 8705 §3.1: SHA-256 thumbprint of the TLS client certificate (DER) presented at the
     * token endpoint, base64url-encoded without padding. When non-null, the issued access
     * token carries `cnf.x5t#S256` bound to this thumbprint, restricting its presentation to
     * resource-server requests over mTLS with a matching certificate. Combines additively with
     * [dpopJkt] when both bindings apply (RFC 8705 §3 + RFC 9449 §6).
     */
    val certificateThumbprintS256: String? = null,
)

/**
 * Create access token command
 *
 * Generates a new access token (JWT format recommended).
 * Includes all necessary claims and bindings.
 */
interface CreateAccessTokenCommand : ServiceCommand<CreateAccessTokenArgs, StringResult, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.accesstoken.create"
    }
}

// ============================================================================
// CreateRefreshTokenCommand
// ============================================================================

/**
 * Arguments for creating a refresh token.
 *
 * The OIDC fields (`authTime`, `acr`, `amr`, `nonce`, `loginSessionId`) are persisted on the
 * stored `RefreshTokenData` so refresh-token rotation (RFC 6749 §6) can reissue an id_token
 * per OIDC Core 1.0 §12 with the original authentication context preserved. Non-OIDC grants
 * (client_credentials, token-exchange) leave them null.
 */
data class CreateRefreshTokenArgs(
    val subject: String,
    val clientId: String,
    val scope: String? = null,
    val resource: List<String> = emptyList(),
    val defaultAccessTokenAudience: String? = null,
    /** OID4VCI configurations authorized for this refresh-token chain. */
    val credentialConfigurationIds: List<String> = emptyList(),
    /** Server-internal issuer-state correlation preserved across refresh-token rotation. */
    val oid4vciIssuerState: String? = null,
    val expiresInSeconds: Int? = null,
    val dpopJkt: String? = null,
    val clientInstanceKeyJkt: String? = null,
    /**
     * Epoch seconds of the original end-user authentication. Persisted on the refresh-token
     * row so refresh-time id_token reissue keeps `auth_time` pinned to the original auth.
     */
    val authTime: Long? = null,
    /**
     * Authentication Context Class Reference, persisted on the refresh-token row.
     */
    val acr: String? = null,
    /**
     * Authentication Methods References, persisted on the refresh-token row.
     */
    val amr: List<String>? = null,
    /**
     * OIDC nonce from the original authorization request, persisted so refresh-time id_token
     * reissue echoes the original nonce.
     */
    val nonce: String? = null,
    /**
     * Cookie-keyed `oidc_login_sid` from the original login session, persisted so refresh-time
     * id_token reissue keeps the same `sid` claim and Back-Channel Logout recipient set.
     */
    val loginSessionId: String? = null,
    /** Serialized private federation metadata; never a public token-response claim. */
    val federationClaims: String? = null,
)

/**
 * Create refresh token command
 *
 * Generates a new refresh token (opaque or JWT).
 */
interface CreateRefreshTokenCommand : ServiceCommand<CreateRefreshTokenArgs, StringResult, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.refreshtoken.create"
    }
}

// ============================================================================
// CreateTokenResponseCommand
// ============================================================================

/**
 * Arguments for creating a token response
 */
data class CreateTokenResponseArgs(
    val accessToken: String,
    val tokenType: String = "Bearer",
    val expiresIn: Int = 3600,
    val refreshToken: String? = null,
    val scope: String? = null,
    val idToken: String? = null,
    val cNonce: String? = null,
    val cNonceExpiresIn: Int? = null,
    val issuedTokenType: String? = null,
    /** OID4VCI 1.1 Section 7.2: authorization_details array to include in the token response. */
    val authorizationDetails: JsonElement? = null,
    val additionalParameters: Map<String, Any> = emptyMap(),
)

/**
 * Create token response command
 *
 * Assembles the complete token response including:
 * - Access token
 * - Token type (Bearer or DPoP)
 * - Expires in
 * - Refresh token (optional)
 * - Scope (optional)
 * - Additional parameters (c_nonce, etc.)
 */
interface CreateTokenResponseCommand : ServiceCommand<CreateTokenResponseArgs, TokenResponse, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.tokenresponse.create"
    }
}

// ============================================================================
// Data Models
// ============================================================================

/**
 * Parsed token request data
 */
data class TokenRequestData(
    /**
     * Grant type from the request
     */
    val grantType: GrantType,
    /**
     * Client ID (from body or authentication)
     */
    val clientId: String,
    /**
     * Client authentication config (extracted from headers/body)
     */
    val clientAuthentication: ClientAuthenticationConfig,
    /**
     * Grant-specific parameters
     */
    val grantParameters: GrantParameters,
    /**
     * DPoP proof JWT (if present)
     */
    val dpopProof: String? = null,
    /**
     * HTTP method and URL (for DPoP verification)
     */
    val httpMethod: String = "POST",
    val httpUrl: String,
)

/**
 * Grant-specific parameters
 */
sealed interface GrantParameters {
    /**
     * Authorization code grant parameters
     */
    data class AuthorizationCode(
        val code: String,
        val redirectUri: String,
        val codeVerifier: String? = null,
        val resource: List<String> = emptyList(),
    ) : GrantParameters

    /**
     * Refresh token grant parameters
     */
    data class RefreshToken(
        val refreshToken: String,
        val scope: String? = null,
        val resource: List<String> = emptyList(),
    ) : GrantParameters

    /**
     * Client credentials grant parameters
     */
    data class ClientCredentials(
        val scope: String? = null,
        val audiences: List<String> = emptyList(),
    ) : GrantParameters

    /**
     * Resource owner password credentials grant parameters (RFC 6749 Section 4.3).
     */
    data class Password(
        val username: String,
        val password: String,
        val scope: String? = null,
    ) : GrantParameters

    /**
     * Pre-authorized code grant parameters (OpenID4VCI)
     */
    data class PreAuthorizedCode(
        val preAuthorizedCode: String,
        val txCode: String? = null,
    ) : GrantParameters

    /**
     * Token exchange grant parameters (RFC 8693)
     */
    data class TokenExchange(
        val subjectToken: String,
        val subjectTokenType: String,
        val actorToken: String? = null,
        val actorTokenType: String? = null,
        val resources: List<String> = emptyList(),
        val audiences: List<String> = emptyList(),
        val scope: String? = null,
        val requestedTokenType: String? = null,
    ) : GrantParameters

    /**
     * Device authorization grant parameters (RFC 8628 §3.4).
     *
     * Per RFC 8628 §3.4 the token request carries `device_code` (REQUIRED) and `client_id`
     * (REQUIRED if the client is not authenticating with the AS via another mechanism). The
     * AS poll responses (`authorization_pending`, `slow_down`, `access_denied`, `expired_token`)
     * are emitted by the token grant branch, not surfaced on these parsed parameters.
     */
    data class DeviceCode(
        val deviceCode: String,
        val clientId: String? = null,
    ) : GrantParameters
}

/**
 * Verified authorization code grant
 */
data class VerifiedAuthorizationCodeGrant(
    /**
     * Authorization code data
     */
    val codeData: AuthorizationCodeData,
    /**
     * Subject (user ID)
     */
    val subject: String,
    /**
     * Client ID
     */
    val clientId: String,
    /**
     * Granted scope
     */
    val scope: String? = null,
    val resource: List<String> = emptyList(),
    val defaultAccessTokenAudience: String? = null,
    /**
     * DPoP JWK thumbprint (if DPoP-bound)
     */
    val dpopJkt: String? = null,
    /**
     * User claims carried through the authorization code exchange.
     * Used for id_token population (scope-filtered) at token issuance.
     */
    val userClaims: Map<String, Any> = emptyMap(),
    /**
     * Additional authorization details
     */
    val additionalData: Map<String, Any> = emptyMap(),
)

/**
 * Verified refresh token grant
 */
data class VerifiedRefreshTokenGrant(
    /**
     * Subject (user ID)
     */
    val subject: String,
    /**
     * Client ID
     */
    val clientId: String,
    /**
     * Granted scope (may be subset of original)
     */
    val scope: String? = null,
    val resource: List<String> = emptyList(),
    val defaultAccessTokenAudience: String? = null,
    /** OID4VCI configurations authorized for this refresh-token chain. */
    val credentialConfigurationIds: List<String> = emptyList(),
    /** Server-internal issuer-state correlation preserved across refresh-token rotation. */
    val oid4vciIssuerState: String? = null,
    /**
     * DPoP JWK thumbprint (if DPoP-bound)
     */
    val dpopJkt: String? = null,
    /** Attested client-instance key binding preserved for the refresh-token chain. */
    val clientInstanceKeyJkt: String? = null,
    /** Existing successor when this request is a lost-response retry inside the grace period. */
    val replacementRefreshToken: String? = null,
    /**
     * Original refresh token ID (for rotation)
     */
    val refreshTokenId: String,
    /**
     * Epoch seconds of the ORIGINAL end-user authentication that minted this chain.
     * Surfaced from `RefreshTokenData.authTime` so OIDC Core 1.0 §12 id_token reissue
     * populates `auth_time` with the original authentication time, not refresh time.
     */
    val authTime: Long? = null,
    /**
     * Authentication Context Class Reference (OpenID Connect Core 1.0 §2) preserved from
     * the original AuthCode grant.
     */
    val acr: String? = null,
    /**
     * Authentication Methods References (OpenID Connect Core 1.0 §2) preserved from the
     * original AuthCode grant.
     */
    val amr: List<String>? = null,
    /**
     * OpenID Connect nonce from the original authorization request, preserved so the
     * refreshed id_token's `nonce` matches the original.
     */
    val nonce: String? = null,
    /**
     * Cookie-keyed `oidc_login_sid` for the original login session, used as the refreshed
     * id_token's `sid` claim.
     */
    val loginSessionId: String? = null,
    /** Private federation metadata retained from the original refresh-token row. */
    val federationClaims: String? = null,
)

/**
 * Verified client credentials grant
 */
data class VerifiedClientCredentialsGrant(
    /**
     * Subject (typically client ID)
     */
    val subject: String,
    /**
     * Client ID
     */
    val clientId: String,
    /**
     * Granted scope
     */
    val scope: String? = null,
    /** Exact access-token audience authorized by this client's registration. */
    val audience: List<String> = emptyList(),
    /** Claims copied only from the authenticated client's server-side registration. */
    val additionalClaims: Map<String, Any> = emptyMap(),
)
