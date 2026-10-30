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
import com.sphereon.oauth2.common.model.OAuth2ResponseMode
import com.sphereon.oauth2.common.model.PkceMethod
import com.sphereon.oauth2.common.model.ResponseType
import com.sphereon.oauth2.server.authorization.model.AuthorizationSession
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ConsentDecision
import com.sphereon.oauth2.server.authorization.model.Prompt
import kotlinx.serialization.json.JsonObject

// ============================================================================
// 1. ParseAuthorizationRequestCommand
// ============================================================================

/**
 * Arguments for parsing an authorization request
 */
data class ParseAuthorizationRequestArgs(
    val queryParameters: Map<String, String>,
)

/**
 * Parse authorization request command
 *
 * RFC 6749 Section 4.1.1: Authorization Request
 *
 * Parses and validates the incoming authorization request.
 * Extracts all parameters from query string.
 */
interface ParseAuthorizationRequestCommand : ServiceCommand<ParseAuthorizationRequestArgs, AuthorizationRequestData, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.authorization.parse"
    }
}

// ============================================================================
// 2. VerifyAuthorizationRequestCommand
// ============================================================================

/**
 * Verify authorization request command
 *
 * RFC 6749 Section 4.1.2.1: Error Response
 *
 * Verifies the authorization request:
 * - Validates client_id
 * - Validates redirect_uri
 * - Validates response_type
 * - Validates scope
 * - Validates PKCE (if present)
 */
interface VerifyAuthorizationRequestCommand : ServiceCommand<AuthorizationRequestData, VerifiedAuthorizationRequest, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.authorization.verify"
    }
}

// ============================================================================
// 3. CreateAuthorizationSessionCommand
// ============================================================================

/**
 * Create authorization session command
 *
 * Creates a session to track the authorization flow across multiple requests.
 * The session stores all request parameters and will be updated as the flow progresses.
 */
interface CreateAuthorizationSessionCommand : ServiceCommand<VerifiedAuthorizationRequest, AuthorizationSession, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.session.create"
    }
}

// ============================================================================
// 4. CreateAuthorizationCodeCommand
// ============================================================================

/**
 * Arguments for creating an authorization code
 */
data class CreateAuthorizationCodeArgs(
    val session: AuthorizationSession,
    val userId: String,
    val consent: ConsentDecision,
    val userClaims: Map<String, Any> = emptyMap(),
    val acr: String? = null,
    val amr: List<String>? = null,
)

/**
 * Create authorization code command
 *
 * Generates an authorization code after successful user authentication and consent.
 *
 * RFC 6749 Section 4.1.2: Authorization Response
 */
interface CreateAuthorizationCodeCommand : ServiceCommand<CreateAuthorizationCodeArgs, StringResult, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.authcode.create"
    }
}

// ============================================================================
// 5. CreateAuthorizationResponseCommand
// ============================================================================

/**
 * Arguments for creating an authorization response
 *
 * @property code The authorization code minted by [CreateAuthorizationCodeCommand].
 * @property state State value echoed from the request (RFC 6749 §4.1.2).
 * @property redirectUri Validated redirect URI; the response is delivered there.
 * @property responseMode Resolved response mode (`query` / `fragment` / `form_post` for the bare
 *   carriers, or one of the JARM `*.jwt` variants when the client requested JARM).
 * @property clientId Client id of the recipient. Required when [responseMode] is a JARM mode (it
 *   becomes the JARM JWT's `aud` claim) and used by the OIDF JARM spec for client-key resolution
 *   when the response is encrypted.
 * @property baseUrlOverride Per-request issuer URL override used when no static issuer is
 *   configured on the AS. Mirrors the same field on token / id-token args; consumed by JARM to
 *   set the response JWT's `iss` claim when [com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.issuer]
 *   is unset.
 */
data class CreateAuthorizationResponseArgs(
    val code: String,
    val state: String? = null,
    val redirectUri: String,
    val responseMode: OAuth2ResponseMode = OAuth2ResponseMode.QUERY,
    val clientId: String? = null,
    val baseUrlOverride: String? = null,
    /**
     * OIDC Core §3.3 (Hybrid Flow) — front-channel id_token minted at /authorize alongside
     * the code. Carried back to the client in the URL fragment or form_post body. Null for
     * pure code flow.
     */
    val idToken: String? = null,
    /**
     * OIDC Core §3.3 (Hybrid Flow with `code token` / `code id_token token`) — front-channel
     * access token. Null for pure code flow and for `code id_token`.
     */
    val accessToken: String? = null,
    /**
     * Token type (typically "Bearer") echoed back when [accessToken] is non-null.
     */
    val tokenType: String? = null,
    /**
     * Expiration (seconds) for the front-channel access token, when present.
     */
    val accessTokenExpiresIn: Int? = null,
)

/**
 * Create authorization response command
 *
 * Creates the authorization response to redirect the user back to the client.
 *
 * RFC 6749 Section 4.1.2: Authorization Response
 */
interface CreateAuthorizationResponseCommand : ServiceCommand<CreateAuthorizationResponseArgs, AuthorizationResponseData, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.authorization.respond"
    }
}

// ============================================================================
// 6. CreateAuthorizationErrorResponseCommand
// ============================================================================

/**
 * Arguments for creating an authorization error response.
 *
 * The [responseMode] must match the mode the client requested in the original authorization
 * request (or its OIDC Core §3.1.2.1 default) — the OIDF RP tests verify that errors are
 * returned via the same mechanism as the success response would have been (query / fragment /
 * form_post).
 */
data class CreateAuthorizationErrorResponseArgs(
    val error: String,
    val errorDescription: String? = null,
    val errorUri: String? = null,
    val state: String? = null,
    val redirectUri: String,
    val responseMode: OAuth2ResponseMode = OAuth2ResponseMode.QUERY,
    val clientId: String? = null,
    val baseUrlOverride: String? = null,
)

/**
 * Create authorization error response command
 *
 * Creates an error response to redirect the user back to the client.
 *
 * RFC 6749 Section 4.1.2.1: Error Response
 */
interface CreateAuthorizationErrorResponseCommand : ServiceCommand<CreateAuthorizationErrorResponseArgs, AuthorizationErrorResponseData, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.authorization.error"
    }
}

// ============================================================================
// Data Models
// ============================================================================

/**
 * Parsed authorization request data
 */
data class AuthorizationRequestData(
    /**
     * Client identifier
     */
    val clientId: String,
    /**
     * Redirect URI. Nullable because OAuth2 RFC 6749 §3.1.2.3 / OIDC §3.1.2.1 allow omission when
     * exactly one redirect URI is registered for the client; the verifier resolves it from the
     * client registration in that case.
     */
    val redirectUri: String? = null,
    /**
     * Response type (code, token, id_token, etc.)
     */
    val responseType: List<ResponseType>,
    /**
     * Requested scope
     */
    val scope: String? = null,
    /**
     * State parameter (RECOMMENDED for CSRF protection)
     */
    val state: String? = null,
    /**
     * PKCE code challenge
     */
    val codeChallenge: String? = null,
    /**
     * PKCE code challenge method
     */
    val codeChallengeMethod: PkceMethod? = null,
    /**
     * DPoP JWK thumbprint (RFC 9449)
     */
    val dpopJkt: String? = null,
    /**
     * Response mode (query, fragment, form_post)
     */
    val responseMode: String? = null,
    /**
     * Nonce (for OpenID Connect)
     */
    val nonce: String? = null,
    /**
     * Display mode (page, popup, touch, wap)
     */
    val display: String? = null,
    /**
     * OIDC `prompt` parameter (Core 1.0 §3.1.2.1) decoded from the space-separated wire value
     * via [Prompt.parseSpaceSeparated]. Empty when the parameter was absent or contained only
     * unrecognised tokens. Drives the Group I session-evaluation table (`none` -> silent flow,
     * `login` / `select_account` -> force reauth, `consent` -> show consent UI).
     */
    val prompt: Set<Prompt> = emptySet(),
    /**
     * Max age (maximum authentication age)
     */
    val maxAge: Int? = null,
    /**
     * UI locales
     */
    val uiLocales: List<String>? = null,
    /**
     * ID token hint
     */
    val idTokenHint: String? = null,
    /**
     * Login hint
     */
    val loginHint: String? = null,
    /**
     * ACR values (authentication context class reference)
     */
    val acrValues: List<String>? = null,
    /**
     * Resource indicators (RFC 8707)
     */
    val resource: List<String>? = null,
    /**
     * Request URI (for JAR)
     */
    val requestUri: String? = null,
    /**
     * Request object (JAR)
     */
    val request: String? = null,
    /**
     * OIDC `claims` parameter (OpenID Connect Core §5.5) — a JSON object that requests specific
     * claims be returned from the UserInfo endpoint and/or included in the ID token.
     * Parsed eagerly so the parser can reject malformed JSON at the boundary, even when the
     * verifier ultimately ignores the value (e.g. when no downstream claims-driven behavior is
     * wired).
     */
    val claims: JsonObject? = null,
    /**
     * Additional parameters
     */
    val additionalParameters: Map<String, String> = emptyMap(),
    /** Process-only verifier result; HTTP parsing never creates or reads this field. */
    @kotlinx.serialization.Transient
    val authorizationEvidence: com.sphereon.oauth2.server.authorization.command.jar.AuthorizationRequestEvidence? = null,
)

/**
 * Verified authorization request
 */
data class VerifiedAuthorizationRequest(
    /**
     * Original request data
     */
    val request: AuthorizationRequestData,
    /**
     * Client ID (validated)
     */
    val clientId: String,
    /**
     * Redirect URI (validated against client registration)
     */
    val redirectUri: String,
    /**
     * Granted scopes (may be subset of requested)
     */
    val grantedScopes: List<String>,
    /** Exact AS-client default access-token audience bound at authorization time. */
    val defaultAccessTokenAudience: String? = null,
    /**
     * Whether PKCE is required for this client
     */
    val pkceRequired: Boolean,
    /**
     * Whether PAR is required for this client
     */
    val parRequired: Boolean,
    /**
     * PKCE `code_challenge_method` resolved after applying server policy. When the request
     * supplies `code_challenge` without `code_challenge_method`, RFC 7636 §4.3 defines the
     * default as `plain`; the verifier may reject that if the server's
     * `pkceMethodsSupported` policy forbids it. `null` means the request did not use PKCE.
     */
    val resolvedPkceMethod: PkceMethod? = null,
    /**
     * Response mode resolved against server metadata and (if applicable) client registration.
     * Parser emits the raw string; the verifier translates to the typed enum and applies the
     * OIDC Core §3.1.2.1 default per response_type when the parameter is absent.
     */
    val responseMode: OAuth2ResponseMode = OAuth2ResponseMode.QUERY,
    /** Credential issuer audiences selected by the unregistered-wallet admission rule. */
    val admittedAudiences: List<String>? = null,
    /** Synthesized registration produced by the typed wallet admission rule. */
    val admittedClient: ClientRegistration? = null,
)

/**
 * Authorization response data
 */
data class AuthorizationResponseData(
    /**
     * Authorization code
     */
    val code: String,
    /**
     * State parameter (echoed from request)
     */
    val state: String?,
    /**
     * Final URL the client should land on. For [OAuth2ResponseMode.QUERY] / [OAuth2ResponseMode.FRAGMENT]
     * this is the registered redirect URI with response parameters appended; for
     * [OAuth2ResponseMode.FORM_POST] this is the bare registered redirect URI (parameters live in
     * [formPostHtml]).
     */
    val redirectUri: String,
    /**
     * Response mode used for this response.
     */
    val responseMode: OAuth2ResponseMode = OAuth2ResponseMode.QUERY,
    /**
     * HTML body for `form_post` responses — an auto-submitting form POSTing the response
     * parameters to [redirectUri]. Populated iff [responseMode] is [OAuth2ResponseMode.FORM_POST];
     * `null` otherwise. Callers emit a `200 OK` with `Content-Type: text/html;charset=UTF-8`
     * when this field is non-null, in place of the usual `302 Location` redirect.
     */
    val formPostHtml: String? = null,
)

/**
 * Authorization error response data.
 *
 * Mirrors [AuthorizationResponseData]: for [OAuth2ResponseMode.QUERY] / [OAuth2ResponseMode.FRAGMENT]
 * the [redirectUri] carries the error parameters and the adapter emits a 302 redirect; for
 * [OAuth2ResponseMode.FORM_POST], [redirectUri] is the bare registered URI and error params live
 * in [formPostHtml] which the adapter renders as a 200-OK auto-submitting form.
 */
data class AuthorizationErrorResponseData(
    /**
     * Error code
     */
    val error: String,
    /**
     * Error description
     */
    val errorDescription: String? = null,
    /**
     * Error URI
     */
    val errorUri: String? = null,
    /**
     * State parameter (echoed from request)
     */
    val state: String? = null,
    /**
     * Redirect URI with error parameters for QUERY/FRAGMENT, bare registered URI for FORM_POST.
     */
    val redirectUri: String,
    /**
     * Response mode used for this error response.
     */
    val responseMode: OAuth2ResponseMode = OAuth2ResponseMode.QUERY,
    /**
     * Auto-submitting HTML form body — populated iff [responseMode] is [OAuth2ResponseMode.FORM_POST];
     * `null` otherwise.
     */
    val formPostHtml: String? = null,
)
