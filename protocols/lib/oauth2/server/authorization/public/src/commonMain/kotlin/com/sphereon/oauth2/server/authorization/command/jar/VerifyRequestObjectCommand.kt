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

package com.sphereon.oauth2.server.authorization.command.jar

import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.ServiceCommand

/**
 * Arguments for [VerifyRequestObjectCommand].
 *
 * Either [requestJwt] (RFC 9101 `request` parameter, inline JAR) or [requestUri] (the
 * `request_uri` value, pre-fetched if needed) is provided. When both are non-null the AS
 * MUST reject per RFC 9101 §5: "request and request_uri parameters MUST NOT be both used".
 *
 * @property requestJwt The compact JWS that carries the authorization request (when present
 *   directly on the wire under `request`).
 * @property requestUri The `request_uri` value as the client supplied it. PAR URNs
 *   (`urn:ietf:params:oauth:request_uri:`) are NOT handled here, they flow through the PAR
 *   retrieval path. Non-PAR URLs are fetched and the response body treated as the JWT.
 * @property clientIdHint Optional hint of the client id from the front-channel query (when
 *   present alongside the `request` / `request_uri` parameter). The verifier compares the
 *   JWT's `iss` / `client_id` against this hint after signature validation.
 * @property issuer Issuer URL to verify against the JWT's `aud` claim (RFC 9101 §10.2). When
 *   the AS has multiple issuers (multi-tenant) the caller resolves the right one before
 *   invocation.
 * @property queryParameters The raw front-channel parameters. After verification the JAR's
 *   claims merge into / override these per RFC 9101 §6.1.
 */
data class VerifyRequestObjectArgs(
    val requestJwt: String? = null,
    val requestUri: String? = null,
    val clientIdHint: String? = null,
    val issuer: String,
    val queryParameters: Map<String, String> = emptyMap(),
)

/**
 * Result of [VerifyRequestObjectCommand]. The merged map already contains the JAR claims
 * overlaid on top of [VerifyRequestObjectArgs.queryParameters], JWT-only claims (iss, aud,
 * exp, iat, jti, nbf) stripped. Pass this directly to [com.sphereon.oauth2.server.authorization.command.ParseAuthorizationRequestCommand].
 */
/** Non-wire process evidence. Implementations supplied by callers are never trusted. */
interface AuthorizationRequestEvidence

data class VerifiedRequestObject(
    val mergedParameters: Map<String, String>,
    val clientId: String,
    val signingAlg: String,
    val authorizationEvidence: AuthorizationRequestEvidence? = null,
)

/**
 * RFC 9101 (JAR) server-side acceptance: parse, verify signature, validate JWT envelope claims,
 * and return the merged authorization request parameters.
 *
 * The verifier:
 *  1. Parses the compact JWS, refuses `alg=none` (RFC 9101 §6 / RFC 8725 §2.1).
 *  2. Loads the client by `iss` / `client_id` claim (cross-checked against [VerifyRequestObjectArgs.clientIdHint]
 *     when supplied per OIDC Core §6.1).
 *  3. Verifies the signature against the client's registered keys (`jwks` inline or `jwks_uri`
 *     fetched via `HttpClientFactory`). When the client pinned `request_object_signing_alg`,
 *     header `alg` MUST match exactly.
 *  4. Validates `typ=oauth-authz-req+jwt` (RFC 9101 §10.8). OpenID Federation RPs may omit `typ`
 *     (OpenID Federation 1.1 §12.1.1.1); a `typ` that is present must still match.
 *  5. Validates `aud` against the AS issuer, and `exp` / `iat` (5-minute skew window).
 *  6. Returns the merged parameter map per RFC 9101 §6.1.
 *
 * Errors:
 *  - [com.sphereon.oauth2.server.authorization.error.AuthorizationServerError.InvalidRequestObject]
 *    for any signature / claim / algorithm violation.
 *  - [com.sphereon.oauth2.server.authorization.error.AuthorizationServerError.InvalidRequestUri]
 *    for fetch failures or unregistered `request_uri` values when registration is required.
 *  - [com.sphereon.oauth2.server.authorization.error.AuthorizationServerError.InvalidRequest]
 *    when both `request` and `request_uri` are supplied.
 */
interface VerifyRequestObjectCommand : ServiceCommand<VerifyRequestObjectArgs, VerifiedRequestObject, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.authorization.verify-request-object"

        /** RFC 9101 §10.8 / OID4VP §5.10.3 — JAR JWT `typ` header. */
        const val JAR_JWT_TYP: String = "oauth-authz-req+jwt"

        /** RFC 9101 §10.2 — clock skew tolerance for `exp` / `iat`. */
        const val CLOCK_SKEW_SECONDS: Int = 300
    }
}
