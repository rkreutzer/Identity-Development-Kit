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

package com.sphereon.oauth2.server.authorization.command.login

import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.core.api.http.describe.EndpointAuthPolicy
import com.sphereon.core.api.http.describe.HttpEndpointDescriptor
import com.sphereon.core.api.http.describe.HttpMethod
import com.sphereon.core.api.http.describe.MediaType
import com.sphereon.core.compat.JsExportCompat

// HTTP endpoint contracts for the AS first-party login surface served at GET /login. The form
// posts back to POST /login and the renderer's static assets are served under /login/assets/.
// The LoginPageRenderer SPI fills in the page; the HTTP layer carries the wire shape.

/**
 * `GET /login`: render the AS login page for a pending authorization session. Reads
 * `session_id`, optional `return_url`, optional `error`, and optional `login_hint` from query
 * parameters.
 */
@JsExportCompat
interface LoginPageHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = "oauth2.authorization.login-page"

        val ENDPOINT: HttpEndpointDescriptor =
            HttpEndpointDescriptor(
                method = HttpMethod.GET,
                pathPattern = "/login",
                produces = setOf(MediaType.Custom("text/html")),
                operationId = "renderLoginPage",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("authorization", "login"),
                summary = "Render the Authorization Server's first-party login page",
            )
    }
}

/**
 * `POST /login`: validate `username` / `password` form fields or a WebAuthn assertion, mint an
 * [com.sphereon.oauth2.server.authorization.storage.OidcLoginSession], set the `oidc_login_sid`
 * cookie, and 302-redirect back to the pending authorization session's `return_url` (typically
 * `/authorize/callback?session_id=...`). On invalid credentials the adapter redirects back to
 * `/login?session_id=...&error=invalid_credentials`.
 */
@JsExportCompat
interface LoginSubmitHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = "oauth2.authorization.login-submit"

        val ENDPOINT: HttpEndpointDescriptor =
            HttpEndpointDescriptor(
                method = HttpMethod.POST,
                pathPattern = "/login",
                consumes = setOf(MediaType.ApplicationFormUrlEncoded),
                operationId = "submitLogin",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("authorization", "login"),
                summary = "Submit password or WebAuthn credentials to the Authorization Server's login form",
            )
    }
}

/**
 * `GET /account-action`: tenant-AS landing for owner/identity activation and password change.
 * The invitation token stays in the URL fragment; the page posts to `/api/account-actions/v1`.
 */
@JsExportCompat
interface AccountActionPageHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = "oauth2.authorization.account-action-page"

        val ENDPOINT: HttpEndpointDescriptor =
            HttpEndpointDescriptor(
                method = HttpMethod.GET,
                pathPattern = "/account-action",
                produces = setOf(MediaType.Custom("text/html")),
                operationId = "renderAccountActionPage",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("authorization", "account-action"),
                summary = "Render the Authorization Server's account-action landing page",
                authPolicy = EndpointAuthPolicy.PUBLIC,
            )
    }
}

/**
 * `POST /login/webauthn/assertion/begin`: mint WebAuthn assertion options for the AS login page
 * or a wallet edge. The browser performs `navigator.credentials.get(...)`; the result is then
 * submitted through `POST /login`.
 */
@JsExportCompat
interface LoginWebAuthnAssertionBeginHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = "oauth2.authorization.login-webauthn-assertion-begin"

        val ENDPOINT: HttpEndpointDescriptor =
            HttpEndpointDescriptor(
                method = HttpMethod.POST,
                pathPattern = "/login/webauthn/assertion/begin",
                consumes = setOf(MediaType.ApplicationJson),
                produces = setOf(MediaType.ApplicationJson),
                operationId = "beginLoginWebAuthnAssertion",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("authorization", "login", "webauthn"),
                summary = "Begin a WebAuthn assertion ceremony for Authorization Server login",
                // Authentication is established by the later assertion verification. This
                // handler validates the pending login session and origin before minting a
                // challenge; PUBLIC keeps its transport session bound to the resolved host.
                authPolicy = EndpointAuthPolicy.PUBLIC,
            )
    }
}

/**
 * `POST /login/cancel`: the user pressed the Cancel button on the AS login form. Redirects
 * back to the registered `redirect_uri` of the pending [PendingAuthorizationSessionStore]
 * entry with `error=access_denied` (RFC 6749 §4.1.2.1) so the relying party can finish its
 * flow gracefully. FAPI2 conformance: `fapi2-security-profile-final-user-rejects-authentication`
 * requires this surface.
 */
@JsExportCompat
interface LoginCancelHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = "oauth2.authorization.login-cancel"

        val ENDPOINT: HttpEndpointDescriptor =
            HttpEndpointDescriptor(
                method = HttpMethod.POST,
                pathPattern = "/login/cancel",
                consumes = setOf(MediaType.ApplicationFormUrlEncoded),
                operationId = "cancelLogin",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("authorization", "login"),
                summary = "User cancelled the login flow; redirect back to the RP with error=access_denied",
            )
    }
}

/**
 * `GET /login/assets/{path...}`: serve a static asset declared by
 * [com.sphereon.oauth2.server.authorization.provider.LoginPageRenderer.staticAssets] by its
 * relative path. The descriptor uses the tail-wildcard primitive so any depth beneath
 * `/login/assets/` is matched by a single route. The implementation reads the relative asset
 * path from the request's `path` and looks it up in the renderer-provided asset map.
 */
@JsExportCompat
interface LoginAssetHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = "oauth2.authorization.login-asset"
        const val ASSETS_PREFIX: String = "/login/assets/"

        val ENDPOINT: HttpEndpointDescriptor =
            HttpEndpointDescriptor(
                method = HttpMethod.GET,
                pathPattern = "/login/assets/{path...}",
                operationId = "loginAsset",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("authorization", "login"),
                summary = "Serve static assets bundled with the login renderer",
            )
    }
}
