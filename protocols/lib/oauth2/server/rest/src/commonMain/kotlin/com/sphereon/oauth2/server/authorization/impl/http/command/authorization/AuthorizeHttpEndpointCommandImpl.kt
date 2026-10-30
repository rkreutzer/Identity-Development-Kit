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

package com.sphereon.oauth2.server.authorization.impl.http.command.authorization

// Role-neutral OAuth HTTP capability. Executable graph bindings remain in the service assembly.

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.command.HttpEndpointCommandAdapter
import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.core.api.http.describe.MediaType
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.model.OAuth2ResponseMode
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestOutcome
import com.sphereon.oauth2.server.authorization.command.AuthorizationResponseData
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationErrorResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationErrorResponseCommand
import com.sphereon.oauth2.server.authorization.command.authorization.AuthorizeHttpEndpointCommand
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestArgs
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestCommand
import com.sphereon.oauth2.server.authorization.impl.http.OAuth2ServerBaseUrlResolver
import com.sphereon.oauth2.server.authorization.impl.http.loginSessionCookieValue
import com.sphereon.oauth2.server.authorization.impl.http.oauth2ErrorResponse
import com.sphereon.oauth2.server.authorization.impl.http.oauth2HtmlErrorPage
import com.sphereon.oauth2.server.authorization.impl.http.parseFormBody
import com.sphereon.oauth2.server.authorization.storage.MutableOidcLoginSessionIdProvider
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.ContributesIntoMap
import dev.zacsweers.metro.StringKey
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.Json

/**
 * HTTP shell over the `/authorize` orchestration. Picks the [HandleAuthorizeRequestCommand] impl
 * whose [HandleAuthorizeRequestCommand.supports] matches (standard vs wallet branch decided by
 * `login_hint=oid4vp:...`), then renders the resulting [AuthorizationRequestOutcome] over HTTP.
 * Post-redirect errors flow through [CreateAuthorizationErrorResponseCommand] so the response
 * mode (query / fragment / form_post) matches the success path.
 *
 * Accepts both `GET` and `POST` per OIDC Core 1.0 §3.1.2.1: `GET` reads parameters from the
 * query string; `POST` requires `application/x-www-form-urlencoded` and reads them from the body.
 * Both code paths converge on the same [HandleAuthorizeRequestArgs] dispatch.
 */
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(AuthorizeHttpEndpointCommand.COMMAND_ID)
class AuthorizeHttpEndpointCommandImpl @Inject constructor(
    execution: SessionExecution,
    private val handleAuthorizeRequestCommands: Set<HandleAuthorizeRequestCommand>,
    createAuthorizationErrorResponseCommandFactory: () -> CreateAuthorizationErrorResponseCommand,
    private val configProvider: OAuth2ServersConfigProvider,
    private val baseUrlResolver: OAuth2ServerBaseUrlResolver,
    private val loginSessionIdProvider: MutableOidcLoginSessionIdProvider,
) : HttpEndpointCommandAdapter(
        id = AuthorizeHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = AuthorizeHttpEndpointCommand.ENDPOINT,
    ),
    AuthorizeHttpEndpointCommand {
    private val createAuthorizationErrorResponseCommand: CreateAuthorizationErrorResponseCommand by lazy(createAuthorizationErrorResponseCommandFactory)

    /** Source-compatible constructor for callers that already own these dependencies. */
    constructor(
        execution: SessionExecution,
        handleAuthorizeRequestCommands: Set<HandleAuthorizeRequestCommand>,
        createAuthorizationErrorResponseCommand: CreateAuthorizationErrorResponseCommand,
        configProvider: OAuth2ServersConfigProvider,
        baseUrlResolver: OAuth2ServerBaseUrlResolver,
        loginSessionIdProvider: MutableOidcLoginSessionIdProvider,
    ) : this(
        execution = execution,
        handleAuthorizeRequestCommands = handleAuthorizeRequestCommands,
        createAuthorizationErrorResponseCommandFactory = { createAuthorizationErrorResponseCommand },
        configProvider = configProvider,
        baseUrlResolver = baseUrlResolver,
        loginSessionIdProvider = loginSessionIdProvider,
    )

    private val json =
        Json {
            prettyPrint = false
            ignoreUnknownKeys = true
        }

    override suspend fun supports(args: Any): Boolean =
        if (args is GenericHttpRequest) {
            (args.method.equals("GET", ignoreCase = true) || args.method.equals("POST", ignoreCase = true)) &&
                args.path == endpoint.pathPattern
        } else {
            false
        }

    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> {
        val request = applyDuring(args)
        request.loginSessionCookieValue()?.let(loginSessionIdProvider::setCurrentLoginSessionId)
        val parameters: Map<String, String> =
            if (request.method.equals("POST", ignoreCase = true)) {
                val contentType = MediaType.parse(request.contentType)
                if (contentType == null || !contentType.matches(MediaType.ApplicationFormUrlEncoded)) {
                    return Ok(
                        oauth2ErrorResponse(
                            400,
                            "invalid_request",
                            "POST /authorize requires Content-Type: application/x-www-form-urlencoded",
                            json,
                        ),
                    )
                }
                val formBody =
                    parseFormBody(request.body)
                        ?: return Ok(oauth2ErrorResponse(400, "invalid_request", "Missing or invalid request body", json))
                formBody.mapValues { (_, values) -> values.first() }
            } else {
                @Suppress("UNCHECKED_CAST")
                request.queryParameters.filterValues { it != null } as Map<String, String>
            }

        if (parameters.containsKey("request") && parameters.containsKey("request_uri")) {
            return Ok(oauth2ErrorResponse(400, "invalid_request", "request and request_uri MUST NOT both be present", json))
        }

        val baseUrl = baseUrlResolver.resolveBaseUrl(request, configProvider)
        val handleArgs =
            HandleAuthorizeRequestArgs(
                queryParameters = parameters,
                returnUrl = "$baseUrl/authorize/callback",
                baseUrlOverride = baseUrl,
            )
        val command =
            handleAuthorizeRequestCommands.firstOrNull { it.supports(handleArgs) }
                ?: return Ok(oauth2ErrorResponse(500, "server_error", "No HandleAuthorizeRequestCommand impl supports the request", json))

        val outcomeResult = command.execute(handleArgs)
        if (!outcomeResult.isOk) {
            return Ok(oauth2ErrorResponse(500, "server_error", outcomeResult.error.message.defaultMessage, json))
        }
        return when (val outcome = outcomeResult.value) {
            is AuthorizationRequestOutcome.PreRedirectError -> {
                // /authorize is browser-facing per OIDC Core §3.1.2.1 — pre-redirect failures
                // (RFC 6749 §4.1.2.1: missing/unverifiable client_id or redirect_uri) leave the
                // user-agent on the AS, so render an HTML error page instead of dumping the raw
                // RFC 6749 §5.2 JSON body into the address bar. The message itself is the same;
                // only the wire shape adapts to the actual consumer.
                Ok(oauth2HtmlErrorPage(outcome.httpStatus, outcome.error, outcome.errorDescription, parameters))
            }

            is AuthorizationRequestOutcome.PostRedirectError -> {
                Ok(emitAuthorizationErrorResponse(outcome))
            }

            is AuthorizationRequestOutcome.AuthInitiated -> {
                Ok(
                    GenericHttpResponse(
                        statusCode = 302,
                        headers = mapOf("Location" to outcome.authProviderRedirectUrl, "Cache-Control" to "no-store"),
                        body = "",
                    ),
                )
            }

            is AuthorizationRequestOutcome.WalletCompleted -> {
                Ok(emitAuthorizationResponse(outcome.authorizationResponseData))
            }

            is AuthorizationRequestOutcome.NeedsLogin -> {
                // Group I: rendering the AS's first-party login surface. When `forceReauth`
                // applies (prompt=login / select_account / max_age stale), the existing
                // `oidc_login_sid` cookie is cleared via a Set-Cookie: Max-Age=0 so the
                // renderer cannot silently reuse the just-rejected session.
                val headers =
                    buildMap {
                        put("Location", outcome.loginUrl)
                        put("Cache-Control", "no-store")
                        if (outcome.forceReauth) {
                            put(
                                "Set-Cookie",
                                "oidc_login_sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
                            )
                        }
                    }
                Ok(
                    GenericHttpResponse(
                        statusCode = 302,
                        headers = headers,
                        body = "",
                    ),
                )
            }
        }
    }

    private suspend fun emitAuthorizationErrorResponse(error: AuthorizationRequestOutcome.PostRedirectError): GenericHttpResponse {
        val errorResp =
            createAuthorizationErrorResponseCommand.execute(
                CreateAuthorizationErrorResponseArgs(
                    error = error.error,
                    errorDescription = error.errorDescription,
                    state = error.state,
                    redirectUri = error.redirectUri,
                    responseMode = error.responseMode,
                ),
            )
        if (!errorResp.isOk) {
            return oauth2ErrorResponse(500, "server_error", "Failed to build error response: ${errorResp.error.message.defaultMessage}", json)
        }
        val data = errorResp.value
        return renderAuthorizationDeliveryResponse(data.responseMode, data.redirectUri, data.formPostHtml)
    }

    private fun emitAuthorizationResponse(response: AuthorizationResponseData): GenericHttpResponse =
        renderAuthorizationDeliveryResponse(response.responseMode, response.redirectUri, response.formPostHtml)
}

/**
 * Centralised HTTP rendering helper for the authorization endpoint's success and error responses.
 * Branches on the resolved [OAuth2ResponseMode.Carrier] so the bare carriers (`query`, `fragment`,
 * `form_post`) and the JARM `*.jwt` variants share one shaping path: the JARM JWT travels in the
 * carrier the response mode resolves to.
 */
internal fun renderAuthorizationDeliveryResponse(
    responseMode: OAuth2ResponseMode,
    redirectUri: String,
    formPostHtml: String?,
): GenericHttpResponse =
    when (responseMode.carrier) {
        OAuth2ResponseMode.Carrier.FORM_POST -> {
            val html =
                formPostHtml
                    ?: error("FORM_POST-carrier response missing formPostHtml")
            GenericHttpResponse(
                statusCode = 200,
                headers =
                    mapOf(
                        "Content-Type" to "text/html;charset=UTF-8",
                        "Cache-Control" to "no-store",
                        "Pragma" to "no-cache",
                    ),
                body = html,
            )
        }

        OAuth2ResponseMode.Carrier.QUERY, OAuth2ResponseMode.Carrier.FRAGMENT -> {
            GenericHttpResponse(
                statusCode = 302,
                headers = mapOf("Location" to redirectUri, "Cache-Control" to "no-store"),
                body = "",
            )
        }
    }
