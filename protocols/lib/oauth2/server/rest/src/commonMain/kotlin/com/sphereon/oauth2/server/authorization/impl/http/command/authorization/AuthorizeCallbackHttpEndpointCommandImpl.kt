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
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.model.OAuth2ResponseMode
import com.sphereon.oauth2.server.authorization.command.AuthorizationResponseData
import com.sphereon.oauth2.server.authorization.command.authorization.AuthorizeCallbackHttpEndpointCommand
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeCallbackArgs
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeCallbackCommand
import com.sphereon.oauth2.server.authorization.impl.http.OAuth2ServerBaseUrlResolver
import com.sphereon.oauth2.server.authorization.impl.http.loginSessionCookieValue
import com.sphereon.oauth2.server.authorization.impl.http.oauth2ErrorResponse
import com.sphereon.oauth2.server.authorization.impl.http.requiredaction.RequiredActionsRedirectHandler
import com.sphereon.oauth2.server.authorization.storage.MutableOidcLoginSessionIdProvider
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.ContributesIntoMap
import dev.zacsweers.metro.StringKey
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.Json

/**
 * HTTP shell over [HandleAuthorizeCallbackCommand]. Resumes the authorization flow after upstream
 * user authentication: looks up the pending session by `session_id`, runs the issuance pipeline,
 * and renders the resulting [AuthorizationResponseData] per its [OAuth2ResponseMode].
 */
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(AuthorizeCallbackHttpEndpointCommand.COMMAND_ID)
class AuthorizeCallbackHttpEndpointCommandImpl @Inject constructor(
    execution: SessionExecution,
    private val handleAuthorizeCallbackCommand: HandleAuthorizeCallbackCommand,
    private val loginSessionIdProvider: MutableOidcLoginSessionIdProvider,
    private val configProvider: OAuth2ServersConfigProvider,
    requiredActionsRedirectHandlerFactory: () -> RequiredActionsRedirectHandler,
    private val baseUrlResolver: OAuth2ServerBaseUrlResolver,
) : HttpEndpointCommandAdapter(
        id = AuthorizeCallbackHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = AuthorizeCallbackHttpEndpointCommand.ENDPOINT,
    ),
    AuthorizeCallbackHttpEndpointCommand {
    private val requiredActionsRedirectHandler: RequiredActionsRedirectHandler by lazy(requiredActionsRedirectHandlerFactory)

    /** Source-compatible constructor for callers that already own these dependencies. */
    constructor(
        execution: SessionExecution,
        handleAuthorizeCallbackCommand: HandleAuthorizeCallbackCommand,
        loginSessionIdProvider: MutableOidcLoginSessionIdProvider,
        configProvider: OAuth2ServersConfigProvider,
        requiredActionsRedirectHandler: RequiredActionsRedirectHandler,
        baseUrlResolver: OAuth2ServerBaseUrlResolver,
    ) : this(
        execution = execution,
        handleAuthorizeCallbackCommand = handleAuthorizeCallbackCommand,
        loginSessionIdProvider = loginSessionIdProvider,
        configProvider = configProvider,
        requiredActionsRedirectHandlerFactory = { requiredActionsRedirectHandler },
        baseUrlResolver = baseUrlResolver,
    )

    private val json =
        Json {
            prettyPrint = false
            ignoreUnknownKeys = true
        }

    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> {
        val request = applyDuring(args)
        request.loginSessionCookieValue()?.let(loginSessionIdProvider::setCurrentLoginSessionId)
        @Suppress("UNCHECKED_CAST")
        val queryParams = request.queryParameters.filterValues { it != null } as Map<String, String>
        val sessionId =
            queryParams["session_id"]
                ?: return Ok(oauth2ErrorResponse(400, "invalid_request", "Missing session_id parameter", json))
        val authenticationSessionId = queryParams["authentication_session_id"]?.takeIf(String::isNotBlank)

        val baseUrlOverride = baseUrlResolver.resolveBaseUrl(request, configProvider)
        val approvalResult =
            handleAuthorizeCallbackCommand.execute(
                HandleAuthorizeCallbackArgs(
                    sessionId = sessionId,
                    authenticationSessionId = authenticationSessionId,
                    baseUrlOverride = baseUrlOverride,
                ),
            )
        if (approvalResult.isOk) {
            return Ok(emitAuthorizationResponse(approvalResult.value))
        }

        val error = approvalResult.error

        // Required-actions gate refusal is the orchestrator's signal to redirect into the
        // IDV runner instead of returning the generic OIDC `interaction_required` JSON. The
        // upstream typed error (AuthorizationServerError.RequiredActionsPending) is mapped
        // into a plain IdkError via IdkError.fromDTO before reaching here, so the handler
        // dispatches off `error.code` + `error.meta` (the wire-shape) rather than the
        // runtime class. The handler returns null whenever it cannot proceed (no strategy,
        // no provider, no pending action) — fall back to JSON below in that case so the
        // client still gets a valid OIDC error per OIDC Core §3.1.2.6.
        requiredActionsRedirectHandler
            .handle(error = error, sessionId = sessionId, baseUrl = baseUrlOverride)
            ?.let { return Ok(it) }

        val errorCode = error.code
        val errorDescription = error.message.defaultMessage ?: "Authorization approval failed"
        val status = if (errorCode == "invalid_request") 400 else 500
        val oauthCode = if (status == 400) "invalid_request" else "server_error"
        return Ok(oauth2ErrorResponse(status, oauthCode, errorDescription, json))
    }

    private fun emitAuthorizationResponse(response: AuthorizationResponseData): GenericHttpResponse =
        renderAuthorizationDeliveryResponse(response.responseMode, response.redirectUri, response.formPostHtml)
}
