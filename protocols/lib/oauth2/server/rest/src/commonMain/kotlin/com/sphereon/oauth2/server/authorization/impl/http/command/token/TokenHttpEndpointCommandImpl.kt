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

// Role-neutral OAuth REST capability. Executable server startup remains in services-oauth2-as-rest.
package com.sphereon.oauth2.server.authorization.impl.http.command.token

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
import com.sphereon.oauth2.server.authorization.audit.OAuth2AuditEmitter
import com.sphereon.oauth2.server.authorization.audit.OAuth2AuditEventType
import com.sphereon.oauth2.server.authorization.command.clientauth.ClientCertificateExtractor
import com.sphereon.oauth2.server.authorization.command.token.HandleTokenRequestArgs
import com.sphereon.oauth2.server.authorization.command.token.HandleTokenRequestCommand
import com.sphereon.oauth2.server.authorization.command.token.TokenHttpEndpointCommand
import com.sphereon.oauth2.server.authorization.dpop.DpopNonceManager
import com.sphereon.oauth2.server.authorization.impl.http.OAuth2ServerBaseUrlResolver
import com.sphereon.oauth2.server.authorization.impl.http.OAuth2ErrorEndpoint
import com.sphereon.oauth2.server.authorization.impl.http.isBasicAuthorizationHeaderInternal
import com.sphereon.oauth2.server.authorization.impl.http.mapOAuth2ErrorToResponse
import com.sphereon.oauth2.server.authorization.impl.http.oauth2ErrorResponse
import com.sphereon.oauth2.server.authorization.impl.http.parseFormBody
import com.sphereon.oauth2.server.authorization.impl.http.withWwwAuthenticateIfBasicInternal
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.ContributesIntoMap
import dev.zacsweers.metro.StringKey
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * HTTP shell over [HandleTokenRequestCommand] (RFC 6749 §3.2: Token Endpoint). Parses the
 * form-encoded body, builds the DPoP `htu` URL, dispatches to the ServiceCommand, and renders
 * the [com.sphereon.oauth2.common.model.TokenResponse] as JSON; on error maps the IdkError to
 * an RFC 6749 §5.2 error response and adds `WWW-Authenticate: Basic` if Basic auth was attempted.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(TokenHttpEndpointCommand.COMMAND_ID)
class TokenHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val handleTokenRequestCommand: HandleTokenRequestCommand,
    private val configProvider: OAuth2ServersConfigProvider,
    private val baseUrlResolver: OAuth2ServerBaseUrlResolver,
    private val dpopNonceManager: Lazy<DpopNonceManager>,
    private val clientCertificateExtractor: ClientCertificateExtractor,
    private val auditEmitter: OAuth2AuditEmitter,
) : HttpEndpointCommandAdapter(
        id = TokenHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = TokenHttpEndpointCommand.ENDPOINT,
    ),
    TokenHttpEndpointCommand {
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
        val requestBody =
            parseFormBody(request.body)
                ?: return Ok(oauth2ErrorResponse(400, "invalid_request", "Missing or invalid request body", json))

        val baseUrlOverride = baseUrlResolver.resolveBaseUrl(request, configProvider)
        // DPoP `htu` (RFC 9449 §4.2) must match the URL the wallet computed from the AS's
        // advertised discovery metadata. Discovery emits `${baseUrl}/token` via the resolver,
        // so reconstruction here uses the same resolver + fixed `/token` suffix — picks up the
        // EDK tenant-public-endpoint overlay's binding-derived base URL automatically.
        val httpUrl = "$baseUrlOverride/token"
        val clientCertificateDer =
            clientCertificateExtractor
                .extractCertificate(request)
                .getOrElse { error ->
                    execution.log.logManager.withTag("TokenHttpEndpoint").warn(
                        "Client certificate extraction failed idk_code=${error.code} error_key=${error.message.i18nKey}",
                    )
                    return Ok(
                        oauth2ErrorResponse(
                            statusCode = 400,
                            error = "invalid_request",
                            errorDescription = "Invalid client certificate",
                            jsonFormat = json,
                        ),
                    )
                }

        val result =
            handleTokenRequestCommand.execute(
                HandleTokenRequestArgs(
                    requestBody = requestBody,
                    requestHeaders = request.headers,
                    httpUrl = httpUrl,
                    baseUrlOverride = baseUrlOverride,
                    clientCertificateDer = clientCertificateDer,
                ),
            )
        // Emit OAuth2 domain audit events on the wire-shape boundary. The grant_type drives the
        // event type so SIEM rules can pivot on `event_type=oauth2.code_to_token` rather than
        // having to inspect the per-command-class audit envelope. Client_id is best-effort:
        // confidential clients may also send it via Basic auth header, so a missing form-body
        // value does not mean the call was anonymous.
        emitTokenAuditEvent(
            grantType = requestBody["grant_type"]?.firstOrNull(),
            clientId = requestBody["client_id"]?.firstOrNull(),
            success = result.isOk,
            errorCode = if (result.isOk) null else result.error.code,
            errorMessage = if (result.isOk) null else result.error.message.defaultMessage,
        )
        val basicAuthWasAttempted = isBasicAuthorizationHeaderInternal(request.headers)
        val dpopProofPresented = (request.headers["DPoP"] ?: request.headers["dpop"]) != null

        val baseResponse =
            if (result.isOk) {
                val responseBody = json.encodeToString(result.value)
                GenericHttpResponse(
                    statusCode = 200,
                    headers =
                        mapOf(
                            "Content-Type" to "application/json",
                            "Cache-Control" to "no-store",
                            "Pragma" to "no-cache",
                        ),
                    body = responseBody,
                )
            } else {
                mapOAuth2ErrorToResponse(
                    result.error,
                    json,
                    execution,
                    endpoint = OAuth2ErrorEndpoint.TOKEN,
                    httpAuthenticationAttempted = basicAuthWasAttempted,
                ).withWwwAuthenticateIfBasicInternal(basicAuthWasAttempted)
            }
        // RFC 9449 §8 SHOULD: emit `DPoP-Nonce` on every DPoP-bearing response so clients can
        // rotate proactively, regardless of success/failure. The error path already attaches
        // the rotated nonce when the error is `use_dpop_nonce`; for the success path and other
        // error paths we attach the current nonce here.
        val finalResponse =
            if (dpopProofPresented && !baseResponse.headers.containsKey("DPoP-Nonce")) {
                baseResponse.copy(headers = baseResponse.headers + ("DPoP-Nonce" to dpopNonceManager.value.currentNonce()))
            } else {
                baseResponse
            }
        return Ok(finalResponse)
    }

    /**
     * Pick the [OAuth2AuditEventType] for the current `grant_type` and emit the success or
     * failure variant. Grant types not in the well-known set (CIBA, device-code, token-
     * exchange, pre-authorized-code) fall back to the closest pair (CODE_TO_TOKEN /
     * CODE_TO_TOKEN_ERROR) with the actual grant_type wire string in metadata so the SIEM
     * rule still has something to filter on. Subject is intentionally omitted: the
     * authorization-code flow's subject lives in the consumed code's data, not in the wire
     * request, and the token endpoint does not have a cheap way to surface it without
     * threading the result type into the emit call.
     */
    private suspend fun emitTokenAuditEvent(
        grantType: String?,
        clientId: String?,
        success: Boolean,
        errorCode: String?,
        errorMessage: String?,
    ) {
        val (successType, failureType) =
            when (grantType) {
                "refresh_token" -> OAuth2AuditEventType.REFRESH_TOKEN to OAuth2AuditEventType.REFRESH_TOKEN_ERROR
                else -> OAuth2AuditEventType.CODE_TO_TOKEN to OAuth2AuditEventType.CODE_TO_TOKEN_ERROR
            }
        auditEmitter.emit(
            type = if (success) successType else failureType,
            tenantId = execution.tenantId,
            clientId = clientId,
            metadata = buildMap { grantType?.let { put("grant_type", it) } },
            errorCode = errorCode,
            errorMessage = errorMessage,
        )
    }
}
