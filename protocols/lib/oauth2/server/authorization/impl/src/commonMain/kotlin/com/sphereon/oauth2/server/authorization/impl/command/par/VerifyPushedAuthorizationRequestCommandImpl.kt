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

package com.sphereon.oauth2.server.authorization.impl.command.par

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData
import com.sphereon.oauth2.server.authorization.command.VerifiedAuthorizationRequest
import com.sphereon.oauth2.server.authorization.command.VerifyPushedAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.command.VerifyPushedAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.command.authorization.matchesRegisteredRedirectUri
import com.sphereon.oauth2.server.authorization.model.ClientType
import com.sphereon.oauth2.server.authorization.provider.CredentialIssuerAudienceResolver
import com.sphereon.oauth2.server.authorization.provider.UnregisteredClientAdmissionRule
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of VerifyPushedAuthorizationRequestCommand
 *
 * Verifies Pushed Authorization Requests (PAR) according to RFC 9126.
 *
 * Verification steps:
 * 1. Verify client is authenticated (client authentication handled separately)
 * 2. Retrieve client registration
 * 3. Verify client is authorized to use authorization_code grant
 * 4. Verify redirect_uri matches registered URIs
 * 5. Verify PKCE is used if required for client
 * 6. Validate requested scope
 * 7. Return verified request data
 *
 * Key differences from regular authorization request verification:
 * - Client MUST be authenticated (RFC 9126 Section 2.1)
 * - Request parameters are protected from tampering
 * - Request can contain large amounts of data
 *
 * Security considerations:
 * - Client authentication is REQUIRED (confidential or public with client authentication)
 * - Request integrity is guaranteed (parameters stored server-side)
 * - Request confidentiality is maintained (parameters not in redirect URL)
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifyPushedAuthorizationRequestCommandImpl", exact = true)
@ExposeImplBinding
class VerifyPushedAuthorizationRequestCommandImpl(
    execution: SessionExecution,
    private val clientRegistry: ClientRegistry,
    private val configProvider: com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider,
    private val credentialIssuerAudienceResolver: CredentialIssuerAudienceResolver,
    private val unregisteredClientAdmissionRule: UnregisteredClientAdmissionRule,
) : TypedServiceCommandAdapter<VerifyPushedAuthorizationRequestArgs, VerifiedAuthorizationRequest, IdkError>(
        commandId = VerifyPushedAuthorizationRequestCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<VerifyPushedAuthorizationRequestArgs>(),
        outputTypeToken = typeToken<VerifiedAuthorizationRequest>(),
    ),
    VerifyPushedAuthorizationRequestCommand {
    override val commandId: String get() = VerifyPushedAuthorizationRequestCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is VerifyPushedAuthorizationRequestArgs

    override suspend fun doExecute(
        args: VerifyPushedAuthorizationRequestArgs,
        applyDuring: (VerifyPushedAuthorizationRequestArgs) -> VerifyPushedAuthorizationRequestArgs,
    ): IdkResult<VerifiedAuthorizationRequest, IdkError> {
        val applied = applyDuring(args)
        return executeInternal(applied.request, applied.clientId).mapError { IdkError.fromDTO(it) }
    }

    private suspend fun executeInternal(
        request: AuthorizationRequestData,
        authenticatedClientId: String,
    ): IdkResult<VerifiedAuthorizationRequest, AuthorizationServerError> {
        // Verify client_id in request matches authenticated client
        if (request.clientId != authenticatedClientId) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "client_id in request does not match authenticated client",
                ),
            )
        }

        // Retrieve client registration
        val registeredClient =
            clientRegistry.getClient(request.clientId)
                .mapError { error -> AuthorizationServerError.ServerError(details = "Failed to retrieve client registration: $error") }
                .getOrElse { return Err(it) }
        val admission = if (registeredClient == null) {
            unregisteredClientAdmissionRule.admit(
                request,
                credentialIssuerAudienceResolver.boundCredentialIssuers(),
                isPushedAuthorizationRequest = true,
            )
        } else null
        val client = registeredClient ?: admission?.client

        if (client == null) {
            return Err(
                AuthorizationServerError.UnauthorizedClient(
                    clientId = request.clientId,
                ),
            )
        }

        // Verify client is authorized to use authorization_code grant
        if (GrantType.AUTHORIZATION_CODE !in client.grantTypes) {
            return Err(
                AuthorizationServerError.UnauthorizedClient(
                    clientId = request.clientId,
                ),
            )
        }

        // OIDC Core §3.1.2.1 / RFC 6749 §3.1.1: every requested response-type value MUST be
        // advertised in `response_types_supported` and registered for the client. PAR-pushed
        // requests bypass the front-channel `verifyAuthorizationRequest` (the redeem path
        // uses the stored verified request directly), so this check has to happen here. FAPI2
        // configurations advertise only `code`; pushing `response_type=token` MUST be rejected
        // with `unsupported_response_type` rather than silently rewritten downstream.
        val serverSupported: Set<String> = configProvider.serverConfig.responseTypesSupported
        request.responseType.forEach { rt ->
            if (rt.value !in serverSupported) {
                return Err(AuthorizationServerError.UnsupportedResponseType(responseType = rt.value))
            }
        }
        val clientAllowed: List<com.sphereon.oauth2.common.model.ResponseType> =
            client.responseTypes.ifEmpty { listOf(com.sphereon.oauth2.common.model.ResponseType.CODE) }
        request.responseType.forEach { rt ->
            if (rt !in clientAllowed) {
                return Err(AuthorizationServerError.UnauthorizedClient(clientId = request.clientId))
            }
        }

        // Verify redirect_uri (RFC 6749 Section 3.1.2.3)
        val redirectUri = request.redirectUri

        if (configProvider.serverConfig.requireRedirectUriInPushedAuthorizationRequests && redirectUri.isNullOrBlank()) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "redirect_uri is required in pushed authorization requests by authorization-server policy",
                ),
            )
        }

        if (redirectUri.isNullOrBlank()) {
            // redirect_uri is optional if client has exactly ONE registered URI
            if (client.redirectUris.size != 1) {
                return Err(
                    AuthorizationServerError.InvalidRequest(
                        details = "redirect_uri is required when client has multiple registered redirect URIs",
                    ),
                )
            }
        } else if (client.redirectUris.isEmpty()) {
            // For an admitted wallet, the explicit URI is stored with this PAR request and the
            // authorization endpoint later requires an exact match against it.
        } else {
            // Verify redirect_uri matches one of the registered URIs per RFC 6749 §3.1.2.2:
            // strict simple-string match wins; otherwise scheme + authority + path match against
            // a registered URI with empty query is acceptable (additional query components on
            // the request are allowed). See RedirectResolution.matchesRegisteredRedirectUri.
            if (!matchesRegisteredRedirectUri(redirectUri, client.redirectUris)) {
                return Err(
                    AuthorizationServerError.InvalidRequest(
                        details = "redirect_uri does not match any registered redirect URI for this client",
                    ),
                )
            }
        }

        // Determine final redirect_uri
        val finalRedirectUri = redirectUri?.takeIf { it.isNotBlank() } ?: client.redirectUris.first()

        // Verify PKCE is used if required
        // Public clients MUST use PKCE (RFC 8252)
        if (client.requirePkce && request.codeChallenge == null) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "PKCE (code_challenge) is required for this client",
                ),
            )
        }

        if (client.clientType == ClientType.PUBLIC && request.codeChallenge == null) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "Public clients MUST use PKCE (RFC 8252)",
                ),
            )
        }

        // Validate requested scope
        // If client has allowedScopes configured, validate that all requested scopes are permitted
        val requestedScope = request.scope
        val grantedScopes =
            if (requestedScope != null && requestedScope.isNotBlank()) {
                val requestedScopes = requestedScope.split(" ").map { it.trim() }.filter { it.isNotEmpty() }
                val allowedScopes = client.allowedScopes
                if (allowedScopes != null) {
                    val disallowed = requestedScopes.filter { it !in allowedScopes }
                    if (disallowed.isNotEmpty()) {
                        return Err(
                            AuthorizationServerError.InvalidScope(
                                scope = disallowed.joinToString(" "),
                                allowedScopes = allowedScopes,
                            ),
                        )
                    }
                }
                requestedScopes
            } else {
                emptyList()
            }

        // Return verified request
        return Ok(
            VerifiedAuthorizationRequest(
                request = request,
                clientId = request.clientId,
                redirectUri = finalRedirectUri,
                grantedScopes = grantedScopes,
                // Code issuance takes the audience from the pushed request; it must match front-channel verification.
                defaultAccessTokenAudience = client.defaultAccessTokenAudience,
                admittedAudiences = admission?.audiences?.toList(),
                admittedClient = admission?.client,
                pkceRequired = client.requirePkce || client.clientType == ClientType.PUBLIC,
                parRequired = false, // Will be determined by client configuration
            ),
        )
    }
}
