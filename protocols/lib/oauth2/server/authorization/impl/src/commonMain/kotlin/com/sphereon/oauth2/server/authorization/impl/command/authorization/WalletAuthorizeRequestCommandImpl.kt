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

package com.sphereon.oauth2.server.authorization.impl.command.authorization

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestOutcome
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationCodeArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationResponseArgs
import com.sphereon.oauth2.server.authorization.command.ParseAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestArgs
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestCommand
import com.sphereon.oauth2.server.authorization.model.ConsentDecision
import com.sphereon.oauth2.server.authorization.provider.UserAuthenticationProvider
import com.sphereon.oauth2.server.authorization.service.AuthorizationServerService
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import com.sphereon.oauth2.server.authorization.provider.CredentialIssuerAudienceResolver
import com.sphereon.oauth2.server.authorization.provider.UnregisteredClientAdmissionRule
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlin.time.Clock

/**
 * Wallet `/authorize` flow: dispatched when `login_hint` starts with `oid4vp:`. The wallet
 * authentication is already complete via the OID4VP session referenced by the hint, so this
 * impl runs the same parse / verify / create-session pipeline as the standard impl, then
 * resolves the authenticated user, fetches claims, issues the authorization code, and assembles
 * the authorization response inline. Returns [AuthorizationRequestOutcome.WalletCompleted] so
 * the HTTP layer renders the authorization response directly.
 */
@SingleIn(SessionScope::class)
@ContributesIntoSet(SessionScope::class, binding = binding<HandleAuthorizeRequestCommand>())
class WalletAuthorizeRequestCommandImpl @Inject constructor(
    execution: SessionExecution,
    private val authorizationServerService: AuthorizationServerService,
    private val clientRegistry: ClientRegistry,
    private val serversConfigProvider: OAuth2ServersConfigProvider,
    userAuthProviderFactory: () -> UserAuthenticationProvider,
    private val credentialIssuerAudienceResolver: CredentialIssuerAudienceResolver,
    private val unregisteredClientAdmissionRule: UnregisteredClientAdmissionRule,
) : TypedServiceCommandAdapter<HandleAuthorizeRequestArgs, AuthorizationRequestOutcome, IdkError>(
        commandId = COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<HandleAuthorizeRequestArgs>(),
        outputTypeToken = typeToken<AuthorizationRequestOutcome>(),
    ),
    HandleAuthorizeRequestCommand {
    private val userAuthProvider: UserAuthenticationProvider by lazy(userAuthProviderFactory)

    /** Source-compatible constructor for callers that already own these dependencies. */
    constructor(
        execution: SessionExecution,
        authorizationServerService: AuthorizationServerService,
        clientRegistry: ClientRegistry,
        serversConfigProvider: OAuth2ServersConfigProvider,
        userAuthProvider: UserAuthenticationProvider,
        credentialIssuerAudienceResolver: CredentialIssuerAudienceResolver,
        unregisteredClientAdmissionRule: UnregisteredClientAdmissionRule,
    ) : this(
        execution = execution,
        authorizationServerService = authorizationServerService,
        clientRegistry = clientRegistry,
        serversConfigProvider = serversConfigProvider,
        userAuthProviderFactory = { userAuthProvider },
        credentialIssuerAudienceResolver = credentialIssuerAudienceResolver,
        unregisteredClientAdmissionRule = unregisteredClientAdmissionRule,
    )

    override val commandId: String get() = COMMAND_ID

    private val commands get() = authorizationServerService.commands

    override suspend fun supports(args: Any): Boolean = args is HandleAuthorizeRequestArgs && args.loginHint?.startsWith("oid4vp:") == true

    override suspend fun doExecute(
        args: HandleAuthorizeRequestArgs,
        applyDuring: (HandleAuthorizeRequestArgs) -> HandleAuthorizeRequestArgs,
    ): IdkResult<AuthorizationRequestOutcome, IdkError> {
        val applied = applyDuring(args)
        val queryParameters = applied.queryParameters
        val loginHint =
            applied.loginHint
                ?: return Ok(
                    AuthorizationRequestOutcome.PreRedirectError(
                        error = "invalid_request",
                        errorDescription = "Wallet flow requires login_hint",
                    ),
                )

        // Parse + trusted-redirect resolution + verify + create-session are identical to the
        // standard flow; we run them here so the wallet path produces the same AuthorizationSession
        // shape before bypassing the auth-provider hop.
        val parseResult = commands.parseAuthorizationRequest.execute(ParseAuthorizationRequestArgs(queryParameters))
        if (!parseResult.isOk) {
            return Ok(
                AuthorizationRequestOutcome.PreRedirectError(
                    error = parseResult.error.code,
                    errorDescription = parseResult.error.message.defaultMessage,
                ),
            )
        }
        val parsed = parseResult.value

        val trusted =
            when (val resolution = resolveTrustedRedirect(parsed, clientRegistry, serversConfigProvider, unregisteredClientAdmissionRule, credentialIssuerAudienceResolver)) {
                is RedirectResolution.RejectPreRedirect -> {
                    return Ok(
                        AuthorizationRequestOutcome.PreRedirectError(
                            error = resolution.error.code,
                            errorDescription = resolution.error.message.defaultMessage,
                        ),
                    )
                }

                is RedirectResolution.Trusted -> {
                    resolution
                }
            }

        val verifyResult = commands.verifyAuthorizationRequest.execute(parsed)
        if (!verifyResult.isOk) {
            return Ok(
                AuthorizationRequestOutcome.PostRedirectError(
                    error = verifyResult.error.code,
                    errorDescription = verifyResult.error.message.defaultMessage,
                    redirectUri = trusted.redirectUri,
                    state = trusted.state,
                    responseMode = trusted.responseMode,
                ),
            )
        }
        val verified = verifyResult.value

        val sessionResult = commands.createAuthorizationSession.execute(verified)
        if (!sessionResult.isOk) {
            return Ok(
                AuthorizationRequestOutcome.PostRedirectError(
                    error = sessionResult.error.code,
                    errorDescription = sessionResult.error.message.defaultMessage,
                    redirectUri = verified.redirectUri,
                    state = verified.request.state,
                    responseMode = verified.responseMode,
                ),
            )
        }
        val session = sessionResult.value

        // Wallet branch: the OID4VP session id encoded in login_hint is the authenticated user
        // context. The user-auth-provider knows how to map it to the local user record.
        val oid4vpSessionId = loginHint.removePrefix("oid4vp:")
        val authResult = userAuthProvider.getAuthenticatedUser(oid4vpSessionId)
        if (authResult.isErr) {
            return Ok(
                AuthorizationRequestOutcome.PostRedirectError(
                    error = "access_denied",
                    errorDescription = "Wallet authentication failed: ${authResult.error.message.defaultMessage}",
                    redirectUri = session.redirectUri,
                    state = session.state,
                    responseMode = session.responseMode,
                ),
            )
        }
        val authenticatedUser =
            authResult.value
                ?: return Ok(
                    AuthorizationRequestOutcome.PostRedirectError(
                        error = "access_denied",
                        errorDescription = "Wallet session not authenticated",
                        redirectUri = session.redirectUri,
                        state = session.state,
                        responseMode = session.responseMode,
                    ),
                )

        // Pull the wallet claims so the issued authorization code can carry them downstream.
        val userClaims =
            userAuthProvider.getUserInfo(authenticatedUser.userId).let { result ->
                if (result.isOk) {
                    val info = result.value
                    buildMap<String, Any> {
                        info.username?.let { put("preferred_username", it) }
                        info.displayName?.let { put("name", it) }
                        info.email?.let { put("email", it) }
                        info.emailVerified?.let { put("email_verified", it) }
                        info.phoneNumber?.let { put("phone_number", it) }
                        info.phoneNumberVerified?.let { put("phone_number_verified", it) }
                        putAll(info.attributes)
                    }
                } else {
                    emptyMap()
                }
            }

        // Auto-approve: the wallet auth is already complete, issue authorization code
        val consent =
            ConsentDecision(
                userId = authenticatedUser.userId,
                clientId = session.clientId,
                granted = true,
                grantedScopes = session.scope?.split(" "),
                grantedAt = Clock.System.now(),
            )

        val codeResult =
            commands.createAuthorizationCode.execute(
                CreateAuthorizationCodeArgs(
                    session = session,
                    userId = authenticatedUser.userId,
                    consent = consent,
                    userClaims = userClaims,
                    acr = authenticatedUser.acr,
                    amr = authenticatedUser.amr,
                ),
            )
        if (codeResult.isErr) {
            return Ok(
                AuthorizationRequestOutcome.PostRedirectError(
                    error = "server_error",
                    errorDescription = codeResult.error.message.defaultMessage,
                    redirectUri = session.redirectUri,
                    state = session.state,
                    responseMode = session.responseMode,
                ),
            )
        }

        val responseResult =
            commands.createAuthorizationResponse.execute(
                CreateAuthorizationResponseArgs(
                    code = codeResult.value.value,
                    state = session.state,
                    redirectUri = session.redirectUri,
                    responseMode = session.responseMode,
                    clientId = session.clientId,
                    baseUrlOverride = applied.baseUrlOverride,
                ),
            )
        if (responseResult.isErr) {
            return Err(responseResult.error)
        }

        return Ok(AuthorizationRequestOutcome.WalletCompleted(authorizationResponseData = responseResult.value))
    }

    companion object {
        const val COMMAND_ID: String = "oauth2.authorization.wallet-authorize-request"
    }
}
