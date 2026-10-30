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
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.server.authorization.command.AuthorizationResponseData
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationCodeArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationResponseArgs
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeCallbackArgs
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeCallbackCommand
import com.sphereon.oauth2.server.authorization.model.ConsentDecision
import com.sphereon.oauth2.server.authorization.provider.AuthenticatedUser
import com.sphereon.oauth2.server.authorization.provider.UserAuthenticationProvider
import com.sphereon.oauth2.server.authorization.service.AuthorizationServerService
import com.sphereon.oauth2.server.authorization.storage.OidcLoginSessionIdProvider
import com.sphereon.oauth2.server.authorization.storage.OidcLoginSessionStore
import com.sphereon.oauth2.server.authorization.storage.PendingAuthorizationSessionStore
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.Clock

/**
 * Implementation of [HandleAuthorizeCallbackCommand]. Folds the full callback flow into one
 * command: pending-session lookup + single-use removal, authenticated-user resolution, consent
 * shaping, code issuance, and authorization-response assembly. The HTTP layer parses the
 * `session_id` query parameter and renders [AuthorizationResponseData] over the chosen
 * response mode (query / fragment / form_post).
 */
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<HandleAuthorizeCallbackCommand>())
class HandleAuthorizeCallbackCommandImpl @Inject constructor(
    execution: SessionExecution,
    private val authorizationServerService: AuthorizationServerService,
    private val pendingAuthorizationSessionStore: PendingAuthorizationSessionStore,
    userAuthProviderFactory: () -> UserAuthenticationProvider,
    private val loginSessionIdProvider: OidcLoginSessionIdProvider,
    private val loginSessionStore: OidcLoginSessionStore,
) : TypedServiceCommandAdapter<HandleAuthorizeCallbackArgs, AuthorizationResponseData, IdkError>(
        commandId = HandleAuthorizeCallbackCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<HandleAuthorizeCallbackArgs>(),
        outputTypeToken = typeToken<AuthorizationResponseData>(),
    ),
    HandleAuthorizeCallbackCommand {
    private val userAuthProvider: UserAuthenticationProvider by lazy(userAuthProviderFactory)

    /** Source-compatible constructor for callers that already own these dependencies. */
    constructor(
        execution: SessionExecution,
        authorizationServerService: AuthorizationServerService,
        pendingAuthorizationSessionStore: PendingAuthorizationSessionStore,
        userAuthProvider: UserAuthenticationProvider,
        loginSessionIdProvider: OidcLoginSessionIdProvider,
        loginSessionStore: OidcLoginSessionStore,
    ) : this(
        execution = execution,
        authorizationServerService = authorizationServerService,
        pendingAuthorizationSessionStore = pendingAuthorizationSessionStore,
        userAuthProviderFactory = { userAuthProvider },
        loginSessionIdProvider = loginSessionIdProvider,
        loginSessionStore = loginSessionStore,
    )

    override val commandId: String get() = HandleAuthorizeCallbackCommand.COMMAND_ID

    private val commands get() = authorizationServerService.commands

    override suspend fun supports(args: Any): Boolean = args is HandleAuthorizeCallbackArgs

    override suspend fun doExecute(
        args: HandleAuthorizeCallbackArgs,
        applyDuring: (HandleAuthorizeCallbackArgs) -> HandleAuthorizeCallbackArgs,
    ): IdkResult<AuthorizationResponseData, IdkError> {
        val applied = applyDuring(args)
        val sessionId = applied.sessionId

        val findResult = pendingAuthorizationSessionStore.consume(sessionId)
        if (findResult.isErr) {
            return Err(findResult.error)
        }
        val session =
            findResult.value
                ?: return Err(
                    IdkError.fromString(
                        code = "invalid_request",
                        message = "No pending authorization session for session_id: $sessionId",
                    ),
                )
        // The storage transaction has claimed this callback once across every replica.

        // Resolve the authenticated user. The federation flow records the user against the
        // pending session id inside the [UserAuthenticationProvider], so the provider lookup
        // wins when present. The AS first-party login flow (Group J) authenticates the user via
        // `POST /login`, sets the `oidc_login_sid` cookie, and writes the user into
        // [OidcLoginSessionStore]; the federation provider has nothing to return for that
        // session id, so we fall back to the cookie-keyed login session.
        val resolvedAuthenticatedUser =
            resolveAuthenticatedUser(applied.authenticationSessionId ?: sessionId)
                ?: return Err(
                    IdkError.fromString(
                        code = "server_error",
                        message = "User not authenticated after login",
                    ),
                )
        val authenticatedUser = resolvedAuthenticatedUser.user

        // Pull user claims so the issued code can carry them downstream. A claims-fetch failure
        // is non-fatal: first-party credentials were already authenticated by the identity-owning
        // runtime and their authorization claims are frozen into the cookie-bound login session.
        // Provider claims, when available, win over those session claims.
        val providerClaims =
            userAuthProvider.getUserInfo(authenticatedUser.userId).let { result ->
                if (result.isOk) result.value.toClaimsMap() else emptyMap()
            }
        val userClaims =
            buildMap<String, Any> {
                putAll(resolvedAuthenticatedUser.sessionClaims)
                if (authenticatedUser.roles.isNotEmpty()) {
                    put(
                        "roles",
                        JsonArray(
                            authenticatedUser.roles
                                .distinct()
                                .sorted()
                                .map(::JsonPrimitive),
                        ),
                    )
                }
                putAll(providerClaims)
            }

        val consent =
            ConsentDecision(
                userId = authenticatedUser.userId,
                clientId = session.clientId,
                granted = true,
                grantedScopes = session.scope?.split(" "),
                grantedAt = Clock.System.now(),
            )

        // Create authorization code
        val code =
            commands.createAuthorizationCode
                .execute(
                    CreateAuthorizationCodeArgs(
                        session = session,
                        userId = authenticatedUser.userId,
                        consent = consent,
                        userClaims = userClaims,
                        acr = authenticatedUser.acr,
                        amr = authenticatedUser.amr,
                    ),
                ).getOrElse { error -> return Err(error) }

        // OIDC Core §3.3 Hybrid Flow — front-channel id_token / access_token mint when the
        // session's response_type asks for them, in addition to the code.
        val frontChannel =
            mintFrontChannelTokens(
                service = authorizationServerService,
                session = session,
                code = code.value,
                subject = authenticatedUser.userId,
                authTime = session.authTime,
                acr = authenticatedUser.acr,
                amr = authenticatedUser.amr,
                baseUrlOverride = applied.baseUrlOverride,
            ).getOrElse { error -> return Err(error) }

        // Create authorization response, threads the session's resolved response_mode through
        // so the adapter can branch on `query` / `fragment` / `form_post` when emitting the
        // final HTTP response.
        return commands.createAuthorizationResponse.execute(
            CreateAuthorizationResponseArgs(
                code = code.value,
                state = session.state,
                redirectUri = session.redirectUri,
                responseMode = session.responseMode,
                clientId = session.clientId,
                baseUrlOverride = applied.baseUrlOverride,
                idToken = frontChannel.idToken,
                accessToken = frontChannel.accessToken,
                tokenType = frontChannel.accessToken?.let { "Bearer" },
                accessTokenExpiresIn = frontChannel.accessTokenExpiresIn,
            ),
        )
    }

    /**
     * Resolve the authenticated user for the given pending session id. Tries the
     * [UserAuthenticationProvider] first (federation flow), then falls back to the cookie-keyed
     * [OidcLoginSessionStore] (AS first-party `/login` flow). Returns null when neither source
     * carries a usable identity, leaving the caller to surface a `server_error`.
     */
    private suspend fun resolveAuthenticatedUser(authenticationSessionId: String): ResolvedAuthenticatedUser? {
        val providerResult = userAuthProvider.getAuthenticatedUser(authenticationSessionId)
        if (providerResult.isOk) {
            providerResult.value?.let { return ResolvedAuthenticatedUser(user = it) }
        }
        val loginSessionId = loginSessionIdProvider.currentLoginSessionId() ?: return null
        val sessionResult = loginSessionStore.findById(loginSessionId)
        if (!sessionResult.isOk) return null
        val session = sessionResult.value ?: return null
        val roles =
            (session.claims["roles"] as? JsonArray)
                ?.mapNotNull { element ->
                    (element as? JsonPrimitive)
                        ?.takeIf(JsonPrimitive::isString)
                        ?.content
                }.orEmpty()
        return ResolvedAuthenticatedUser(
            user =
                AuthenticatedUser(
                    userId = session.sub,
                    authenticatedAt = session.authTime,
                    authenticationMethod = session.authMethod,
                    acr = session.acr,
                    amr = session.amr,
                    roles = roles,
                ),
            sessionClaims = session.claims,
        )
    }

    private data class ResolvedAuthenticatedUser(
        val user: AuthenticatedUser,
        val sessionClaims: Map<String, JsonElement> = emptyMap(),
    )
}
