/*
 * Copyright 2023-2026 Sphereon International B.V.
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

package com.sphereon.oauth2.server.authorization.impl.provider

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.conf.PrincipalConfigService
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.server.authorization.provider.AuthenticatedUser
import com.sphereon.oauth2.server.authorization.provider.AuthenticationContext
import com.sphereon.oauth2.server.authorization.provider.AuthenticationError
import com.sphereon.oauth2.server.authorization.provider.AuthenticationHint
import com.sphereon.oauth2.server.authorization.provider.AuthenticationMethod
import com.sphereon.oauth2.server.authorization.provider.UserAuthenticationProvider
import com.sphereon.oauth2.server.authorization.provider.UserCredentials
import com.sphereon.oauth2.server.authorization.provider.UserInfo
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Provider
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

/**
 * Selects the active [UserAuthenticationProvider] from the keyed multibinding driven by
 * `oauth2.user-provider.mode`. Reads the key once per session and caches the resolved provider
 * (the binding is `@SingleIn(SessionScope::class)`, so each HTTP session sees its own
 * configuration snapshot).
 *
 * This is the IDK-default delegate: tenant-flat, single config layer. EDK ships
 * [com.sphereon.identity.auth.impl.EdkTenantAwareUserAuthenticationProviderDelegate] which
 * `replaces` this delegate to layer the lookup through App, Tenant, and Principal config
 * scopes (matching `feedback_session_scope_tenant.md` and the IDK→EDK→VDX strategic boundary).
 *
 * Fail-fast on an unknown mode: a silent fallback would mask a deployment misconfiguration,
 * which can swap the auth surface area without anyone noticing.
 *
 * Config:
 * ```
 * oauth2.user-provider.mode = federated | local | noop
 * ```
 */
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<UserAuthenticationProvider>())
class UserAuthenticationProviderDelegate @Inject constructor(
    providersFactory: () -> Map<String, Provider<UserAuthenticationProvider>>,
    private val configService: PrincipalConfigService,
) : UserAuthenticationProvider {
    private val providers: Map<String, Provider<UserAuthenticationProvider>> by lazy(providersFactory)

    /** Source-compatible constructor for callers that already own these dependencies. */
    constructor(
        providers: Map<String, UserAuthenticationProvider>,
        configService: PrincipalConfigService,
    ) : this(
        providersFactory = { providers.mapValues { (_, provider) -> Provider { provider } } },
        configService = configService,
    )

    val selected: UserAuthenticationProvider by lazy {
        val mode = configService.getPropertyAsString(MODE_KEY)?.trim()?.lowercase() ?: DEFAULT_MODE
        providers[mode]?.invoke()
            ?: error(
                "Unsupported $MODE_KEY: '$mode' (registered keys: ${providers.keys}). " +
                    "Set $MODE_KEY to one of those keys.",
            )
    }

    override suspend fun getAuthenticatedUser(sessionId: String,): IdkResult<AuthenticatedUser?, AuthenticationError> = selected.getAuthenticatedUser(sessionId)

    override suspend fun initiateAuthentication(
        sessionId: String,
        returnUrl: String,
        hint: AuthenticationHint?,
        context: AuthenticationContext?,
    ): IdkResult<String, AuthenticationError> = selected.initiateAuthentication(sessionId, returnUrl, hint, context)

    override suspend fun authenticateWithCredentials(
        credentials: UserCredentials,
        context: AuthenticationContext?,
    ): IdkResult<String?, AuthenticationError> = selected.authenticateWithCredentials(credentials, context)

    override suspend fun authenticateUserWithCredentials(
        credentials: UserCredentials,
        context: AuthenticationContext?,
    ): IdkResult<AuthenticatedUser?, AuthenticationError> = selected.authenticateUserWithCredentials(credentials, context)

    override suspend fun logout(userId: String): IdkResult<Unit, AuthenticationError> = selected.logout(userId)

    override suspend fun getUserInfo(userId: String): IdkResult<UserInfo, AuthenticationError> = selected.getUserInfo(userId)

    override suspend fun isAuthenticationMethodAvailable(method: AuthenticationMethod,): IdkResult<Boolean, AuthenticationError> = selected.isAuthenticationMethodAvailable(method)

    companion object {
        const val MODE_KEY: String = "oauth2.user-provider.mode"
        const val DEFAULT_MODE: String = "federated"
    }
}
