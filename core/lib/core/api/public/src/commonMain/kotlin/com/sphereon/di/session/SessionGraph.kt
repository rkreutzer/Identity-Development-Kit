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
 *
 */

package com.sphereon.di.session

import com.sphereon.di.supervisedChild
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.log.SessionLogManager
import com.sphereon.di.context.SecuredTenantContextDetails
import com.sphereon.di.context.PrincipalType
import com.sphereon.di.context.UserScope
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.ForScope
import dev.zacsweers.metro.GraphExtension
import dev.zacsweers.metro.Multibinds
import dev.zacsweers.metro.Named
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.SingleIn
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineName
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import software.amazon.app.platform.scope.Scoped
import software.amazon.app.platform.scope.coroutine.CoroutineScopeScoped
import software.amazon.app.platform.scope.coroutine.DefaultCoroutineDispatcher
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Graph extension for SessionScope. Accessors for session-scoped dependencies.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("SessionGraph", exact = true)
@SingleIn(SessionScope::class)
@GraphExtension(SessionScope::class)
interface SessionGraph {
    @get:Named("sessionId")
    val sessionId: String

    @get:Named("correlationId")
    val correlationId: String

    val sessionContext: SessionContext
    val sessionExecution: SessionExecution
    val logManager: SessionLogManager
    val instance: SessionInstance

    @ContributesTo(UserScope::class)
    @GraphExtension.Factory
    interface Factory {
        fun createSessionGraph(
            @Provides @Named("sessionId")
            sessionId: String,
            @Provides @Named("correlationId")
            correlationId: String = sessionId,
            /**
             * Validated transport credentials for THIS session (e.g. the bearer JWT a
             * REST request presented, after upstream signature/iss/exp validation).
             * Session-scoped on purpose: the UserScope [com.sphereon.di.context.UserContext]
             * is cached per tenant+principal and must never carry one request's token.
             * When non-null the session-scoped [SessionContext] surfaces a [com.sphereon.di.context.UserContext]
             * whose `secureDetails` carries these credentials.
             */
            @Provides
            secureDetails: SecuredTenantContextDetails? = null,
            /** Server-derived principal classification for this authenticated session. */
            @Provides @Named("principalType")
            principalType: PrincipalType? = null,
        ): SessionGraph
    }

    /** All [Scoped] instances part of the session scope. */
    @ForScope(SessionScope::class)
    val sessionScopedInstances: Set<Scoped>

    /** The coroutine scope that runs as long as the session scope is alive. */
    @ForScope(SessionScope::class)
    val sessionScopeCoroutineScopeScoped: CoroutineScopeScoped
}

/**
 * Provides coroutine scope and Scoped set for SessionScope.
 * Separated from GraphExtension so Metro merges them as contributed bindings.
 */
@ContributesTo(SessionScope::class)
interface SessionScopedProviders {
    @Provides
    @SingleIn(SessionScope::class)
    @ForScope(SessionScope::class)
    fun provideSessionScopeCoroutineScopeScoped(
        @DefaultCoroutineDispatcher dispatcher: CoroutineDispatcher,
    ): CoroutineScopeScoped = CoroutineScopeScoped(dispatcher + SupervisorJob() + CoroutineName("SessionScope"))

    @Provides
    @ForScope(SessionScope::class)
    fun provideSessionCoroutineScope(
        @ForScope(SessionScope::class) sessionScopeCoroutineScopeScoped: CoroutineScopeScoped,
    ): CoroutineScope = sessionScopeCoroutineScopeScoped.supervisedChild()

    @Multibinds(allowEmpty = true)
    @ForScope(SessionScope::class)
    fun sessionScopedSet(): Set<Scoped>
}
