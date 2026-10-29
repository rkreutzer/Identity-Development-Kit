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

package com.sphereon.di.context

import com.sphereon.di.supervisedChild
import com.sphereon.core.api.log.UserContextLogManager
import com.sphereon.di.session.SessionContextManager
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.ForScope
import dev.zacsweers.metro.GraphExtension
import dev.zacsweers.metro.Multibinds
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
 * Graph extension for UserScope. Accessors for user-scoped dependencies.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("UserContextGraph", exact = true)
@SingleIn(UserScope::class)
@GraphExtension(UserScope::class)
interface UserContextGraph {
    val sessionContextManager: SessionContextManager
    val instance: UserContextInstance
    val userContext: UserContext

    @ContributesTo(AppScope::class)
    @GraphExtension.Factory
    interface Factory {
        fun createUserContext(
            @Provides userContext: UserContext,
        ): UserContextGraph
    }

    /** All [Scoped] instances part of the context scope. */
    @ForScope(UserScope::class)
    val contextScopedInstances: Set<Scoped>

    /** The coroutine scope that runs as long as the context scope is alive. */
    @ForScope(UserScope::class)
    val contextScopeCoroutineScopeScoped: CoroutineScopeScoped

    val logManager: UserContextLogManager
}

/**
 * Provides coroutine scope and Scoped set for UserScope.
 * Separated from GraphExtension so Metro merges them as contributed bindings.
 */
@ContributesTo(UserScope::class)
interface UserContextScopedProviders {
    @Provides
    @SingleIn(UserScope::class)
    @ForScope(UserScope::class)
    fun provideContextScopeCoroutineScopeScoped(
        @DefaultCoroutineDispatcher dispatcher: CoroutineDispatcher,
    ): CoroutineScopeScoped = CoroutineScopeScoped(dispatcher + SupervisorJob() + CoroutineName("UserScope"))

    @Provides
    @ForScope(UserScope::class)
    fun provideContextCoroutineScope(
        @ForScope(UserScope::class) contextScopeCoroutineScopeScoped: CoroutineScopeScoped,
    ): CoroutineScope = contextScopeCoroutineScopeScoped.supervisedChild()

    @Multibinds(allowEmpty = true)
    @ForScope(UserScope::class)
    fun userScopedSet(): Set<Scoped>
}
