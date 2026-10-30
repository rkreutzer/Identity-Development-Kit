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

package com.sphereon.di.app

import com.sphereon.di.supervisedChild
import com.sphereon.core.api.conf.AppConfigService
import com.sphereon.core.api.conf.PropertiesFileAppPropertySource
import com.sphereon.core.api.conf.PropertySourceBootstrap
import com.sphereon.di.context.UserContextManager
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.DependencyGraph
import dev.zacsweers.metro.ForScope
import dev.zacsweers.metro.Multibinds
import dev.zacsweers.metro.Named
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.SingleIn
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import software.amazon.app.platform.scope.Scoped
import software.amazon.app.platform.scope.coroutine.CoroutineScopeScoped
import software.amazon.app.platform.scope.coroutine.DefaultCoroutineDispatcher
import software.amazon.app.platform.scope.coroutine.IoCoroutineDispatcher
import software.amazon.app.platform.scope.coroutine.metro.AppScopeCoroutineScopeGraph
import software.amazon.app.platform.scope.coroutine.metro.CoroutineDispatcherGraph
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Shared interface for the app graph. The final components live in the platform specific source
 * folders in order to have access to platform specific code.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("AppGraph", exact = true)
interface AppGraph : App {
    val userContextManager: UserContextManager

    /** All [Scoped] instances part of the app scope. */
    @ForScope(AppScope::class)
    public val appScopedInstances: Set<Scoped>

    /** The coroutine scope that runs as long as the app scope is alive. */
    @ForScope(AppScope::class)
    public val appScopeCoroutineScopeScoped: CoroutineScopeScoped

    fun destroy()
}

/**
 * API to get the application and ID. There are different implementations for Android, iOS, Jvm, Native etc.
 * their implementations are bound to this interface through code-gen. The platform implementation can be found in the respective platform folders
 *
 * Typically, the graph extending this abstract version will have the @DependencyGraph annotation on it
 *
 * So we expect in your app to have your App Graph have the @DependencyGraph on it and extend this graph.
 *
 * @property application The application itself. Be aware that not every platform will provide a useful implementation.
 * Mainly the mobile platforms provide an actual application you can use properties/methods from
 * @property appId The application ID. This string is provided by the host platform.
 * @property profile The profile of the application. This is typically used for development and testing or for different deployments of the same app.
 * @property version The version of the application.
 *
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("AbstractAppGraph", exact = true)
abstract class AbstractAppGraph : AppGraph {
    abstract override val application: Any

    @get:Named("version")
    abstract override val version: String

    @get:Named("appId")
    abstract override val appId: String

    @get:Named("profile")
    abstract override val profile: String

    abstract override val rootScopeProvider: RootScopeProvider

    @ForScope(AppScope::class)
    abstract override val appScopedInstances: Set<Scoped>

    @ForScope(AppScope::class)
    abstract override val appScopeCoroutineScopeScoped: CoroutineScopeScoped

    open fun initRootScopeProvider(): AppGraph {
        rootScopeProvider.create(this)
        (this as? PropertySourceBootstrap.Graph)?.propertySourceBootstrap?.registerAppSources()
        val appConfigService = (this as? AppConfigService.Graph)?.appConfigService
        val propertiesSource = (this as? PropertiesFileAppPropertySource.Graph)?.propertiesFileAppPropertySource
        if (appConfigService != null && propertiesSource != null) {
            val localSources = appConfigService.getPropertySources(includeParents = false)
            if (!localSources.contains(propertiesSource.getName())) {
                appConfigService.addPropertySource(propertiesSource)
            }
        }
        return this
    }

    override fun destroy() {
        if (!rootScopeProvider.isDestroyed() && !rootScopeProvider.rootScope.isDestroyed()) {
            rootScopeProvider.destroy()
        }
        try {
            // Let's be sure to also cleanup our instance. Should be handled by the above call though
            appScopeCoroutineScopeScoped.cancel()
        } catch (_: Exception) {
            // Ignored: coroutine scope may already be cancelled during cleanup
        }
    }
}

@ContributesTo(
    AppScope::class,
    replaces = [
        software.amazon.app.platform.scope.coroutine.metro.CoroutineDispatcherGraph::class,
        software.amazon.app.platform.scope.coroutine.metro.AppScopeCoroutineScopeGraph::class,
    ],
)
interface AppScopedProviders {
    @Multibinds(allowEmpty = true)
    @ForScope(AppScope::class)
    fun appScopedSet(): Set<Scoped>

    @Provides
    @DefaultCoroutineDispatcher
    fun provideIdkDefaultCoroutineDispatcher(): CoroutineDispatcher = Dispatchers.Default

    @Provides
    @software.amazon.app.platform.scope.coroutine.IoCoroutineDispatcher
    fun provideIdkIoCoroutineDispatcher(): CoroutineDispatcher = Dispatchers.Default

    @Provides
    @SingleIn(AppScope::class)
    @ForScope(AppScope::class)
    fun provideIdkAppScopeCoroutineScopeScoped(
        @software.amazon.app.platform.scope.coroutine.IoCoroutineDispatcher dispatcher: CoroutineDispatcher,
    ): software.amazon.app.platform.scope.coroutine.CoroutineScopeScoped =
        software.amazon.app.platform.scope.coroutine.CoroutineScopeScoped(
            dispatcher + kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.CoroutineName("AppScope"),
        )

    @Provides
    @ForScope(AppScope::class)
    fun provideIdkAppCoroutineScope(
        @ForScope(AppScope::class) scoped: software.amazon.app.platform.scope.coroutine.CoroutineScopeScoped,
    ): kotlinx.coroutines.CoroutineScope = scoped.supervisedChild()
}
