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

import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationErrorResponseCommand
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeCallbackCommand
import com.sphereon.oauth2.server.authorization.impl.http.OAuth2ServerBaseUrlResolver
import com.sphereon.oauth2.server.authorization.impl.http.command.TestSessionExecution
import com.sphereon.oauth2.server.authorization.impl.http.requiredaction.RequiredActionsRedirectHandler
import com.sphereon.oauth2.server.authorization.storage.MutableOidcLoginSessionIdProvider
import dev.zacsweers.metro.Provider
import java.lang.reflect.Modifier
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Builds the authorize and authorize-callback HTTP handlers through the factories Metro generated
 * for their SessionScope bindings, which is what the route's session graph calls, with a counting
 * provider per dependency. Resolving a handler must only construct what every request on the route
 * uses: the authorization error response is only built for a post-redirect error, and the
 * required-actions redirect only for a refused callback.
 */
class AuthorizeRouteHandlerConstructionTest {
    private val constructed = linkedMapOf<String, Int>()

    private fun counted(
        name: String,
        instance: () -> Any,
    ): Provider<Any> {
        constructed[name] = 0
        return Provider {
            constructed.merge(name, 1, Int::plus)
            instance()
        }
    }

    private fun <T> viaMetroFactory(
        type: Class<T>,
        vararg providers: Provider<*>,
    ): T {
        val contributions = Class.forName("${type.name}Contributions\$ToSessionScope")
        val factory =
            contributions.declaredClasses.single {
                it.simpleName.startsWith("Provide") && it.simpleName.endsWith("MetroFactory")
            }
        val create =
            factory.declaredMethods.single {
                it.name == "create" && Modifier.isStatic(it.modifiers) && it.parameterCount == providers.size
            }
        return type.cast((create.invoke(null, *providers) as Provider<*>).invoke())
    }

    @Test
    fun authorizeHandlerDefersTheAuthorizationErrorResponse() {
        viaMetroFactory(
            AuthorizeHttpEndpointCommandImpl::class.java,
            counted("SessionExecution") { TestSessionExecution() },
            counted("HandleAuthorizeRequestCommands") { emptySet<Any>() },
            counted("CreateAuthorizationErrorResponseCommand") { stub<CreateAuthorizationErrorResponseCommand>() },
            counted("OAuth2ServersConfigProvider") { stub<OAuth2ServersConfigProvider>() },
            counted("OAuth2ServerBaseUrlResolver") { stub<OAuth2ServerBaseUrlResolver>() },
            counted("MutableOidcLoginSessionIdProvider") { stub<MutableOidcLoginSessionIdProvider>() },
        )
        println("AuthorizeHttpEndpointCommandImpl resolution: $constructed")

        assertEquals(0, constructed.getValue("CreateAuthorizationErrorResponseCommand"), "Only a post-redirect error builds its response")
        assertEquals(1, constructed.getValue("HandleAuthorizeRequestCommands"))
    }

    @Test
    fun authorizeCallbackHandlerDefersTheRequiredActionsRedirect() {
        viaMetroFactory(
            AuthorizeCallbackHttpEndpointCommandImpl::class.java,
            counted("SessionExecution") { TestSessionExecution() },
            counted("HandleAuthorizeCallbackCommand") { stub<HandleAuthorizeCallbackCommand>() },
            counted("MutableOidcLoginSessionIdProvider") { stub<MutableOidcLoginSessionIdProvider>() },
            counted("OAuth2ServersConfigProvider") { stub<OAuth2ServersConfigProvider>() },
            counted("RequiredActionsRedirectHandler") { stub<RequiredActionsRedirectHandler>() },
            counted("OAuth2ServerBaseUrlResolver") { stub<OAuth2ServerBaseUrlResolver>() },
        )
        println("AuthorizeCallbackHttpEndpointCommandImpl resolution: $constructed")

        assertEquals(0, constructed.getValue("RequiredActionsRedirectHandler"), "Only a refused callback consults the required-actions redirect")
        assertEquals(1, constructed.getValue("HandleAuthorizeCallbackCommand"))
    }

    private inline fun <reified T : Any> stub(): T =
        Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { proxy, method, args ->
            when (method.name) {
                "equals" -> proxy === args?.firstOrNull()
                "hashCode" -> System.identityHashCode(proxy)
                "toString" -> "stub ${T::class.java.simpleName}"
                else -> error("Construction must not call ${T::class.java.simpleName}.${method.name}")
            }
        } as T
}
