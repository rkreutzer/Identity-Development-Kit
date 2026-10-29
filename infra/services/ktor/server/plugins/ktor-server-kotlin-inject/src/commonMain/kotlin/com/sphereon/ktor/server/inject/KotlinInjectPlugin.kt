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

package com.sphereon.ktor.server.inject

import com.sphereon.core.api.app.CoreApiAppExtensionGraph
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteSelection
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteSelector
import com.sphereon.core.api.log.LogService
import com.sphereon.di.app.AppGraph
import com.sphereon.ktor.server.inject.interceptor.UserContextInterceptor
import com.sphereon.ktor.server.inject.resolver.PrincipalResolver
import com.sphereon.ktor.server.inject.resolver.TenantResolver
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.BaseApplicationPlugin
import io.ktor.server.application.createRouteScopedPlugin
import io.ktor.server.application.hooks.CallFailed
import io.ktor.server.application.hooks.ResponseSent
import io.ktor.server.application.plugin
import io.ktor.server.request.header
import io.ktor.server.request.httpMethod
import io.ktor.server.request.path
import io.ktor.server.response.respondText
import io.ktor.server.routing.RoutingPipelineCall
import io.ktor.server.routing.routing
import io.ktor.util.AttributeKey

/**
 * Ktor server plugin that provides kotlin-inject, kotlin-inject-anvil (Amazon), and
 * Amazon App Platform injection support for the Identity Development Kit (IDK).
 *
 * This plugin enables the three-scope architecture:
 * - **AppScope**: Singleton instances shared across the entire application
 * - **UserScope**: Principal and tenant scoped instances (per user/tenant combination)
 * - **SessionScope**: Session scoped instances (per request/response)
 *
 * **Multiplatform Compatible:**
 * This plugin is fully multiplatform and works on JVM, JavaScript, Native, and GraalVM.
 * Services are accessed via graph inspection (properties and provider methods) using reflection.
 *
 * **Key Features:**
 * - Request-scoped context resolution (tenant + principal + session)
 * - Service access via extension functions using graph inspection
 * - Thread-safe per-request isolation
 * - Configurable authentication and resolver strategies
 * - Works across all Kotlin platforms
 *
 * **Installation:**
 * ```kotlin
 * install(KotlinInjectPlugin) {
 *     appGraph = myAppGraph
 *
 *     // Optional: custom resolvers
 *     tenantResolver = MyTenantResolver()
 *     principalResolver = MyPrincipalResolver()
 * }
 * ```
 *
 * **Usage in Routes:**
 * ```kotlin
 * routing {
 *     get("/api/resource") {
 *         // Access app-scoped services via extension functions
 *         val appService = call.getAppService<MyAppService>()
 *
 *         // Or directly from graph
 *         val appConfig = call.appGraph.appConfigEnvironment
 *
 *         // Access user-scoped services
 *         val userService = call.getUserService<MyUserService>()
 *
 *         // Access session-scoped services
 *         val sessionService = call.getSessionService<MySessionService>()
 *
 *         // Access context instances directly
 *         val userInstance = call.userInstance
 *         val sessionInstance = call.sessionInstance
 *     }
 * }
 * ```
 *
 * @see KotlinInjectConfiguration for configuration options
 */
class KotlinInjectPlugin(
    configuration: KotlinInjectConfiguration,
) {
    val appGraph: AppGraph =
        configuration.appGraph
            ?: throw IllegalStateException("AppGraph is required. Please provide it in the configuration.")

    val tenantResolver: TenantResolver = configuration.tenantResolver
    val principalResolver: PrincipalResolver = configuration.principalResolver
    val ignoredPathPrefixes: List<String> = configuration.ignoredPathPrefixes
    val validatedSecureDetailsFactory: ValidatedRequestSecureDetailsFactory? = configuration.validatedSecureDetailsFactory

    // Get the app-scoped logger from the graph
    private val logger: LogService by lazy {
        (appGraph as CoreApiAppExtensionGraph).appLogManager.withTag("KotlinInjectPlugin")
    }

    init {
        logger.info("Initializing KotlinInject plugin with AppGraph: ${appGraph::class.simpleName}")
        logger.info("Plugin is multiplatform compatible - services accessed via graph inspection")
    }

    companion object Plugin : BaseApplicationPlugin<Application, KotlinInjectConfiguration, KotlinInjectPlugin> {
        override val key: AttributeKey<KotlinInjectPlugin> = AttributeKey("KotlinInject")

        override fun install(
            pipeline: Application,
            configure: KotlinInjectConfiguration.() -> Unit,
        ): KotlinInjectPlugin {
            val configuration = KotlinInjectConfiguration().apply(configure)
            val plugin = KotlinInjectPlugin(configuration)

            // Install the interceptor for automatic context resolution
            val interceptor =
                UserContextInterceptor(
                    appGraph = plugin.appGraph,
                    tenantResolver = plugin.tenantResolver,
                    principalResolver = plugin.principalResolver,
                    validatedSecureDetailsFactory = plugin.validatedSecureDetailsFactory,
                )

            val requestScopePlugin =
                createRouteScopedPlugin("KotlinInjectRequestScope") {
                    onCall { call ->
                        // A real browser preflight has no bearer token. Route-scoped CORS validates
                        // it without route selection or tenant/user/session construction.
                        if (
                            call.request.httpMethod == HttpMethod.Options &&
                            call.request.header(HttpHeaders.Origin) != null &&
                            call.request.header("Access-Control-Request-Method") != null
                        ) {
                            return@onCall
                        }
                        if (plugin.ignoredPathPrefixes.any { call.request.path().startsWith(it) }) {
                            return@onCall
                        }

                        // Ktor has already selected the concrete route at this point. Universal
                        // catch-all nodes are preselected from the AppScope metadata catalog before
                        // any tenant, user, SessionScope, adapter, or endpoint command is created.
                        if (call.isUniversalHttpAdapterRoute()) {
                            val routePolicy = call.requireUniversalHttpAdapterRoutePolicy()
                            val selector =
                                (plugin.appGraph as HttpAdapterRouteSelector.Graph).httpAdapterRouteSelector
                            when (
                                val selection =
                                    selector.select(
                                        call.request.httpMethod.value,
                                        routePolicy.selectionPath(call.request.path()),
                                        routePolicy.allowedAdapterIds,
                                    )
                            ) {
                                is HttpAdapterRouteSelection.Selected -> {
                                    call.attributes.put(SelectedHttpAdapterRouteAttribute, selection.match)
                                }

                                is HttpAdapterRouteSelection.NotFound -> {
                                    call.respondText(
                                        "Not found",
                                        status = HttpStatusCode.NotFound,
                                    )
                                    return@onCall
                                }

                                is HttpAdapterRouteSelection.Ambiguous -> {
                                    plugin.logger.error(
                                        message = "HTTP_ROUTE_SELECTION_FAILED",
                                        metadata =
                                            mapOf(
                                                "reason" to "ambiguous_route",
                                                "method" to selection.method,
                                                "candidateCount" to selection.candidates.size.toString(),
                                            ),
                                    )
                                    call.respondText("Internal server error", status = HttpStatusCode.InternalServerError)
                                    return@onCall
                                }

                                is HttpAdapterRouteSelection.Misconfigured -> {
                                    plugin.logger.error(
                                        message = "HTTP_ROUTE_SELECTION_FAILED",
                                        metadata = mapOf("reason" to "misconfigured_route", "detail" to selection.message),
                                    )
                                    call.respondText("Internal server error", status = HttpStatusCode.InternalServerError)
                                    return@onCall
                                }
                            }
                        }

                        interceptor.intercept(call)
                    }
                    on(ResponseSent) { call -> call.destroyRequestSessionIfPresent() }
                    on(CallFailed) { call, _ -> call.destroyRequestSessionIfPresent() }
                }

            // Installing on the routing root moves session creation behind Ktor's authoritative
            // route resolution while retaining the same interceptor for every selected route.
            pipeline.routing { install(requestScopePlugin) }

            plugin.logger.info("KotlinInject plugin installed successfully")

            return plugin
        }
    }
}

private fun io.ktor.server.application.ApplicationCall.isUniversalHttpAdapterRoute(): Boolean {
    var route = (this as? RoutingPipelineCall)?.route
    while (route != null) {
        if (route.attributes.getOrNull(UniversalHttpAdapterRouteAttribute) == true) return true
        route = route.parent
    }
    return false
}

private fun io.ktor.server.application.ApplicationCall.requireUniversalHttpAdapterRoutePolicy(): UniversalHttpAdapterRoutePolicy {
    var route = (this as? RoutingPipelineCall)?.route
    while (route != null) {
        route.attributes.getOrNull(UniversalHttpAdapterRoutePolicyAttribute)?.let { return it }
        route = route.parent
    }
    error("Universal HTTP adapter route has no immutable selection policy")
}

private fun io.ktor.server.application.ApplicationCall.destroyRequestSessionIfPresent() {
    if (attributes.getOrNull(RequestSessionDestroyedAttribute) == true) return
    attributes.put(RequestSessionDestroyedAttribute, true)
    attributes.getOrNull(UserContextInterceptor.RequestContextKey)?.sessionInstance?.destroy()
}

private val RequestSessionDestroyedAttribute: AttributeKey<Boolean> =
    AttributeKey("sphereon.inject.requestSessionDestroyed")

/**
 * Extension property to access the KotlinInject plugin instance.
 */
val Application.kotlinInject: KotlinInjectPlugin
    get() = plugin(KotlinInjectPlugin)
