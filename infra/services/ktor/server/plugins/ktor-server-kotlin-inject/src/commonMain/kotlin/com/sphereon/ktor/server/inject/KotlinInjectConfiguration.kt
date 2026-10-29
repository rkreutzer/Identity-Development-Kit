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

import com.sphereon.di.app.AppGraph
import com.sphereon.core.defaults.context.ValidatedJwtClaimsInput
import com.sphereon.di.context.IdentityResolutionResult
import com.sphereon.di.context.SecuredTenantContextDetails
import io.ktor.server.application.ApplicationCall
import com.sphereon.ktor.server.inject.resolver.DefaultPrincipalResolver
import com.sphereon.ktor.server.inject.resolver.PrincipalResolver
import com.sphereon.ktor.server.inject.resolver.TenantResolver

/**
 * Configuration for the KotlinInject Ktor plugin.
 *
 * **Required:**
 * - [appGraph]: The root kotlin-inject AppGraph instance
 *
 * **Optional:**
 * - [tenantResolver]: Required strategy backed by validated JWT claims
 * - [principalResolver]: Strategy backed by validated JWT authentication
 *
 * **Example:**
 * ```kotlin
 * install(KotlinInject) {
 *     appGraph = MyAppGraph.create(...)
 *
 *     // Use custom resolvers
 *     tenantResolver = JwtTenantResolver()
 *     principalResolver = JwtPrincipalResolver()
 *
 * }
 * ```
 */
class KotlinInjectConfiguration {
    /**
     * Optional host projection of an already validated bearer into request-scoped credentials.
     * Invoked only with validated JWT input and the final resolved identity. The host may retain
     * stronger validation provenance here; it must preserve the exact bearer, issuer and lifetime.
     * It also owns any service-audience marker on its result. The default projection stays generic.
     */
    var validatedSecureDetailsFactory: ValidatedRequestSecureDetailsFactory? = null
    /**
     * The root kotlin-inject AppGraph instance.
     * This is the entry point to the kotlin-inject dependency injection tree.
     *
     * **Required** - must be set in the configuration.
     */
    var appGraph: AppGraph? = null

    /**
     * Custom tenant resolver implementation.
     *
     * Tenant resolution from a client-controlled header is unsafe — the previous
     * `DefaultTenantResolver` that read `X-Tenant-ID` has been removed. Deployments
     * MUST provide a real strategy; the canonical option is to install the
     * `TenantResolutionPlugin` from `services/ktor-server-tenant-resolution` which
     * delegates to the IDK `TenantResolutionHandler` chain (JWT + host).
     */
    private var _tenantResolver: TenantResolver? = null

    /**
     * Custom principal resolver implementation.
     * If not set, the validated-JWT resolver is used.
     */
    private var _principalResolver: PrincipalResolver? = null

    /**
     * The tenant resolver to use for extracting tenant information from requests.
     *
     * REQUIRED — there is no default. Header-based tenant resolution was removed
     * because client-supplied headers cannot be trusted. Use the
     * `TenantResolutionPlugin` (from `services/ktor-server-tenant-resolution`),
     * which composes a Ktor [TenantResolver] backed by the IDK
     * [com.sphereon.di.context.TenantResolutionHandler] chain (JWT, custom domain,
     * platform subdomain).
     */
    var tenantResolver: TenantResolver
        get() =
            _tenantResolver
                ?: throw IllegalStateException(
                    "tenantResolver is required. Install the TenantResolutionPlugin and assign its produced resolver, " +
                        "or provide a custom strategy. Header-based resolution has been removed.",
                )
        set(value) {
            _tenantResolver = value
        }

    /**
     * The principal resolver to use for extracting principal information from requests.
     * Defaults to the validated-JWT resolver.
     */
    var principalResolver: PrincipalResolver
        get() = _principalResolver ?: DefaultPrincipalResolver()
        set(value) {
            _principalResolver = value
        }

    /**
     * Request path prefixes that do not need request-scoped DI. Liveness and
     * metrics probes must remain independent from tenant/principal resolution
     * and from remote configuration sources.
     */
    var ignoredPathPrefixes: List<String> = listOf("/health", "/ready", "/metrics")
}

fun interface ValidatedRequestSecureDetailsFactory {
    fun create(
        call: ApplicationCall,
        validatedJwt: ValidatedJwtClaimsInput,
        identity: IdentityResolutionResult,
    ): SecuredTenantContextDetails
}
