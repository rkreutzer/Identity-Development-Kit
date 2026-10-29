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

import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesTo
import kotlinx.coroutines.flow.StateFlow
import software.amazon.app.platform.scope.Scope
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

@OptIn(ExperimentalObjCName::class)
@ObjCName("UserContextManager", exact = true)
interface UserContextManager {
    // Primary access method - always returns instance (anonymous if map empty)
    fun getActive(): UserContextInstance

    /**
     * Returns true if there is an active context (anonymous or authenticated, but not background service).
     */
    fun hasActive(): Boolean

    /**
     * Returns true if there is an authenticated user context (not anonymous and not background service).
     */
    fun hasAuthenticated(): Boolean

    // Instance-based access (primary approach)
    fun get(
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
        makeActive: Boolean = false,
    ): UserContextInstance?

    fun getById(
        contextId: String,
        makeActive: Boolean = false,
    ): UserContextInstance?

    fun has(
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
    ): Boolean

    fun hasById(contextId: String): Boolean

    // Context switching (updates flows)
    fun activateById(contextId: String): Boolean

    fun activate(
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
    ): Boolean

    // Context listing
    fun listIds(): Set<String>

    // Context creation (returns instances)
    fun createOrGetFromCallbacks(
        tenantInput: () -> TenantInput,
        principalInput: () -> PrincipalInput,
    ): UserContextInstance

    /**
     * Creates an ordinary application-user context from unresolved inputs.
     *
     * Authentication ingress that already classified the identity must use
     * [createOrGetFromResolvedInputs] instead.
     */
    fun createOrGetFromInputs(
        tenantInput: TenantInput,
        principalInput: PrincipalInput,
        makeActive: Boolean = true,
    ): UserContextInstance

    /**
     * Creates a context from identity inputs and an authoritative resolution result.
     *
     * Use this path when authentication already resolved and classified the identity.
     * The manager independently resolves its normal inputs, verifies that tenant and
     * principal match the authoritative result, and only then creates the typed context.
     */
    fun createOrGetFromResolvedInputs(
        tenantInput: TenantInput,
        principalInput: PrincipalInput,
        identityResolution: IdentityResolutionResult,
        makeActive: Boolean = true,
    ): UserContextInstance

    /**
     * Creates an ordinary application-user context from resolved data.
     *
     * Callers with an authoritative classification must use the required-type
     * overload below.
     */
    fun createOrGet(
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
        makeActive: Boolean = true,
    ): UserContextInstance

    /**
     * Creates a context from already-resolved tenant and principal data with an
     * authoritative principal type.
     *
     * Use this overload when the caller already owns a trusted identity result,
     * such as a validated session context. The type is required and is never
     * inferred from identity strings.
     */
    fun createOrGet(
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
        principalType: PrincipalType,
        makeActive: Boolean = true,
    ): UserContextInstance

    @Deprecated(
        message = "Use createOrGet(tenantAware, principalAware, principalType, makeActive) instead to avoid principal classification and tenant boundary ambiguities.",
    )
    fun createOrGetFromData(
        tenantData: TenantContextData,
        principalValue: Any?,
        makeActive: Boolean = true,
    ): UserContextInstance

    @Deprecated(
        message = "Use createOrGet(tenantAware, principalAware, principalType, makeActive) instead to avoid principal classification and tenant boundary ambiguities.",
    )
    fun createOrGetFromData(
        tenantData: TenantContextData,
        principalValue: Any?,
        principalType: PrincipalType,
        makeActive: Boolean = true,
    ): UserContextInstance =
        createOrGetFromData(
            tenantData = tenantData,
            principalValue = principalValue,
            makeActive = makeActive,
        )

    fun createOrGetWithId(
        contextId: String,
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
        makeActive: Boolean = true,
    ): UserContextInstance

    // Context cleanup
    fun destroyById(contextId: String)

    fun destroy(
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
    )

    fun destroyAll()

    val activeInstance: StateFlow<UserContextInstance>

    // Singleton context instances - always available
    fun getBackgroundService(): UserContextInstance

    fun getAnonymous(makeActive: Boolean = false): UserContextInstance

    fun getBackgroundServiceId(): String

    // Utility methods (delegate to active context instance)
    fun isAnonymous(): Boolean

    @ContributesTo(AppScope::class)
    interface Graph {
        val userContextManager: UserContextManager
    }
}
