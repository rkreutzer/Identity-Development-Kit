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

package com.sphereon.core.defaults.context

import com.sphereon.core.api.conf.AppConfigService
import com.sphereon.core.api.conf.ConfigBootstrapGuard
import com.sphereon.core.api.conf.PrincipalConfigService
import com.sphereon.core.api.conf.PropertiesFilePrincipalPropertySource
import com.sphereon.core.api.conf.PropertiesFileTenantPropertySource
import com.sphereon.core.api.conf.PropertySourceBootstrap
import com.sphereon.core.api.conf.TenantConfigService
import com.sphereon.core.api.context.ContextScopedResourceInvalidator
import com.sphereon.core.api.log.AppLogManager
import com.sphereon.core.api.session.currentTimeMillis
import com.sphereon.di.app.App
import com.sphereon.di.app.RootScopeProvider
import com.sphereon.di.context.AnonymousUserGraphManager
import com.sphereon.di.context.ClassifiedPrincipalInput
import com.sphereon.di.context.IdentityConstants
import com.sphereon.di.context.IdentityResolutionResult
import com.sphereon.di.context.PrincipalAware
import com.sphereon.di.context.PrincipalInput
import com.sphereon.di.context.PrincipalResolutionHandler
import com.sphereon.di.context.PrincipalType
import com.sphereon.di.context.TenantAware
import com.sphereon.di.context.TenantContextData
import com.sphereon.di.context.TenantInput
import com.sphereon.di.context.TenantResolutionHandler
import com.sphereon.di.context.UserContext
import com.sphereon.di.context.UserContextGraph
import com.sphereon.di.context.UserContextInstance
import com.sphereon.di.context.UserContextManager
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.atomicfu.AtomicRef
import kotlinx.atomicfu.atomic
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import software.amazon.app.platform.scope.coroutine.addCoroutineScopeScoped
import software.amazon.app.platform.scope.coroutine.coroutineScope
import software.amazon.app.platform.scope.di.metro.addMetroDependencyGraph
import software.amazon.app.platform.scope.register
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

@Inject
@SingleIn(AppScope::class)
@ContributesBinding(AppScope::class, binding = binding<UserContextManager>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("UserContextManagerImpl", exact = true)
class UserContextManagerImpl(
    private val rootScopeProvider: RootScopeProvider,
    private val contextGraphFactory: UserContextGraph.Factory,
    private val principalResolutionHandler: PrincipalResolutionHandler,
    private val tenantResolutionHandler: TenantResolutionHandler,
    private val anonymousUserGraphManager: AnonymousUserGraphManager,
    private val propertySourceBootstrap: PropertySourceBootstrap,
    private val appConfigService: AppConfigService,
    private val contextScopedResourceInvalidators: Set<ContextScopedResourceInvalidator>,
    appLogManager: AppLogManager,
    val app: App,
) : SynchronizedObject(),
    UserContextManager {
    private val log = appLogManager.withTag("UserContextManager")

    init {
        check(!rootScopeProvider.isDestroyed()) {
            "Root scope has not been initialized yet. Call init() on the App Graph first"
        }
    }

    // Internal map for management (only for regular user contexts, not anonymous or background)
    // Each UserContextInstance already contains graph, scope, and context
    // Using AtomicRef for thread-safe access
    private val instances: AtomicRef<Map<String, UserContextInstance>> = atomic(emptyMap())
    private val lastAccessEpochMs: AtomicRef<Map<String, Long>> = atomic(emptyMap())

    // Active instance tracking (atomic reference for thread-safe reads)
    private val activeAuthenticatedInstance: AtomicRef<UserContextInstance?> = atomic(null)

    // Hot flow that emits the active instance
    // Note: This flow is backed by AtomicRef but exposed as StateFlow for API compatibility
    private val _activeInstance = MutableStateFlow<UserContextInstance?>(null)

    init {
        rootScopeProvider.rootScope.coroutineScope().launch {
            while (isActive) {
                val intervalMs = cleanupIntervalMs()
                delay(intervalMs)
                runCatching { runIdleCleanup() }
                    .onFailure { error ->
                        log.warn(
                            "VDX_USER_CONTEXT_IDLE_CLEANUP_FAILED error=${error.message?.sanitizeLogToken() ?: error::class.simpleName}",
                        )
                    }
            }
        }
    }

    override val activeInstance: StateFlow<UserContextInstance> by lazy {
        _activeInstance
            .map {
                it ?: anonymousUserGraphManager.getAnonymousGraph().instance
            }.stateIn(
                rootScopeProvider.rootScope.coroutineScope(),
                SharingStarted.Lazily,
                anonymousUserGraphManager.getAnonymousGraph().instance,
            )
    }

    // Primary access method - always returns instance (anonymous if map empty)
    override fun getActive(): UserContextInstance {
        // Fast path: lock-free read
        return activeAuthenticatedInstance.value ?: anonymousUserGraphManager.getAnonymousGraph().instance
    }

    override fun hasActive(): Boolean {
        // Returns true if there's an active context (anonymous or authenticated, but NOT background service)
        val current = activeAuthenticatedInstance.value
        return current != null && current.contextId != UserContext.BACKGROUND_SERVICE
    }

    override fun hasAuthenticated(): Boolean {
        // Check if there's at least one regular user context (excluding anonymous and background)
        return instances.value.isNotEmpty()
    }

    // Instance-based access (primary approach) - with makeActive capability
    override fun get(
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
        makeActive: Boolean,
    ): UserContextInstance? {
        val contextId = generateContextId(tenantAware.tenant, principalAware.principal)
        return getById(contextId, makeActive)
    }

    override fun getById(
        contextId: String,
        makeActive: Boolean,
    ): UserContextInstance? {
        // Check if it's a special context managed by AnonymousUserGraphManager
        val existingInstance =
            when (contextId) {
                UserContext.ANONYMOUS -> anonymousUserGraphManager.getAnonymousGraph().instance
                UserContext.BACKGROUND_SERVICE -> anonymousUserGraphManager.getBackgroundGraph().instance
                else -> instances.value[contextId]?.also { touchContext(contextId) }
            }

        // Background service can NEVER be made active
        if (existingInstance != null && makeActive && contextId != UserContext.BACKGROUND_SERVICE) {
            setActiveInstance(existingInstance)
        }

        return existingInstance
    }

    override fun has(
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
    ): Boolean {
        val contextId = generateContextId(tenantAware.tenant, principalAware.principal)
        return hasById(contextId)
    }

    override fun hasById(contextId: String): Boolean =
        when (contextId) {
            UserContext.ANONYMOUS -> true

            // Anonymous context always exists
            UserContext.BACKGROUND_SERVICE -> true

            // Background context always exists
            else -> instances.value.containsKey(contextId)
        }

    // Context switching (updates flows)
    override fun activateById(contextId: String): Boolean {
        // Background service can NEVER be activated
        if (contextId == UserContext.BACKGROUND_SERVICE) {
            return false
        }

        val instance =
            when (contextId) {
                UserContext.ANONYMOUS -> anonymousUserGraphManager.getAnonymousGraph().instance
                else -> instances.value[contextId]
            }
        return if (instance != null) {
            if (contextId != UserContext.ANONYMOUS) {
                touchContext(contextId)
            }
            setActiveInstance(instance)
            true
        } else {
            false
        }
    }

    override fun activate(
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
    ): Boolean {
        val contextId = generateContextId(tenantAware.tenant, principalAware.principal)
        return activateById(contextId)
    }

    // Context listing
    override fun listIds(): Set<String> {
        val regularIds = instances.value.keys
        // Anonymous and background contexts always exist
        return regularIds + setOf(UserContext.ANONYMOUS, UserContext.BACKGROUND_SERVICE)
    }

    // Context creation (returns instances)
    override fun createOrGetFromCallbacks(
        tenantInput: () -> TenantInput,
        principalInput: () -> PrincipalInput,
    ): UserContextInstance = createOrGetFromInputs(tenantInput(), principalInput())

    override fun createOrGetFromInputs(
        tenantInput: TenantInput,
        principalInput: PrincipalInput,
        makeActive: Boolean,
    ): UserContextInstance {
        val tenantContext =
            com.sphereon.core.api.coroutines
                .runBlockingCompat { tenantResolutionHandler.resolveTenant(tenantInput) }
        val principal = principalResolutionHandler.resolvePrincipal(principalInput, tenantContext)
        return createOrGetContextInternal(
            tenantContextData = tenantContext.tenant,
            principal = principal,
            // An identity string carries no classification, so an ordinary input stays USER.
            // An input that knows what it is (a Temporal worker's system principal, a scheduler
            // dispatch) says so, and must be believed: the same identity comes back over the
            // transport as a workload token, and both paths key the same `tenant:principal`
            // context. Defaulting those to USER makes whichever path runs second fail with
            // "Principal classification mismatch for existing context".
            principalType = (principalInput as? ClassifiedPrincipalInput)?.principalType ?: PrincipalType.USER,
            makeActive = makeActive,
        ).instance
    }

    override fun createOrGetFromResolvedInputs(
        tenantInput: TenantInput,
        principalInput: PrincipalInput,
        identityResolution: IdentityResolutionResult,
        makeActive: Boolean,
    ): UserContextInstance {
        // Bridge: TenantResolutionHandler.resolveTenant is now suspend (so Ktor
        // request-path callers don't have to runBlocking on their event loop).
        // This synchronous facade is still needed for Spring filters and other
        // non-coroutine callers — they pay the runBlocking cost here, OFF the
        // Ktor hot path. On JS/wasmJs this only works when the suspend chain
        // does not actually suspend; otherwise it throws at runtime.
        val tenantContext =
            com.sphereon.core.api.coroutines
                .runBlockingCompat { tenantResolutionHandler.resolveTenant(tenantInput) }
        val principal = principalResolutionHandler.resolvePrincipal(principalInput, tenantContext)
        require(identityResolution.tenantId == tenantContext.tenant.tenantId) {
            "Authoritative tenant does not match the resolved context tenant"
        }
        require(identityResolution.principalId == principal.principal?.toString()) {
            "Authoritative principal does not match the resolved context principal"
        }
        return createOrGetContextInternal(
            tenantContextData = tenantContext.tenant,
            principal = principal,
            principalType = identityResolution.principalType,
            makeActive = makeActive,
        ).instance
    }

    override fun createOrGet(
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
        makeActive: Boolean,
    ): UserContextInstance =
        createOrGet(
            tenantAware = tenantAware,
            principalAware = principalAware,
            principalType = PrincipalType.USER,
            makeActive = makeActive,
        )

    override fun createOrGet(
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
        principalType: PrincipalType,
        makeActive: Boolean,
    ): UserContextInstance =
        createOrGetContextInternal(
            tenantContextData = tenantAware.tenant,
            principal = principalAware,
            principalType = principalType,
            makeActive = makeActive,
        ).instance

    @Deprecated(
        message = "Use createOrGet(tenantAware, principalAware, principalType, makeActive) instead to avoid principal classification and tenant boundary ambiguities.",
    )
    override fun createOrGetFromData(
        tenantData: TenantContextData,
        principalValue: Any?,
        makeActive: Boolean,
    ): UserContextInstance =
        createOrGetFromData(
            tenantData = tenantData,
            principalValue = principalValue,
            principalType = PrincipalType.USER,
            makeActive = makeActive,
        )

    @Deprecated(
        message = "Use createOrGet(tenantAware, principalAware, principalType, makeActive) instead to avoid principal classification and tenant boundary ambiguities.",
    )
    override fun createOrGetFromData(
        tenantData: TenantContextData,
        principalValue: Any?,
        principalType: PrincipalType,
        makeActive: Boolean,
    ): UserContextInstance {
        val principalAware =
            object : PrincipalAware {
                override val principal = principalValue
            }
        return createOrGetContextInternal(
            tenantContextData = tenantData,
            principal = principalAware,
            principalType = principalType,
            makeActive = makeActive,
        ).instance
    }

    override fun createOrGetWithId(
        contextId: String,
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
        makeActive: Boolean,
    ): UserContextInstance {
        // If requesting a special context ID, delegate to the appropriate method
        return when (contextId) {
            UserContext.ANONYMOUS -> {
                val graph = anonymousUserGraphManager.getAnonymousGraph()
                if (makeActive) {
                    setActiveInstance(graph.instance)
                }
                graph.instance
            }

            UserContext.BACKGROUND_SERVICE -> {
                // Background service can NEVER be made active
                val graph = anonymousUserGraphManager.getBackgroundGraph()
                graph.instance
            }

            else -> {
                createOrGetContextInternal(
                    tenantContextData = tenantAware.tenant,
                    principal = principalAware,
                    principalType = PrincipalType.USER,
                    makeActive = makeActive,
                    contextId = contextId,
                ).instance
            }
        }
    }

    // Context cleanup
    override fun destroyById(contextId: String) {
        when (contextId) {
            UserContext.ANONYMOUS -> {
                anonymousUserGraphManager.clearAnonymous()
            }

            UserContext.BACKGROUND_SERVICE -> {
                anonymousUserGraphManager.clearBackground()
            }

            else -> {
                var remainingInstancesAfterDestroy = emptyList<UserContextInstance>()
                val instance =
                    synchronized(this) {
                        val currentInstances = instances.value
                        val instance = currentInstances[contextId]
                        if (instance != null) {
                            // Remove from map first
                            val updatedInstances = currentInstances - contextId
                            instances.value = updatedInstances
                            lastAccessEpochMs.value = lastAccessEpochMs.value - contextId
                            remainingInstancesAfterDestroy = updatedInstances.values.toList()

                            // Clear active if this was the active context
                            if (activeAuthenticatedInstance.value?.contextId == contextId) {
                                setActiveInstance(null)
                            }
                        }
                        instance
                    }
                instance?.let { destroyedInstance ->
                    var destroyError: Throwable? = null
                    val rootChildrenBefore = rootChildrenCount()
                    log.debug(
                        "VDX_USER_CONTEXT_DESTROY_START contextId=${destroyedInstance.contextId.sanitizeLogToken()} " +
                            "tenant=${destroyedInstance.context.tenant.tenantId.sanitizeLogToken()} " +
                            "principal=${destroyedInstance.principalLogToken()} reason=destroy-by-id " +
                            "retainedContextsAfterRemove=${remainingInstancesAfterDestroy.size} " +
                            "rootChildrenBefore=${rootChildrenBefore ?: "unknown"}",
                    )
                    runCatching { destroyedInstance.scope.destroy() }
                        .onSuccess {
                            log.debug(
                                "VDX_USER_CONTEXT_DESTROYED contextId=${destroyedInstance.contextId.sanitizeLogToken()} " +
                                    "tenant=${destroyedInstance.context.tenant.tenantId.sanitizeLogToken()} " +
                                    "principal=${destroyedInstance.principalLogToken()} reason=destroy-by-id " +
                                    "retainedContexts=${remainingInstancesAfterDestroy.size} " +
                                    "rootChildrenAfter=${rootChildrenCount() ?: "unknown"}",
                            )
                        }.onFailure { error ->
                            destroyError = error
                            log.warn(
                                "VDX_USER_CONTEXT_DESTROY_FAILED contextId=${destroyedInstance.contextId.sanitizeLogToken()} " +
                                    "tenant=${destroyedInstance.context.tenant.tenantId.sanitizeLogToken()} " +
                                    "principal=${destroyedInstance.principalLogToken()} reason=destroy-by-id " +
                                    "retainedContexts=${remainingInstancesAfterDestroy.size} " +
                                    "error=${error.message?.sanitizeLogToken() ?: error::class.simpleName}",
                            )
                        }
                    invalidateResourcesForDestroyedContexts(
                        destroyedInstances = listOf(destroyedInstance),
                        remainingInstances = remainingInstancesAfterDestroy,
                        reason = "destroy-by-id",
                    )
                    destroyError?.let { throw it }
                }
            }
        }
    }

    override fun destroy(
        tenantAware: TenantAware,
        principalAware: PrincipalAware,
    ) {
        val contextId = generateContextId(tenantAware.tenant, principalAware.principal)
        destroyById(contextId)
    }

    override fun destroyAll() {
        val instancesToDestroy =
            synchronized(this) {
                // Capture all instances to destroy
                val instancesToDestroy = instances.value.values.toList()

                // Clear all state first
                instances.value = emptyMap()
                lastAccessEpochMs.value = emptyMap()
                setActiveInstance(null)
                instancesToDestroy
            }

        // Destroy regular contexts after clearing state, but keep invalidation guaranteed.
        var firstDestroyError: Throwable? = null
        instancesToDestroy.forEach { instance ->
            val rootChildrenBefore = rootChildrenCount()
            log.debug(
                "VDX_USER_CONTEXT_DESTROY_START contextId=${instance.contextId.sanitizeLogToken()} " +
                    "tenant=${instance.context.tenant.tenantId.sanitizeLogToken()} " +
                    "principal=${instance.principalLogToken()} reason=destroy-all retainedContextsAfterRemove=0 " +
                    "rootChildrenBefore=${rootChildrenBefore ?: "unknown"}",
            )
            runCatching { instance.scope.destroy() }
                .onSuccess {
                    log.debug(
                        "VDX_USER_CONTEXT_DESTROYED contextId=${instance.contextId.sanitizeLogToken()} " +
                            "tenant=${instance.context.tenant.tenantId.sanitizeLogToken()} " +
                            "principal=${instance.principalLogToken()} reason=destroy-all retainedContexts=0 " +
                            "rootChildrenAfter=${rootChildrenCount() ?: "unknown"}",
                    )
                }.onFailure { error ->
                    if (firstDestroyError == null) firstDestroyError = error
                    log.warn(
                        "VDX_USER_CONTEXT_DESTROY_FAILED contextId=${instance.contextId.sanitizeLogToken()} " +
                            "tenant=${instance.context.tenant.tenantId.sanitizeLogToken()} " +
                            "principal=${instance.principalLogToken()} reason=destroy-all retainedContexts=0 " +
                            "error=${error.message?.sanitizeLogToken() ?: error::class.simpleName}",
                    )
                }
        }
        invalidateResourcesForDestroyedContexts(
            destroyedInstances = instancesToDestroy,
            remainingInstances = emptyList(),
            reason = "destroy-all",
        )
        firstDestroyError?.let { throw it }

        // Destroy special contexts managed by AnonymousUserManager
        anonymousUserGraphManager.clearAll()
    }

    // Singleton context instances - always available
    override fun getBackgroundService(): UserContextInstance {
        // Background service can NEVER be made active
        val graph = anonymousUserGraphManager.getBackgroundGraph()
        return graph.instance
    }

    override fun getAnonymous(makeActive: Boolean): UserContextInstance {
        val graph = anonymousUserGraphManager.getAnonymousGraph()
        if (makeActive) {
            setActiveInstance(graph.instance)
        }
        return graph.instance
    }

    override fun getBackgroundServiceId(): String = UserContext.BACKGROUND_SERVICE

    // Utility methods (delegate to active context instance)
    override fun isAnonymous(): Boolean {
        val activeInstance = activeAuthenticatedInstance.value ?: return true
        return activeInstance.context.principal == IdentityConstants.ANONYMOUS_PRINCIPAL_ID
    }

    // Private helper methods

    private fun createOrGetContextInternal(
        tenantContextData: TenantContextData,
        principal: PrincipalAware,
        principalType: PrincipalType,
        makeActive: Boolean,
        contextId: String = generateContextId(tenantContextData, principal.principal),
    ): UserContextGraph {
        // Fast path: lock-free read if already exists
        instances.value[contextId]?.let { instance ->
            require(instance.context.principalType == principalType) {
                "Principal classification mismatch for existing context '$contextId'"
            }
            touchContext(contextId)
            if (makeActive) {
                setActiveInstance(instance)
            }
            return instance.graph
        }

        // Slow path: need to create, use synchronized block with double-check
        return synchronized(this) {
            // Double-check after acquiring lock
            instances.value[contextId]?.let { instance ->
                require(instance.context.principalType == principalType) {
                    "Principal classification mismatch for existing context '$contextId'"
                }
                touchContext(contextId)
                if (makeActive) {
                    setActiveInstance(instance)
                }
                return instance.graph
            }

            // Create new context
            val context =
                UserContextImpl(
                    tenant = tenantContextData,
                    principal = principal.principal,
                    principalType = principalType,
                )
            val rootChildrenBefore = rootChildrenCount()
            val retainedContextsBefore = instances.value.size
            log.debug(
                "VDX_USER_CONTEXT_CREATE_START contextId=${contextId.sanitizeLogToken()} " +
                    "tenant=${tenantContextData.tenantId.sanitizeLogToken()} " +
                    "principal=${principal.principalLogToken()} makeActive=$makeActive " +
                    "retainedContextsBefore=$retainedContextsBefore rootChildrenBefore=${rootChildrenBefore ?: "unknown"}",
            )
            val contextGraph = contextGraphFactory.createUserContext(context)

            val scope =
                rootScopeProvider.rootScope.buildChild("${app.appId}:${app.profile}:$contextId") {
                    addMetroDependencyGraph(contextGraph)
                    addService("context", context)
                    addCoroutineScopeScoped(contextGraph.contextScopeCoroutineScopeScoped)
                }

            // Initialize the instance with its graph and scope
            val instance = contextGraph.instance

            (instance as? UserContextInstanceImpl)?.initialize(contextGraph, scope)

            ConfigBootstrapGuard.withContextRegistration {
                registerContextConfigSources(
                    contextGraph = contextGraph,
                    tenantId = tenantContextData.tenantId,
                    principalId = principal.principal?.toString() ?: IdentityConstants.ANONYMOUS_PRINCIPAL_ID,
                )

                log.debug("instance context: ${instance.context}")

                // Store the instance atomically
                instances.value = instances.value + (contextId to instance)
                touchContext(contextId)

                // Set as active if requested (before registration to ensure getActive() returns correct instance)
                if (makeActive) {
                    setActiveInstance(instance)
                }

                // Register instances after the instance is stored and active
                scope.register(contextGraph.contextScopedInstances)
                log.debug(
                    "VDX_USER_CONTEXT_CREATED contextId=${contextId.sanitizeLogToken()} " +
                        "tenant=${tenantContextData.tenantId.sanitizeLogToken()} " +
                        "principal=${principal.principalLogToken()} makeActive=$makeActive " +
                        "retainedContextsAfter=${instances.value.size} rootChildrenAfter=${rootChildrenCount() ?: "unknown"}",
                )
            }

            contextGraph
        }
    }

    /**
     * Sets the active instance atomically and updates the flow.
     * This ensures both the atomic reference and the StateFlow are kept in sync.
     */
    private fun setActiveInstance(instance: UserContextInstance?) {
        activeAuthenticatedInstance.value = instance
        _activeInstance.value = instance
    }

    internal fun runIdleCleanup(nowEpochMs: Long = currentTimeMillis()) {
        if (!idleCleanupEnabled()) return
        val timeoutMs = idleTimeoutMs()
        if (timeoutMs <= 0L) return
        val cutoff = nowEpochMs - timeoutMs
        val candidates =
            lastAccessEpochMs.value
                .filterValues { it <= cutoff }
                .keys
        if (candidates.isEmpty()) return

        var destroyedContextIds = emptyList<String>()
        var instancesToDestroy = emptyList<UserContextInstance>()
        var remainingInstancesAfterDestroy = emptyList<UserContextInstance>()
        synchronized(this) {
            val currentInstances = instances.value
            val currentLastAccess = lastAccessEpochMs.value
            val toDestroy =
                candidates
                    .filter { contextId ->
                        contextId != UserContext.ANONYMOUS &&
                            contextId != UserContext.BACKGROUND_SERVICE &&
                            currentInstances.containsKey(contextId) &&
                            (currentLastAccess[contextId] ?: Long.MAX_VALUE) <= cutoff
                    }
            if (toDestroy.isNotEmpty()) {
                val toDestroySet = toDestroy.toSet()
                instancesToDestroy = toDestroy.mapNotNull { currentInstances[it] }
                destroyedContextIds = toDestroy
                val updatedInstances = currentInstances.filterKeys { it !in toDestroySet }
                instances.value = updatedInstances
                lastAccessEpochMs.value = currentLastAccess.filterKeys { it !in toDestroySet }
                remainingInstancesAfterDestroy = updatedInstances.values.toList()

                if (activeAuthenticatedInstance.value?.contextId in toDestroySet) {
                    setActiveInstance(null)
                }
            }
        }

        if (destroyedContextIds.isEmpty()) return

        instancesToDestroy.forEach { instance ->
            val rootChildrenBefore = rootChildrenCount()
            log.debug(
                "VDX_USER_CONTEXT_DESTROY_START contextId=${instance.contextId.sanitizeLogToken()} " +
                    "tenant=${instance.context.tenant.tenantId.sanitizeLogToken()} " +
                    "principal=${instance.principalLogToken()} reason=idle-cleanup " +
                    "retainedContextsAfterRemove=${remainingInstancesAfterDestroy.size} " +
                    "rootChildrenBefore=${rootChildrenBefore ?: "unknown"} idleTimeoutMs=$timeoutMs",
            )
            runCatching { instance.scope.destroy() }
                .onSuccess {
                    log.debug(
                        "VDX_USER_CONTEXT_DESTROYED contextId=${instance.contextId.sanitizeLogToken()} " +
                            "tenant=${instance.context.tenant.tenantId.sanitizeLogToken()} " +
                            "principal=${instance.principalLogToken()} reason=idle-cleanup " +
                            "retainedContexts=${remainingInstancesAfterDestroy.size} " +
                            "rootChildrenAfter=${rootChildrenCount() ?: "unknown"} idleTimeoutMs=$timeoutMs",
                    )
                }.onFailure { error ->
                    log.warn(
                        "VDX_USER_CONTEXT_IDLE_DESTROY_FAILED contextId=${instance.contextId.sanitizeLogToken()} " +
                            "idleTimeoutMs=$timeoutMs error=${error.message?.sanitizeLogToken() ?: error::class.simpleName}",
                    )
                }
        }

        // Automatic UserScope eviction must not infer AppScope tenant teardown.
        // Those resources are shared with background and later user contexts.
        // Invalidating them here can race background work and turns every request
        // after the user-context timeout into a cold application start.
        log.debug(
            "VDX_USER_CONTEXT_IDLE_APP_RESOURCES_RETAINED destroyedContexts=${destroyedContextIds.size} " +
                "remainingContexts=${remainingInstancesAfterDestroy.size} idleTimeoutMs=$timeoutMs",
        )

        destroyedContextIds.forEach { contextId ->
            log.info(
                "VDX_USER_CONTEXT_IDLE_DESTROYED contextId=${contextId.sanitizeLogToken()} " +
                    "idleTimeoutMs=$timeoutMs remaining=${instances.value.size}",
            )
        }
    }

    private fun invalidateResourcesForDestroyedContexts(
        destroyedInstances: List<UserContextInstance>,
        remainingInstances: Collection<UserContextInstance>,
        reason: String,
    ) {
        if (destroyedInstances.isEmpty()) return

        val remainingTenantIds = remainingInstances.map { it.context.tenant.tenantId }.toSet()
        val remainingPrincipals =
            remainingInstances
                .map {
                    it.context.tenant.tenantId to
                        (it.context.principal?.toString() ?: IdentityConstants.ANONYMOUS_PRINCIPAL_ID)
                }.toSet()
        val destroyedByTenant = destroyedInstances.groupBy { it.context.tenant.tenantId }

        com.sphereon.core.api.coroutines.runBlockingCompat {
            destroyedByTenant.forEach { (tenantId, tenantInstances) ->
                tenantInstances
                    .map { it.context.principal?.toString() ?: IdentityConstants.ANONYMOUS_PRINCIPAL_ID }
                    .distinct()
                    .filter { principalId -> tenantId to principalId !in remainingPrincipals }
                    .forEach { principalId ->
                        notifyContextResourceInvalidators(
                            scope = "PRINCIPAL",
                            tenantId = tenantId,
                            principalId = principalId,
                            reason = reason,
                        )
                    }
                if (tenantId !in remainingTenantIds) {
                    notifyContextResourceInvalidators(
                        scope = "TENANT",
                        tenantId = tenantId,
                        principalId = null,
                        reason = reason,
                    )
                }
            }
        }
    }

    private fun rootChildrenCount(): Int? = runCatching { rootScopeProvider.rootScope.children().size }.getOrNull()

    private suspend fun notifyContextResourceInvalidators(
        scope: String,
        tenantId: String,
        principalId: String?,
        reason: String,
    ) {
        contextScopedResourceInvalidators.forEach { invalidator ->
            runCatching {
                if (principalId == null) {
                    invalidator.invalidateTenantContext(tenantId, reason)
                } else {
                    invalidator.invalidatePrincipalContext(tenantId, principalId, reason)
                }
            }.onFailure { error ->
                val principalPart = principalId?.let { " principal=${it.sanitizeLogToken()}" } ?: ""
                log.warn(
                    "VDX_CONTEXT_RESOURCE_INVALIDATION_FAILED invalidator=${invalidator::class.simpleName?.sanitizeLogToken() ?: "unknown"} " +
                        "scope=$scope tenant=${tenantId.sanitizeLogToken()}$principalPart reason=${reason.sanitizeLogToken()} " +
                        "error=${error.message?.sanitizeLogToken() ?: error::class.simpleName}",
                )
            }
        }
    }

    private fun touchContext(contextId: String) {
        if (contextId == UserContext.ANONYMOUS || contextId == UserContext.BACKGROUND_SERVICE) return
        val now = currentTimeMillis()
        while (true) {
            if (!instances.value.containsKey(contextId)) return
            val current = lastAccessEpochMs.value
            val updated = current + (contextId to now)
            if (lastAccessEpochMs.compareAndSet(current, updated)) {
                if (!instances.value.containsKey(contextId)) {
                    removeLastAccess(contextId)
                }
                return
            }
        }
    }

    private fun removeLastAccess(contextId: String) {
        while (true) {
            val current = lastAccessEpochMs.value
            if (!current.containsKey(contextId)) return
            val updated = current - contextId
            if (lastAccessEpochMs.compareAndSet(current, updated)) return
        }
    }

    private fun idleCleanupEnabled(): Boolean =
        appConfigService
            .getPropertyAsString(USER_CONTEXT_IDLE_CLEANUP_ENABLED, "true")
            ?.toBooleanStrictOrNull()
            ?: true

    private fun idleTimeoutMs(): Long =
        appConfigService
            .getPropertyAsString(USER_CONTEXT_IDLE_TIMEOUT_MS, DEFAULT_USER_CONTEXT_IDLE_TIMEOUT_MS.toString())
            ?.toLongOrNull()
            ?.coerceAtLeast(0L)
            ?: DEFAULT_USER_CONTEXT_IDLE_TIMEOUT_MS

    private fun cleanupIntervalMs(): Long =
        appConfigService
            .getPropertyAsString(USER_CONTEXT_IDLE_CLEANUP_INTERVAL_MS, DEFAULT_USER_CONTEXT_IDLE_CLEANUP_INTERVAL_MS.toString())
            ?.toLongOrNull()
            ?.coerceAtLeast(1_000L)
            ?: DEFAULT_USER_CONTEXT_IDLE_CLEANUP_INTERVAL_MS

    private fun generateContextId(
        tenant: TenantContextData,
        principalValue: Any?,
        suffix: String = "default",
    ): String = "${tenant.tenantId}:$principalValue:$suffix"

    private fun registerContextConfigSources(
        contextGraph: UserContextGraph,
        tenantId: String,
        principalId: String,
    ) {
        val tenantConfigService = (contextGraph as? TenantConfigService.Graph)?.tenantConfigService
        val tenantPropertySource = (contextGraph as? PropertiesFileTenantPropertySource.Graph)?.propertiesFileTenantPropertySource
        if (tenantConfigService != null && tenantPropertySource != null) {
            val localSources = tenantConfigService.getPropertySources(includeParents = false)
            if (!localSources.contains(tenantPropertySource.getName())) {
                tenantConfigService.addPropertySource(tenantPropertySource)
            }
        }

        val principalConfigService = (contextGraph as? PrincipalConfigService.Graph)?.principalConfigService
        val principalPropertySource = (contextGraph as? PropertiesFilePrincipalPropertySource.Graph)?.propertiesFilePrincipalPropertySource
        if (principalConfigService != null && principalPropertySource != null) {
            val localSources = principalConfigService.getPropertySources(includeParents = false)
            if (!localSources.contains(principalPropertySource.getName())) {
                principalConfigService.addPropertySource(principalPropertySource)
            }
        }

        tenantConfigService?.let { propertySourceBootstrap.registerTenantSources(it, tenantId) }
        principalConfigService?.let { propertySourceBootstrap.registerPrincipalSources(it, tenantId, principalId) }
    }

    private companion object {
        const val USER_CONTEXT_IDLE_CLEANUP_ENABLED = "context.user.idle-cleanup.enabled"
        const val USER_CONTEXT_IDLE_TIMEOUT_MS = "context.user.idle-timeout-ms"
        const val USER_CONTEXT_IDLE_CLEANUP_INTERVAL_MS = "context.user.idle-cleanup.interval-ms"
        const val DEFAULT_USER_CONTEXT_IDLE_TIMEOUT_MS = 300_000L
        const val DEFAULT_USER_CONTEXT_IDLE_CLEANUP_INTERVAL_MS = 60_000L
    }
}

private fun String.sanitizeLogToken(): String =
    trim()
        .ifBlank { "<blank>" }
        .replace(Regex("[^A-Za-z0-9._:@-]"), "_")
        .take(160)

private fun PrincipalAware.principalLogToken(): String = (principal?.toString() ?: IdentityConstants.ANONYMOUS_PRINCIPAL_ID).sanitizeLogToken()

private fun UserContextInstance.principalLogToken(): String = (context.principal?.toString() ?: IdentityConstants.ANONYMOUS_PRINCIPAL_ID).sanitizeLogToken()
