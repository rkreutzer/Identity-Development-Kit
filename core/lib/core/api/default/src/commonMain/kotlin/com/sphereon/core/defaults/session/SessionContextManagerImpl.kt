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

package com.sphereon.core.defaults.session

import com.sphereon.core.api.conf.ConfigBootstrapGuard
import com.sphereon.core.api.log.UserContextLogManager
import com.sphereon.core.api.session.SessionScopeResolutionOutcome
import com.sphereon.core.api.session.SessionScopeResolutionPhase
import com.sphereon.core.api.session.SessionScopeResolutionSource
import com.sphereon.core.api.session.SessionScopeResolutionTelemetry
import com.sphereon.core.api.session.SessionScopeTelemetry
import com.sphereon.di.context.AnonymousUserGraphManager
import com.sphereon.di.context.IdentityConstants
import com.sphereon.di.context.SecuredTenantContextDetails
import com.sphereon.di.context.PrincipalType
import com.sphereon.di.context.UserContext
import com.sphereon.di.context.UserContextInstance
import com.sphereon.di.context.UserContextManager
import com.sphereon.di.context.UserScope
import com.sphereon.di.context.createAnonymousSessionContext
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionContextManager
import com.sphereon.di.session.SessionGraph
import com.sphereon.di.session.SessionInstance
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.atomicfu.AtomicRef
import kotlinx.atomicfu.atomic
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import software.amazon.app.platform.scope.Scope
import software.amazon.app.platform.scope.Scoped
import software.amazon.app.platform.scope.coroutine.addCoroutineScopeScoped
import software.amazon.app.platform.scope.di.metro.addMetroDependencyGraph
import software.amazon.app.platform.scope.register
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

@Inject
@SingleIn(UserScope::class)
@ContributesBinding(UserScope::class, binding = binding<SessionContextManager>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("SessionContextManagerImpl", exact = true)
class SessionContextManagerImpl(
    private val sessionGraphFactory: SessionGraph.Factory,
    val userContextManager: UserContextManager,
    private val userContextInstance: UserContextInstance,
    private val anonymousUserGraphManager: AnonymousUserGraphManager,
    userContextLogManager: UserContextLogManager,
    private val sessionScopeTelemetry: SessionScopeTelemetry? = null,
) : SynchronizedObject(),
    SessionContextManager {
    private val log = userContextLogManager.withTag("SessionContextManager")

    private fun startTiming(
        source: SessionScopeResolutionSource,
        makeActive: Boolean,
        secureDetailsPresent: Boolean,
        initialElapsedUs: Long = 0L,
    ): SessionScopeTimingAttempt =
        SessionScopeTimingAttempt(
            source = source,
            telemetry = runCatching {
                sessionScopeTelemetry?.startResolution(source, secureDetailsPresent, makeActive)
            }.getOrNull(),
            emitLog = { message -> log.info(message) },
            initialElapsedUs = initialElapsedUs,
        )

    // Active instance tracking (atomic reference for thread-safe reads)
    private val activeInstanceRef: AtomicRef<SessionInstance?> = atomic(null)

    // StateFlow that mirrors activeInstanceRef for reactive observation
    private val _activeInstance = MutableStateFlow<SessionInstance?>(null)

    /**
     * Reactive flow of the active session instance.
     * Emits whenever the active session changes.
     */
    override val activeInstance: StateFlow<SessionInstance?> = _activeInstance.asStateFlow()

    // Internal map for management (stores all sessions for this user/tenant context)
    // Using AtomicRef instead of MutableStateFlow for better thread-safety
    private val instances: AtomicRef<Map<String, SessionInstance>> = atomic(emptyMap())

    // Primary access method - always returns instance (anonymous if map empty)
    override fun getActive(): SessionInstance {
        // Fast path: lock-free read
        activeInstanceRef.value?.let { return it }

        // No active session - return the anonymous session (always from anonymous user graph)
        return getOrCreateAnonymousSessionInternal(false)
    }

    override fun hasActive(): Boolean {
        val current = activeInstanceRef.value
        return current != null && current.sessionId != ANONYMOUS_SESSION_ID
    }

    // Instance-based access (primary approach) - with makeActive capability
    // Ensures session uniqueness: the same session ID always returns the same instance within this user/tenant scope
    override fun getById(
        sessionId: String,
        makeActive: Boolean,
    ): SessionInstance? {
        // Read the atomic value once
        val currentInstances = instances.value
        val existingInstance = currentInstances[sessionId]

        if (existingInstance != null && makeActive) {
            setActiveInstance(existingInstance)
        }

        return existingInstance
    }

    override fun hasById(sessionId: String): Boolean = instances.value.containsKey(sessionId)

    // Session switching (updates flows)
    override fun activateById(sessionId: String): Boolean {
        // Read the atomic value once
        val currentInstances = instances.value
        val instance = currentInstances[sessionId]
        return if (instance != null) {
            setActiveInstance(instance)
            true
        } else {
            false
        }
    }

    // Session listing
    override fun listIds(): Set<String> = instances.value.keys

    // Session creation (returns instances)
    override fun createOrGetFromCallbacks(sessionContextProvider: () -> SessionContext): SessionInstance {
        val timing = startTiming(SessionScopeResolutionSource.CALLBACKS, makeActive = true, secureDetailsPresent = false)
        val runtimeSessionContext =
            try {
                timing.measure(SessionScopeResolutionPhase.SESSION_CONTEXT_CREATION) { sessionContextProvider() }
            } catch (failure: Throwable) {
                timing.complete(SessionScopeResolutionOutcome.FAILURE, failure)
                throw failure
            }
        timing.setSecureDetailsPresent(runtimeSessionContext.context.secureDetails != null)
        val sessionId = runtimeSessionContext.sessionId
        return getOrCreateSessionInternal(
            sessionId = sessionId,
            sessionContext = runtimeSessionContext,
            correlationId = runtimeSessionContext.correlationId,
            makeActive = true,
            secureDetails = runtimeSessionContext.context.secureDetails,
            principalType = runtimeSessionContext.context.principalType,
            source = SessionScopeResolutionSource.CALLBACKS,
            timingAttempt = timing,
        ).instance
    }

    override fun createOrGetFromId(
        sessionId: String,
        correlationId: String,
        makeActive: Boolean,
        secureDetails: SecuredTenantContextDetails?,
        principalType: PrincipalType,
    ): SessionInstance {
        requireNotNull(sessionId) { "sessionId must not be null" }
        return getOrCreateSessionInternal(
            sessionId = sessionId,
            sessionContext = null,
            correlationId = correlationId,
            makeActive = makeActive,
            secureDetails = secureDetails,
            principalType = principalType,
            source = SessionScopeResolutionSource.ID_SECURE_IDENTITY,
        ).instance
    }

    // Session cleanup
    override fun destroyById(sessionId: String) {
        val destroyed =
            synchronized(this) {
                // Read the atomic value once
                val currentInstances = instances.value
                val instance = currentInstances[sessionId]
                if (instance != null) {
                    val destructionStarted = kotlin.time.TimeSource.Monotonic.markNow()
                    val destructionTelemetry = runCatching { sessionScopeTelemetry?.startDestruction() }.getOrNull()
                    val parentScope = runCatching { instance.scope.parent }.getOrNull()
                    val parentChildrenBefore = parentScope?.let { parent -> runCatching { parent.children().size }.getOrNull() }

                    // Remove from map first
                    instances.value = currentInstances - sessionId

                    // Clear active if this was the active session
                    val currentActive = activeInstanceRef.value
                    if (currentActive?.sessionId == sessionId) {
                        setActiveInstance(null)
                    }

                    // Destroy scope last
                    log.debug(
                        "VDX_SESSION_SCOPE_DESTROY_START sessionId=${sessionId.sanitizeLogToken()} " +
                            "contextId=${userContextInstance.contextId.sanitizeLogToken()} " +
                            "remainingSessions=${instances.value.size} parentChildrenBefore=${parentChildrenBefore ?: "unknown"}",
                    )
                    runCatching { instance.scope.destroy() }
                        .onSuccess {
                            val parentChildrenAfter = parentScope?.let { parent -> runCatching { parent.children().size }.getOrNull() }
                            log.debug(
                                "VDX_SESSION_SCOPE_DESTROYED sessionId=${sessionId.sanitizeLogToken()} " +
                                    "contextId=${userContextInstance.contextId.sanitizeLogToken()} " +
                                    "remainingSessions=${instances.value.size} parentChildrenAfter=${parentChildrenAfter ?: "unknown"}",
                            )
                        }.onFailure { error ->
                            completeDestructionTiming(destructionStarted, destructionTelemetry, success = false, failure = error)
                            log.warn(
                                "VDX_SESSION_SCOPE_DESTROY_FAILED sessionId=${sessionId.sanitizeLogToken()} " +
                                    "contextId=${userContextInstance.contextId.sanitizeLogToken()} " +
                                    "remainingSessions=${instances.value.size} error=${error.message?.sanitizeLogToken() ?: error::class.simpleName}",
                            )
                            throw error
                        }
                    completeDestructionTiming(destructionStarted, destructionTelemetry, success = true)
                    true
                } else {
                    false
                }
            }
        if (!destroyed) {
            log.debug(
                "VDX_SESSION_SCOPE_DESTROY_SKIPPED sessionId=${sessionId.sanitizeLogToken()} " +
                    "contextId=${userContextInstance.contextId.sanitizeLogToken()} reason=not-found",
            )
        }
    }

    override fun destroyAll() {
        val instancesToDestroy =
            synchronized(this) {
                val instancesToDestroy = instances.value.values.toList()

                // Clear all state first
                instances.value = emptyMap()
                setActiveInstance(null)

                instancesToDestroy
            }

        instancesToDestroy.forEach { instance ->
            val destructionStarted = kotlin.time.TimeSource.Monotonic.markNow()
            val destructionTelemetry = runCatching { sessionScopeTelemetry?.startDestruction() }.getOrNull()
            val parentScope = runCatching { instance.scope.parent }.getOrNull()
            val parentChildrenBefore = parentScope?.let { parent -> runCatching { parent.children().size }.getOrNull() }
            log.debug(
                "VDX_SESSION_SCOPE_DESTROY_START sessionId=${instance.sessionId.sanitizeLogToken()} " +
                    "contextId=${userContextInstance.contextId.sanitizeLogToken()} remainingSessions=0 " +
                    "parentChildrenBefore=${parentChildrenBefore ?: "unknown"} reason=destroy-all",
            )
            // Same monitor as session creation: destroying removes the scope from the context's child set.
            runCatching { synchronized(this) { instance.scope.destroy() } }
                .onSuccess {
                    val parentChildrenAfter = parentScope?.let { parent -> runCatching { parent.children().size }.getOrNull() }
                    log.debug(
                        "VDX_SESSION_SCOPE_DESTROYED sessionId=${instance.sessionId.sanitizeLogToken()} " +
                            "contextId=${userContextInstance.contextId.sanitizeLogToken()} remainingSessions=0 " +
                            "parentChildrenAfter=${parentChildrenAfter ?: "unknown"} reason=destroy-all",
                    )
                }.onFailure { error ->
                    completeDestructionTiming(destructionStarted, destructionTelemetry, success = false, failure = error)
                    log.warn(
                        "VDX_SESSION_SCOPE_DESTROY_FAILED sessionId=${instance.sessionId.sanitizeLogToken()} " +
                            "contextId=${userContextInstance.contextId.sanitizeLogToken()} remainingSessions=0 " +
                            "error=${error.message?.sanitizeLogToken() ?: error::class.simpleName} reason=destroy-all",
                    )
                    throw error
                }
            completeDestructionTiming(destructionStarted, destructionTelemetry, success = true)
        }
    }

    // Special session types - return instances (convenience methods)
    override fun getOrCreateBackgroundService(makeActive: Boolean): SessionInstance {
        // Background sessions are ALWAYS created in the background service graph's scope
        val contextScopeStarted = kotlin.time.TimeSource.Monotonic.markNow()
        val backgroundGraph = anonymousUserGraphManager.getBackgroundGraph()
        val backgroundScope = backgroundGraph.instance.scope
        val backgroundSessionManager = backgroundGraph.sessionContextManager

        // Only the owning manager emits the resolution operation.
        if (this !== backgroundSessionManager) {
            return backgroundSessionManager.getOrCreateBackgroundService(false)
        }
        val initialContextScopeUs = contextScopeStarted.elapsedNow().inWholeMicroseconds
        val timing =
            startTiming(
                SessionScopeResolutionSource.BACKGROUND,
                makeActive = false,
                secureDetailsPresent = false,
                initialElapsedUs = initialContextScopeUs,
            )
        timing.recordPhase(
            SessionScopeResolutionPhase.CONTEXT_SCOPE_RESOLUTION,
            initialContextScopeUs,
        )

        // First check if it's already created (fast path)
        val existingInstance =
            timing.measure(SessionScopeResolutionPhase.CONTEXT_SCOPE_RESOLUTION) {
                backgroundSessionManager.getById(ANONYMOUS_SESSION_ID)
            }
        if (existingInstance != null) {
            logSessionReused(
                sessionId = ANONYMOUS_SESSION_ID,
                source = "background",
                makeActive = false,
                secureDetailsPresent = false,
            )
            // Background service can never be made active
            timing.complete(SessionScopeResolutionOutcome.REUSE)
            return existingInstance
        }

        // We ARE the background session manager, create the session with synchronization
        return try {
            synchronized(this) {
                // Double-check after acquiring lock - read atomic value once
                val currentInstances =
                    timing.measure(SessionScopeResolutionPhase.CONTEXT_SCOPE_RESOLUTION) { instances.value }
                val existing = currentInstances[ANONYMOUS_SESSION_ID]
                if (existing != null) {
                    timing.complete(SessionScopeResolutionOutcome.REUSE)
                    return existing
                }

                ConfigBootstrapGuard.withContextRegistration {
                    val backgroundCorrelationId = IdentityConstants.ANONYMOUS_ID
                    val anonymousSessionContext =
                        timing.measure(SessionScopeResolutionPhase.SESSION_CONTEXT_CREATION) {
                            createAnonymousSessionContext(ANONYMOUS_SESSION_ID, backgroundCorrelationId)
                        }
                    val sessionGraph =
                        timing.measure(SessionScopeResolutionPhase.METRO_GRAPH_CREATION) {
                            sessionGraphFactory.createSessionGraph(ANONYMOUS_SESSION_ID, backgroundCorrelationId)
                        }
                    val parentChildrenBefore = runCatching { backgroundScope.children().size }.getOrNull()
                    logSessionCreateStart(
                        sessionId = ANONYMOUS_SESSION_ID,
                        source = SessionScopeResolutionSource.BACKGROUND.value,
                        makeActive = false,
                        secureDetailsPresent = false,
                        retainedSessionsBefore = currentInstances.size,
                        parentChildrenBefore = parentChildrenBefore,
                    )

                    val scope =
                        timing.measure(SessionScopeResolutionPhase.SCOPE_CREATION) {
                            backgroundScope.buildChild("session:$ANONYMOUS_SESSION_ID") {
                                addMetroDependencyGraph(sessionGraph)
                                addService("sessionContext", anonymousSessionContext)
                                addCoroutineScopeScoped(sessionGraph.sessionScopeCoroutineScopeScoped)
                            }
                        }

                    // Initialize the instance with its graph and scope.
                    val instance =
                        timing.measure(SessionScopeResolutionPhase.SESSION_INSTANCE_INITIALIZATION) {
                            sessionGraph.instance.also { resolvedInstance ->
                                (resolvedInstance as? SessionInstanceImpl)?.initialize(sessionGraph, scope)
                            }
                        }

                    // Store the instance atomically.
                    instances.value = currentInstances + (ANONYMOUS_SESSION_ID to instance)

                    // Background service can never be made active (no need to set activeInstanceRef).

                    materializeAndRegisterScopedInstances(
                        timing = timing,
                        materialize = { sessionGraph.sessionScopedInstances },
                        register = { instances -> scope.register(instances) },
                    )
                    logSessionCreated(
                        sessionId = ANONYMOUS_SESSION_ID,
                        source = SessionScopeResolutionSource.BACKGROUND.value,
                        makeActive = false,
                        secureDetailsPresent = false,
                        retainedSessionsAfter = instances.value.size,
                        parentChildrenAfter = runCatching { backgroundScope.children().size }.getOrNull(),
                    )

                    timing.complete(SessionScopeResolutionOutcome.CREATE)
                    instance
                }
            }
        } catch (failure: Throwable) {
            timing.complete(SessionScopeResolutionOutcome.FAILURE, failure)
            throw failure
        }
    }

    override fun getAnonymous(makeActive: Boolean): SessionInstance = getOrCreateAnonymousSessionInternal(makeActive)

    override fun getBackgroundServiceId(): String = ANONYMOUS_SESSION_ID

    // Private helper methods
    private fun getOrCreateAnonymousSessionInternal(makeActive: Boolean): SessionInstance {
        // Anonymous sessions are ALWAYS created in the anonymous user graph's scope
        val contextScopeStarted = kotlin.time.TimeSource.Monotonic.markNow()
        val anonymousUserGraph = anonymousUserGraphManager.getAnonymousGraph()
        val anonymousScope = anonymousUserGraph.instance.scope
        val anonymousSessionManager = anonymousUserGraph.sessionContextManager

        // Only the owning manager emits the resolution operation.
        if (this !== anonymousSessionManager) {
            return anonymousSessionManager.getAnonymous(false)
        }
        val initialContextScopeUs = contextScopeStarted.elapsedNow().inWholeMicroseconds
        val timing =
            startTiming(
                SessionScopeResolutionSource.ANONYMOUS,
                makeActive,
                secureDetailsPresent = false,
                initialElapsedUs = initialContextScopeUs,
            )
        timing.recordPhase(
            SessionScopeResolutionPhase.CONTEXT_SCOPE_RESOLUTION,
            initialContextScopeUs,
        )

        // First check if it's already created (fast path)
        val existingInstance =
            timing.measure(SessionScopeResolutionPhase.CONTEXT_SCOPE_RESOLUTION) {
                anonymousSessionManager.getById(ANONYMOUS_SESSION_ID)
            }
        if (existingInstance != null) {
            logSessionReused(
                sessionId = ANONYMOUS_SESSION_ID,
                source = "anonymous",
                makeActive = makeActive,
                secureDetailsPresent = false,
            )
            if (makeActive && this === anonymousSessionManager) {
                setActiveInstance(existingInstance)
            }
            timing.complete(SessionScopeResolutionOutcome.REUSE)
            return existingInstance
        }

        // We ARE the anonymous session manager, create the session with synchronization
        return try {
            synchronized(this) {
                // Double-check after acquiring lock - read atomic value once
                val currentInstances =
                    timing.measure(SessionScopeResolutionPhase.CONTEXT_SCOPE_RESOLUTION) { instances.value }
                val existing = currentInstances[ANONYMOUS_SESSION_ID]
                if (existing != null) {
                    timing.measure(SessionScopeResolutionPhase.CONTEXT_SCOPE_RESOLUTION) {
                        if (makeActive) {
                            setActiveInstance(existing)
                        }
                    }
                    timing.complete(SessionScopeResolutionOutcome.REUSE)
                    return existing
                }

                ConfigBootstrapGuard.withContextRegistration {
                    val anonymousCorrelationId = IdentityConstants.ANONYMOUS_ID
                    val anonymousSessionContext =
                        timing.measure(SessionScopeResolutionPhase.SESSION_CONTEXT_CREATION) {
                            createAnonymousSessionContext(ANONYMOUS_SESSION_ID, anonymousCorrelationId)
                        }
                    val sessionGraph =
                        timing.measure(SessionScopeResolutionPhase.METRO_GRAPH_CREATION) {
                            sessionGraphFactory.createSessionGraph(ANONYMOUS_SESSION_ID, anonymousCorrelationId)
                        }
                    val parentChildrenBefore = runCatching { anonymousScope.children().size }.getOrNull()
                    logSessionCreateStart(
                        sessionId = ANONYMOUS_SESSION_ID,
                        source = SessionScopeResolutionSource.ANONYMOUS.value,
                        makeActive = makeActive,
                        secureDetailsPresent = false,
                        retainedSessionsBefore = currentInstances.size,
                        parentChildrenBefore = parentChildrenBefore,
                    )

                    val scope =
                        timing.measure(SessionScopeResolutionPhase.SCOPE_CREATION) {
                            anonymousScope.buildChild("session:$ANONYMOUS_SESSION_ID") {
                                addMetroDependencyGraph(sessionGraph)
                                addService("sessionContext", anonymousSessionContext)
                                addCoroutineScopeScoped(sessionGraph.sessionScopeCoroutineScopeScoped)
                            }
                        }

                    // Initialize the instance with its graph and scope.
                    val instance =
                        timing.measure(SessionScopeResolutionPhase.SESSION_INSTANCE_INITIALIZATION) {
                            sessionGraph.instance.also { resolvedInstance ->
                                (resolvedInstance as? SessionInstanceImpl)?.initialize(sessionGraph, scope)
                            }
                        }

                    // Store the instance atomically.
                    instances.value = currentInstances + (ANONYMOUS_SESSION_ID to instance)

                    // Set as active if requested.
                    if (makeActive) {
                        setActiveInstance(instance)
                    }

                    materializeAndRegisterScopedInstances(
                        timing = timing,
                        materialize = { sessionGraph.sessionScopedInstances },
                        register = { instances -> scope.register(instances) },
                    )
                    logSessionCreated(
                        sessionId = ANONYMOUS_SESSION_ID,
                        source = SessionScopeResolutionSource.ANONYMOUS.value,
                        makeActive = makeActive,
                        secureDetailsPresent = false,
                        retainedSessionsAfter = instances.value.size,
                        parentChildrenAfter = runCatching { anonymousScope.children().size }.getOrNull(),
                    )

                    timing.complete(SessionScopeResolutionOutcome.CREATE)
                    instance
                }
            }
        } catch (failure: Throwable) {
            timing.complete(SessionScopeResolutionOutcome.FAILURE, failure)
            throw failure
        }
    }

    private fun getOrCreateSessionInternal(
        sessionId: String,
        sessionContext: SessionContext?,
        correlationId: String,
        makeActive: Boolean,
        secureDetails: SecuredTenantContextDetails? = null,
        principalType: PrincipalType? = null,
        source: SessionScopeResolutionSource,
        timingAttempt: SessionScopeTimingAttempt? = null,
    ): SessionGraph {
        val timing = timingAttempt ?: startTiming(source, makeActive, secureDetails != null)
        // Fast-path: lock-free read if already created
        // Read the atomic value once to avoid multiple atomic reads
        val currentInstances =
            timing.measure(SessionScopeResolutionPhase.CONTEXT_SCOPE_RESOLUTION) { instances.value }
        val existing = currentInstances[sessionId]
        if (existing != null) {
            logSessionReused(
                sessionId = sessionId,
                source = source.value,
                makeActive = makeActive,
                secureDetailsPresent = secureDetails != null,
            )
            timing.measure(SessionScopeResolutionPhase.CONTEXT_SCOPE_RESOLUTION) {
                if (makeActive) {
                    setActiveInstance(existing)
                }
            }
            timing.complete(SessionScopeResolutionOutcome.REUSE)
            return existing.graph
        }

        // Slow path. Building a session graph and materializing its scoped instances can resolve
        // configuration, which may block on I/O or on a lock. None of that runs under this manager's
        // monitor: holding it there would stall every session creation in this context behind one
        // slow build. The monitor guards the registry and the context scope's child set, which is not
        // thread-safe: only the build that wins registration attaches its session scope, under it.
        return try {
            val built =
                ConfigBootstrapGuard.withContextRegistration {
                    buildSession(
                        sessionId = sessionId,
                        sessionContext = sessionContext,
                        correlationId = correlationId,
                        makeActive = makeActive,
                        secureDetails = secureDetails,
                        principalType = principalType,
                        source = source,
                        timing = timing,
                    )
                }
            var attachedScope: Scope? = null
            val registered =
                synchronized(this) {
                    val lockedInstances =
                        timing.measure(SessionScopeResolutionPhase.CONTEXT_SCOPE_RESOLUTION) { instances.value }
                    val winner =
                        lockedInstances[sessionId] ?: built.instance.also { instance ->
                            // Only the winner attaches a scope, so a losing build never enters the
                            // context scope's child set and has nothing to release.
                            val scope = timing.measure(SessionScopeResolutionPhase.SCOPE_CREATION) { built.attachScope() }
                            timing.measure(SessionScopeResolutionPhase.SESSION_INSTANCE_INITIALIZATION) {
                                (instance as? SessionInstanceImpl)?.initialize(built.sessionGraph, scope)
                            }
                            attachedScope = scope
                            instances.value = lockedInstances + (sessionId to instance)
                        }
                    if (makeActive) {
                        setActiveInstance(winner)
                    }
                    winner
                }
            val scope = attachedScope
            if (registered !== built.instance || scope == null) {
                // Another caller registered this session while this one was building. Keep theirs. This
                // build attached no scope, so nothing exits it: cancel its graph's session coroutine scope
                // here, outside the monitor, so nothing it launched keeps running.
                runCatching { built.sessionGraph.sessionScopeCoroutineScopeScoped.onExitScope() }
                    .onFailure { error ->
                        log.warn(
                            "VDX_SESSION_SCOPE_DUPLICATE_RELEASE_FAILED sessionId=${sessionId.sanitizeLogToken()} " +
                                "contextId=${userContextInstance.contextId.sanitizeLogToken()} " +
                                "error=${error.message?.sanitizeLogToken() ?: error::class.simpleName}",
                        )
                    }
                logSessionReused(
                    sessionId = sessionId,
                    source = source.value,
                    makeActive = makeActive,
                    secureDetailsPresent = secureDetails != null,
                )
                timing.complete(SessionScopeResolutionOutcome.REUSE)
                return registered.graph
            }

            // Materialization and registration are deliberately separate. Evaluating the Metro
            // property may construct contributed SessionScope objects; the exact materialized
            // collection is retained and passed once to registration. The session is already
            // registered, as before, so code that runs here can look it up.
            ConfigBootstrapGuard.withContextRegistration {
                materializeAndRegisterScopedInstances(
                    timing = timing,
                    materialize = { built.sessionGraph.sessionScopedInstances },
                    register = { scopedInstances -> scope.register(scopedInstances) },
                )
            }
            logSessionCreated(
                sessionId = sessionId,
                source = source.value,
                makeActive = makeActive,
                secureDetailsPresent = secureDetails != null,
                retainedSessionsAfter = instances.value.size,
                parentChildrenAfter = runCatching { built.contextScope.children().size }.getOrNull(),
            )

            timing.complete(SessionScopeResolutionOutcome.CREATE)
            built.sessionGraph
        } catch (failure: Throwable) {
            timing.complete(SessionScopeResolutionOutcome.FAILURE, failure)
            throw failure
        }
    }

    /**
     * Creates the session context, graph and instance. Runs without the manager's monitor. The session
     * scope is attached later, under the monitor, by the build that wins registration.
     */
    private fun buildSession(
        sessionId: String,
        sessionContext: SessionContext?,
        correlationId: String,
        makeActive: Boolean,
        secureDetails: SecuredTenantContextDetails?,
        principalType: PrincipalType?,
        source: SessionScopeResolutionSource,
        timing: SessionScopeTimingAttempt,
    ): BuiltSession {
        // Determine the correct scope for this session.
        val contextScope =
            timing.measure(SessionScopeResolutionPhase.CONTEXT_SCOPE_RESOLUTION) {
                when {
                    isBackgroundContext() -> anonymousUserGraphManager.getBackgroundGraph().instance.scope
                    isAnonymousContext() -> anonymousUserGraphManager.getAnonymousGraph().instance.scope
                    else -> getContextScope()
                }
            }
        val parentChildrenBefore = runCatching { contextScope.children().size }.getOrNull()
        logSessionCreateStart(
            sessionId = sessionId,
            source = source.value,
            makeActive = makeActive,
            secureDetailsPresent = secureDetails != null,
            retainedSessionsBefore = instances.value.size,
            parentChildrenBefore = parentChildrenBefore,
        )

        // Create the session context. Callback construction was timed by the caller.
        val actualSessionContext =
            sessionContext ?: timing.measure(SessionScopeResolutionPhase.SESSION_CONTEXT_CREATION) {
                if (sessionId == ANONYMOUS_SESSION_ID) {
                    createAnonymousSessionContext(sessionId, correlationId)
                } else {
                    SessionContextImpl(
                        context = userContextInstance.context,
                        sessionId = sessionId,
                        correlationId = correlationId,
                        secureDetails = secureDetails,
                        principalType = principalType,
                    )
                }
            }

        // Create the session graph and scope. The per-session secure details ride the
        // graph factory so the DI-resolved SessionContext (what SessionExecution sees)
        // carries the same credentials as the scope-service copy above.
        val sessionGraph =
            timing.measure(SessionScopeResolutionPhase.METRO_GRAPH_CREATION) {
                sessionGraphFactory.createSessionGraph(
                    sessionId,
                    actualSessionContext.correlationId,
                    secureDetails,
                    principalType,
                )
            }
        val instance = timing.measure(SessionScopeResolutionPhase.SESSION_INSTANCE_INITIALIZATION) { sessionGraph.instance }
        return BuiltSession(sessionId, contextScope, sessionGraph, actualSessionContext, instance)
    }

    private class BuiltSession(
        val sessionId: String,
        val contextScope: Scope,
        val sessionGraph: SessionGraph,
        val sessionContext: SessionContext,
        val instance: SessionInstance,
    ) {
        /** Adds the session scope to the context scope's child set. Call only under the manager's monitor. */
        fun attachScope(): Scope =
            contextScope.buildChild("session:$sessionId") {
                addMetroDependencyGraph(sessionGraph)
                addService("sessionContext", sessionContext)
                addCoroutineScopeScoped(sessionGraph.sessionScopeCoroutineScopeScoped)
            }
    }

    /**
     * Sets the active instance atomically and updates the flow.
     * This ensures both the atomic reference and the StateFlow are kept in sync.
     */
    private fun setActiveInstance(instance: SessionInstance?) {
        activeInstanceRef.value = instance
        _activeInstance.value = instance
    }

    private fun completeDestructionTiming(
        started: kotlin.time.TimeMark,
        telemetry: com.sphereon.core.api.session.SessionScopeDestructionTelemetry?,
        success: Boolean,
        failure: Throwable? = null,
    ) {
        val totalUs = started.elapsedNow().inWholeMicroseconds.coerceAtLeast(0)
        runCatching { telemetry?.complete(success, totalUs, failure) }
        log.info("VDX_SESSION_SCOPE_DESTROY_TIMING outcome=${if (success) "success" else "failure"} totalUs=$totalUs")
    }

    private fun logSessionCreateStart(
        sessionId: String,
        source: String,
        makeActive: Boolean,
        secureDetailsPresent: Boolean,
        retainedSessionsBefore: Int,
        parentChildrenBefore: Int?,
    ) {
        log.debug(
            "VDX_SESSION_SCOPE_CREATE_START sessionId=${sessionId.sanitizeLogToken()} " +
                "contextId=${userContextInstance.contextId.sanitizeLogToken()} source=${source.sanitizeLogToken()} " +
                "makeActive=$makeActive secureDetails=$secureDetailsPresent retainedSessionsBefore=$retainedSessionsBefore " +
                "parentChildrenBefore=${parentChildrenBefore ?: "unknown"}",
        )
    }

    private fun logSessionCreated(
        sessionId: String,
        source: String,
        makeActive: Boolean,
        secureDetailsPresent: Boolean,
        retainedSessionsAfter: Int,
        parentChildrenAfter: Int?,
    ) {
        log.debug(
            "VDX_SESSION_SCOPE_CREATED sessionId=${sessionId.sanitizeLogToken()} " +
                "contextId=${userContextInstance.contextId.sanitizeLogToken()} source=${source.sanitizeLogToken()} " +
                "makeActive=$makeActive secureDetails=$secureDetailsPresent retainedSessionsAfter=$retainedSessionsAfter " +
                "parentChildrenAfter=${parentChildrenAfter ?: "unknown"}",
        )
    }

    private fun logSessionReused(
        sessionId: String,
        source: String,
        makeActive: Boolean,
        secureDetailsPresent: Boolean,
    ) {
        log.trace(
            "VDX_SESSION_SCOPE_REUSED sessionId=${sessionId.sanitizeLogToken()} " +
                "contextId=${userContextInstance.contextId.sanitizeLogToken()} source=${source.sanitizeLogToken()} " +
                "makeActive=$makeActive secureDetails=$secureDetailsPresent retainedSessions=${instances.value.size}",
        )
    }

    // Get the context scope from the active user context
    private fun getContextScope(): Scope = userContextInstance.scope

    // Check if we're in a background context
    private fun isBackgroundContext(): Boolean = userContextInstance.contextId == UserContext.BACKGROUND_SERVICE

    // Check if we're in an anonymous context
    private fun isAnonymousContext(): Boolean = userContextInstance.contextId == UserContext.ANONYMOUS

    companion object {
        const val ANONYMOUS_SESSION_ID = IdentityConstants.ANONYMOUS_SESSION_ID
    }
}

private fun String.sanitizeLogToken(): String =
    trim()
        .ifBlank { "<blank>" }
        .replace(Regex("[^A-Za-z0-9._:@-]"), "_")
        .take(160)

internal fun interface SessionScopeMonotonicClock {
    fun nowUs(): Long
}

internal fun <T : Scoped> materializeAndRegisterScopedInstances(
    timing: SessionScopeTimingAttempt,
    materialize: () -> Set<T>,
    register: (Set<T>) -> Unit,
): Set<T> {
    val materializedInstances =
        timing.measure(SessionScopeResolutionPhase.SCOPED_INSTANCE_MATERIALIZATION, materialize)
    timing.setMaterializedInstanceCount(materializedInstances.size)
    timing.measure(SessionScopeResolutionPhase.SCOPED_INSTANCE_REGISTRATION) {
        register(materializedInstances)
    }
    return materializedInstances
}

private object DefaultSessionScopeMonotonicClock : SessionScopeMonotonicClock {
    private val origin = kotlin.time.TimeSource.Monotonic.markNow()

    override fun nowUs(): Long = origin.elapsedNow().inWholeMicroseconds
}

internal class SessionScopeTimingAttempt(
    private val source: SessionScopeResolutionSource,
    private val telemetry: SessionScopeResolutionTelemetry?,
    private val emitLog: (String) -> Unit,
    private val clock: SessionScopeMonotonicClock = DefaultSessionScopeMonotonicClock,
    private val initialElapsedUs: Long = 0L,
) {
    private val startedUs = clock.nowUs()
    private val phasesUs = linkedMapOf<SessionScopeResolutionPhase, Long>()
    private var materializedInstanceCount = 0
    private var completed = false

    fun <T> measure(phase: SessionScopeResolutionPhase, block: () -> T): T {
        val phaseStartedUs = clock.nowUs()
        try {
            return block()
        } finally {
            recordPhase(phase, clock.nowUs() - phaseStartedUs)
        }
    }

    fun recordPhase(phase: SessionScopeResolutionPhase, durationUs: Long) {
        if (completed) return
        val boundedDuration = durationUs.coerceAtLeast(0)
        phasesUs[phase] = (phasesUs[phase] ?: 0L) + boundedDuration
        runCatching { telemetry?.recordPhase(phase, boundedDuration) }
    }

    fun setMaterializedInstanceCount(count: Int) {
        materializedInstanceCount = count.coerceAtLeast(0)
        runCatching { telemetry?.setMaterializedInstanceCount(materializedInstanceCount) }
    }

    fun setSecureDetailsPresent(present: Boolean) {
        runCatching { telemetry?.setSecureDetailsPresent(present) }
    }

    fun complete(outcome: SessionScopeResolutionOutcome, failure: Throwable? = null) {
        if (completed) return
        completed = true
        val totalUs = initialElapsedUs.coerceAtLeast(0) + (clock.nowUs() - startedUs).coerceAtLeast(0)
        runCatching {
            emitLog(
                "VDX_SESSION_SCOPE_TIMING " +
                    "outcome=${outcome.value} source=${source.value} totalUs=$totalUs " +
                    "contextScopeUs=${phase(SessionScopeResolutionPhase.CONTEXT_SCOPE_RESOLUTION)} " +
                    "sessionContextUs=${phase(SessionScopeResolutionPhase.SESSION_CONTEXT_CREATION)} " +
                    "metroGraphUs=${phase(SessionScopeResolutionPhase.METRO_GRAPH_CREATION)} " +
                    "scopeCreationUs=${phase(SessionScopeResolutionPhase.SCOPE_CREATION)} " +
                    "instanceInitializationUs=${phase(SessionScopeResolutionPhase.SESSION_INSTANCE_INITIALIZATION)} " +
                    "scopedInstancesMaterializationUs=${phase(SessionScopeResolutionPhase.SCOPED_INSTANCE_MATERIALIZATION)} " +
                    "scopedInstancesRegistrationUs=${phase(SessionScopeResolutionPhase.SCOPED_INSTANCE_REGISTRATION)} " +
                "materializedInstanceCount=$materializedInstanceCount",
            )
        }
        runCatching { telemetry?.complete(outcome, totalUs, failure) }
    }

    internal fun recordedPhases(): Map<SessionScopeResolutionPhase, Long> = phasesUs.toMap()

    private fun phase(phase: SessionScopeResolutionPhase): Long = phasesUs[phase] ?: 0L
}
