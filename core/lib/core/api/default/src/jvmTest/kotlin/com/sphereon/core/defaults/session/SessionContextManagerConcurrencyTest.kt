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

package com.sphereon.core.defaults.session

import com.sphereon.core.api.testutil.createCoreApiTestAppGraph
import com.sphereon.core.defaults.context.DefaultPrincipalInputString
import com.sphereon.core.defaults.context.DefaultTenantInputString
import com.sphereon.di.app.AppGraph
import com.sphereon.di.context.AnonymousUserGraphManager
import com.sphereon.di.context.PrincipalType
import com.sphereon.di.context.SecuredTenantContextDetails
import com.sphereon.di.context.UserContextInstance
import com.sphereon.di.session.SessionGraph
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.isActive

class SessionContextManagerConcurrencyTest {
    @Test
    fun aBlockedSessionBuildDoesNotBlockCreatingAnotherSession() {
        val appGraph = createCoreApiTestAppGraph(this, "session-manager-concurrency-test", "test-profile", "0.0.1-TEST")
        val pool = Executors.newFixedThreadPool(2)
        val slowBuildEntered = CountDownLatch(1)
        val releaseSlowBuild = CountDownLatch(1)
        try {
            val userContextInstance = userContext(appGraph)
            val manager =
                manager(appGraph, userContextInstance) { sessionId ->
                    if (sessionId == SLOW_SESSION_ID) {
                        slowBuildEntered.countDown()
                        releaseSlowBuild.await(30, TimeUnit.SECONDS)
                    }
                }

            val slow = pool.submit(Callable { manager.createOrGetFromId(SLOW_SESSION_ID, principalType = PrincipalType.USER) })
            assertTrue(slowBuildEntered.await(5, TimeUnit.SECONDS))

            val other = pool.submit(Callable { manager.createOrGetFromId(OTHER_SESSION_ID, principalType = PrincipalType.USER) })
            val otherInstance =
                try {
                    other.get(5, TimeUnit.SECONDS)
                } catch (_: TimeoutException) {
                    null
                }
            releaseSlowBuild.countDown()

            assertNotNull(otherInstance, "a blocked session build held up creating an unrelated session")
            assertEquals(OTHER_SESSION_ID, otherInstance.sessionId)
            assertEquals(SLOW_SESSION_ID, slow.get(10, TimeUnit.SECONDS).sessionId)
            assertEquals(setOf(SLOW_SESSION_ID, OTHER_SESSION_ID), manager.listIds())
        } finally {
            releaseSlowBuild.countDown()
            pool.shutdownNow()
            appGraph.destroy()
        }
    }

    @Test
    fun concurrentCreationOfOneSessionKeepsOneInstanceAndDestroysTheOther() {
        val appGraph = createCoreApiTestAppGraph(this, "session-manager-race-test", "test-profile", "0.0.1-TEST")
        val pool = Executors.newFixedThreadPool(2)
        // Both builds must be in progress at the same time, so both reach the insert.
        val bothBuilding = CyclicBarrier(2)
        try {
            val userContextInstance = userContext(appGraph)
            val manager =
                manager(appGraph, userContextInstance) { sessionId ->
                    if (sessionId == RACED_SESSION_ID) bothBuilding.await(5, TimeUnit.SECONDS)
                }

            val first = pool.submit(Callable { manager.createOrGetFromId(RACED_SESSION_ID, principalType = PrincipalType.USER) })
            val second = pool.submit(Callable { manager.createOrGetFromId(RACED_SESSION_ID, principalType = PrincipalType.USER) })
            val firstInstance = first.get(10, TimeUnit.SECONDS)
            val secondInstance = second.get(10, TimeUnit.SECONDS)

            assertSame(firstInstance, secondInstance)
            assertSame(firstInstance, manager.getById(RACED_SESSION_ID))
            val liveSessionScopes =
                userContextInstance.scope.children().filter { it.name == "session:$RACED_SESSION_ID" && !it.isDestroyed() }
            assertEquals(1, liveSessionScopes.size, "the losing session build must be destroyed")
        } finally {
            pool.shutdownNow()
            appGraph.destroy()
        }
    }

    @Test
    fun aLosingConcurrentBuildCancelsTheCoroutineScopeOfItsGraph() {
        val appGraph = createCoreApiTestAppGraph(this, "session-manager-loser-test", "test-profile", "0.0.1-TEST")
        val pool = Executors.newFixedThreadPool(2)
        val bothBuilding = CyclicBarrier(2)
        val builtGraphs = java.util.concurrent.CopyOnWriteArrayList<SessionGraph>()
        try {
            val userContextInstance = userContext(appGraph)
            val manager =
                manager(appGraph, userContextInstance, onBuilt = { graph -> builtGraphs += graph }) { sessionId ->
                    if (sessionId == RACED_SESSION_ID) bothBuilding.await(5, TimeUnit.SECONDS)
                }

            val first = pool.submit(Callable { manager.createOrGetFromId(RACED_SESSION_ID, principalType = PrincipalType.USER) })
            val second = pool.submit(Callable { manager.createOrGetFromId(RACED_SESSION_ID, principalType = PrincipalType.USER) })
            val winner = first.get(10, TimeUnit.SECONDS)
            assertSame(winner, second.get(10, TimeUnit.SECONDS))

            assertEquals(2, builtGraphs.size)
            val loser = builtGraphs.single { it !== winner.graph }
            assertTrue(!loser.sessionScopeCoroutineScopeScoped.isActive, "the losing build's session coroutine scope must be cancelled")
            assertTrue(winner.graph.sessionScopeCoroutineScopeScoped.isActive, "the registered session keeps its coroutine scope")
        } finally {
            pool.shutdownNow()
            appGraph.destroy()
        }
    }

    @Test
    fun concurrentSessionChurnLeavesAContextScopeThatDestroys() {
        val appGraph = createCoreApiTestAppGraph(this, "session-manager-churn-test", "test-profile", "0.0.1-TEST")
        val pool = Executors.newFixedThreadPool(CHURN_THREADS)
        val start = CyclicBarrier(CHURN_THREADS)
        try {
            val userContextInstance = userContext(appGraph)
            val manager = manager(appGraph, userContextInstance) {}
            val workers =
                (0 until CHURN_THREADS).map { worker ->
                    pool.submit(
                        Callable {
                            start.await(5, TimeUnit.SECONDS)
                            repeat(CHURN_ROUNDS) { round ->
                                val sessionId = "churn-$worker-$round"
                                manager.createOrGetFromId(sessionId, principalType = PrincipalType.USER)
                                manager.destroyById(sessionId)
                            }
                        },
                    )
                }
            workers.forEach { it.get(120, TimeUnit.SECONDS) }
            assertTrue(manager.listIds().none { it.startsWith("churn-") })
        } finally {
            pool.shutdownNow()
        }
        // A context scope whose child set was mutated concurrently can keep a destroyed session scope,
        // and destroying the app then spins forever. Destroy on a daemon thread so a regression fails
        // this test instead of hanging the test JVM.
        val destroyer = Thread({ appGraph.destroy() }, "session-churn-destroy").apply { isDaemon = true; start() }
        destroyer.join(30_000)
        assertTrue(!destroyer.isAlive, "destroying the app after concurrent session churn did not finish")
    }

    private fun userContext(appGraph: AppGraph): UserContextInstance =
        appGraph.userContextManager.createOrGetFromInputs(
            DefaultTenantInputString("test-tenant"),
            DefaultPrincipalInputString("test-user"),
        )

    /** A manager whose session graph builds first run [beforeBuild], to stall or synchronize them. */
    private fun manager(
        appGraph: AppGraph,
        userContextInstance: UserContextInstance,
        onBuilt: (SessionGraph) -> Unit = {},
        beforeBuild: (String) -> Unit,
    ): SessionContextManagerImpl {
        val delegate = userContextInstance.graph as SessionGraph.Factory
        val factory =
            object : SessionGraph.Factory {
                override fun createSessionGraph(
                    sessionId: String,
                    correlationId: String,
                    secureDetails: SecuredTenantContextDetails?,
                    principalType: PrincipalType?,
                ): SessionGraph {
                    beforeBuild(sessionId)
                    return delegate.createSessionGraph(sessionId, correlationId, secureDetails, principalType).also(onBuilt)
                }
            }
        return SessionContextManagerImpl(
            sessionGraphFactory = factory,
            userContextManager = appGraph.userContextManager,
            userContextInstance = userContextInstance,
            anonymousUserGraphManager = (appGraph as AnonymousUserGraphManager.Graph).anonymousUserGraphManager,
            userContextLogManager = userContextInstance.graph.logManager,
        )
    }

    private companion object {
        const val SLOW_SESSION_ID = "slow-session"
        const val OTHER_SESSION_ID = "other-session"
        const val RACED_SESSION_ID = "raced-session"
        const val CHURN_THREADS = 16
        const val CHURN_ROUNDS = 3000
    }
}
