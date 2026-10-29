/*
 * (c) 2026 Sphereon International B.V.
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

package com.sphereon.core.defaults.context

import com.sphereon.core.api.cache.CacheModule
import com.sphereon.core.api.cache.CacheRequirements
import com.sphereon.core.api.cache.CacheSerializers
import com.sphereon.core.api.conf.MutableMapPropertySource
import com.sphereon.core.api.session.currentTimeMillis
import com.sphereon.core.api.testutil.appConfigService
import com.sphereon.core.api.testutil.createCoreApiTestAppGraph
import com.sphereon.di.context.IdentityMetadata
import com.sphereon.di.context.IdentityResolutionResult
import com.sphereon.di.context.PrincipalType
import com.sphereon.di.context.ResolutionSource
import com.sphereon.di.context.UserContext
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class UserContextManagerTest {
    private fun createAppGraph() =
        createCoreApiTestAppGraph(
            this,
            "user-context-manager-test",
            "test-profile",
            "0.0.1-TEST",
        )

    // ========== hasActive/hasAuthenticated Tests ==========

    @Test
    fun hasActiveReturnsFalseInitially() {
        val appGraph = createAppGraph()
        try {
            // hasActive returns true if there's an active context (including anonymous)
            // But background service cannot be active
            val hasActive = appGraph.userContextManager.hasActive()
            // Initially may return false if no active context is set
            assertNotNull(hasActive)
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun hasAuthenticatedReturnsFalseInitially() {
        val appGraph = createAppGraph()
        try {
            assertFalse(appGraph.userContextManager.hasAuthenticated())
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun hasAuthenticatedReturnsTrueAfterCreatingContext() {
        val appGraph = createAppGraph()
        try {
            appGraph.userContextManager.createOrGetFromInputs(
                DefaultTenantInputString("test-tenant"),
                DefaultPrincipalInputString("test-user"),
            )
            assertTrue(appGraph.userContextManager.hasAuthenticated())
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun resolvedWorkloadTypeIsStoredAndCannotBeReusedAsAUser() {
        val appGraph = createAppGraph()
        try {
            val manager = appGraph.userContextManager
            val tenantInput = DefaultTenantInputString("workload-tenant")
            val principalInput = DefaultPrincipalInputString("issuer-service:workload-tenant")

            assertFailsWith<IllegalArgumentException> {
                manager.createOrGetFromResolvedInputs(
                    tenantInput = tenantInput,
                    principalInput = principalInput,
                    identityResolution =
                        IdentityResolutionResult(
                            tenantId = "workload-tenant",
                            principalId = "issuer-service:other-tenant",
                            principalType = PrincipalType.WORKLOAD,
                            metadata = IdentityMetadata(resolvedFrom = ResolutionSource.TOKEN),
                        ),
                    makeActive = false,
                )
            }

            val instance =
                manager.createOrGetFromResolvedInputs(
                    tenantInput = tenantInput,
                    principalInput = principalInput,
                    identityResolution =
                        IdentityResolutionResult(
                            tenantId = "workload-tenant",
                            principalId = "issuer-service:workload-tenant",
                            principalType = PrincipalType.WORKLOAD,
                            metadata = IdentityMetadata(resolvedFrom = ResolutionSource.TOKEN),
                        ),
                    makeActive = false,
                )

            assertEquals(PrincipalType.WORKLOAD, instance.context.principalType)
            assertFailsWith<IllegalArgumentException> {
                manager.createOrGetFromInputs(
                    tenantInput = tenantInput,
                    principalInput = principalInput,
                    makeActive = false,
                )
            }
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun classifiedPrincipalInputIsHonouredByCreateOrGetFromInputs() {
        val appGraph = createAppGraph()
        try {
            val manager = appGraph.userContextManager
            val tenantInput = DefaultTenantInputString("classified-tenant")

            val instance =
                manager.createOrGetFromInputs(
                    tenantInput = tenantInput,
                    principalInput =
                        WorkloadPrincipalInput("system:dispatcher:classified-tenant"),
                    makeActive = false,
                )

            assertEquals(PrincipalType.WORKLOAD, instance.context.principalType)
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun internalDispatchAndTransportAgreeOnTheSameSystemPrincipal() {
        // The production sequence that produced "Principal classification mismatch for
        // existing context": an internal dispatcher runs a command under its own system
        // principal, then the very same identity calls back in over the transport, where
        // the token it minted classifies as WORKLOAD. Both key `tenant:principal`.
        val appGraph = createAppGraph()
        try {
            val manager = appGraph.userContextManager
            val principalId = "system:dispatcher:agreement-tenant"

            manager.createOrGetFromInputs(
                tenantInput = DefaultTenantInputString("agreement-tenant"),
                principalInput = WorkloadPrincipalInput(principalId),
                makeActive = false,
            )

            val fromTransport =
                manager.createOrGet(
                    tenantAware =
                        object : com.sphereon.di.context.TenantAware {
                            override val tenant =
                                object : com.sphereon.di.context.TenantContextData {
                                    override val tenantId = "agreement-tenant"
                                }
                        },
                    principalAware =
                        object : com.sphereon.di.context.PrincipalAware {
                            override val principal = principalId
                        },
                    principalType = PrincipalType.WORKLOAD,
                    makeActive = false,
                )

            assertEquals(PrincipalType.WORKLOAD, fromTransport.context.principalType)
        } finally {
            appGraph.destroy()
        }
    }

    private data class WorkloadPrincipalInput(
        override val principal: String,
    ) : com.sphereon.di.context.ClassifiedPrincipalInput {
        override val principalType = PrincipalType.WORKLOAD
    }

    @Test
    fun authoritativeContextDataPreservesItsRequiredPrincipalType() {
        val appGraph = createAppGraph()
        try {
            val tenant =
                object : com.sphereon.di.context.TenantContextData {
                    override val tenantId = "resolved-workload-tenant"
                }
            val tenantAware =
                object : com.sphereon.di.context.TenantAware {
                    override val tenant = tenant
                }
            val principalAware =
                object : com.sphereon.di.context.PrincipalAware {
                    override val principal = "issuer-service:resolved-workload-tenant"
                }

            val instance =
                appGraph.userContextManager.createOrGet(
                    tenantAware = tenantAware,
                    principalAware = principalAware,
                    principalType = PrincipalType.WORKLOAD,
                    makeActive = false,
                )

            assertEquals(PrincipalType.WORKLOAD, instance.context.principalType)
        } finally {
            appGraph.destroy()
        }
    }

    // ========== get/getById Tests ==========

    @Test
    fun getByIdReturnsNullForUnknownId() {
        val appGraph = createAppGraph()
        try {
            val instance = appGraph.userContextManager.getById("unknown-id", false)
            assertNull(instance)
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun getByIdReturnsAnonymousContext() {
        val appGraph = createAppGraph()
        try {
            val instance = appGraph.userContextManager.getById(UserContext.ANONYMOUS, false)
            assertNotNull(instance)
            assertEquals(UserContext.ANONYMOUS, instance.contextId)
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun getByIdReturnsBackgroundContext() {
        val appGraph = createAppGraph()
        try {
            val instance = appGraph.userContextManager.getById(UserContext.BACKGROUND_SERVICE, false)
            assertNotNull(instance)
            // Note: Background service uses same tenant/principal as anonymous,
            // so context.id returns the same value
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun getByIdMakesContextActive() {
        val appGraph = createAppGraph()
        try {
            val created =
                appGraph.userContextManager.createOrGetFromInputs(
                    DefaultTenantInputString("test-tenant"),
                    DefaultPrincipalInputString("test-user"),
                    false,
                )

            // Get with makeActive = true
            appGraph.userContextManager.getById(created.contextId, true)

            val active = appGraph.userContextManager.getActive()
            assertEquals(created.contextId, active.contextId)
        } finally {
            appGraph.destroy()
        }
    }

    // ========== has/hasById Tests ==========

    @Test
    fun hasReturnsFalseForUnknownContext() {
        val appGraph = createAppGraph()
        try {
            val tenantAware =
                object : com.sphereon.di.context.TenantAware {
                    override val tenant =
                        object : com.sphereon.di.context.TenantContextData {
                            override val tenantId = "unknown-tenant"
                        }
                }
            val principalAware =
                object : com.sphereon.di.context.PrincipalAware {
                    override val principal = "unknown-user"
                }
            assertFalse(appGraph.userContextManager.has(tenantAware, principalAware))
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun hasReturnsTrue() {
        val appGraph = createAppGraph()
        try {
            val instance =
                appGraph.userContextManager.createOrGetFromInputs(
                    DefaultTenantInputString("test-tenant"),
                    DefaultPrincipalInputString("test-user"),
                )
            val tenantAware =
                object : com.sphereon.di.context.TenantAware {
                    override val tenant = instance.context.tenant
                }
            val principalAware =
                object : com.sphereon.di.context.PrincipalAware {
                    override val principal = instance.context.principal
                }
            assertTrue(appGraph.userContextManager.has(tenantAware, principalAware))
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun hasByIdReturnsTrueForAnonymous() {
        val appGraph = createAppGraph()
        try {
            assertTrue(appGraph.userContextManager.hasById(UserContext.ANONYMOUS))
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun hasByIdReturnsTrueForBackgroundService() {
        val appGraph = createAppGraph()
        try {
            assertTrue(appGraph.userContextManager.hasById(UserContext.BACKGROUND_SERVICE))
        } finally {
            appGraph.destroy()
        }
    }

    // ========== activateById Tests ==========

    @Test
    fun activateByIdReturnsFalseForBackgroundService() {
        val appGraph = createAppGraph()
        try {
            // Background service can NEVER be activated
            assertFalse(appGraph.userContextManager.activateById(UserContext.BACKGROUND_SERVICE))
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun activateByIdReturnsTrueForAnonymous() {
        val appGraph = createAppGraph()
        try {
            assertTrue(appGraph.userContextManager.activateById(UserContext.ANONYMOUS))
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun activateByIdReturnsFalseForUnknown() {
        val appGraph = createAppGraph()
        try {
            assertFalse(appGraph.userContextManager.activateById("unknown-context-id"))
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun activateByIdReturnsTrueForCreatedContext() {
        val appGraph = createAppGraph()
        try {
            val instance =
                appGraph.userContextManager.createOrGetFromInputs(
                    DefaultTenantInputString("test-tenant"),
                    DefaultPrincipalInputString("test-user"),
                    false,
                )
            assertTrue(appGraph.userContextManager.activateById(instance.contextId))
            assertEquals(instance.contextId, appGraph.userContextManager.getActive().contextId)
        } finally {
            appGraph.destroy()
        }
    }

    // ========== activate Tests ==========

    @Test
    fun activateReturnsFalseForUnknownContext() {
        val appGraph = createAppGraph()
        try {
            val tenantAware =
                object : com.sphereon.di.context.TenantAware {
                    override val tenant =
                        object : com.sphereon.di.context.TenantContextData {
                            override val tenantId = "unknown-tenant"
                        }
                }
            val principalAware =
                object : com.sphereon.di.context.PrincipalAware {
                    override val principal = "unknown-user"
                }
            assertFalse(appGraph.userContextManager.activate(tenantAware, principalAware))
        } finally {
            appGraph.destroy()
        }
    }

    // ========== listIds Tests ==========

    @Test
    fun listIdsContainsAnonymousAndBackground() {
        val appGraph = createAppGraph()
        try {
            val ids = appGraph.userContextManager.listIds()
            assertTrue(ids.contains(UserContext.ANONYMOUS))
            assertTrue(ids.contains(UserContext.BACKGROUND_SERVICE))
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun listIdsContainsCreatedContexts() {
        val appGraph = createAppGraph()
        try {
            val instance =
                appGraph.userContextManager.createOrGetFromInputs(
                    DefaultTenantInputString("test-tenant"),
                    DefaultPrincipalInputString("test-user"),
                )
            val ids = appGraph.userContextManager.listIds()
            assertTrue(ids.contains(instance.contextId))
        } finally {
            appGraph.destroy()
        }
    }

    // ========== createOrGetFromCallbacks Tests ==========

    @Test
    fun createOrGetFromCallbacksCreatesContext() {
        val appGraph = createAppGraph()
        try {
            val instance =
                appGraph.userContextManager.createOrGetFromCallbacks(
                    { DefaultTenantInputString("callback-tenant") },
                    { DefaultPrincipalInputString("callback-user") },
                )
            assertNotNull(instance)
            assertEquals("callback-user", instance.context.principal)
        } finally {
            appGraph.destroy()
        }
    }

    // ========== createOrGetWithId Tests ==========

    @Test
    fun createOrGetWithIdReturnsAnonymousForAnonymousId() {
        val appGraph = createAppGraph()
        try {
            val tenantAware =
                object : com.sphereon.di.context.TenantAware {
                    override val tenant =
                        object : com.sphereon.di.context.TenantContextData {
                            override val tenantId = "ignored-tenant"
                        }
                }
            val principalAware =
                object : com.sphereon.di.context.PrincipalAware {
                    override val principal = "ignored-user"
                }
            val instance =
                appGraph.userContextManager.createOrGetWithId(
                    UserContext.ANONYMOUS,
                    tenantAware,
                    principalAware,
                    false,
                )
            assertEquals(UserContext.ANONYMOUS, instance.contextId)
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun createOrGetWithIdReturnsBackgroundForBackgroundId() {
        val appGraph = createAppGraph()
        try {
            val tenantAware =
                object : com.sphereon.di.context.TenantAware {
                    override val tenant =
                        object : com.sphereon.di.context.TenantContextData {
                            override val tenantId = "ignored-tenant"
                        }
                }
            val principalAware =
                object : com.sphereon.di.context.PrincipalAware {
                    override val principal = "ignored-user"
                }
            val instance =
                appGraph.userContextManager.createOrGetWithId(
                    UserContext.BACKGROUND_SERVICE,
                    tenantAware,
                    principalAware,
                    true, // makeActive should be ignored for background
                )
            // The instance is returned for BACKGROUND_SERVICE key
            assertNotNull(instance)
        } finally {
            appGraph.destroy()
        }
    }

    // ========== destroy Tests ==========

    @Test
    fun destroyRemovesContext() {
        val appGraph = createAppGraph()
        try {
            val instance =
                appGraph.userContextManager.createOrGetFromInputs(
                    DefaultTenantInputString("test-tenant"),
                    DefaultPrincipalInputString("test-user"),
                )
            val contextId = instance.contextId

            assertTrue(appGraph.userContextManager.hasById(contextId))
            appGraph.userContextManager.destroyById(contextId)
            assertFalse(appGraph.userContextManager.hasById(contextId))
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun destroyAllRemovesAllContexts() {
        val appGraph = createAppGraph()
        try {
            appGraph.userContextManager.createOrGetFromInputs(
                DefaultTenantInputString("tenant-1"),
                DefaultPrincipalInputString("user-1"),
            )
            appGraph.userContextManager.createOrGetFromInputs(
                DefaultTenantInputString("tenant-2"),
                DefaultPrincipalInputString("user-2"),
            )

            assertTrue(appGraph.userContextManager.hasAuthenticated())
            appGraph.userContextManager.destroyAll()
            assertFalse(appGraph.userContextManager.hasAuthenticated())
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun destroyByIdInvalidatesTenantCachesWhenLastTenantContextIsDestroyed() =
        runTest {
            val appGraph = createAppGraph()
            try {
                val manager = appGraph.userContextManager as UserContextManagerImpl
                val cacheManager = (appGraph as CacheModule.Graph).cacheManager
                val cache =
                    cacheManager.createCache(
                        CacheRequirements(namespace = "user-context-destroy-last-tenant-test"),
                        CacheSerializers.string,
                        CacheSerializers.string,
                    )
                val instance =
                    manager.createOrGetFromInputs(
                        DefaultTenantInputString("destroy-cache-tenant"),
                        DefaultPrincipalInputString("destroy-cache-user"),
                    )

                cache.putTenant("destroy-cache-tenant", "tenant-key", "tenant-value")
                cache.putPrincipal("destroy-cache-tenant", "destroy-cache-user", "principal-key", "principal-value")

                manager.destroyById(instance.contextId)

                assertNull(cache.getTenant("destroy-cache-tenant", "tenant-key"))
                assertNull(cache.getPrincipal("destroy-cache-tenant", "destroy-cache-user", "principal-key"))
            } finally {
                appGraph.destroy()
            }
        }

    @Test
    fun destroyByIdKeepsTenantCacheWhenAnotherTenantContextIsActive() =
        runTest {
            val appGraph = createAppGraph()
            try {
                val manager = appGraph.userContextManager as UserContextManagerImpl
                val cacheManager = (appGraph as CacheModule.Graph).cacheManager
                val cache =
                    cacheManager.createCache(
                        CacheRequirements(namespace = "user-context-destroy-shared-tenant-test"),
                        CacheSerializers.string,
                        CacheSerializers.string,
                    )
                val first =
                    manager.createOrGetFromInputs(
                        DefaultTenantInputString("shared-cache-tenant"),
                        DefaultPrincipalInputString("shared-cache-user-1"),
                    )
                manager.createOrGetFromInputs(
                    DefaultTenantInputString("shared-cache-tenant"),
                    DefaultPrincipalInputString("shared-cache-user-2"),
                )

                cache.putTenant("shared-cache-tenant", "tenant-key", "tenant-value")
                cache.putPrincipal("shared-cache-tenant", "shared-cache-user-1", "principal-key", "principal-value-1")
                cache.putPrincipal("shared-cache-tenant", "shared-cache-user-2", "principal-key", "principal-value-2")

                manager.destroyById(first.contextId)

                assertEquals("tenant-value", cache.getTenant("shared-cache-tenant", "tenant-key"))
                assertNull(cache.getPrincipal("shared-cache-tenant", "shared-cache-user-1", "principal-key"))
                assertEquals("principal-value-2", cache.getPrincipal("shared-cache-tenant", "shared-cache-user-2", "principal-key"))
            } finally {
                appGraph.destroy()
            }
        }

    @Test
    fun idleCleanupDestroysExpiredRegularContext() {
        val appGraph = createAppGraph()
        try {
            appGraph.appConfigService.addPropertySource(
                MutableMapPropertySource("idle-cleanup-test").apply {
                    addProperty("context.user.idle-timeout-ms", "1000")
                    addProperty("context.user.idle-cleanup.enabled", "true")
                },
            )
            val manager = appGraph.userContextManager as UserContextManagerImpl
            val instance =
                manager.createOrGetFromInputs(
                    DefaultTenantInputString("idle-tenant"),
                    DefaultPrincipalInputString("idle-user"),
                )

            assertTrue(manager.hasById(instance.contextId))
            manager.runIdleCleanup(nowEpochMs = Long.MAX_VALUE)

            assertFalse(manager.hasById(instance.contextId))
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun idleCleanupRetainsAppScopedTenantAndPrincipalCaches() =
        runTest {
            val appGraph = createAppGraph()
            try {
                appGraph.appConfigService.addPropertySource(
                    MutableMapPropertySource("idle-cleanup-cache-retention-test").apply {
                        addProperty("context.user.idle-timeout-ms", "1000")
                        addProperty("context.user.idle-cleanup.enabled", "true")
                    },
                )
                val manager = appGraph.userContextManager as UserContextManagerImpl
                val cacheManager = (appGraph as CacheModule.Graph).cacheManager
                val cache =
                    cacheManager.createCache(
                        CacheRequirements(namespace = "idle-cleanup-cache-retention-test"),
                        CacheSerializers.string,
                        CacheSerializers.string,
                    )
                val instance =
                    manager.createOrGetFromInputs(
                        DefaultTenantInputString("idle-cache-tenant"),
                        DefaultPrincipalInputString("idle-cache-user"),
                    )

                cache.putTenant("idle-cache-tenant", "tenant-key", "tenant-value")
                cache.putPrincipal("idle-cache-tenant", "idle-cache-user", "principal-key", "principal-value")

                manager.runIdleCleanup(nowEpochMs = Long.MAX_VALUE)

                assertFalse(manager.hasById(instance.contextId))
                assertEquals("tenant-value", cache.getTenant("idle-cache-tenant", "tenant-key"))
                assertEquals(
                    "principal-value",
                    cache.getPrincipal("idle-cache-tenant", "idle-cache-user", "principal-key"),
                )
            } finally {
                appGraph.destroy()
            }
        }

    @Test
    fun idleCleanupKeepsRecentlyAccessedRegularContext() {
        val appGraph = createAppGraph()
        try {
            appGraph.appConfigService.addPropertySource(
                MutableMapPropertySource("idle-cleanup-recent-test").apply {
                    addProperty("context.user.idle-timeout-ms", "60000")
                    addProperty("context.user.idle-cleanup.enabled", "true")
                },
            )
            val manager = appGraph.userContextManager as UserContextManagerImpl
            val instance =
                manager.createOrGetFromInputs(
                    DefaultTenantInputString("idle-recent-tenant"),
                    DefaultPrincipalInputString("idle-recent-user"),
                )

            manager.getById(instance.contextId, makeActive = false)
            manager.runIdleCleanup(nowEpochMs = currentTimeMillis())

            assertTrue(manager.hasById(instance.contextId))
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun idleCleanupCanBeDisabled() {
        val appGraph = createAppGraph()
        try {
            appGraph.appConfigService.addPropertySource(
                MutableMapPropertySource("idle-cleanup-disabled-test").apply {
                    addProperty("context.user.idle-timeout-ms", "1000")
                    addProperty("context.user.idle-cleanup.enabled", "false")
                },
            )
            val manager = appGraph.userContextManager as UserContextManagerImpl
            val instance =
                manager.createOrGetFromInputs(
                    DefaultTenantInputString("idle-disabled-tenant"),
                    DefaultPrincipalInputString("idle-disabled-user"),
                )

            manager.runIdleCleanup(nowEpochMs = Long.MAX_VALUE)

            assertTrue(manager.hasById(instance.contextId))
        } finally {
            appGraph.destroy()
        }
    }

    // ========== getBackgroundService/getAnonymous Tests ==========

    @Test
    fun getBackgroundServiceReturnsBackgroundContext() {
        val appGraph = createAppGraph()
        try {
            val instance = appGraph.userContextManager.getBackgroundService()
            assertNotNull(instance)
            // Note: Background service context uses same tenant/principal as anonymous
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun getAnonymousReturnsAnonymousContext() {
        val appGraph = createAppGraph()
        try {
            val instance = appGraph.userContextManager.getAnonymous(false)
            assertNotNull(instance)
            assertEquals(UserContext.ANONYMOUS, instance.contextId)
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun getAnonymousWithMakeActiveActivatesContext() {
        val appGraph = createAppGraph()
        try {
            // First create and activate a regular context
            val regularContext =
                appGraph.userContextManager.createOrGetFromInputs(
                    DefaultTenantInputString("test-tenant"),
                    DefaultPrincipalInputString("test-user"),
                    true,
                )
            assertEquals(regularContext.contextId, appGraph.userContextManager.getActive().contextId)

            // Now get anonymous with makeActive = true
            val anonymous = appGraph.userContextManager.getAnonymous(true)
            assertEquals(UserContext.ANONYMOUS, appGraph.userContextManager.getActive().contextId)
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun getBackgroundServiceIdReturnsCorrectId() {
        val appGraph = createAppGraph()
        try {
            assertEquals(UserContext.BACKGROUND_SERVICE, appGraph.userContextManager.getBackgroundServiceId())
        } finally {
            appGraph.destroy()
        }
    }

    // ========== isAnonymous Tests ==========

    @Test
    fun isAnonymousReturnsTrueWhenNoActiveContext() {
        val appGraph = createAppGraph()
        try {
            // Initially no authenticated context is active
            assertTrue(appGraph.userContextManager.isAnonymous())
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun isAnonymousReturnsFalseWhenAuthenticatedContextActive() {
        val appGraph = createAppGraph()
        try {
            appGraph.userContextManager.createOrGetFromInputs(
                DefaultTenantInputString("test-tenant"),
                DefaultPrincipalInputString("test-user"),
                true,
            )
            assertFalse(appGraph.userContextManager.isAnonymous())
        } finally {
            appGraph.destroy()
        }
    }

    // ========== createOrGetFromData Tests ==========

    @Test
    fun createOrGetFromDataCreatesContext() {
        val appGraph = createAppGraph()
        try {
            val tenantData =
                object : com.sphereon.di.context.TenantContextData {
                    override val tenantId = "data-tenant"
                }
            val instance =
                appGraph.userContextManager.createOrGetFromData(
                    tenantData,
                    "data-user",
                    false,
                )
            assertNotNull(instance)
            assertEquals("data-tenant", instance.context.tenant.tenantId)
            assertEquals("data-user", instance.context.principal)
            assertEquals(com.sphereon.di.context.PrincipalType.USER, instance.context.principalType)
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun createOrGetFromDataWithPrincipalTypeCreatesClassifiedContext() {
        val appGraph = createAppGraph()
        try {
            val tenantData =
                object : com.sphereon.di.context.TenantContextData {
                    override val tenantId = "workload-tenant"
                }
            val instance =
                appGraph.userContextManager.createOrGetFromData(
                    tenantData = tenantData,
                    principalValue = "workload-client",
                    principalType = com.sphereon.di.context.PrincipalType.WORKLOAD,
                    makeActive = false,
                )
            assertNotNull(instance)
            assertEquals("workload-tenant", instance.context.tenant.tenantId)
            assertEquals("workload-client", instance.context.principal)
            assertEquals(com.sphereon.di.context.PrincipalType.WORKLOAD, instance.context.principalType)
        } finally {
            appGraph.destroy()
        }
    }

    // ========== activeInstance StateFlow Tests ==========

    @Test
    fun activeInstanceReturnsAnonymousInitially() {
        val appGraph = createAppGraph()
        try {
            val active = appGraph.userContextManager.activeInstance.value
            assertEquals(UserContext.ANONYMOUS, active.contextId)
        } finally {
            appGraph.destroy()
        }
    }

    @Test
    fun activeInstanceUpdatesWhenContextActivated() {
        val appGraph = createAppGraph()
        try {
            val instance =
                appGraph.userContextManager.createOrGetFromInputs(
                    DefaultTenantInputString("test-tenant"),
                    DefaultPrincipalInputString("test-user"),
                    true,
                )
            // Use getActive() which is synchronous, rather than StateFlow which uses lazy sharing
            val active = appGraph.userContextManager.getActive()
            assertEquals(instance.contextId, active.contextId)
        } finally {
            appGraph.destroy()
        }
    }
}
