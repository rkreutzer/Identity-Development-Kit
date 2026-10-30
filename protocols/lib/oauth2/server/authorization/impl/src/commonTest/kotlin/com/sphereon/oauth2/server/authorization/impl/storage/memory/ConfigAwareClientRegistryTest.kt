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

package com.sphereon.oauth2.server.authorization.impl.storage.memory

import com.sphereon.core.api.Err
import com.sphereon.core.api.Ok
import com.sphereon.oauth2.server.authorization.provider.ExternalClientSource
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.conf.OpaqueSecretResolver
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.log.LogLevel
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.core.defaults.random.defaultSecureRandom
import com.sphereon.oauth2.common.config.ClientRegistrySourcePrecedence
import com.sphereon.oauth2.common.config.InternalClientConfig
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceIdProvider
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.server.authorization.impl.config.OAuth2ClientsConfigBinder as ProductionOAuth2ClientsConfigBinder
import com.sphereon.oauth2.server.authorization.impl.config.OAuth2ClientMetadataCache
import com.sphereon.oauth2.server.authorization.impl.config.NoOpSessionLogService
import com.sphereon.oauth2.server.authorization.impl.config.OAuth2ServersConfigBinder
import com.sphereon.oauth2.server.authorization.impl.config.RecordingSessionLogService
import com.sphereon.oauth2.server.authorization.impl.config.TestSessionExecution
import com.sphereon.oauth2.server.authorization.impl.config.TypeAwarePrincipalConfigService
import com.sphereon.oauth2.server.authorization.impl.command.clientauth.toVerifiedClientAuthorization
import com.sphereon.oauth2.server.authorization.impl.testutil.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientType
import com.sphereon.oauth2.server.authorization.storage.ClientSecretHasher
import com.sphereon.oauth2.server.authorization.storage.ClientRegistrationStore
import com.sphereon.oauth2.server.authorization.storage.DynamicClientRegistrationMetadata
import com.sphereon.oauth2.server.authorization.storage.StoredClientRegistration
import kotlinx.coroutines.test.runTest
import kotlin.time.Clock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@Suppress("FunctionName")
private fun OAuth2ClientsConfigBinder(
    execution: TestSessionExecution,
    opaqueSecretResolver: OpaqueSecretResolver,
    metadataCache: OAuth2ClientMetadataCache = OAuth2ClientMetadataCache(),
): ProductionOAuth2ClientsConfigBinder =
    ProductionOAuth2ClientsConfigBinder(execution, opaqueSecretResolver, metadataCache)

class ConfigAwareClientRegistryTest {
    @Test
    fun parsedMetadataIsSharedButResolvedSecretMaterialRemainsRequestLocal() =
        runTest {
            val configService =
                TypeAwarePrincipalConfigService(
                    properties =
                        mapOf(
                            "oauth2.clients.workload.client-id" to "workload-client",
                            "oauth2.clients.workload.client-secret-id" to "sec_workload_client_0001",
                            "oauth2.clients.workload.grant-types" to "client_credentials",
                        ),
                    normalizeKeys = true,
                )
            val execution =
                TestSessionExecution(
                    principal = configService,
                    tenantId = "tenant-one",
                    principalId = "workload-one",
                )
            val metadataCache = OAuth2ClientMetadataCache()
            var currentSecret = "first-secret"
            var secretResolutions = 0
            val resolver =
                OpaqueSecretResolver {
                    secretResolutions += 1
                    Ok(currentSecret)
                }

            val first =
                OAuth2ClientsConfigBinder(execution, resolver, metadataCache)
                    .loadClientRegistrations(activeServerId = "platform")
            val readsAfterFirstParse = configService.propertyReadCount
            currentSecret = "second-secret"
            val second =
                OAuth2ClientsConfigBinder(execution, resolver, metadataCache)
                    .loadClientRegistrations(activeServerId = "platform")

            assertEquals("first-secret", first.value["workload-client"]?.clientSecret)
            assertEquals("second-secret", second.value["workload-client"]?.clientSecret)
            assertEquals(2, secretResolutions, "plaintext secret material must resolve in every request")
            assertEquals(
                readsAfterFirstParse,
                configService.propertyReadCount,
                "the unchanged non-secret metadata snapshot must not be parsed again",
            )
        }

    @Test
    fun clientIdTokenSigningAlgorithmIsBoundFromConfiguration() =
        runTest {
            val configService =
                TypeAwarePrincipalConfigService(
                    properties =
                        mapOf(
                            "oauth2.clients.portal.client-id" to "portal",
                            "oauth2.clients.portal.grant-types" to "authorization_code",
                            "oauth2.clients.portal.id-token-signed-response-alg" to "RS384",
                        ),
                    normalizeKeys = true,
                )
            val execution = TestSessionExecution(configService)

            val clients =
                OAuth2ClientsConfigBinder(execution, rejectingOpaqueSecrets)
                    .loadClientRegistrations(activeServerId = "primary")

            assertTrue(clients.isOk)
            assertEquals("RS384", clients.value["portal"]?.idTokenSignedResponseAlg)
        }

    @Test
    fun recreatedPrincipalConfigViewCannotReuseAnOldRevisionEntry() =
        runTest {
            val metadataCache = OAuth2ClientMetadataCache()

            suspend fun load(
                configService: TypeAwarePrincipalConfigService,
                clientId: String,
            ) =
                OAuth2ClientsConfigBinder(
                    TestSessionExecution(configService, tenantId = "tenant-one", principalId = "workload-one"),
                    rejectingOpaqueSecrets,
                    metadataCache,
                ).loadClientRegistrations(activeServerId = "platform").value[clientId]

            val oldView =
                TypeAwarePrincipalConfigService(
                    mapOf(
                        "oauth2.clients.active.client-id" to "old-client",
                        "oauth2.clients.active.grant-types" to "client_credentials",
                    ),
                    normalizeKeys = true,
                )
            val replacementView =
                TypeAwarePrincipalConfigService(
                    mapOf(
                        "oauth2.clients.active.client-id" to "replacement-client",
                        "oauth2.clients.active.grant-types" to "client_credentials",
                    ),
                    normalizeKeys = true,
                )

            assertNotNull(load(oldView, "old-client"))
            assertNotNull(load(replacementView, "replacement-client"))
        }

    @Test
    fun opaqueInternalClientEnumerationIsSharedUntilItsConfigRevisionChanges() =
        runTest {
            val prefix = "oauth2.servers.platform.internal-clients.kms-tenant-one"
            val configService =
                TypeAwarePrincipalConfigService(
                    mapOf(
                        "$prefix.client-id" to "kms-client-one",
                        "$prefix.tenant-id" to "tenant-one",
                    ),
                    normalizeKeys = true,
                )
            val execution =
                TestSessionExecution(configService, tenantId = "tenant-one", principalId = "kms-client-one")
            val metadataCache = OAuth2ClientMetadataCache()

            val first =
                OAuth2ClientsConfigBinder(execution, rejectingOpaqueSecrets, metadataCache)
                    .loadOpaqueInternalClientRegistrations("platform")
            val readsAfterFirstParse = configService.propertyReadCount
            val repeated =
                OAuth2ClientsConfigBinder(execution, rejectingOpaqueSecrets, metadataCache)
                    .loadOpaqueInternalClientRegistrations("platform")

            assertNotNull(first.value["kms-client-one"])
            assertNotNull(repeated.value["kms-client-one"])
            assertEquals(readsAfterFirstParse, configService.propertyReadCount)

            configService.putProperty("$prefix.client-id", "kms-client-rotated")
            val revised =
                OAuth2ClientsConfigBinder(execution, rejectingOpaqueSecrets, metadataCache)
                    .loadOpaqueInternalClientRegistrations("platform")

            assertNotNull(revised.value["kms-client-rotated"])
            assertTrue(configService.propertyReadCount > readsAfterFirstParse)
        }

    @Test
    fun opaqueInternalClientEnumerationIsSharedAcrossRecreatedPrincipalViews() =
        runTest {
            val prefix = "oauth2.servers.platform.internal-clients.issuer-tenant-one"
            val tenantConfigOwner =
                TypeAwarePrincipalConfigService(
                    mapOf(
                        "$prefix.client-id" to "issuer-service:tenant-one",
                        "$prefix.tenant-id" to "tenant-one",
                        "$prefix.client-secret-id" to "sec_issuer_tenant_0001",
                    ),
                    normalizeKeys = true,
                )
            val sharedTenantConfig = tenantConfigOwner.parent
            val metadataCache = OAuth2ClientMetadataCache()

            suspend fun load(principalId: String) =
                OAuth2ClientsConfigBinder(
                    TestSessionExecution(
                        principal =
                            TypeAwarePrincipalConfigService(
                                properties = emptyMap(),
                                normalizeKeys = true,
                                tenantConfigOverride = sharedTenantConfig,
                            ),
                        tenantId = "tenant-one",
                        principalId = principalId,
                    ),
                    rejectingOpaqueSecrets,
                    metadataCache,
                ).loadOpaqueInternalClientRegistrations("platform")

            val first = load("workload-one")
            val readsAfterFirst = tenantConfigOwner.propertyReadCount
            val second = load("workload-two")

            val firstRegistration = assertNotNull(first.value["issuer-service:tenant-one"])
            assertNotNull(second.value["issuer-service:tenant-one"])
            assertEquals(
                readsAfterFirst,
                tenantConfigOwner.propertyReadCount,
                "a recreated principal UserScope must reuse unchanged tenant-owned opaque metadata",
            )
            assertNull(firstRegistration.registration.clientSecret)
            assertEquals("sec_issuer_tenant_0001", firstRegistration.credential.secretId)
        }

    @Test
    fun principalScopedOpaqueInternalClientDefinitionIsRejected() =
        runTest {
            val prefix = "oauth2.servers.platform.internal-clients.issuer-tenant-one"
            val tenantConfigOwner =
                TypeAwarePrincipalConfigService(
                    mapOf(
                        "$prefix.client-id" to "issuer-service:tenant-one",
                        "$prefix.tenant-id" to "tenant-one",
                    ),
                    normalizeKeys = true,
                )
            val principal =
                TypeAwarePrincipalConfigService(
                    properties = emptyMap(),
                    normalizeKeys = true,
                    tenantConfigOverride = tenantConfigOwner.parent,
                    principalScopedProperties =
                        mapOf("$prefix.client-id" to "principal-controlled-client"),
                )
            val execution =
                TestSessionExecution(
                    principal = principal,
                    tenantId = "tenant-one",
                    principalId = "workload-one",
                )

            val result =
                OAuth2ClientsConfigBinder(execution, rejectingOpaqueSecrets)
                    .loadOpaqueInternalClientRegistrations("platform")

            assertTrue(result.isErr)
            assertTrue(result.error.details.contains("tenant-owned"))
        }

    @Test
    fun tokenExchangeAuthorityIsBoundOnlyFromServerConfigurationAndSurvivesLookup() =
        runTest {
            val secrets = resolvingOpaqueSecrets(emptyMap())
            val execution =
                TestSessionExecution(
                    TypeAwarePrincipalConfigService(
                        properties =
                            mapOf(
                                "oauth2.clients.operator.client-id" to "operator-cli",
                                "oauth2.clients.operator.client-type" to "public",
                                "oauth2.clients.operator.token-endpoint-auth-method" to "none",
                                "oauth2.clients.operator.grant-types" to "authorization_code,urn:ietf:params:oauth:grant-type:token-exchange",
                                "oauth2.clients.operator.token-exchange.mode" to "operator-delegation",
                                "oauth2.clients.operator.token-exchange.audiences" to "enterprise-platform,enterprise-tenant-kms",
                                "oauth2.clients.operator.token-exchange.provisioning" to "true",
                                "oauth2.clients.plain.client-id" to "plain-client",
                                "oauth2.clients.plain.client-type" to "public",
                                "oauth2.clients.plain.token-endpoint-auth-method" to "none",
                                "oauth2.clients.plain.grant-types" to "authorization_code",
                            ),
                        normalizeKeys = true,
                    ),
                )
            val registry =
                ConfigAwareClientRegistry(
                    execution = execution,
                    backingStorage = InMemoryOAuth2BackingStorageImpl(),
                    configBinder = OAuth2ClientsConfigBinder(execution, secrets),
                    asInstanceIdProvider =
                        object : OAuth2ServerInstanceIdProvider {
                            override fun currentAsInstanceId(): String? = null
                        },
                    serversConfigProvider = TestOAuth2ServersConfigProvider(OAuth2ServersConfig()),
                    opaqueInternalClientSecretVerifier = lazyOf(DefaultOpaqueInternalClientSecretVerifier(secrets)),
                    clientRegistrationStore = InMemoryClientRegistrationStore(),
                    clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                    externalClientSources = lazyOf(emptySet()),
                )

            val operator = assertNotNull(registry.getClient("operator-cli").value)
            assertEquals(
                mapOf("mode" to "operator-delegation", "audiences" to "enterprise-platform,enterprise-tenant-kms", "provisioning" to "true"),
                operator.tokenExchangeAuthority,
            )
            assertTrue(operator.additionalMetadata.keys.none { it.contains("exchange") }, "authority is never issuance metadata")
            assertEquals(operator.tokenExchangeAuthority, operator.toVerifiedClientAuthorization().tokenExchangeAuthority)
            assertTrue(assertNotNull(registry.getClient("plain-client").value).tokenExchangeAuthority.isEmpty())

            val selfGranted =
                ClientRegistration(
                    clientId = "dyn-self-granted",
                    clientName = "self-granted",
                    clientType = ClientType.PUBLIC,
                    grantTypes = listOf(GrantType.TOKEN_EXCHANGE),
                    tokenEndpointAuthMethod = ClientAuthenticationMethod.NONE,
                    tokenExchangeAuthority = mapOf("mode" to "operator-delegation", "audiences" to "enterprise-platform", "provisioning" to "true"),
                )
            assertTrue(registry.registerClient(selfGranted).isErr, "dynamic registration cannot grant exchange authority")
            assertNull(registry.getClient("dyn-self-granted").value)

            val plain = assertNotNull(registry.registerClient(selfGranted.copy(tokenExchangeAuthority = emptyMap())).value)
            assertTrue(
                registry.updateClient(plain.clientId, plain.copy(tokenExchangeAuthority = mapOf("mode" to "workload"))).isErr,
                "dynamic update cannot grant exchange authority",
            )
            assertTrue(assertNotNull(registry.getClient(plain.clientId).value).tokenExchangeAuthority.isEmpty())
        }

    @Test
    fun principalResolvedRegistrationsAndCredentialsRemainRequestViewLocal() =
        runTest {
            val sharedBackingStorage = InMemoryOAuth2BackingStorageImpl()
            val secrets =
                resolvingOpaqueSecrets(
                    mapOf(
                        "sec_principal_one_0001" to "principal-one-secret",
                        "sec_principal_two_0001" to "principal-two-secret",
                    ),
                )

            fun registry(
                clientId: String,
                secretId: String,
            ): ConfigAwareClientRegistry {
                val execution =
                    TestSessionExecution(
                        TypeAwarePrincipalConfigService(
                            properties =
                                mapOf(
                                    "oauth2.clients.active.client-id" to clientId,
                                    "oauth2.clients.active.client-secret-id" to secretId,
                                    "oauth2.clients.active.grant-types" to "client_credentials",
                                ),
                            normalizeKeys = true,
                        ),
                    )
                return ConfigAwareClientRegistry(
                    execution = execution,
                    backingStorage = sharedBackingStorage,
                    configBinder = OAuth2ClientsConfigBinder(execution, secrets),
                    asInstanceIdProvider =
                        object : OAuth2ServerInstanceIdProvider {
                            override fun currentAsInstanceId(): String? = null
                        },
                    serversConfigProvider = TestOAuth2ServersConfigProvider(OAuth2ServersConfig()),
                    opaqueInternalClientSecretVerifier = lazyOf(DefaultOpaqueInternalClientSecretVerifier(secrets)),
                    clientRegistrationStore = InMemoryClientRegistrationStore(),
                    clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                    externalClientSources = lazyOf(emptySet()),
                )
            }

            val principalOneRegistry = registry("principal-one-client", "sec_principal_one_0001")
            val principalTwoRegistry = registry("principal-two-client", "sec_principal_two_0001")

            assertNotNull(principalOneRegistry.getClient("principal-one-client").value)
            assertEquals(null, principalOneRegistry.getClient("principal-two-client").value)
            assertTrue(principalOneRegistry.verifyClientCredentials("principal-one-client", "principal-one-secret").value)
            assertFalse(principalOneRegistry.verifyClientCredentials("principal-two-client", "principal-two-secret").value)

            assertNotNull(principalTwoRegistry.getClient("principal-two-client").value)
            assertEquals(null, principalTwoRegistry.getClient("principal-one-client").value)
            assertTrue(principalTwoRegistry.verifyClientCredentials("principal-two-client", "principal-two-secret").value)
            assertFalse(principalTwoRegistry.verifyClientCredentials("principal-one-client", "principal-one-secret").value)
        }

    @Test
    fun requestViewAssemblesConfigurationOnceAndPreservesCredentialFailureSemantics() =
        runTest {
            var configReadCount = 0
            val configService =
                TypeAwarePrincipalConfigService(
                    properties =
                        mapOf(
                            "oauth2.servers.default-server" to "platform",
                            "oauth2.servers.platform.mode" to "HOSTED",
                            "oauth2.clients.operator.client-id" to "operator-client",
                            "oauth2.clients.operator.client-secret-id" to "sec_operator_client_0001",
                            "oauth2.clients.operator.grant-types" to "client_credentials",
                        ),
                    subPropertiesOverride = { prefixes, stripPrefix, properties ->
                        configReadCount++
                        val prefix = prefixes.single().replace("-", ".")
                        properties
                            .filterKeys { key -> key == prefix || key.startsWith("$prefix.") }
                            .mapKeys { (key, _) ->
                                if (stripPrefix) key.removePrefix("$prefix.") else key
                            }
                    },
                    normalizeKeys = true,
                )
            val execution = TestSessionExecution(configService)
            val secrets = resolvingOpaqueSecrets(mapOf("sec_operator_client_0001" to "operator-secret"))
            val registry =
                ConfigAwareClientRegistry(
                    execution = execution,
                    backingStorage = InMemoryOAuth2BackingStorageImpl(),
                    configBinder = OAuth2ClientsConfigBinder(execution, secrets),
                    asInstanceIdProvider =
                        object : OAuth2ServerInstanceIdProvider {
                            override fun currentAsInstanceId(): String = "platform"
                        },
                    serversConfigProvider =
                        TestOAuth2ServersConfigProvider(
                            OAuth2ServersConfig(
                                defaultServer = "platform",
                                servers = mapOf("platform" to OAuth2ServerInstanceConfig()),
                            ),
                        ),
                    opaqueInternalClientSecretVerifier = lazyOf(DefaultOpaqueInternalClientSecretVerifier(secrets)),
                    clientRegistrationStore = InMemoryClientRegistrationStore(),
                    clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                    externalClientSources = lazyOf(emptySet()),
                )

            val viewResult = registry.resolveClientRegistryRequestView()

            assertTrue(viewResult.isOk, viewResult.errorOrNull()?.details)
            val view = viewResult.value
            assertNotNull(view.getClient("operator-client").value)
            assertTrue(view.verifyClientCredentials("operator-client", "operator-secret").value)
            assertFalse(view.verifyClientCredentials("operator-client", "wrong-secret").value)
            assertEquals(3, configReadCount)
        }

    @Test
    fun scopedTenantAsClientAppearsAfterInitialMissAndOpaqueProvisioningWithoutRegistryRestart() =
        runTest {
            val tenantId = "9f90ec38-8fbf-41f5-9c67-c45a00845a92"
            val role = "tenant-as-$tenantId"
            val prefix = "oauth2.servers.platform.internal-clients.$role"
            val secretId = "sec_tenant_as_dynamic_0001"
            val configService =
                TypeAwarePrincipalConfigService(
                    mapOf(
                        "oauth2.servers.default-server" to "platform",
                        "oauth2.servers.platform.mode" to "HOSTED",
                    ),
                    normalizeKeys = true,
                )
            val execution = TestSessionExecution(configService)
            val serversConfigProvider = OAuth2ServersConfigBinder(execution, com.sphereon.oauth2.common.config.DefaultOAuth2ServerInstanceIdProvider())
            val registry =
                ConfigAwareClientRegistry(
                    execution = execution,
                    backingStorage = InMemoryOAuth2BackingStorageImpl(),
                    configBinder =
                        OAuth2ClientsConfigBinder(
                            execution,
                            resolvingOpaqueSecrets(mapOf(secretId to "shared-secret")),
                        ),
                    asInstanceIdProvider =
                        object : OAuth2ServerInstanceIdProvider {
                            override fun currentAsInstanceId(): String = "platform"
                        },
                    serversConfigProvider = serversConfigProvider,
                    opaqueInternalClientSecretVerifier =
                        lazyOf(DefaultOpaqueInternalClientSecretVerifier(
                            resolvingOpaqueSecrets(mapOf(secretId to "shared-secret")),
                        )),
                    clientRegistrationStore = InMemoryClientRegistrationStore(),
                    clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                    externalClientSources = lazyOf(emptySet()),
                )

            val clientId = "tenant-as-service:$tenantId"
            assertEquals(null, registry.getClient(clientId).value)

            configService.putProperty("$prefix.client-id", clientId)
            configService.putProperty("$prefix.client-secret-id", secretId)
            configService.putProperty(
                "$prefix.grant-types",
                "client_credentials,urn:ietf:params:oauth:grant-type:token-exchange",
            )
            configService.putProperty("$prefix.tenant-id", tenantId)
            configService.putProperty("$prefix.default-access-token-audience", "enterprise-platform")
            configService.putProperty("$prefix.allowed-access-token-audiences", "enterprise-tenant-kms")

            assertTrue(registry.verifyClientCredentials(clientId, "shared-secret").value)
            assertFalse(registry.verifyClientCredentials(clientId, "wrong-secret").value)
            val registration = assertNotNull(registry.getClient(clientId).value)
            assertEquals(listOf(GrantType.CLIENT_CREDENTIALS, GrantType.TOKEN_EXCHANGE), registration.grantTypes)
            assertEquals(tenantId, registration.additionalMetadata["tenant_id"])
        }

    @Test
    fun repeatedLookupsBindConfigurationOnceUntilConfigurationChanges() =
        runTest {
            var configReadCount = 0
            val configService =
                TypeAwarePrincipalConfigService(
                    properties =
                        mapOf(
                            "oauth2.clients.operator.client-id" to "operator-client",
                            "oauth2.clients.operator.client-secret-id" to "sec_operator_client_0001",
                            "oauth2.clients.operator.grant-types" to "client_credentials",
                        ),
                    subPropertiesOverride = { prefixes, stripPrefix, properties ->
                        configReadCount++
                        val prefix = prefixes.single().replace("-", ".")
                        properties
                            .filterKeys { key -> key == prefix || key.startsWith("$prefix.") }
                            .mapKeys { (key, _) ->
                                if (stripPrefix) key.removePrefix("$prefix.") else key
                            }
                    },
                    normalizeKeys = true,
                )
            val execution = TestSessionExecution(configService)
            val secrets =
                resolvingOpaqueSecrets(
                    mapOf(
                        "sec_operator_client_0001" to "operator-secret",
                        "sec_operator_client_0002" to "rotated-secret",
                    ),
                )
            val registry =
                ConfigAwareClientRegistry(
                    execution = execution,
                    backingStorage = InMemoryOAuth2BackingStorageImpl(),
                    configBinder = OAuth2ClientsConfigBinder(execution, secrets),
                    asInstanceIdProvider =
                        object : OAuth2ServerInstanceIdProvider {
                            override fun currentAsInstanceId(): String? = null
                        },
                    serversConfigProvider = TestOAuth2ServersConfigProvider(OAuth2ServersConfig()),
                    opaqueInternalClientSecretVerifier = lazyOf(DefaultOpaqueInternalClientSecretVerifier(secrets)),
                    clientRegistrationStore = InMemoryClientRegistrationStore(),
                    clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                    externalClientSources = lazyOf(emptySet()),
                )

            assertNotNull(registry.getClient("operator-client").value)
            val readsAfterFirstLookup = configReadCount

            repeat(20) {
                assertNotNull(registry.getClient("operator-client").value)
                assertTrue(registry.verifyClientCredentials("operator-client", "operator-secret").value)
            }
            assertEquals(readsAfterFirstLookup, configReadCount)

            configService.putProperty("oauth2.clients.operator.client-secret-id", "sec_operator_client_0002")

            assertTrue(registry.verifyClientCredentials("operator-client", "rotated-secret").value)
            assertFalse(registry.verifyClientCredentials("operator-client", "operator-secret").value)
            assertTrue(configReadCount > readsAfterFirstLookup)
        }

    @Test
    fun freshRequestMemoizerObservesClientPublishedBeforeRevisionNotification() =
        runTest {
            val configService = TypeAwarePrincipalConfigService(emptyMap(), normalizeKeys = true)
            val secrets = resolvingOpaqueSecrets(mapOf("sec_docs_playground_0001" to "unused-public-client-secret"))

            fun registry(): ConfigAwareClientRegistry {
                val execution = TestSessionExecution(configService)
                return ConfigAwareClientRegistry(
                    execution = execution,
                    backingStorage = InMemoryOAuth2BackingStorageImpl(),
                    configBinder = OAuth2ClientsConfigBinder(execution, secrets),
                    asInstanceIdProvider =
                        object : OAuth2ServerInstanceIdProvider {
                            override fun currentAsInstanceId(): String? = null
                        },
                    serversConfigProvider = TestOAuth2ServersConfigProvider(OAuth2ServersConfig()),
                    opaqueInternalClientSecretVerifier = lazyOf(DefaultOpaqueInternalClientSecretVerifier(secrets)),
                    clientRegistrationStore = InMemoryClientRegistrationStore(),
                    clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                    externalClientSources = lazyOf(emptySet()),
                    // A new inbound request receives a new SessionScope memoizer. This models a
                    // just-provisioned docs client whose invalidation event has not yet advanced
                    // the old request's property-source revision.
                    configuredClientSetMemoizer = ConfiguredClientSetMemoizer(),
                )
            }

            assertEquals(null, registry().getClient("docs-playground").value)

            configService.putPropertyWithoutRevision("oauth2.clients.docs-playground.client-id", "docs-playground")
            configService.putPropertyWithoutRevision("oauth2.clients.docs-playground.client-type", "PUBLIC")
            configService.putPropertyWithoutRevision(
                "oauth2.clients.docs-playground.grant-types",
                "authorization_code,refresh_token",
            )

            val registration = assertNotNull(registry().getClient("docs-playground").value)
            assertEquals("docs-playground", registration.clientId)
            assertEquals(ClientAuthenticationMethod.NONE, registration.tokenEndpointAuthMethod)
        }

    @Test
    fun repeatRequestsShareConfiguredClientSetUntilPrincipalConfigurationChanges() =
        runTest {
            var configReadCount = 0
            val configService =
                TypeAwarePrincipalConfigService(
                    properties =
                        mapOf(
                            "oauth2.clients.operator.client-id" to "operator-client",
                            "oauth2.clients.operator.client-secret-id" to "sec_operator_client_0001",
                            "oauth2.clients.operator.grant-types" to "client_credentials",
                        ),
                    subPropertiesOverride = { prefixes, stripPrefix, properties ->
                        configReadCount++
                        val prefix = prefixes.single().replace("-", ".")
                        properties
                            .filterKeys { key -> key == prefix || key.startsWith("$prefix.") }
                            .mapKeys { (key, _) ->
                                if (stripPrefix) key.removePrefix("$prefix.") else key
                            }
                    },
                    normalizeKeys = true,
                )
            val secrets = resolvingOpaqueSecrets(mapOf("sec_operator_client_0001" to "operator-secret"))
            val memoizer = ConfiguredClientSetMemoizer()
            fun registry(): ConfigAwareClientRegistry {
                val execution = TestSessionExecution(configService)
                return ConfigAwareClientRegistry(
                    execution = execution,
                    backingStorage = InMemoryOAuth2BackingStorageImpl(),
                    configBinder = OAuth2ClientsConfigBinder(execution, secrets),
                    asInstanceIdProvider =
                        object : OAuth2ServerInstanceIdProvider {
                            override fun currentAsInstanceId(): String? = null
                        },
                    serversConfigProvider = TestOAuth2ServersConfigProvider(OAuth2ServersConfig()),
                    opaqueInternalClientSecretVerifier = lazyOf(DefaultOpaqueInternalClientSecretVerifier(secrets)),
                    clientRegistrationStore = InMemoryClientRegistrationStore(),
                    clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                    externalClientSources = lazyOf(emptySet()),
                    configuredClientSetMemoizer = memoizer,
                )
            }

            assertNotNull(registry().getClient("operator-client").value)
            val readsAfterFirstRequest = configReadCount

            assertNotNull(registry().getClient("operator-client").value)
            assertEquals(readsAfterFirstRequest, configReadCount)

            configService.putProperty("oauth2.clients.operator.client-secret-id", "sec_operator_client_0001")
            assertNotNull(registry().getClient("operator-client").value)
            assertTrue(configReadCount > readsAfterFirstRequest)
        }

    @Test
    fun opaqueInternalClientRejectsLegacyProviderReference() =
        runTest {
            val prefix = "oauth2.servers.platform.internal-clients.tenant-as-tenant-123"
            val execution =
                TestSessionExecution(
                    TypeAwarePrincipalConfigService(
                        mapOf(
                            "oauth2.servers.default-server" to "platform",
                            "oauth2.servers.platform.mode" to "HOSTED",
                            "$prefix.client-id" to "tenant-as-service:tenant-123",
                            "$prefix.client-secret-id" to "\${secret:tenant-as/client}",
                        ),
                        normalizeKeys = true,
                    ),
                )
            val registry =
                ConfigAwareClientRegistry(
                    execution = execution,
                    backingStorage = InMemoryOAuth2BackingStorageImpl(),
                    configBinder = OAuth2ClientsConfigBinder(execution, rejectingOpaqueSecrets),
                    asInstanceIdProvider =
                        object : OAuth2ServerInstanceIdProvider {
                            override fun currentAsInstanceId(): String = "platform"
                        },
                    serversConfigProvider = OAuth2ServersConfigBinder(execution, com.sphereon.oauth2.common.config.DefaultOAuth2ServerInstanceIdProvider()),
                    opaqueInternalClientSecretVerifier =
                        lazyOf(DefaultOpaqueInternalClientSecretVerifier(rejectingOpaqueSecrets)),
                    clientRegistrationStore = InMemoryClientRegistrationStore(),
                    clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                    externalClientSources = lazyOf(emptySet()),
                )

            assertTrue(registry.getClient("tenant-as-service:tenant-123").isErr)
        }

    @Test
    fun configuredClientSecretRefreshesWithoutRecreatingSessionRegistry() =
        runTest {
            val resolvedSecrets =
                mutableMapOf(
                    "sec_issuer_initial_0001" to "initial-secret",
                    "sec_issuer_rotated_0001" to "rotated-secret",
                )
            val configService =
                TypeAwarePrincipalConfigService(
                    mapOf(
                        "oauth2.clients.issuer.client-id" to "issuer-service",
                        "oauth2.clients.issuer.client-secret-id" to "sec_issuer_initial_0001",
                        "oauth2.clients.issuer.grant-types" to "client_credentials",
                    ),
                    normalizeKeys = true,
                )
            val execution = TestSessionExecution(configService)
            val registry =
                ConfigAwareClientRegistry(
                    execution = execution,
                    backingStorage = InMemoryOAuth2BackingStorageImpl(),
                    configBinder =
                        OAuth2ClientsConfigBinder(
                            execution,
                            resolvingOpaqueSecrets(resolvedSecrets),
                        ),
                    asInstanceIdProvider =
                        object : OAuth2ServerInstanceIdProvider {
                            override fun currentAsInstanceId(): String? = null
                        },
                    serversConfigProvider = TestOAuth2ServersConfigProvider(OAuth2ServersConfig()),
                    opaqueInternalClientSecretVerifier =
                        lazyOf(DefaultOpaqueInternalClientSecretVerifier(
                            resolvingOpaqueSecrets(resolvedSecrets),
                        )),
                    clientRegistrationStore = InMemoryClientRegistrationStore(),
                    clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                    externalClientSources = lazyOf(emptySet()),
                )

            assertTrue(registry.verifyClientCredentials("issuer-service", "initial-secret").value)

            configService.putProperty("oauth2.clients.issuer.client-secret-id", "sec_issuer_rotated_0001")

            assertFalse(registry.verifyClientCredentials("issuer-service", "initial-secret").value)
            assertTrue(registry.verifyClientCredentials("issuer-service", "rotated-secret").value)
        }

    @Test
    fun compactJwkSetAuthoredByPlatformConfigIsPropagatedToClientRegistration() = runTest {
        val binder =
            OAuth2ClientsConfigBinder(
                TestSessionExecution(
                    TypeAwarePrincipalConfigService(
                        mapOf(
                            "oauth2.servers.default.clients.oidf.client-id" to "oidf-client",
                            "oauth2.servers.default.clients.oidf.client-type" to "confidential",
                            "oauth2.servers.default.clients.oidf.grant-types" to "authorization_code,refresh_token",
                            "oauth2.servers.default.clients.oidf.token-endpoint-auth-method" to "private_key_jwt",
                            "oauth2.servers.default.clients.oidf.token-endpoint-auth-signing-alg" to "ES256",
                            "oauth2.servers.default.clients.oidf.jwks" to
                                """{"keys":[{"kty":"EC","crv":"P-256","kid":"oidf-client-key","x":"yHNp8QgNiVSxSxIH_n_nH23dpUDlNhbgvLKSrjK1hDs","y":"3_rlpW_FXqghp8dKPpkjfvbfACQQFLFZwJXxOr319Ac","use":"sig","alg":"ES256"}]}""",
                        ),
                        normalizeKeys = true,
                    ),
                ),
                rejectingOpaqueSecrets,
            )

        val result = binder.loadClientRegistrations(serverId = "default")

        assertTrue(result.isOk)
        val registration = assertNotNull(result.value["oidf-client"])
        assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, registration.tokenEndpointAuthMethod)
        assertEquals(listOf("ES256"), registration.tokenEndpointAuthSigningAlg)
        assertEquals("oidf-client-key", registration.jwks?.single()?.kid)
    }

    @Test
    fun configuredClientAudiencePolicyIsPropagatedToClientRegistration() = runTest {
        val binder =
            OAuth2ClientsConfigBinder(
                TestSessionExecution(
                    TypeAwarePrincipalConfigService(
                        mapOf(
                            "oauth2.clients.issuer.client-id" to "issuer-service",
                            "oauth2.clients.issuer.grant-types" to "client_credentials",
                            "oauth2.clients.issuer.default-access-token-audience" to "enterprise-platform",
                            "oauth2.clients.issuer.allowed-access-token-audiences" to
                                "enterprise-tenant-kms,enterprise-wallet-interaction",
                            "oauth2.clients.issuer.token-endpoint-auth-method" to "private_key_jwt",
                            "oauth2.clients.issuer.token-endpoint-auth-signing-alg" to "ES256,PS256",
                        ),
                        normalizeKeys = true,
                    ),
                ),
                rejectingOpaqueSecrets,
            )

        val result = binder.loadClientRegistrations()

        assertTrue(result.isOk)
        val registration = assertNotNull(result.value["issuer-service"])
        assertEquals("enterprise-platform", registration.defaultAccessTokenAudience)
        assertEquals(
            setOf("enterprise-tenant-kms", "enterprise-wallet-interaction"),
            registration.allowedAccessTokenAudiences,
        )
        assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, registration.tokenEndpointAuthMethod)
        assertEquals(listOf("ES256", "PS256"), registration.tokenEndpointAuthSigningAlg)
    }

    @Test
    fun serverCanUseGlobalClientWithoutInheritingItsAudiencePolicy() = runTest {
        val serverId = "acme"
        val configService =
            TypeAwarePrincipalConfigService(
                mapOf(
                    "oauth2.clients.operator.client-id" to "platform-operator-cli",
                    "oauth2.clients.operator.client-type" to "public",
                    "oauth2.clients.operator.grant-types" to "authorization_code",
                    "oauth2.clients.operator.default-access-token-audience" to "enterprise-platform",
                    "oauth2.clients.operator.allowed-access-token-audiences" to "enterprise-platform",
                    "oauth2.servers.$serverId.inherit-global-client-audiences" to "false",
                ),
                normalizeKeys = true,
            )
        val execution = TestSessionExecution(configService, tenantId = "tenant-acme")
        val registry =
            ConfigAwareClientRegistry(
                execution = execution,
                backingStorage = InMemoryOAuth2BackingStorageImpl(),
                configBinder = OAuth2ClientsConfigBinder(execution, rejectingOpaqueSecrets),
                asInstanceIdProvider =
                    object : OAuth2ServerInstanceIdProvider {
                        override fun currentAsInstanceId(): String = serverId
                    },
                serversConfigProvider =
                    TestOAuth2ServersConfigProvider(
                        OAuth2ServersConfig(
                            defaultServer = serverId,
                            servers = mapOf(serverId to OAuth2ServerInstanceConfig()),
                        ),
                    ),
                opaqueInternalClientSecretVerifier =
                    lazyOf(DefaultOpaqueInternalClientSecretVerifier(rejectingOpaqueSecrets)),
                clientRegistrationStore = InMemoryClientRegistrationStore(),
                clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                externalClientSources = lazyOf(emptySet()),
            )

        val registration = assertNotNull(registry.getClient("platform-operator-cli").value)
        assertNull(registration.defaultAccessTokenAudience)
        assertTrue(registration.allowedAccessTokenAudiences.isEmpty())
    }

    @Test
    fun internalClientDefaultAudienceIsPropagatedToClientRegistration() =
        runTest {
            val serverId = "platform"
            val config =
                OAuth2ServersConfig(
                    defaultServer = serverId,
                    servers =
                        mapOf(
                            serverId to
                                OAuth2ServerInstanceConfig(
                                    internalClients =
                                        mapOf(
                                            "tenantas" to
                                                InternalClientConfig(
                                                    clientId = "tenant-as-service",
                                                    clientSecret = "tenant-as-secret",
                                                    grantTypes = setOf(GrantType.CLIENT_CREDENTIALS, GrantType.TOKEN_EXCHANGE),
                                                    tenantId = "tenant-acme",
                                                    defaultAccessTokenAudience = "enterprise-platform",
                                                    allowedAccessTokenAudiences = setOf("enterprise-tenant-kms"),
                                                ),
                                        ),
                                ),
                        ),
                )
            val execution = TestSessionExecution(TypeAwarePrincipalConfigService(emptyMap()))
            val registry =
                ConfigAwareClientRegistry(
                    execution = execution,
                    backingStorage = InMemoryOAuth2BackingStorageImpl(),
                    configBinder =
                        OAuth2ClientsConfigBinder(
                            execution,
                            rejectingOpaqueSecrets,
                        ),
                    asInstanceIdProvider =
                        object : OAuth2ServerInstanceIdProvider {
                            override fun currentAsInstanceId(): String = serverId
                        },
                    serversConfigProvider = TestOAuth2ServersConfigProvider(config),
                    opaqueInternalClientSecretVerifier =
                        lazyOf(DefaultOpaqueInternalClientSecretVerifier(rejectingOpaqueSecrets)),
                    clientRegistrationStore = InMemoryClientRegistrationStore(),
                    clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                    externalClientSources = lazyOf(emptySet()),
                )

            val result = registry.getClient("tenant-as-service")

            assertTrue(result.isOk)
            val registration = assertNotNull(result.value)
            assertEquals("tenant-as-secret", registration.clientSecret)
            assertEquals(listOf(GrantType.CLIENT_CREDENTIALS, GrantType.TOKEN_EXCHANGE), registration.grantTypes)
            assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, registration.tokenEndpointAuthMethod)
            assertEquals("enterprise-platform", registration.defaultAccessTokenAudience)
            assertEquals(setOf("enterprise-tenant-kms"), registration.allowedAccessTokenAudiences)
            assertEquals("tenant-acme", registration.additionalMetadata["tenant_id"])
        }

    @Test
    fun configuredClientPrincipalRolesArePropagatedToClientRegistration() =
        runTest {
            val binder =
                OAuth2ClientsConfigBinder(
                    TestSessionExecution(
                        TypeAwarePrincipalConfigService(
                            mapOf(
                                "oauth2.clients.workload.client-id" to "tenant-workload",
                                "oauth2.clients.workload.grant-types" to "client_credentials",
                                "oauth2.clients.workload.default-access-token-audience" to "enterprise-platform",
                                "oauth2.clients.workload.principal-roles" to "tenant-admin",
                                "oauth2.clients.plain.client-id" to "plain-workload",
                                "oauth2.clients.plain.grant-types" to "client_credentials",
                            ),
                            normalizeKeys = true,
                        ),
                    ),
                    rejectingOpaqueSecrets,
                )

            val result = binder.loadClientRegistrations()

            assertTrue(result.isOk)
            assertEquals(listOf("tenant-admin"), assertNotNull(result.value["tenant-workload"]).principalRoles)
            assertTrue(assertNotNull(result.value["plain-workload"]).principalRoles.isEmpty())
        }

    @Test
    fun dynamicRegistrationRoundTripsPrincipalRolesThroughTheStore() =
        runTest {
            val execution = TestSessionExecution(TypeAwarePrincipalConfigService(emptyMap(), normalizeKeys = true))
            val store = InMemoryClientRegistrationStore()
            fun registry(): ConfigAwareClientRegistry =
                ConfigAwareClientRegistry(
                    execution = execution,
                    backingStorage = InMemoryOAuth2BackingStorageImpl(),
                    configBinder = OAuth2ClientsConfigBinder(execution, rejectingOpaqueSecrets),
                    asInstanceIdProvider =
                        object : OAuth2ServerInstanceIdProvider {
                            override fun currentAsInstanceId(): String? = null
                        },
                    serversConfigProvider =
                        TestOAuth2ServersConfigProvider(
                            OAuth2ServersConfig(
                                defaultServer = SERVER_ID,
                                servers = mapOf(SERVER_ID to OAuth2ServerInstanceConfig()),
                            ),
                        ),
                    opaqueInternalClientSecretVerifier = lazyOf(DefaultOpaqueInternalClientSecretVerifier(rejectingOpaqueSecrets)),
                    clientRegistrationStore = store,
                    clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                    externalClientSources = lazyOf(emptySet()),
                )
            val registration =
                ClientRegistration(
                    clientId = "dyn-workload",
                    clientSecret = "workload-secret",
                    clientType = ClientType.CONFIDENTIAL,
                    grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                    defaultAccessTokenAudience = "enterprise-platform",
                    principalRoles = listOf("tenant-admin"),
                    tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                )

            assertTrue(registry().registerClient(registration).isOk)
            val stored = store.findByClientId(execution.tenantId, SERVER_ID, "dyn-workload")
            assertTrue(stored.isOk)
            assertEquals(listOf("tenant-admin"), assertNotNull(stored.value).registration.principalRoles)

            val reloaded = registry().getClient("dyn-workload")
            assertTrue(reloaded.isOk)
            assertEquals(listOf("tenant-admin"), assertNotNull(reloaded.value).principalRoles)
        }

    @Test
    fun configuredClientSecretRejectsLegacyPlaintextAndProviderReference() =
        runTest {
            listOf("literal-plaintext", "\${secret:oauth/issuer/client-secret}").forEach { legacyValue ->
                val configService =
                    TypeAwarePrincipalConfigService(
                        mapOf(
                            "oauth2.clients.issuer.client-id" to "issuer-service",
                            "oauth2.clients.issuer.client-secret" to legacyValue,
                            "oauth2.clients.issuer.grant-types" to "client_credentials",
                        ),
                        normalizeKeys = true,
                    )
                val binder = OAuth2ClientsConfigBinder(TestSessionExecution(configService), rejectingOpaqueSecrets)

                val result = binder.loadClientRegistrations()

                assertTrue(result.isErr)
            }
        }

    @Test
    fun configuredClientSecretIdRejectsLegacyProviderReference() =
        runTest {
            val configService =
                TypeAwarePrincipalConfigService(
                    mapOf(
                        "oauth2.clients.issuer.client-id" to "issuer-service",
                        "oauth2.clients.issuer.client-secret-id" to "\${secret:oauth/issuer/client-secret}",
                        "oauth2.clients.issuer.grant-types" to "client_credentials",
                    ),
                    normalizeKeys = true,
                )
            val binder = OAuth2ClientsConfigBinder(TestSessionExecution(configService), rejectingOpaqueSecrets)

            val result = binder.loadClientRegistrations()

            assertTrue(result.isErr)
        }

    @Test
    fun persistedClientWinsOverConfigurationOnATenantAuthorizationServer() =
        runTest {
            val store = InMemoryClientRegistrationStore()
            val registry = precedenceRegistry(ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY, store)
            storeClient(store, clientName = "persisted", secret = "persisted-secret")

            assertEquals("persisted", assertNotNull(registry.getClient(SHARED_CLIENT_ID).value).clientName)
            assertTrue(registry.verifyClientCredentials(SHARED_CLIENT_ID, "persisted-secret").value)
            assertEquals(
                "persisted",
                assertNotNull(
                    registry.listClients(limit = 10, offset = 0).value.single { it.clientId == SHARED_CLIENT_ID },
                ).clientName,
                "the listing path must agree with the authentication path",
            )
        }

    @Test
    fun configuredClientWinsOverPersistenceOnAConfigurationPrimaryAuthorizationServer() =
        runTest {
            val store = InMemoryClientRegistrationStore()
            val registry = precedenceRegistry(ClientRegistrySourcePrecedence.CONFIGURATION_PRIMARY, store)
            storeClient(store, clientName = "persisted", secret = "persisted-secret")

            assertEquals("configured", assertNotNull(registry.getClient(SHARED_CLIENT_ID).value).clientName)
            assertTrue(registry.verifyClientCredentials(SHARED_CLIENT_ID, CONFIGURED_SECRET).value)
            assertFalse(registry.verifyClientCredentials(SHARED_CLIENT_ID, "persisted-secret").value)
            assertEquals(
                "configured",
                assertNotNull(
                    registry.listClients(limit = 10, offset = 0).value.single { it.clientId == SHARED_CLIENT_ID },
                ).clientName,
                "the listing path must agree with the authentication path",
            )
        }

    @Test
    fun opaqueInternalClientCredentialsWinUnderEitherPrecedence() =
        runTest {
            ClientRegistrySourcePrecedence.entries.forEach { precedence ->
                val store = InMemoryClientRegistrationStore()
                val registry =
                    precedenceRegistry(
                        precedence,
                        store,
                        extraProperties =
                            mapOf(
                                "oauth2.servers.$SERVER_ID.internal-clients.workload.client-id" to INTERNAL_CLIENT_ID,
                                "oauth2.servers.$SERVER_ID.internal-clients.workload.client-secret-id" to INTERNAL_SECRET_ID,
                                "oauth2.servers.$SERVER_ID.internal-clients.workload.grant-types" to "client_credentials",
                                "oauth2.servers.$SERVER_ID.internal-clients.workload.tenant-id" to TENANT_ID,
                            ),
                    )
                storeClient(store, clientName = "persisted", secret = "persisted-secret", clientId = INTERNAL_CLIENT_ID)

                assertTrue(
                    registry.verifyClientCredentials(INTERNAL_CLIENT_ID, INTERNAL_SECRET).value,
                    "opaque internal clients keep priority under $precedence",
                )
                assertFalse(registry.verifyClientCredentials(INTERNAL_CLIENT_ID, "persisted-secret").value)
            }
        }

    @Test
    fun unknownClientIdFailsClosedUnderEitherPrecedence() =
        runTest {
            ClientRegistrySourcePrecedence.entries.forEach { precedence ->
                val registry = precedenceRegistry(precedence, InMemoryClientRegistrationStore())

                assertNull(registry.getClient("absent-client").value)
                assertFalse(registry.verifyClientCredentials("absent-client", CONFIGURED_SECRET).value)
            }
        }

    @Test
    fun configuredSecretCannotAuthenticateAClientIdOwnedByPersistentStorage() =
        runTest {
            val store = InMemoryClientRegistrationStore()
            val registry = precedenceRegistry(ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY, store)
            storeClient(store, clientName = "persisted", secret = "persisted-secret")

            assertFalse(
                registry.verifyClientCredentials(SHARED_CLIENT_ID, CONFIGURED_SECRET).value,
                "a persisted client id must authenticate against its stored secret only",
            )
            assertTrue(registry.verifyClientCredentials(SHARED_CLIENT_ID, "persisted-secret").value)
            assertFalse(registry.verifyClientCredentials(SHARED_CLIENT_ID, "neither-secret").value)
        }

    @Test
    fun configuredSecretAuthenticatesWhenPersistentStorageHasNoRegistrationForTheClientId() =
        runTest {
            val registry =
                precedenceRegistry(ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY, InMemoryClientRegistrationStore())

            assertTrue(registry.verifyClientCredentials(SHARED_CLIENT_ID, CONFIGURED_SECRET).value)
            assertEquals("configured", assertNotNull(registry.getClient(SHARED_CLIENT_ID).value).clientName)
        }

    @Test
    fun revokedStoredRegistrationDoesNotBlockTheConfiguredClient() =
        runTest {
            val store = InMemoryClientRegistrationStore()
            val registry = precedenceRegistry(ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY, store)
            storeClient(store, clientName = "persisted", secret = "persisted-secret")
            assertTrue(store.revoke(TENANT_ID, SERVER_ID, SHARED_CLIENT_ID).value)

            assertTrue(registry.verifyClientCredentials(SHARED_CLIENT_ID, CONFIGURED_SECRET).value)
            assertFalse(registry.verifyClientCredentials(SHARED_CLIENT_ID, "persisted-secret").value)
            assertEquals("configured", assertNotNull(registry.getClient(SHARED_CLIENT_ID).value).clientName)
        }

    @Test
    fun configuredSecretKeepsAuthenticatingAlongsidePersistenceOnAConfigurationPrimaryServer() =
        runTest {
            val store = InMemoryClientRegistrationStore()
            val registry = precedenceRegistry(ClientRegistrySourcePrecedence.CONFIGURATION_PRIMARY, store)
            storeClient(store, clientName = "persisted", secret = "persisted-secret")

            assertTrue(registry.verifyClientCredentials(SHARED_CLIENT_ID, CONFIGURED_SECRET).value)
            assertFalse(registry.verifyClientCredentials(SHARED_CLIENT_ID, "persisted-secret").value)
        }

    @Test
    fun shadowedConfiguredClientIsReportedOnceWhilePersistentStorageOwnsTheClientId() =
        runTest {
            val store = InMemoryClientRegistrationStore()
            val log = RecordingSessionLogService()
            val registry = precedenceRegistry(ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY, store, log = log)
            storeClient(store, clientName = "persisted", secret = "persisted-secret")

            registry.verifyClientCredentials(SHARED_CLIENT_ID, CONFIGURED_SECRET)
            registry.verifyClientCredentials(SHARED_CLIENT_ID, "persisted-secret")
            registry.getClient(SHARED_CLIENT_ID)
            registry.listClients(limit = 10, offset = 0)

            val warnings = log.messages.filter { it.level == LogLevel.WARN }
            assertEquals(1, warnings.size, "the shadowed configuration entry must be reported once, not per request")
            assertTrue(warnings.single().message.contains(SHARED_CLIENT_ID))
            assertTrue(warnings.single().message.contains(SERVER_ID))
            assertFalse(warnings.single().message.contains(CONFIGURED_SECRET))
        }

    @Test
    fun noShadowWarningWithoutAPersistedRegistrationOrUnderConfigurationPrimary() =
        runTest {
            val withoutPersistedClient = RecordingSessionLogService()
            precedenceRegistry(
                ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY,
                InMemoryClientRegistrationStore(),
                log = withoutPersistedClient,
            ).also {
                it.verifyClientCredentials(SHARED_CLIENT_ID, CONFIGURED_SECRET)
                it.listClients(limit = 10, offset = 0)
            }

            val configurationPrimaryStore = InMemoryClientRegistrationStore()
            val configurationPrimary = RecordingSessionLogService()
            val configurationPrimaryRegistry =
                precedenceRegistry(ClientRegistrySourcePrecedence.CONFIGURATION_PRIMARY, configurationPrimaryStore, log = configurationPrimary)
            storeClient(configurationPrimaryStore, clientName = "persisted", secret = "persisted-secret")
            configurationPrimaryRegistry.verifyClientCredentials(SHARED_CLIENT_ID, CONFIGURED_SECRET)
            configurationPrimaryRegistry.getClient(SHARED_CLIENT_ID)
            configurationPrimaryRegistry.listClients(limit = 10, offset = 0)

            assertTrue(withoutPersistedClient.messages.none { it.level == LogLevel.WARN })
            assertTrue(configurationPrimary.messages.none { it.level == LogLevel.WARN })
        }

    private class RecordingExternalSource(
        private val answer: IdkResult<ClientRegistration?, AuthorizationServerError.StorageError>,
    ) : ExternalClientSource {
        val asked = mutableListOf<String>()

        override suspend fun resolve(clientId: String): IdkResult<ClientRegistration?, AuthorizationServerError.StorageError> {
            asked += clientId
            return answer
        }
    }

    private fun externalClient(clientId: String) =
        ClientRegistration(clientId = clientId, grantTypes = listOf(GrantType.AUTHORIZATION_CODE), clientType = ClientType.PUBLIC)

    @Test
    fun externalSourcesAreAskedOnlyForClientsNeitherConfiguredNorStored() =
        runTest {
            val external = "https://rp.example.com"
            val source = RecordingExternalSource(Ok(externalClient(external)))
            for (precedence in ClientRegistrySourcePrecedence.entries) {
                source.asked.clear()
                val view =
                    precedenceRegistry(precedence, InMemoryClientRegistrationStore(), externalClientSources = setOf(source))
                        .resolveClientRegistryRequestView().value
                assertNotNull(view.getClient(SHARED_CLIENT_ID).value)
                assertEquals(emptyList(), source.asked)
                assertEquals(external, view.getClient(external).value?.clientId)
                assertEquals(listOf(external), source.asked)
            }
        }

    @Test
    fun aRevokedStoredRegistrationIsNotReadmittedByAnExternalSource() =
        runTest {
            val external = "https://rp.example.com"
            for (precedence in ClientRegistrySourcePrecedence.entries) {
                val store = InMemoryClientRegistrationStore()
                storeClient(store, clientName = "registered", secret = "registered-secret", clientId = external)
                assertTrue(store.revoke(TENANT_ID, SERVER_ID, external).value)
                val source = RecordingExternalSource(Ok(externalClient(external)))
                val view = precedenceRegistry(precedence, store, externalClientSources = setOf(source))
                    .resolveClientRegistryRequestView().value

                assertNull(view.getClient(external).value, "a revoked registration stops the client ($precedence)")
                assertEquals(emptyList(), source.asked, "no external source is consulted for a revoked client ($precedence)")
            }
        }

    @Test
    fun externalClientClaimedByTwoSourcesOrRenamedIsNotResolved() =
        runTest {
            val external = "https://rp.example.com"
            val twice =
                precedenceRegistry(
                    ClientRegistrySourcePrecedence.CONFIGURATION_PRIMARY,
                    InMemoryClientRegistrationStore(),
                    externalClientSources = setOf(RecordingExternalSource(Ok(externalClient(external))), RecordingExternalSource(Ok(externalClient(external)))),
                ).resolveClientRegistryRequestView().value
            assertNull(twice.getClient(external).value)

            val renamed =
                precedenceRegistry(
                    ClientRegistrySourcePrecedence.CONFIGURATION_PRIMARY,
                    InMemoryClientRegistrationStore(),
                    externalClientSources = setOf(RecordingExternalSource(Ok(externalClient("https://other.example.com")))),
                ).resolveClientRegistryRequestView().value
            assertTrue(renamed.getClient(external).isErr)

            val failing =
                precedenceRegistry(
                    ClientRegistrySourcePrecedence.CONFIGURATION_PRIMARY,
                    InMemoryClientRegistrationStore(),
                    externalClientSources = setOf(RecordingExternalSource(Err(AuthorizationServerError.StorageError("lookup", "unavailable")))),
                ).resolveClientRegistryRequestView().value
            assertTrue(failing.getClient(external).isErr)
        }

    private fun precedenceRegistry(
        precedence: ClientRegistrySourcePrecedence,
        store: ClientRegistrationStore,
        extraProperties: Map<String, String> = emptyMap(),
        log: SessionLogService = NoOpSessionLogService,
        externalClientSources: Set<ExternalClientSource> = emptySet(),
    ): ConfigAwareClientRegistry {
        val configService =
            TypeAwarePrincipalConfigService(
                properties =
                    mapOf(
                        "oauth2.servers.default-server" to SERVER_ID,
                        "oauth2.servers.$SERVER_ID.mode" to "HOSTED",
                        "oauth2.clients.shared.client-id" to SHARED_CLIENT_ID,
                        "oauth2.clients.shared.client-name" to "configured",
                        "oauth2.clients.shared.client-secret-id" to CONFIGURED_SECRET_ID,
                        "oauth2.clients.shared.grant-types" to "client_credentials",
                    ) + extraProperties,
                normalizeKeys = true,
            )
        val execution = TestSessionExecution(configService, tenantId = TENANT_ID, log = log)
        val secrets =
            resolvingOpaqueSecrets(
                mapOf(
                    CONFIGURED_SECRET_ID to CONFIGURED_SECRET,
                    INTERNAL_SECRET_ID to INTERNAL_SECRET,
                ),
            )
        return ConfigAwareClientRegistry(
            execution = execution,
            backingStorage = InMemoryOAuth2BackingStorageImpl(),
            configBinder = OAuth2ClientsConfigBinder(execution, secrets),
            asInstanceIdProvider =
                object : OAuth2ServerInstanceIdProvider {
                    override fun currentAsInstanceId(): String = SERVER_ID
                },
            serversConfigProvider =
                TestOAuth2ServersConfigProvider(
                    OAuth2ServersConfig(
                        defaultServer = SERVER_ID,
                        servers = mapOf(SERVER_ID to OAuth2ServerInstanceConfig(clientRegistrySourcePrecedence = precedence)),
                    ),
                ),
            opaqueInternalClientSecretVerifier = lazyOf(DefaultOpaqueInternalClientSecretVerifier(secrets)),
            clientRegistrationStore = store,
            clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
            externalClientSources = lazyOf(externalClientSources),
        )
    }

    @Test
    fun platformServerIsConfigurationPrimaryFromShippedConfigurationAlone() =
        runTest {
            val configService =
                TypeAwarePrincipalConfigService(
                    properties =
                        mapOf(
                            "oauth2.servers.default.mode" to "HOSTED",
                            "oauth2.servers.default.issuer" to "https://platform.example.com",
                            "oauth2.servers.default.client-registry-source-precedence" to "configuration-primary",
                            "oauth2.clients.shared.client-id" to SHARED_CLIENT_ID,
                            "oauth2.clients.shared.client-name" to "configured",
                            "oauth2.clients.shared.client-secret-id" to CONFIGURED_SECRET_ID,
                            "oauth2.clients.shared.grant-types" to "client_credentials",
                        ),
                    normalizeKeys = true,
                )
            val execution = TestSessionExecution(configService, tenantId = TENANT_ID)
            val secrets = resolvingOpaqueSecrets(mapOf(CONFIGURED_SECRET_ID to CONFIGURED_SECRET))
            val serversConfigProvider = OAuth2ServersConfigBinder(execution, com.sphereon.oauth2.common.config.DefaultOAuth2ServerInstanceIdProvider())

            val serversConfig = serversConfigProvider.getConfig()
            assertEquals("default", serversConfig.defaultServer)
            assertEquals(
                ClientRegistrySourcePrecedence.CONFIGURATION_PRIMARY,
                assertNotNull(serversConfig.servers["default"]).clientRegistrySourcePrecedence,
                "the shipped platform configuration alone must classify the platform AS, with no bootstrap write",
            )

            val store = InMemoryClientRegistrationStore()
            val registry =
                ConfigAwareClientRegistry(
                    execution = execution,
                    backingStorage = InMemoryOAuth2BackingStorageImpl(),
                    configBinder = OAuth2ClientsConfigBinder(execution, secrets),
                    // No HTTP adapter has set an AS instance id, which is how every non-HTTP
                    // lookup (service JWT over gRPC) reaches the registry.
                    asInstanceIdProvider =
                        object : OAuth2ServerInstanceIdProvider {
                            override fun currentAsInstanceId(): String? = null
                        },
                    serversConfigProvider = serversConfigProvider,
                    opaqueInternalClientSecretVerifier = lazyOf(DefaultOpaqueInternalClientSecretVerifier(secrets)),
                    clientRegistrationStore = store,
                    clientSecretHasher = ClientSecretHasher(defaultSecureRandom()),
                    externalClientSources = lazyOf(emptySet()),
                )
            storeClient(store, clientName = "persisted", secret = "persisted-secret")

            assertEquals("configured", assertNotNull(registry.getClient(SHARED_CLIENT_ID).value).clientName)
            assertTrue(registry.verifyClientCredentials(SHARED_CLIENT_ID, CONFIGURED_SECRET).value)
        }

    private suspend fun storeClient(
        store: ClientRegistrationStore,
        clientName: String,
        secret: String,
        clientId: String = SHARED_CLIENT_ID,
    ) {
        val now = Clock.System.now()
        store.save(
            TENANT_ID,
            StoredClientRegistration(
                tenantId = TENANT_ID,
                authorizationServerId = SERVER_ID,
                clientId = clientId,
                clientSecretHash = ClientSecretHasher(defaultSecureRandom()).hash(secret),
                registeredAt = now,
                updatedAt = now,
                registration =
                    DynamicClientRegistrationMetadata(
                        clientName = clientName,
                        grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                        tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                    ),
            ),
        )
    }

    private companion object {
        const val TENANT_ID = "tenant-one"
        const val SERVER_ID = "tenant-as"
        const val SHARED_CLIENT_ID = "shared-client"
        const val CONFIGURED_SECRET_ID = "sec_shared_client_0001"
        const val CONFIGURED_SECRET = "configured-secret"
        const val INTERNAL_CLIENT_ID = "workload-client"
        const val INTERNAL_SECRET_ID = "sec_workload_internal_0001"
        const val INTERNAL_SECRET = "internal-secret"

        val rejectingOpaqueSecrets =
            OpaqueSecretResolver {
                Err(IdkError.NOT_FOUND_ERROR(resource = "secret", message = "Secret not found"))
            }

        fun resolvingOpaqueSecrets(values: Map<String, String>) =
            OpaqueSecretResolver { secretId ->
                values[secretId]
                    ?.let { Ok(it) }
                    ?: Err(IdkError.NOT_FOUND_ERROR(resource = "secret", message = "Secret not found"))
            }
    }
}
