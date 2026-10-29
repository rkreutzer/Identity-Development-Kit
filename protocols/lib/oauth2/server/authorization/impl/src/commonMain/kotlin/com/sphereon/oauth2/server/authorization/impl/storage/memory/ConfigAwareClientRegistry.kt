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
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.ConfigLevel
import com.sphereon.core.api.conf.configContentRevision
import com.sphereon.core.api.security.ConstantTime
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.server.authorization.provider.ExternalClientSource
import com.sphereon.oauth2.common.config.ClientRegistrySourcePrecedence
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceIdProvider
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.config.OAuth2ClientsConfigBinder
import com.sphereon.oauth2.server.authorization.impl.config.OpaqueInternalClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientType
import com.sphereon.oauth2.server.authorization.storage.ClientSecretHasher
import com.sphereon.oauth2.server.authorization.storage.ClientRegistrationStore
import com.sphereon.oauth2.server.authorization.storage.ClientRegistrationStatus
import com.sphereon.oauth2.server.authorization.storage.DynamicClientRegistrationMetadata
import com.sphereon.oauth2.server.authorization.storage.StoredClientRegistration
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.time.TimeSource

/**
 * Session-scoped client registry that overlays principal-resolved static client configuration
 * on top of the durable dynamic-client store used by tests, dev flows, and provisioned
 * infrastructure clients (for example RFC 8628 device-flow screens).
 *
 * Configured clients are available for the current session context. Programmatically registered
 * clients persist through [ClientRegistrationStore]: an in-memory default keeps historical
 * behaviour when no durable backend is on the classpath, while the EDK Postgres implementation
 * swaps in via its `replaces` binding so registrations survive restarts.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<ClientRegistry>())
class ConfigAwareClientRegistry(
    private val execution: SessionExecution,
    private val backingStorage: InMemoryOAuth2BackingStorage,
    private val configBinder: OAuth2ClientsConfigBinder,
    private val asInstanceIdProvider: OAuth2ServerInstanceIdProvider,
    private val serversConfigProvider: OAuth2ServersConfigProvider,
    private val opaqueInternalClientSecretVerifier: Lazy<OpaqueInternalClientSecretVerifier>,
    private val clientRegistrationStore: ClientRegistrationStore,
    private val clientSecretHasher: ClientSecretHasher,
    private val externalClientSources: Lazy<Set<ExternalClientSource>>,
    private val clock: Clock = Clock.System,
    private val configuredClientSetMemoizer: ConfiguredClientSetMemoizer = ConfiguredClientSetMemoizer(),
) : ClientRegistry {
    private val partitionKey = OAuth2StoragePartitionKey.appLevel()
    private val partition get() = backingStorage.getPartition(partitionKey)
    private val shadowWarningMutex = Mutex()
    private val shadowWarnedClientIds = mutableSetOf<String>()

    /**
     * Configured clients merged from two sources:
     *
     *  - `oauth2.clients.<id>.*` — the global public client registry consumed by the
     *    authorization code / device / pre-authorized-code flows.
     *  - `oauth2.servers.<asId>.clients.<id>.*` — active-AS-scoped public clients, overlaid
     *    on top of the global registry when an AS instance is resolved.
     *  - `oauth2.servers.<asId>.internal-clients.<role>.*` — server-to-server resource-server
     *    clients (e.g. the OID4VCI / OID4VP / introspection callers). They authenticate via
     *    `client_secret_basic` and are recognized as resource servers by the introspection
     *    command, which lifts the §2.2 confused-deputy ownership check for them.
     *
     * Keeping both lists in the same registry means client authentication code paths don't have
     * to special-case internal callers — they look up the clientId here just like any other
     * client. Internal IDs colliding with regular `oauth2.clients` IDs are rejected loudly to
     * surface operator misconfiguration.
     */
    private suspend fun configuredClientSet(): IdkResult<ConfiguredClientSet, AuthorizationServerError.StorageError> {
        // Resolving the key refreshes every refreshable property source before hashing it, so this
        // is a potential I/O step on the token path and not just a map lookup. It is measured
        // separately from the binds it guards.
        val keyResolution = TimeSource.Monotonic.markNow()
        val key = resolutionKey()
        val keyResolutionMs = keyResolution.elapsedNow().inWholeMilliseconds
        return configuredClientSetMemoizer
            .getOrResolve(key, ::resolveConfiguredClientSet)
            .also {
                execution.log.debug(
                    "VDX_OAUTH2_CLIENT_REGISTRY_TIMING stage=config-revision-resolution elapsedMs=$keyResolutionMs",
                )
            }
    }

    /**
     * Identity of the configuration this registry last resolved against: the active AS instance
     * plus the revision of every property source that can feed a client registration.
     *
     * A registry instance is `@SingleIn(SessionScope::class)` and a session is created per
     * inbound request (the transport derives its id from the request's trace id). This memoizer
     * owns the assembled request view, including any resolved configured-client or typed
     * bootstrap secret, and therefore never crosses the request boundary. The lower-level
     * [com.sphereon.oauth2.server.authorization.impl.config.OAuth2ClientMetadataCache] shares only
     * parsed non-secret metadata and opaque locators under the exact principal config view and
     * revision. The opaque-client verifier still resolves and compares protected credentials per
     * request.
     *
     * Keying on the configuration revision keeps the re-read that tenant provisioning depends
     * on: a client published mid-request, or a secret id rotated mid-request, moves the revision
     * and the next lookup rebinds. Opaque internal client secrets are not affected either way —
     * only the credential locator is carried here, and the verifier resolves the secret itself on
     * every verification.
     */
    private fun resolutionKey(): ResolutionKey =
        ResolutionKey(
            tenantId = execution.tenantId,
            asInstanceId = asInstanceIdProvider.currentAsInstanceId(),
            configRevision = execution.conf.conf(ConfigLevel.PRINCIPAL).configContentRevision(),
        )

    private suspend fun resolveConfiguredClientSet(): IdkResult<ConfiguredClientSet, AuthorizationServerError.StorageError> {
        val started = TimeSource.Monotonic.markNow()
        val serversConfig = serversConfigProvider.getConfig()
        val serversConfigMs = started.elapsedNow().inWholeMilliseconds
        val activeServerId = activeServerId(serversConfig)
        val globalBind = TimeSource.Monotonic.markNow()
        val globalClients = configBinder.loadClientRegistrations(activeServerId = activeServerId)
        val globalBindMs = globalBind.elapsedNow().inWholeMilliseconds
        if (globalClients.isErr) return Err(globalClients.error)
        val serverBind = TimeSource.Monotonic.markNow()
        val serverClients = configBinder.loadClientRegistrations(activeServerId)
        val serverBindMs = serverBind.elapsedNow().inWholeMilliseconds
        if (serverClients.isErr) return Err(serverClients.error)
        val opaqueBind = TimeSource.Monotonic.markNow()
        val opaqueInternalClients = configBinder.loadOpaqueInternalClientRegistrations(activeServerId)
        val opaqueBindMs = opaqueBind.elapsedNow().inWholeMilliseconds
        if (opaqueInternalClients.isErr) return Err(opaqueInternalClients.error)
        val inheritGlobalClientAudiences =
            execution.conf.conf(ConfigLevel.PRINCIPAL)
                .getPropertyAsString("oauth2.servers.$activeServerId.inherit-global-client-audiences", null)
                ?.trim()
                ?.lowercase()
                ?.let { configured ->
                    require(configured == "true" || configured == "false") {
                        "oauth2.servers.$activeServerId.inherit-global-client-audiences must be true or false"
                    }
                    configured.toBoolean()
                }
                ?: true
        val merged = LinkedHashMap(
            if (inheritGlobalClientAudiences) {
                globalClients.value
            } else {
                globalClients.value.mapValues { (_, registration) ->
                    registration.copy(
                        defaultAccessTokenAudience = null,
                        allowedAccessTokenAudiences = emptySet(),
                    )
                }
            },
        )
        for ((clientId, registration) in serverClients.value) {
            merged[clientId] = registration
        }
        val typedInternalClients = loadInternalClientRegistrations(serversConfig)
        for ((clientId, registration) in typedInternalClients) {
            require(!merged.containsKey(clientId)) {
                "Internal client id '$clientId' collides with an `oauth2.clients` registration"
            }
            merged[clientId] = registration
        }
        for ((clientId, configured) in opaqueInternalClients.value) {
            require(!merged.containsKey(clientId)) {
                "Opaque internal client id '$clientId' collides with another OAuth2 client registration"
            }
            merged[clientId] = configured.registration
        }
        execution.log.debug(
            "VDX_OAUTH2_CLIENT_REGISTRY_TIMING stage=configured-client-set " +
                "elapsedMs=${started.elapsedNow().inWholeMilliseconds} " +
                "serversConfigMs=$serversConfigMs globalBindMs=$globalBindMs " +
                "serverBindMs=$serverBindMs opaqueBindMs=$opaqueBindMs " +
                "global=${globalClients.value.size} server=${serverClients.value.size} " +
                "typedInternal=${typedInternalClients.size} opaqueInternal=${opaqueInternalClients.value.size}",
        )
        return Ok(
            ConfiguredClientSet(
                registrations = merged,
                opaqueInternalClients = opaqueInternalClients.value,
                sourcePrecedence = sourcePrecedence(serversConfig, activeServerId),
                activeServerId = activeServerId,
            ),
        )
    }

    private suspend fun configuredClients(): IdkResult<Map<String, ClientRegistration>, AuthorizationServerError.StorageError> {
        val configured = configuredClientSet()
        return if (configured.isOk) Ok(configured.value.registrations) else Err(configured.error)
    }

    /**
     * Source the active authorization server treats as authoritative when a client id exists in
     * both. Resolved once per configured-client set so every read path of this registry (lookup,
     * credential verification, listing) agrees on one order.
     */
    private fun sourcePrecedence(
        serversConfig: OAuth2ServersConfig,
        activeServerId: String,
    ): ClientRegistrySourcePrecedence =
        serversConfig.servers[activeServerId]?.clientRegistrySourcePrecedence
            ?: ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY

    private fun activeServerId(serversConfig: OAuth2ServersConfig): String =
        asInstanceIdProvider.currentAsInstanceId() ?: serversConfig.defaultServer

    private fun loadInternalClientRegistrations(serversConfig: OAuth2ServersConfig): Map<String, ClientRegistration> {
        val result = linkedMapOf<String, ClientRegistration>()
        for ((_, server) in serversConfig.servers) {
            for ((_, credentials) in server.internalClients) {
                val clientId = credentials.clientId
                if (clientId.isBlank()) continue
                result[clientId] =
                    ClientRegistration(
                        clientId = clientId,
                        clientSecret = credentials.clientSecret,
                        clientType = ClientType.CONFIDENTIAL,
                        grantTypes = credentials.grantTypes.toList(),
                        defaultAccessTokenAudience = credentials.defaultAccessTokenAudience,
                        allowedAccessTokenAudiences = credentials.allowedAccessTokenAudiences,
                        tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                        additionalMetadata = credentials.tenantId?.let { mapOf(TENANT_ID_CLAIM to it) }.orEmpty(),
                        tokenExchangeAuthority = credentials.tokenExchangeAuthority,
                    )
            }
        }
        return result
    }

    /**
     * The authorization server a client lookup belongs to. A client id is unique only within one
     * server, so every store call carries it alongside the tenant.
     */
    private suspend fun currentServerId(): String {
        val configured = configuredClientSet()
        return if (configured.isOk) configured.value.activeServerId else OAuth2ServersConfig().defaultServer
    }

    /**
     * Token-exchange authority is registration-controlled only through server-side configuration.
     * The durable dynamic store has no field for it, and a dynamic registration must never be able
     * to grant itself delegation authority, so a dynamic write carrying it is refused rather than
     * silently dropped.
     */
    private fun rejectDynamicExchangeAuthority(
        operation: String,
        registration: ClientRegistration,
    ): AuthorizationServerError.StorageError? =
        if (registration.tokenExchangeAuthority.isEmpty()) {
            null
        } else {
            AuthorizationServerError.StorageError(
                operation = operation,
                details = "Token-exchange authority can only be configured for server-configured clients",
            )
        }

    /** Tenant the durable dynamic registrations partition under (same discipline as signing keys). */
    private fun dynamicTenantId(): String = execution.tenantId

    /**
     * ACTIVE dynamic registrations from [clientRegistrationStore] mapped onto full model objects.
     * REVOKED tombstones never surface here; admin surfaces read the store directly.
     */
    internal suspend fun dynamicClients(): Map<String, ClientRegistration> {
        val stored = clientRegistrationStore.list(dynamicTenantId(), currentServerId(), limit = Int.MAX_VALUE)
        if (stored.isErr) return emptyMap()
        return stored.value
            .filter { it.status == ClientRegistrationStatus.ACTIVE && !it.registration.isExpired() }
            .associate { it.clientId to it.toClientRegistration() }
    }

    /** Targeted dynamic lookup for the hot read path; avoids materializing the whole tenant set. */
    /**
     * Asks every external source; a client that two sources both claim is ambiguous and is not resolved.
     */
    private suspend fun externalClient(clientId: String): IdkResult<ClientRegistration?, AuthorizationServerError.StorageError> {
        var found: ClientRegistration? = null
        for (source in externalClientSources.value) {
            val resolved = source.resolve(clientId)
            if (resolved.isErr) return Err(resolved.error)
            val client = resolved.value ?: continue
            if (client.clientId != clientId) {
                return Err(AuthorizationServerError.StorageError("external-client-lookup", "Source returned a different client id"))
            }
            if (found != null) {
                execution.log.warn("VDX_OAUTH2_CLIENT_REGISTRY_AMBIGUOUS_EXTERNAL_CLIENT clientId=$clientId")
                return Ok(null)
            }
            found = client
        }
        return Ok(found)
    }

    private suspend fun dynamicClient(clientId: String): DurableClientLookup {
        val stored = clientRegistrationStore.findByClientId(dynamicTenantId(), currentServerId(), clientId)
        if (stored.isErr) {
            return DurableClientLookup.Failed(
                AuthorizationServerError.StorageError("client-registration-lookup", "The client registration store could not be read"),
            )
        }
        val record = stored.value ?: return DurableClientLookup.Absent
        if (record.status != ClientRegistrationStatus.ACTIVE) return DurableClientLookup.Blocked
        // An expired registration no longer admits the client, but it does not bar trust from being established again.
        if (record.registration.isExpired()) return DurableClientLookup.Absent
        return DurableClientLookup.Active(record.toClientRegistration())
    }

    /** Maps a durable record back onto the full registration model using config-binder defaults. */
    private fun StoredClientRegistration.toClientRegistration(): ClientRegistration =
        ClientRegistration(
            clientId = clientId,
            // Plaintext secrets are never recoverable from the durable hash; confidential dynamic
            // clients authenticate through the hash verifier wired into the request view instead.
            clientSecret = null,
            clientName = registration.clientName,
            clientType = if (registration.tokenEndpointAuthMethod == ClientAuthenticationMethod.NONE) ClientType.PUBLIC else ClientType.CONFIDENTIAL,
            grantTypes = registration.grantTypes,
            responseTypes = registration.responseTypes,
            redirectUris = registration.redirectUris,
            allowedScopes = registration.allowedScopes,
            defaultAccessTokenAudience = registration.defaultAccessTokenAudience,
            allowedAccessTokenAudiences = registration.allowedAccessTokenAudiences,
            principalRoles = registration.principalRoles,
            tokenEndpointAuthMethod = registration.tokenEndpointAuthMethod,
            tokenEndpointAuthSigningAlg = registration.tokenEndpointAuthSigningAlg,
            jwks = registration.jwks,
            jwksUri = registration.jwksUri,
            requirePkce = registration.requirePkce ?: (registration.clientType == ClientType.PUBLIC),
            requirePushedAuthorizationRequests = registration.requirePushedAuthorizationRequests,
            dpopBoundAccessTokens = registration.dpopBoundAccessTokens,
            accessTokenLifetime = registration.accessTokenLifetime,
            idTokenSignedResponseAlg = registration.idTokenSignedResponseAlg,
            requestObjectSigningAlg = registration.requestObjectSigningAlg,
            requestUris = registration.requestUris,
            postLogoutRedirectUris = registration.postLogoutRedirectUris,
            additionalMetadata = registration.metadata,
            expiresAt = registration.expiresAt,
        )

    private fun DynamicClientRegistrationMetadata.isExpired(): Boolean =
        expiresAt?.let { it <= clock.now().epochSeconds } == true

    private suspend fun ClientRegistration.toStored(
        now: Instant,
        existing: StoredClientRegistration?,
        serverId: String,
    ): StoredClientRegistration {
        val secret = clientSecret
        val secretHash =
            when {
                secret == null -> existing?.clientSecretHash
                else -> clientSecretHasher.hash(secret)
            }
        val metadata = DynamicClientRegistrationMetadata(
            clientName = clientName,
            grantTypes = grantTypes,
            responseTypes = responseTypes,
            redirectUris = redirectUris,
            allowedScopes = allowedScopes,
            defaultAccessTokenAudience = defaultAccessTokenAudience,
            allowedAccessTokenAudiences = allowedAccessTokenAudiences,
            principalRoles = principalRoles,
            tokenEndpointAuthMethod = tokenEndpointAuthMethod,
            tokenEndpointAuthSigningAlg = tokenEndpointAuthSigningAlg,
            jwks = jwks,
            jwksUri = jwksUri,
            requirePkce = requirePkce,
            requirePushedAuthorizationRequests = requirePushedAuthorizationRequests,
            dpopBoundAccessTokens = dpopBoundAccessTokens,
            accessTokenLifetime = accessTokenLifetime,
            idTokenSignedResponseAlg = idTokenSignedResponseAlg,
            requestObjectSigningAlg = requestObjectSigningAlg,
            requestUris = requestUris,
            postLogoutRedirectUris = postLogoutRedirectUris,
            metadata = additionalMetadata.mapValues { (_, value) -> value.toString() },
            expiresAt = expiresAt,
        )
        return StoredClientRegistration(
            tenantId = dynamicTenantId(),
            authorizationServerId = serverId,
            clientId = clientId,
            clientSecretHash = secretHash,
            status = existing?.status ?: ClientRegistrationStatus.ACTIVE,
            registeredAt = existing?.registeredAt ?: now,
            updatedAt = now,
            registration = metadata,
        )
    }

    internal suspend fun resolveClientRegistryRequestView(): IdkResult<ClientRegistry, AuthorizationServerError.StorageError> {
        val configured = configuredClientSet()
        if (configured.isErr) return Err(configured.error)
        return Ok(
            ConfigAwareClientRegistryRequestView(
                owner = this,
                configuredClients = configured.value.registrations,
                localClients = partition.clients.toMap(),
                sourcePrecedence = configured.value.sourcePrecedence,
                opaqueInternalClients = configured.value.opaqueInternalClients,
                opaqueInternalClientSecretVerifier = opaqueInternalClientSecretVerifier,
                dynamicLookup = ::dynamicClient,
                externalLookup = ::externalClient,
                dynamicSecretVerifier = { clientId, secret ->
                    val stored =
                        clientRegistrationStore.findByClientId(dynamicTenantId(), configured.value.activeServerId, clientId)
                    val active = stored.getOrNull()?.takeIf { it.status == ClientRegistrationStatus.ACTIVE }
                    DurableClientSecretVerification(
                        activeRegistrationExists = active != null,
                        secretMatches = active != null && clientSecretHasher.verify(secret, active.clientSecretHash),
                    )
                },
                shadowedConfiguredClientWarner = { clientId ->
                    warnShadowedConfiguredClient(clientId, configured.value.activeServerId)
                },
            ),
        )
    }

    /**
     * Reports a configuration entry whose client id an ACTIVE persisted registration already owns
     * under [ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY], where it can neither be looked up
     * nor authenticate. Reported once per client id for the lifetime of this session-scoped
     * registry, so a busy token endpoint does not repeat it per request. Secret material is never
     * part of the message.
     */
    private suspend fun warnShadowedConfiguredClient(
        clientId: String,
        activeServerId: String,
    ) {
        val firstReport = shadowWarningMutex.withLock { shadowWarnedClientIds.add(clientId) }
        if (!firstReport) return
        execution.log.warn(
            "VDX_OAUTH2_CLIENT_REGISTRY_SHADOWED_CONFIGURED_CLIENT clientId=$clientId " +
                "asId=$activeServerId precedence=${ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY.configValue} " +
                "reason=an ACTIVE persisted registration owns this client id, so the configured entry is never used",
        )
    }

    override suspend fun getClient(clientId: String): IdkResult<ClientRegistration?, AuthorizationServerError.StorageError> {
        val view = resolveClientRegistryRequestView()
        return if (view.isOk) view.value.getClient(clientId) else Err(view.error)
    }

    override suspend fun registerClient(registration: ClientRegistration): IdkResult<ClientRegistration, AuthorizationServerError.StorageError> {
        rejectDynamicExchangeAuthority("registerClient", registration)?.let { return Err(it) }
        val configured = configuredClients()
        if (configured.isErr) return Err(configured.error)
        val loadedConfiguredClients = configured.value
        if (loadedConfiguredClients.containsKey(registration.clientId) || partition.clients.containsKey(registration.clientId)) {
            return Err(
                AuthorizationServerError.StorageError(
                    operation = "registerClient",
                    details = "Client with ID ${registration.clientId} already exists",
                ),
            )
        }
        val existing = clientRegistrationStore.findByClientId(dynamicTenantId(), currentServerId(), registration.clientId)
        if (existing.isErr) {
            return Err(
                AuthorizationServerError.StorageError(
                    operation = "registerClient",
                    details = existing.error.toString(),
                ),
            )
        }
        if (existing.value?.status == ClientRegistrationStatus.ACTIVE) {
            return Err(
                AuthorizationServerError.StorageError(
                    operation = "registerClient",
                    details = "Client with ID ${registration.clientId} already exists",
                ),
            )
        }
        val saved =
            clientRegistrationStore.save(
                dynamicTenantId(),
                registration.toStored(clock.now(), null, currentServerId()),
            )
        return when {
            saved.isOk -> Ok(registration)
            else ->
                Err(
                    AuthorizationServerError.StorageError(
                        operation = "registerClient",
                        details = saved.error.toString(),
                    ),
                )
        }
    }

    override suspend fun updateClient(
        clientId: String,
        registration: ClientRegistration,
    ): IdkResult<ClientRegistration, AuthorizationServerError> =
        withConfiguredClients { configured ->
            when {
                registration.tokenExchangeAuthority.isNotEmpty() -> Err(rejectDynamicExchangeAuthority("updateClient", registration)!!)

                configured.containsKey(clientId) -> {
                    Err(
                        AuthorizationServerError.StorageError(
                            operation = "updateClient",
                            details = "Configured client '$clientId' cannot be updated at runtime",
                        ),
                    )
                }

                partition.clients.containsKey(clientId) -> {
                    partition.clients[clientId] = registration
                    Ok(registration)
                }

                else -> {
                    val stored = clientRegistrationStore.findByClientId(dynamicTenantId(), currentServerId(), clientId)
                    when {
                        stored.isErr -> {
                            Err(
                                AuthorizationServerError.StorageError(
                                    operation = "updateClient",
                                    details = stored.error.toString(),
                                ),
                            )
                        }

                        stored.value == null || stored.value!!.status != ClientRegistrationStatus.ACTIVE -> {
                            Err(AuthorizationServerError.ClientNotFound(clientId = clientId))
                        }

                        else -> {
                            val saved =
                                clientRegistrationStore.save(
                                    dynamicTenantId(),
                                    registration.toStored(clock.now(), stored.value!!, currentServerId()).copy(status = ClientRegistrationStatus.ACTIVE),
                                )
                            if (saved.isOk) {
                                Ok(registration)
                            } else {
                                Err(
                                    AuthorizationServerError.StorageError(
                                        operation = "updateClient",
                                        details = saved.error.toString(),
                                    ),
                                )
                            }
                        }
                    }
                }
            }
        }

    override suspend fun deleteClient(clientId: String): IdkResult<Unit, AuthorizationServerError> =
        withConfiguredClients { configured ->
            when {
                configured.containsKey(clientId) -> {
                    Err(
                        AuthorizationServerError.StorageError(
                            operation = "deleteClient",
                            details = "Configured client '$clientId' cannot be deleted at runtime",
                        ),
                    )
                }

                partition.clients.remove(clientId) != null -> {
                    Ok(Unit)
                }

                else -> {
                    val revoked = clientRegistrationStore.revoke(dynamicTenantId(), currentServerId(), clientId)
                    when {
                        revoked.isOk && revoked.value -> Ok(Unit)
                        revoked.isOk ->
                            // False means absent or already revoked; both surface as not-found
                            // to preserve the SPI contract callers already code against.
                            Err(AuthorizationServerError.ClientNotFound(clientId = clientId))
                        else ->
                            Err(
                                AuthorizationServerError.StorageError(
                                    operation = "deleteClient",
                                    details = revoked.error.toString(),
                                ),
                            )
                    }
                }
            }
        }

    override suspend fun listClients(
        limit: Int,
        offset: Int,
    ): IdkResult<List<ClientRegistration>, AuthorizationServerError.StorageError> =
        withMergedClients { clients ->
            Ok(
                clients.values
                    .drop(offset)
                    .take(limit)
                    .toList(),
            )
        }

    override suspend fun findClientsByName(name: String): IdkResult<List<ClientRegistration>, AuthorizationServerError.StorageError> =
        withMergedClients { clients ->
            Ok(
                clients.values.filter { client ->
                    client.clientName?.contains(name, ignoreCase = true) == true
                },
            )
        }

    override suspend fun clientExists(clientId: String): IdkResult<Boolean, AuthorizationServerError.StorageError> = withMergedClients { clients -> Ok(clients.containsKey(clientId)) }

    override suspend fun verifyClientCredentials(
        clientId: String,
        clientSecret: String,
    ): IdkResult<Boolean, AuthorizationServerError.StorageError> {
        val view = resolveClientRegistryRequestView()
        return if (view.isOk) {
            view.value.verifyClientCredentials(clientId, clientSecret)
        } else {
            Err(view.error)
        }
    }

    private suspend inline fun <T> withConfiguredClients(action: (Map<String, ClientRegistration>) -> IdkResult<T, AuthorizationServerError>): IdkResult<T, AuthorizationServerError> {
        val configured = configuredClients()
        return if (configured.isOk) {
            action(configured.value)
        } else {
            Err(configured.error)
        }
    }

    /**
     * Listing merge. The authoritative source is merged last so it wins on a colliding client id,
     * matching the order the request view consults on the authentication path.
     */
    private suspend inline fun <T> withMergedClients(action: (Map<String, ClientRegistration>) -> IdkResult<T, AuthorizationServerError.StorageError>): IdkResult<T, AuthorizationServerError.StorageError> {
        val configured = configuredClientSet()
        if (configured.isErr) return Err(configured.error)
        val configuredRegistrations = configured.value.registrations
        val durableClients = dynamicClients()
        if (configured.value.sourcePrecedence == ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY) {
            for (clientId in configuredRegistrations.keys) {
                if (durableClients.containsKey(clientId)) {
                    warnShadowedConfiguredClient(clientId, configured.value.activeServerId)
                }
            }
        }
        val persisted = partition.clients + durableClients
        return action(
            when (configured.value.sourcePrecedence) {
                ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY -> configuredRegistrations + persisted
                ClientRegistrySourcePrecedence.CONFIGURATION_PRIMARY -> persisted + configuredRegistrations
            },
        )
    }

    @ContributesTo(SessionScope::class)
    interface Graph {
        val clientRegistry: ClientRegistry
    }

    private companion object {
        const val TENANT_ID_CLAIM = "tenant_id"
    }
}

internal data class ResolutionKey(
    val tenantId: String,
    val asInstanceId: String?,
    val configRevision: Long,
)

internal data class ConfiguredClientSet(
    val registrations: Map<String, ClientRegistration>,
    val opaqueInternalClients: Map<String, OpaqueInternalClientRegistration>,
    val sourcePrecedence: ClientRegistrySourcePrecedence,
    val activeServerId: String,
)

/**
 * Outcome of checking a presented secret against the durable client registration store: whether an
 * ACTIVE registration owns the client id at all, and whether its stored secret matched.
 */
internal data class DurableClientSecretVerification(
    val activeRegistrationExists: Boolean,
    val secretMatches: Boolean,
)

/**
 * Request-scoped memoization of the assembled revision-addressed OAuth client view.
 *
 * The key carries the tenant, active AS, and content revision, so repeated lookups in the same
 * request do not rebind configuration or re-resolve configured secrets. It deliberately does not
 * survive the request because [ConfiguredClientSet] may contain resolved plaintext client-secret
 * material. Parsed non-secret configuration has a separate AppScope cache whose key includes the
 * authoritative UserScope config identity and revision. Failures are not cached.
 */
@Inject
@SingleIn(SessionScope::class)
class ConfiguredClientSetMemoizer {
    private val stateMutex = Mutex()
    private val values = LinkedHashMap<ResolutionKey, ConfiguredClientSet>()
    private val inFlight = mutableMapOf<ResolutionKey, Mutex>()

    internal suspend fun getOrResolve(
        key: ResolutionKey,
        resolve: suspend () -> IdkResult<ConfiguredClientSet, AuthorizationServerError.StorageError>,
    ): IdkResult<ConfiguredClientSet, AuthorizationServerError.StorageError> {
        val keyMutex =
            stateMutex.withLock {
                values[key]?.let { return Ok(it) }
                inFlight.getOrPut(key) { Mutex() }
            }
        return keyMutex.withLock {
            try {
                stateMutex.withLock {
                    values[key]?.let { return@withLock Ok(it) }
                }?.let { return it }

                val resolved = resolve()
                if (resolved.isOk) {
                    stateMutex.withLock { remember(key, resolved.value) }
                }
                resolved
            } finally {
                stateMutex.withLock {
                    if (inFlight[key] === keyMutex) inFlight.remove(key)
                }
            }
        }
    }

    private fun remember(
        key: ResolutionKey,
        value: ConfiguredClientSet,
    ) {
        values[key] = value
        while (values.size > MAX_ENTRIES) {
            values.entries.iterator().run {
                if (hasNext()) {
                    next()
                    remove()
                }
            }
        }
    }

    private companion object {
        const val MAX_ENTRIES = 256
    }
}

/** What the durable client store says about one client id. */
private sealed interface DurableClientLookup {
    /** An active, unexpired registration. */
    data class Active(val registration: ClientRegistration) : DurableClientLookup

    /** A stored registration that is revoked or suspended; the client is refused by every source. */
    data object Blocked : DurableClientLookup

    /** No stored registration, or an expired one. */
    data object Absent : DurableClientLookup

    data class Failed(val error: AuthorizationServerError.StorageError) : DurableClientLookup
}

private class ConfigAwareClientRegistryRequestView(
    private val owner: ClientRegistry,
    private val configuredClients: Map<String, ClientRegistration>,
    private val localClients: Map<String, ClientRegistration>,
    private val sourcePrecedence: ClientRegistrySourcePrecedence,
    private val opaqueInternalClients: Map<String, OpaqueInternalClientRegistration>,
    private val opaqueInternalClientSecretVerifier: Lazy<OpaqueInternalClientSecretVerifier>,
    private val dynamicLookup: suspend (String) -> DurableClientLookup,
    private val externalLookup: suspend (String) -> IdkResult<ClientRegistration?, AuthorizationServerError.StorageError>,
    private val dynamicSecretVerifier: suspend (String, String) -> DurableClientSecretVerification,
    private val shadowedConfiguredClientWarner: suspend (String) -> Unit,
) : ClientRegistry by owner {
    override suspend fun getClient(clientId: String): IdkResult<ClientRegistration?, AuthorizationServerError.StorageError> {
        var durable: DurableClientLookup? = null
        suspend fun durable(): DurableClientLookup = durable ?: dynamicLookup(clientId).also { durable = it }
        val registered =
            when (sourcePrecedence) {
                ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY -> {
                    val stored = durable()
                    if (stored is DurableClientLookup.Failed) return Err(stored.error)
                    (stored as? DurableClientLookup.Active)?.registration
                        ?.also { if (configuredClients.containsKey(clientId)) shadowedConfiguredClientWarner(clientId) }
                        ?: localClients[clientId]
                        ?: configuredClients[clientId]
                }

                ClientRegistrySourcePrecedence.CONFIGURATION_PRIMARY ->
                    configuredClients[clientId] ?: localClients[clientId] ?: run {
                        val stored = durable()
                        if (stored is DurableClientLookup.Failed) return Err(stored.error)
                        (stored as? DurableClientLookup.Active)?.registration
                    }
            }
        if (registered != null) return Ok(registered)
        // A revoked or suspended registration stops the client: no external source may admit it again.
        if (durable() == DurableClientLookup.Blocked) return Ok(null)
        return externalLookup(clientId)
    }

    override suspend fun verifyClientCredentials(
        clientId: String,
        clientSecret: String,
    ): IdkResult<Boolean, AuthorizationServerError.StorageError> {
        // Opaque internal clients are a deployment-internal mechanism with their own credential
        // resolution, and keep absolute priority under either precedence.
        opaqueInternalClients[clientId]?.let { configured ->
            return opaqueInternalClientSecretVerifier.value.verify(configured.credential, clientSecret)
        }
        // Configured secrets compare constant-time; the durable-hash verifier fails closed for
        // absent registrations, so an unknown client id authenticates under neither order.
        return Ok(
            when (sourcePrecedence) {
                ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY -> {
                    // Ownership decides here, not first match: once an ACTIVE persisted
                    // registration holds the client id, only its stored secret can authenticate
                    // it, and a configured entry for the same id is dead rather than a fallback.
                    // Both sources are still examined before either answer is read, so the
                    // persisted branch does no less work than the configured one and response
                    // time cannot be used to probe which client ids are stored.
                    val durable = dynamicSecretVerifier(clientId, clientSecret)
                    val configuredMatches = matchesConfiguredSecret(clientId, clientSecret)
                    if (durable.activeRegistrationExists) {
                        if (configuredClients.containsKey(clientId)) shadowedConfiguredClientWarner(clientId)
                        durable.secretMatches
                    } else {
                        configuredMatches
                    }
                }

                ClientRegistrySourcePrecedence.CONFIGURATION_PRIMARY ->
                    if (configuredSecret(clientId) != null) {
                        matchesConfiguredSecret(clientId, clientSecret)
                    } else {
                        dynamicSecretVerifier(clientId, clientSecret).secretMatches
                    }
            },
        )
    }

    private fun configuredSecret(clientId: String): String? = configuredClients[clientId]?.clientSecret

    private fun matchesConfiguredSecret(
        clientId: String,
        clientSecret: String,
    ): Boolean {
        val expectedSecret = configuredSecret(clientId) ?: return false
        return ConstantTime.equalsCT(expectedSecret, clientSecret)
    }
}
