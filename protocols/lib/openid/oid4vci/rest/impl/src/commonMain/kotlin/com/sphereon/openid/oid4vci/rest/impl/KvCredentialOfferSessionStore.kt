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

package com.sphereon.openid.oid4vci.rest.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.callback.CallbackSigningAlgorithm
import com.sphereon.core.api.log.AppLogManager
import com.sphereon.data.store.kv.InMemoryKvStoreConfig
import com.sphereon.data.store.kv.KotlinxSerializationJsonKvCodec
import com.sphereon.data.store.kv.KvNamespace
import com.sphereon.data.store.kv.KvStore
import com.sphereon.data.store.kv.KvStoreBackends
import com.sphereon.data.store.kv.KvStoreConfigBase
import com.sphereon.data.store.kv.KvStoreScopeBinding
import com.sphereon.data.store.kv.KvStoreVersioning
import com.sphereon.data.store.kv.KvVersionAppendResult
import com.sphereon.data.store.kv.impl.KvStoreManager
import com.sphereon.data.store.kv.impl.KvStoreService
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vci.issuer.command.OfferRateLimit
import com.sphereon.openid.oid4vci.issuer.command.OfferUriLifecycle
import com.sphereon.openid.oid4vci.rest.CredentialOfferSession
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStatus
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStore
import com.sphereon.openid.oid4vci.rest.CredentialOfferTemplate
import com.sphereon.openid.oid4vci.rest.IssuanceCallbackConfig
import com.sphereon.openid.oid4vci.rest.OfferRequestClaim
import com.sphereon.openid.oid4vci.rest.OfferRequestOutcome
import com.sphereon.openid.oid4vci.rest.OfferRequestReservation
import com.sphereon.openid.oid4vci.rest.OfferRequestState
import com.sphereon.openid.oid4vci.rest.Oid4vciRestConfigProvider
import com.sphereon.openid.oid4vci.rest.Oid4vciRestErrorCodes
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ExposeImplBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

/**
 * [CredentialOfferSessionStore] on a KV store.
 *
 * A correlation id is claimed on a version chain by an optimistic append, so the claim, the takeover of an expired claim,
 * the recording of the offer and the release of a refused claim are each decided by the version the caller read. Of
 * several callers acting on the same claim exactly one wins and the others are shown the claim that did.
 *
 * That guarantee only holds on a store every replica shares. A claim is therefore refused unless the deployment declares
 * the store [STORE_ID], and refused on a process-local backend (`memory`, `kottage`) unless [PROCESS_LOCAL_PROPERTY]
 * states that a single process serves the deployment. Whether the declared backend really is shared is the
 * deployment's responsibility: the store can only see the backend id.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<CredentialOfferSessionStore>())
@ExposeImplBinding
class KvCredentialOfferSessionStore(
    private val kvStoreManager: KvStoreManager,
    private val kvStoreService: KvStoreService,
    private val execution: SessionExecution,
    appLogManager: AppLogManager,
    private val configProvider: Oid4vciRestConfigProvider,
) : CredentialOfferSessionStore {
    private val log = appLogManager.withTag("KvCredentialOfferSessionStore")
    private val json = Json

    // Claims are read back by every replica of a rolling upgrade, so an older reader skips a field it does not know.
    private val requestJson = Json { ignoreUnknownKeys = true }

    private val namespace =
        KvNamespace(
            name = STORE_ID,
            codec = KotlinxSerializationJsonKvCodec(json = json, serializer = CredentialOfferSessionEntry.serializer()),
        )

    private val offerIdIndexNamespace =
        KvNamespace(
            name = "$STORE_ID.offer-id",
            codec = KotlinxSerializationJsonKvCodec(json = json, serializer = String.serializer()),
        )

    private val requestNamespace =
        KvNamespace(
            name = "$STORE_ID.requests",
            codec = KotlinxSerializationJsonKvCodec(json = requestJson, serializer = OfferRequestReservation.serializer()),
        )

    private val defaultStoreConfig: KvStoreConfigBase =
        InMemoryKvStoreConfig(
            id = STORE_ID,
            scopeBinding = KvStoreScopeBinding.TENANT,
        )

    /** The store, and the configuration the deployment declared for it (null when it declares none). */
    private class Backing(
        val kv: KvStore,
        val declared: KvStoreConfigBase?,
    )

    // A failed initialisation is not cached, so a configuration that could not be read is read again by the next call.
    private val resolvedBacking by lazy {
        val declared = lookupDeclaredConfig()
        val effective = declared ?: defaultStoreConfig
        require(effective.scopeBinding == defaultStoreConfig.scopeBinding) {
            "KV store '${defaultStoreConfig.id}' must use scopeBinding=${defaultStoreConfig.scopeBinding}, but was ${effective.scopeBinding}"
        }
        Backing(kvStoreManager.createFromKvStoreConfig(effective, execution), declared)
    }

    /** The configuration declared for [STORE_ID], null when none is. Throws when a declaration exists and cannot be read. */
    private fun lookupDeclaredConfig(): KvStoreConfigBase? =
        try {
            kvStoreService.getStoreConfig(STORE_ID)
        } catch (notFound: IllegalArgumentException) {
            if (notFound.message?.startsWith(NOT_DECLARED_MESSAGE_PREFIX) == true) {
                null
            } else {
                throw IllegalStateException("The KV store '$STORE_ID' is declared but its configuration cannot be read: ${notFound.message}", notFound)
            }
        }

    private fun backing(): IdkResult<Backing, IdkError> =
        try {
            Ok(resolvedBacking)
        } catch (failure: IllegalArgumentException) {
            Err(sessionStoreError("The KV store of the credential offer sessions is not usable: ${failure.message}", failure))
        } catch (failure: IllegalStateException) {
            Err(sessionStoreError("The KV store of the credential offer sessions is not usable: ${failure.message}", failure))
        }

    private fun sessionStoreError(
        message: String,
        cause: Exception,
    ): IdkError = IdkError.fromString(message = message, exception = cause, code = SESSION_STORE_ERROR)

    override suspend fun create(session: CredentialOfferSession): IdkResult<CredentialOfferSession, IdkError> {
        val kv = backing().getOrElse { return Err(it) }.kv
        val entry = CredentialOfferSessionEntry.fromPublic(session)
        val expiresAt = session.expiresAt
        val ttl =
            if (expiresAt != null) {
                ((expiresAt - session.createdAt) / 1000).coerceAtLeast(1) + RETENTION_GRACE_SECONDS
            } else {
                CredentialOfferSessionStore.DEFAULT_TTL_SECONDS
            }

        val result =
            kv
                .put(namespace, session.correlationId, entry, ttl.seconds)
                .map {
                    session
                }.mapError { e ->
                    IdkError.fromString(
                        message = "Failed to create credential offer session: ${e.message}",
                        exception = IllegalStateException(e.toString()),
                        code = SESSION_STORE_ERROR,
                    )
                }
        if (result.isOk) {
            kv.put(offerIdIndexNamespace, session.offerId, session.correlationId, ttl.seconds).getOrElse { return Err(it) }
        }
        return result
    }

    override suspend fun get(correlationId: String): IdkResult<CredentialOfferSession?, IdkError> {
        val kv = backing().getOrElse { return Err(it) }.kv
        return kv
            .get(namespace, correlationId)
            .map { entry ->
                entry?.toPublic()
            }.mapError { e ->
                IdkError.fromString(
                    message = "Failed to read credential offer session: ${e.message}",
                    exception = IllegalStateException(e.toString()),
                    code = SESSION_STORE_ERROR,
                )
            }
    }

    override suspend fun getByOfferId(offerId: String): IdkResult<CredentialOfferSession?, IdkError> {
        val kv = backing().getOrElse { return Err(it) }.kv
        val correlationId =
            kv.get<String>(offerIdIndexNamespace, offerId).getOrElse { e ->
                return Err(
                    IdkError.fromString(
                        message = "Failed to read offer-id index: ${e.message}",
                        exception = IllegalStateException(e.toString()),
                        code = SESSION_STORE_ERROR,
                    ),
                )
            } ?: return Ok(null)
        return get(correlationId)
    }

    override suspend fun update(session: CredentialOfferSession): IdkResult<CredentialOfferSession, IdkError> {
        val kv = backing().getOrElse { return Err(it) }.kv
        val entry = CredentialOfferSessionEntry.fromPublic(session)
        val updateExpiresAt = session.expiresAt
        val ttl =
            if (updateExpiresAt != null) {
                val remaining = (updateExpiresAt - Clock.System.now().toEpochMilliseconds()) / 1000
                remaining.coerceAtLeast(1) + RETENTION_GRACE_SECONDS
            } else {
                CredentialOfferSessionStore.DEFAULT_TTL_SECONDS
            }

        return kv
            .put(namespace, session.correlationId, entry, ttl.seconds)
            .map {
                session
            }.mapError { e ->
                IdkError.fromString(
                    message = "Failed to update credential offer session: ${e.message}",
                    exception = IllegalStateException(e.toString()),
                    code = SESSION_STORE_ERROR,
                )
            }
    }

    override suspend fun claimRequest(reservation: OfferRequestReservation): IdkResult<OfferRequestClaim, IdkError> {
        requireUsableKey(reservation.key)?.let { return Err(it) }
        val versioning = claimStore().getOrElse { return Err(it) }
        return appendClaim(versioning, reservation, expectedVersion = null)
    }

    override suspend fun reclaimRequest(
        observed: OfferRequestClaim,
        replacement: OfferRequestReservation,
    ): IdkResult<OfferRequestClaim, IdkError> {
        requireUsableKey(replacement.key)?.let { return Err(it) }
        val versioning = claimStore().getOrElse { return Err(it) }
        val expectedVersion =
            observed.version
                ?: return Err(IdkError.INVALID_STATE(message = "Correlation id '${replacement.key}' cannot be reclaimed from a claim that carries no version"))
        return appendClaim(versioning, replacement, expectedVersion)
    }

    override suspend fun completeRequest(
        claim: OfferRequestClaim,
        outcome: OfferRequestOutcome,
    ): IdkResult<OfferRequestClaim, IdkError> {
        val versioning = claimStore().getOrElse { return Err(it) }
        val expectedVersion =
            claim.version
                ?: return Err(IdkError.INVALID_STATE(message = "Correlation id '${claim.reservation.key}' cannot be completed from a claim that carries no version"))
        val reservation = claim.reservation
        val completed =
            reservation.copy(
                state = OfferRequestState.COMPLETED,
                outcome = outcome,
                expiresAt = maxOf(reservation.expiresAt, outcome.offerExpiresAt),
            )
        return appendClaim(versioning, completed, expectedVersion, recoverLapsedHead = false)
    }

    override suspend fun releaseRequest(claim: OfferRequestClaim): IdkResult<Boolean, IdkError> {
        val versioning = claimStore().getOrElse { return Err(it) }
        val expectedVersion = claim.version ?: return Ok(false)
        // A released claim stays in the chain with the state RELEASED. That frees the key through the same
        // version-checked append as a takeover, so a claim somebody else holds by now is left alone.
        val released = claim.reservation.copy(state = OfferRequestState.RELEASED, outcome = null)
        return versioning
            .append(requestNamespace, released.key, expectedVersion, released, RELEASED_CLAIM_TTL_SECONDS.seconds)
            .map { it is KvVersionAppendResult.Applied }
    }

    /**
     * Appends [reservation] to its key's chain if the chain's head is still [expectedVersion] (null: no chain yet).
     * Anything else answers with the head that is there, so the caller can see who holds the key.
     *
     * A head that lapses between the failed append and the read is an ordinary race on a TTL store, not a corrupt one.
     * With [recoverLapsedHead] the append is attempted again against whatever is left of the chain (a lapsed head means no
     * chain, so a plain claim applies); a few rounds bound the retry.
     */
    private suspend fun appendClaim(
        versioning: KvStoreVersioning,
        reservation: OfferRequestReservation,
        expectedVersion: String?,
        recoverLapsedHead: Boolean = true,
    ): IdkResult<OfferRequestClaim, IdkError> {
        var expected = expectedVersion
        repeat(LAPSED_HEAD_ROUNDS) {
            val ttl = ((reservation.expiresAt - Clock.System.now().toEpochMilliseconds()) / 1000).coerceAtLeast(1) + RETENTION_GRACE_SECONDS
            when (
                val appended = versioning.append(requestNamespace, reservation.key, expected, reservation, ttl.seconds).getOrElse { return Err(it) }
            ) {
                is KvVersionAppendResult.Applied ->
                    return Ok(OfferRequestClaim(claimed = true, reservation = reservation, version = appended.entry.versionId))
                is KvVersionAppendResult.Conflict -> {
                    val head = appended.currentHead
                    if (head != null) {
                        return Ok(OfferRequestClaim(claimed = false, reservation = head.value, version = head.versionId))
                    }
                    if (!recoverLapsedHead) {
                        return Ok(OfferRequestClaim(claimed = false, reservation = reservation))
                    }
                    expected = null
                }
            }
        }
        return Err(
            IdkError.fromString(
                code = Oid4vciRestErrorCodes.CORRELATION_ID_IN_DOUBT,
                message = "Correlation id '${reservation.key}' is contended and cannot be claimed right now",
                category = ErrorCategory.CONFLICT,
            ),
        )
    }

    private fun requireUsableKey(key: String): IdkError? =
        if (key.isBlank()) {
            IdkError.ILLEGAL_ARGUMENT_ERROR(message = "A correlation id that makes a call idempotent must not be blank")
        } else {
            null
        }

    /**
     * The versioned view of the store a claim needs. A claim is refused unless the deployment declares the store, because
     * without a declaration it lives in this process only, and on a process-local backend unless that was acknowledged.
     */
    private fun claimStore(): IdkResult<KvStoreVersioning, IdkError> {
        val backing = backing().getOrElse { return Err(it) }
        val declared =
            backing.declared
                ?: return Err(
                    IdkError.fromString(
                        code = KV_STORE_NOT_DECLARED,
                        message =
                            "An idempotent credential offer request needs the KV store '$STORE_ID' declared in the configuration " +
                                "(kv.stores.$STORE_ID), on a backend every replica shares. Without it the claim lives in this process only.",
                    ),
                )
        if (declared.backendId in PROCESS_LOCAL_BACKENDS && !processLocalAcknowledged()) {
            return Err(
                IdkError.fromString(
                    code = KV_STORE_NOT_SHARED,
                    message =
                        "The KV store '$STORE_ID' runs on the process-local backend '${declared.backendId}', so two replicas could each " +
                            "claim the same correlation id. Declare a shared backend, or set $PROCESS_LOCAL_PROPERTY=true when one process serves the deployment.",
                ),
            )
        }
        return (backing.kv as? KvStoreVersioning)?.let { Ok(it) }
            ?: Err(
                IdkError.fromString(
                    code = KV_VERSIONING_REQUIRED,
                    message = "An idempotent credential offer request requires an atomic versioned KV backend",
                ),
            )
    }

    private fun processLocalAcknowledged(): Boolean = configProvider.getConfig().allowProcessLocalRequestStore

    override suspend fun delete(correlationId: String): IdkResult<Boolean, IdkError> {
        val kv = backing().getOrElse { return Err(it) }.kv
        val session = get(correlationId).getOrElse { return Err(it) }
        if (session != null) {
            kv.delete(offerIdIndexNamespace, session.offerId)
        }
        val deleted =
            kv.delete(namespace, correlationId).mapError { e ->
                IdkError.fromString(
                    message = "Failed to delete credential offer session: ${e.message}",
                    exception = IllegalStateException(e.toString()),
                    code = SESSION_STORE_ERROR,
                )
            }
        if (deleted.isOk) {
            withdrawRequest(correlationId)
        }
        return deleted
    }

    /**
     * Marks the correlation id [key], when one was claimed under that id, as withdrawn, so a repeat of the request is told the
     * offer was deleted. Best effort: a store that never claimed anything has nothing to withdraw, and a failure leaves the
     * key claimed, which is the same as before the withdrawal existed.
     */
    private suspend fun withdrawRequest(key: String) {
        val versioning = claimStore().getOrElse { return }
        val head =
            versioning.getHead(requestNamespace, key).getOrElse { failure ->
                log.warn("The correlation id '$key' was not withdrawn after its offer was deleted, because its claim cannot be read: ${failure.message.defaultMessage}")
                return
            } ?: return
        if (head.value.state == OfferRequestState.WITHDRAWN) {
            return
        }
        val withdrawn = head.value.copy(state = OfferRequestState.WITHDRAWN, outcome = null)
        val ttl = ((withdrawn.expiresAt - Clock.System.now().toEpochMilliseconds()) / 1000).coerceAtLeast(1) + RETENTION_GRACE_SECONDS
        versioning
            .append(requestNamespace, key, head.versionId, withdrawn, ttl.seconds)
            .fold(
                success = { },
                failure = { failure ->
                    log.warn("The correlation id '$key' was not withdrawn after its offer was deleted: ${failure.message.defaultMessage}")
                },
            )
    }

    companion object {
        /** The id of the KV store the sessions and request claims live in, as a deployment declares it. */
        const val STORE_ID: String = "oid4vci.rest.sessions"

        /** Config property that acknowledges that one process serves the deployment, which allows claims on a process-local backend. */
        const val PROCESS_LOCAL_PROPERTY: String = "oid4vci.rest.requests.allowProcessLocalStore"

        const val SESSION_STORE_ERROR: String = "OID4VCI_SESSION_STORE_ERROR"
        const val KV_STORE_NOT_DECLARED: String = "KV_STORE_NOT_DECLARED"
        const val KV_STORE_NOT_SHARED: String = "KV_STORE_NOT_SHARED"
        const val KV_VERSIONING_REQUIRED: String = "KV_VERSIONING_REQUIRED"

        /** Start of the message with which the KV config binder reports an id nobody declared. */
        private const val NOT_DECLARED_MESSAGE_PREFIX: String = "KV store config not found for store ID"

        private val PROCESS_LOCAL_BACKENDS: Set<String> = setOf(KvStoreBackends.MEMORY, KvStoreBackends.KOTTAGE)

        /** How long the marker of a released claim lingers. It only has to outlive a retry that read the claim before the release. */
        private const val RELEASED_CLAIM_TTL_SECONDS: Long = 60

        /**
         * How long a session and its claim outlive their offer. The status read answers a completed issuance from the
         * stored session after the protocol session has expired, and a repeat of the request is told the offer expired
         * instead of finding nothing and creating another one.
         */
        private const val RETENTION_GRACE_SECONDS: Long = 3_600

        /** How often an append is attempted again when the head it conflicted with lapsed before it could be read. */
        private const val LAPSED_HEAD_ROUNDS: Int = 3
    }

    @Serializable
    internal data class CredentialOfferSessionEntry(
        val correlationId: String,
        val instanceId: String,
        val offerId: String,
        val issuanceSessionId: String,
        val status: String,
        val callbackUrl: String? = null,
        val callbackStatuses: List<String>? = null,
        val callbackIncludeIssuanceData: Boolean = false,
        val callbackSecretRef: String? = null,
        val callbackSigning: String? = null,
        val state: String? = null,
        val createdAt: Long,
        val lastUpdatedAt: Long,
        val expiresAt: Long? = null,
        val uriLifecycle: String = OfferUriLifecycle.SINGLE_USE.name,
        val rateLimitMaxPerWindow: Int? = null,
        val rateLimitWindowSeconds: Long? = null,
        val offerTemplate: CredentialOfferTemplate? = null,
        val authorizationPolicySnapshot: com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationPolicySnapshot? = null,
    ) {
        fun toPublic(): CredentialOfferSession {
            val callbackConfig =
                callbackUrl?.let { url ->
                    IssuanceCallbackConfig(
                        url = url,
                        statuses =
                            callbackStatuses?.mapNotNull { name ->
                                CredentialOfferSessionStatus.entries.firstOrNull { it.name == name }
                            } ?: emptyList(),
                        includeIssuanceData = callbackIncludeIssuanceData,
                        secretRef = callbackSecretRef,
                        signing = callbackSigning?.let { name -> CallbackSigningAlgorithm.entries.firstOrNull { it.name == name } },
                    )
                }
            val resolvedLifecycle =
                OfferUriLifecycle.entries.firstOrNull { it.name == uriLifecycle }
                    ?: OfferUriLifecycle.SINGLE_USE
            val resolvedRateLimit =
                if (rateLimitMaxPerWindow != null && rateLimitWindowSeconds != null) {
                    OfferRateLimit(maxPerWindow = rateLimitMaxPerWindow, windowSeconds = rateLimitWindowSeconds)
                } else {
                    null
                }
            return CredentialOfferSession(
                correlationId = correlationId,
                instanceId = instanceId,
                offerId = offerId,
                issuanceSessionId = issuanceSessionId,
                status =
                    CredentialOfferSessionStatus.entries.firstOrNull { it.name == status }
                        ?: CredentialOfferSessionStatus.ERROR,
                callbackConfig = callbackConfig,
                state = state,
                createdAt = createdAt,
                lastUpdatedAt = lastUpdatedAt,
                expiresAt = expiresAt,
                uriLifecycle = resolvedLifecycle,
                rateLimit = resolvedRateLimit,
                offerTemplate = offerTemplate,
                authorizationPolicySnapshot = authorizationPolicySnapshot,
            )
        }

        companion object {
            fun fromPublic(session: CredentialOfferSession): CredentialOfferSessionEntry =
                CredentialOfferSessionEntry(
                    correlationId = session.correlationId,
                    instanceId = session.instanceId,
                    offerId = session.offerId,
                    issuanceSessionId = session.issuanceSessionId,
                    status = session.status.name,
                    callbackUrl = session.callbackConfig?.url,
                    callbackStatuses = session.callbackConfig?.statuses?.map { it.name },
                    callbackIncludeIssuanceData = session.callbackConfig?.includeIssuanceData ?: false,
                    callbackSecretRef = session.callbackConfig?.secretRef,
                    callbackSigning = session.callbackConfig?.signing?.name,
                    state = session.state,
                    createdAt = session.createdAt,
                    lastUpdatedAt = session.lastUpdatedAt,
                    expiresAt = session.expiresAt,
                    uriLifecycle = session.uriLifecycle.name,
                    rateLimitMaxPerWindow = session.rateLimit?.maxPerWindow,
                    rateLimitWindowSeconds = session.rateLimit?.windowSeconds,
                    offerTemplate = session.offerTemplate,
                    authorizationPolicySnapshot = session.authorizationPolicySnapshot,
                )
        }
    }
}
