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
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKey
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKeyState
import com.sphereon.oauth2.server.authorization.storage.RotationResult
import com.sphereon.oauth2.server.authorization.storage.SigningKeyStore
import com.sphereon.oauth2.server.authorization.storage.SigningKeyStoreError
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * In-memory implementation of [SigningKeyStore]. Default binding for IDK consumers and tests
 * that do not have a Postgres-backed store on the classpath. Production deployments override
 * with the EDK Postgres impl which contributes a binding that replaces this one.
 *
 * Concurrency model: a per-tenant `mutableMapOf` guarded by a single `synchronizedObject`.
 * The KMP-friendly synchronisation is intentional — multiple session-scoped commands
 * (CreateAccessTokenCommandImpl, GetJwksCommandImpl, RotateSigningKeyCommandImpl) read and
 * write through the same store from concurrent coroutines, and the rotate operation MUST be
 * atomic w.r.t. concurrent reads to avoid a brief "two ACTIVE keys for one algorithm" or
 * "no ACTIVE key for that algorithm" window. JVM `synchronized` is sufficient here; the data
 * set is small (typically 1-3 keys per tenant) so contention is negligible.
 *
 * Persistence: NONE — keys are lost on JVM restart, which is the whole point this is a
 * sprint-1 default. Production deployments use the EDK Postgres impl. Inserting a key here
 * after restart is the bootstrap's responsibility.
 */
@Inject
@SingleIn(AppScope::class)
@ContributesBinding(AppScope::class, binding = binding<SigningKeyStore>())
class InMemorySigningKeyStore(
    private val clock: Clock = Clock.System,
) : SynchronizedObject(),
    SigningKeyStore {
    /**
     * `tenantId → kid → key`. The inner map preserves insertion order which lets `listAll`
     * keep deterministic ordering for tests; the priority + createdAt ordering happens in
     * the read methods.
     */
    private val keysByTenant: MutableMap<String, MutableMap<String, OAuth2SigningKey>> = mutableMapOf()
    private val revisionsByTenant: MutableMap<String, Long> = mutableMapOf()

    override suspend fun contentRevision(tenantId: String): IdkResult<Long, SigningKeyStoreError> =
        synchronizedRead { Ok(revisionsByTenant[tenantId] ?: 0L) }

    override suspend fun getActive(tenantId: String): IdkResult<OAuth2SigningKey?, SigningKeyStoreError> =
        synchronizedRead {
            val now = clock.now()
            val active =
                keysByTenant[tenantId]
                    ?.values
                    ?.filter { it.state == OAuth2SigningKeyState.ACTIVE && it.notBefore <= now }
                    ?.maxWithOrNull(activePriorityOrder)
            Ok(active)
        }

    override suspend fun listPublishable(tenantId: String): IdkResult<List<OAuth2SigningKey>, SigningKeyStoreError> =
        synchronizedRead {
            val publishable =
                keysByTenant[tenantId]
                    ?.values
                    ?.filter { it.state != OAuth2SigningKeyState.DISABLED }
                    ?.sortedWith(activePriorityOrder.reversed())
                    ?: emptyList()
            Ok(publishable)
        }

    override suspend fun listAll(tenantId: String): IdkResult<List<OAuth2SigningKey>, SigningKeyStoreError> =
        synchronizedRead {
            Ok(keysByTenant[tenantId]?.values?.toList() ?: emptyList())
        }

    override suspend fun findByKid(
        tenantId: String,
        kid: String,
    ): IdkResult<OAuth2SigningKey?, SigningKeyStoreError> =
        synchronizedRead {
            Ok(keysByTenant[tenantId]?.get(kid))
        }

    override suspend fun register(key: OAuth2SigningKey): IdkResult<Unit, SigningKeyStoreError> {
        val result =
            synchronizedWrite {
                val tenantKeys = keysByTenant.getOrPut(key.tenantId) { mutableMapOf() }
                if (tenantKeys.containsKey(key.kid)) {
                    Err(SigningKeyStoreError.DuplicateKid(tenantId = key.tenantId, kid = key.kid))
                } else {
                    tenantKeys[key.kid] = key
                    advanceRevisionLocked(key.tenantId)
                    Ok(Unit)
                }
            }
        return result
    }

    override suspend fun appendPreservingDefault(
        key: OAuth2SigningKey,
    ): IdkResult<OAuth2SigningKey, SigningKeyStoreError> = synchronizedWrite {
        fun refused(details: String) = Err(SigningKeyStoreError.StorageFailure("appendPreservingDefault", details))
        val now = clock.now()
        if (key.tenantId.isBlank() || key.state != OAuth2SigningKeyState.ACTIVE || key.notBefore > now ||
            key.keyInfo.alias.isNullOrBlank() || key.keyInfo.providerId.isNullOrBlank()
        ) return@synchronizedWrite refused("An eligible tenant-owned ACTIVE signing descriptor is required")
        val tenantKeys = keysByTenant[key.tenantId]
            ?: return@synchronizedWrite refused("An eligible default signing key is required")
        if (tenantKeys.containsKey(key.kid)) {
            return@synchronizedWrite Err(SigningKeyStoreError.DuplicateKid(key.tenantId, key.kid))
        }
        val default = tenantKeys.values.filter {
            it.state == OAuth2SigningKeyState.ACTIVE && it.notBefore <= now
        }.maxWithOrNull(activePriorityOrder)
            ?: return@synchronizedWrite refused("An eligible default signing key is required")
        if (default.priority == Int.MIN_VALUE) {
            return@synchronizedWrite refused("The default signing-key priority cannot be preserved without overflow")
        }
        val appended = key.copy(priority = default.priority - 1)
        tenantKeys[appended.kid] = appended
        advanceRevisionLocked(appended.tenantId)
        Ok(appended)
    }

    override suspend fun rotate(newActive: OAuth2SigningKey): IdkResult<RotationResult, SigningKeyStoreError> {
        val result =
            synchronizedWrite {
                val tenantKeys = keysByTenant.getOrPut(newActive.tenantId) { mutableMapOf() }
                if (tenantKeys.containsKey(newActive.kid)) {
                    return@synchronizedWrite Err(SigningKeyStoreError.DuplicateKid(tenantId = newActive.tenantId, kid = newActive.kid))
                }
                val demoted =
                    tenantKeys.values
                        .filter {
                            it.state == OAuth2SigningKeyState.ACTIVE &&
                                it.algorithm == newActive.algorithm
                        }
                        .map { it.copy(state = OAuth2SigningKeyState.LEGACY) }
                demoted.forEach { tenantKeys[it.kid] = it }
                tenantKeys[newActive.kid] = newActive.copy(state = OAuth2SigningKeyState.ACTIVE)
                advanceRevisionLocked(newActive.tenantId)
                Ok(RotationResult(newActive = tenantKeys.getValue(newActive.kid), demotedToLegacy = demoted))
            }
        return result
    }

    override suspend fun setState(
        tenantId: String,
        kid: String,
        newState: OAuth2SigningKeyState,
    ): IdkResult<Boolean, SigningKeyStoreError> {
        val result =
            synchronizedWrite {
                val tenantKeys = keysByTenant[tenantId] ?: return@synchronizedWrite Ok(false)
                val existing = tenantKeys[kid] ?: return@synchronizedWrite Err(SigningKeyStoreError.KeyNotFound(tenantId, kid))
                if (existing.state == newState) {
                    Ok(false)
                } else {
                    tenantKeys[kid] = existing.copy(state = newState)
                    advanceRevisionLocked(tenantId)
                    Ok(true)
                }
            }
        return result
    }

    private fun advanceRevisionLocked(tenantId: String) {
        val current = revisionsByTenant[tenantId] ?: 0L
        check(current != Long.MAX_VALUE) { "Signing-key content revision exhausted for tenant '$tenantId'" }
        revisionsByTenant[tenantId] = current + 1L
    }

    /**
     * Comparator for picking the highest-priority ACTIVE key. Higher [OAuth2SigningKey.priority]
     * wins; ties broken by newer [OAuth2SigningKey.createdAt]. Used in `maxWithOrNull` so the
     * "winner" comes out as the maximum.
     */
    private val activePriorityOrder: Comparator<OAuth2SigningKey> =
        compareBy<OAuth2SigningKey> { it.priority }.thenBy { it.createdAt }

    private inline fun <T> synchronizedRead(block: () -> IdkResult<T, SigningKeyStoreError>): IdkResult<T, SigningKeyStoreError> =
        runCatching {
            synchronized(this) { block() }
        }.getOrElse { e ->
            Err(SigningKeyStoreError.StorageFailure(operation = "read", details = e.message ?: "unknown"))
        }

    private inline fun <T> synchronizedWrite(block: () -> IdkResult<T, SigningKeyStoreError>): IdkResult<T, SigningKeyStoreError> =
        runCatching {
            synchronized(this) { block() }
        }.getOrElse { e ->
            Err(SigningKeyStoreError.StorageFailure(operation = "write", details = e.message ?: "unknown"))
        }
}

/**
 * Convenience for IDK callers that only need the current epoch instant when constructing
 * an [OAuth2SigningKey] for [SigningKeyStore.register]. Kept as a top-level helper so tests
 * and the service bootstrap can use it without instantiating a Clock locally.
 */
fun nowAs(clock: Clock = Clock.System): Instant = clock.now()
