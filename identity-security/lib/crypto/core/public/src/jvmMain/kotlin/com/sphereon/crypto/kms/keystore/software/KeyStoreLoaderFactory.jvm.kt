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

package com.sphereon.crypto.kms.keystore.software

import com.sphereon.crypto.core.kms.KeyStoreLoaderOpts
import com.sphereon.crypto.core.kms.model.PredefinedKeyStoreTypes
import com.mayakapps.kache.InMemoryKache
import com.mayakapps.kache.KacheStrategy
import kotlinx.atomicfu.atomic
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.MessageDigest
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.KeyStore
import java.util.concurrent.ConcurrentHashMap
import javax.net.ssl.KeyManagerFactory

/**
 * Factory for loading KeyStore instances based on given options.
 *
 * Maintains a map of supported [PredefinedKeyStoreTypes] to corresponding [KeyStoreLoader] implementations.
 */
object KeyStoreLoaderFactory {
    private val loaders: Map<String, BaseKeyStoreLoader> =
        mapOf(
            PredefinedKeyStoreTypes.JKS.keyStoreType to JksLoader(),
            PredefinedKeyStoreTypes.PKCS12.keyStoreType to Pkcs12Loader(),
            PredefinedKeyStoreTypes.BKS.keyStoreType to BksLoader(),
        )
    internal data class Snapshot(val keyStore: KeyStore, val fileRevision: String?)

    private val keyStoreCache = atomic<Map<KeyStoreCacheKey, Snapshot>>(emptyMap())
    private val inFlightLoads = atomic<Map<KeyStoreCacheKey, CompletableDeferred<Snapshot>>>(emptyMap())

    /**
     * Load a [KeyStore] using the provided [com.sphereon.crypto.kms.keystore.KeyStoreLoaderOpts].
     *
     * Delegates to the appropriate [KeyStoreLoader] based on [opts.type].
     *
     * @param opts configuration options for the KeyStore to load
     * @return the initialized [KeyStore]
     * @throws UnsupportedOperationException if no loader exists for the given type
     */
    suspend fun load(
        opts: KeyStoreLoaderOpts,
        forceReload: Boolean = false,
    ): KeyStore = loadSnapshot(opts, forceReload).keyStore

    internal suspend fun loadSnapshot(
        opts: KeyStoreLoaderOpts,
        forceReload: Boolean = false,
    ): Snapshot {
        val cacheKey = opts.cacheKeyOrNull()
        if (cacheKey == null) {
            return Snapshot(loadUncached(opts), null)
        }
        if (!forceReload) {
            cachedSnapshot(cacheKey, opts)?.let { return it }
        }
        return loadSingleFlight(cacheKey, opts, forceReload)
    }

    private suspend fun cachedSnapshot(key: KeyStoreCacheKey, opts: KeyStoreLoaderOpts): Snapshot? {
        val cached = keyStoreCache.value[key] ?: return null
        return cached.takeIf { it.fileRevision == fileRevision(opts.source) }
    }

    // Hash only encrypted file bytes in-process. Content identity detects replacement even
    // when filesystem timestamp resolution, length or clock ordering cannot distinguish it.
    internal suspend fun fileRevision(source: KeyStoreLoaderOpts.Source): String? {
        val fileSource = source as? KeyStoreLoaderOpts.Source.File ?: return null
        return withContext(Dispatchers.IO) {
            val file = PathPlaceholderInterpreter.resolve(fileSource.path) ?: java.io.File(fileSource.path)
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { input ->
                val buffer = ByteArray(8192)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            }
            digest.digest().joinToString("") { "%02x".format(it) }
        }
    }

    internal fun contentRevision(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private suspend fun loadUncachedSnapshot(opts: KeyStoreLoaderOpts): Snapshot =
        loaders[opts.type]?.loadSnapshot(opts)
            ?: throw UnsupportedOperationException("Unsupported keystore type: ${opts.type}")

    internal fun clearCache() {
        keyStoreCache.value = emptyMap()
        inFlightLoads.value = emptyMap()
    }

    internal fun invalidateTenant(tenantId: String): KeyStoreLoaderCacheInvalidationResult {
        val tenantSegment = TenantKeyStorePathResolver.tenantPathSegment(tenantId)
        val keyStoreInvalidation = removeKeyStoreEntries { it.matchesTenantSegment(tenantSegment) }
        val inFlightInvalidation = removeInFlightEntries { it.matchesTenantSegment(tenantSegment) }
        return KeyStoreLoaderCacheInvalidationResult(
            keyStoresBefore = keyStoreInvalidation.before,
            keyStoresAfter = keyStoreInvalidation.after,
            keyStoresEvicted = keyStoreInvalidation.evicted,
            inFlightBefore = inFlightInvalidation.before,
            inFlightAfter = inFlightInvalidation.after,
            inFlightEvicted = inFlightInvalidation.evicted,
        )
    }

    private suspend fun loadSingleFlight(
        cacheKey: KeyStoreCacheKey,
        opts: KeyStoreLoaderOpts,
        forceReload: Boolean,
    ): Snapshot {
        while (true) {
            if (!forceReload) {
                cachedSnapshot(cacheKey, opts)?.let { return it }
            }

            val currentInFlight = inFlightLoads.value
            currentInFlight[cacheKey]?.let { return it.await() }

            val load = CompletableDeferred<Snapshot>()
            if (inFlightLoads.compareAndSet(currentInFlight, currentInFlight + (cacheKey to load))) {
                try {
                    val keyStore = loadUncachedSnapshot(opts)
                    val previous = keyStoreCache.value[cacheKey]
                    if (previous != null && previous.fileRevision != keyStore.fileRevision) {
                        SoftwareKeyStoreStateCache.stateFor(cacheKey).invalidate()
                    }
                    if (inFlightLoads.value[cacheKey] === load) {
                        putCached(cacheKey, keyStore)
                    }
                    load.complete(keyStore)
                    return keyStore
                } catch (t: Throwable) {
                    load.completeExceptionally(t)
                    throw t
                } finally {
                    removeInFlight(cacheKey, load)
                }
            }
        }
    }

    private suspend fun loadUncached(opts: KeyStoreLoaderOpts): KeyStore =
        with(opts) {
            loaders[type]?.load(opts)
                ?: throw UnsupportedOperationException("Unsupported keystore type: $type")
        }

    private fun putCached(
        key: KeyStoreCacheKey,
        keyStore: Snapshot,
    ) {
        while (true) {
            val current = keyStoreCache.value
            if (keyStoreCache.compareAndSet(current, current + (key to keyStore))) {
                return
            }
        }
    }

    private fun removeKeyStoreEntries(matches: (KeyStoreCacheKey) -> Boolean): CacheInvalidationCounters = removeKeyStoreCacheEntries(matches)

    private fun removeInFlightEntries(matches: (KeyStoreCacheKey) -> Boolean): CacheInvalidationCounters = removeInFlightLoadEntries(matches)

    private fun removeKeyStoreCacheEntries(matches: (KeyStoreCacheKey) -> Boolean): CacheInvalidationCounters {
        while (true) {
            val current = keyStoreCache.value
            val updated = current.filterKeys { !matches(it) }
            if (updated.size == current.size) {
                return CacheInvalidationCounters(
                    before = current.size,
                    after = current.size,
                    evicted = 0,
                )
            }
            if (keyStoreCache.compareAndSet(current, updated)) {
                return CacheInvalidationCounters(
                    before = current.size,
                    after = updated.size,
                    evicted = current.size - updated.size,
                )
            }
        }
    }

    private fun removeInFlightLoadEntries(matches: (KeyStoreCacheKey) -> Boolean): CacheInvalidationCounters {
        while (true) {
            val current = inFlightLoads.value
            val updated = current.filterKeys { !matches(it) }
            if (updated.size == current.size) {
                return CacheInvalidationCounters(
                    before = current.size,
                    after = current.size,
                    evicted = 0,
                )
            }
            if (inFlightLoads.compareAndSet(current, updated)) {
                return CacheInvalidationCounters(
                    before = current.size,
                    after = updated.size,
                    evicted = current.size - updated.size,
                )
            }
        }
    }

    private fun removeInFlight(
        key: KeyStoreCacheKey,
        load: CompletableDeferred<Snapshot>,
    ) {
        while (true) {
            val current = inFlightLoads.value
            if (current[key] !== load) {
                return
            }
            if (inFlightLoads.compareAndSet(current, current - key)) {
                return
            }
        }
    }

    private fun KeyStoreLoaderOpts.cacheKeyOrNull(): KeyStoreCacheKey? =
        when (source) {
            is KeyStoreLoaderOpts.Source.Channel -> {
                null
            }

            else -> {
                KeyStoreCacheKey(
                    source = source.canonicalCacheSource(),
                    type = type,
                    password = keyStorePassword,
                )
            }
        }

    private fun KeyStoreLoaderOpts.Source.canonicalCacheSource(): KeyStoreLoaderOpts.Source = canonicalKeyStoreCacheSource()
}

/**
 * Canonical identity of a keystore, shared by every cache that keys on one.
 *
 * File paths are placeholder-resolved and absolute so that two configurations naming the same file
 * different ways land on the same entry. Keeping this in one place is what lets the keystore cache,
 * the key manager cache and the resolved-key cache agree on what "the same keystore" means.
 */
internal fun KeyStoreLoaderOpts.Source.canonicalKeyStoreCacheSource(): KeyStoreLoaderOpts.Source =
    when (this) {
        is KeyStoreLoaderOpts.Source.File -> {
            val resolvedFile = PathPlaceholderInterpreter.resolve(path) ?: java.io.File(path)
            copy(path = resolvedFile.absolutePath)
        }

        else -> {
            this
        }
    }

internal fun keyStoreCacheKey(
    type: String,
    source: KeyStoreLoaderOpts.Source,
    password: String?,
): KeyStoreCacheKey =
    KeyStoreCacheKey(
        source = source.canonicalKeyStoreCacheSource(),
        type = type,
        password = password,
    )

internal fun KeyStoreCacheKey.matchesTenantSegment(tenantSegment: String): Boolean {
    val path = (source as? KeyStoreLoaderOpts.Source.File)?.path ?: return false
    return path
        .replace('\\', '/')
        .split('/')
        .any { it == tenantSegment }
}

internal data class KeyStoreLoaderCacheInvalidationResult(
    val keyStoresBefore: Int,
    val keyStoresAfter: Int,
    val keyStoresEvicted: Int,
    val inFlightBefore: Int,
    val inFlightAfter: Int,
    val inFlightEvicted: Int,
)

private data class CacheInvalidationCounters(
    val before: Int,
    val after: Int,
    val evicted: Int,
)

data class KeyStoreCacheKey(
    val source: KeyStoreLoaderOpts.Source,
    val type: String,
    val password: String?,
)

object KeyManagerFactoryCache {
    private val kmfCache = ConcurrentHashMap<KeyStoreCacheKey, KeyManagerFactory>()
    private val mutex = Mutex()

    suspend fun getOrLoad(opts: KeyStoreLoaderOpts): KeyManagerFactory {
        val key =
            KeyStoreCacheKey(
                source = opts.source,
                type = opts.type,
                password = opts.keyStorePassword,
            )

        kmfCache[key]?.let { return it }

        // Only one coroutine at a time loads a given key
        return mutex.withLock {
            kmfCache[key] ?: run {
                val ks = KeyStoreLoaderFactory.load(opts)
                val kmf =
                    KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
                        init(ks, opts.keyStorePassword?.toCharArray())
                    }
                kmfCache[key] = kmf
                kmf
            }
        }
    }

    internal fun invalidateTenant(tenantId: String): KeyManagerFactoryCacheInvalidationResult {
        val tenantSegment = TenantKeyStorePathResolver.tenantPathSegment(tenantId)
        val before = kmfCache.size
        val evicted =
            kmfCache.keys
                .filter { it.matchesTenantSegment(tenantSegment) }
                .count { key -> kmfCache.remove(key) != null }
        val after = kmfCache.size
        return KeyManagerFactoryCacheInvalidationResult(
            before = before,
            after = after,
            evicted = evicted,
        )
    }
}

internal data class KeyManagerFactoryCacheInvalidationResult(
    val before: Int,
    val after: Int,
    val evicted: Int,
)

/**
 * The per-keystore state that must outlive a single [SoftwareKeyStoreService] instance.
 *
 * Nothing keeps a keystore service alive between operations: `RealSoftwareKeyStoreFactory` is an
 * `@AssistedFactory` and `KmsProviderManagerImpl` is deliberately stateless, so a provider lookup
 * builds a new service every call. Holding this state on the instance meant the resolved-key cache
 * always started empty and the DER->JWK and certificate-encoding conversions it exists to avoid ran
 * again on every operation.
 *
 * The conversions are a pure function of the keystore entry, so sharing them is safe for the same
 * keystore identity. Isolation comes from that identity: a tenant's keystore path is resolved by
 * [TenantKeyStorePathResolver] before it reaches here, so two tenants never share an entry, and
 * [SoftwareKeyStoreStateCache.invalidateTenant] evicts a tenant's shard on context invalidation.
 */
internal class SharedKeyStoreState {
    private val entries = BoundedTtlStore<String, Any>(maxEntries = MAX_RESOLVED_KEYS_PER_KEYSTORE, ttlMillis = RESOLVED_KEY_TTL_MILLIS)

    @Volatile
    var isValid: Boolean = true

    suspend fun resolved(alias: String): Any? = entries.get(alias)

    suspend fun putResolved(
        alias: String,
        value: Any,
    ) {
        entries.put(alias, value)
    }

    suspend fun size(): Int = entries.size()

    suspend fun invalidate() {
        isValid = false
        entries.clear()
        isValid = true
    }
}

/**
 * App-level, tenant-sharded cache of [SharedKeyStoreState], keyed on the same canonical keystore
 * identity as [KeyStoreLoaderFactory]'s keystore cache and [KeyManagerFactoryCache].
 *
 * Deliberately in-process and non-serialising rather than built on the general `Cache` abstraction.
 * A resolved key carries private JWK material, and `ScopedCacheImpl` serialises values into a
 * `CacheBackend` that may be distributed, which would write private keys out of this process. What
 * the abstraction does give, bounded size and expiry, is provided here directly by [BoundedTtlMap].
 *
 * Eviction has three triggers: least-recently-used once a bound is reached, idle expiry after
 * [RESOLVED_KEY_TTL_MILLIS] so resolved private key material does not linger indefinitely after last
 * use, and explicit invalidation on writes, disk reloads and tenant context invalidation.
 */
internal object SoftwareKeyStoreStateCache {
    private val states = BoundedTtlStore<KeyStoreCacheKey, SharedKeyStoreState>(maxEntries = MAX_KEYSTORES, ttlMillis = RESOLVED_KEY_TTL_MILLIS)

    suspend fun stateFor(key: KeyStoreCacheKey): SharedKeyStoreState = states.getOrPut(key) { SharedKeyStoreState() }

    suspend fun invalidateTenant(tenantId: String): SoftwareKeyStoreStateCacheInvalidationResult {
        val tenantSegment = TenantKeyStorePathResolver.tenantPathSegment(tenantId)
        val before = states.size()
        val evicted = states.removeIf { it.matchesTenantSegment(tenantSegment) }
        return SoftwareKeyStoreStateCacheInvalidationResult(before = before, after = states.size(), evicted = evicted)
    }

    internal suspend fun clear() {
        states.clear()
    }
}

private const val MAX_KEYSTORES = 256L
private const val MAX_RESOLVED_KEYS_PER_KEYSTORE = 512L
private const val RESOLVED_KEY_TTL_MILLIS = 15L * 60L * 1000L

/**
 * A bounded, expiring in-memory store built on the same Kache LRU the platform's local cache backend
 * uses, so eviction behaviour here matches the rest of the product rather than being hand-rolled.
 *
 * The value is held as an object rather than serialised bytes. That is deliberate: the platform's
 * `CacheBackend` contract stores `ByteArray`, and a resolved key carries private JWK material whose
 * type also exposes an `Any?` field and polymorphic serializers. Encoding it would both need a
 * serialisation design it does not have and copy private key material into a general cache buffer.
 *
 * Kache's LRU chain mutates even on reads and is not safe to touch concurrently, so every operation
 * holds [mutex], exactly as `KacheCacheBackend` does.
 */
internal class BoundedTtlStore<K : Any, V : Any>(
    maxEntries: Long,
    private val ttlMillis: Long,
) {
    private class Entry<V>(
        val value: V,
        val expiresAtMillis: Long,
    )

    private val cache =
        InMemoryKache<K, Entry<V>>(maxSize = maxEntries) {
            strategy = KacheStrategy.LRU
        }
    private val mutex = Mutex()

    suspend fun size(): Int = mutex.withLock { cache.getKeys().size }

    suspend fun get(key: K): V? =
        mutex.withLock {
            val entry = cache.getIfAvailable(key) ?: return null
            if (System.currentTimeMillis() >= entry.expiresAtMillis) {
                cache.remove(key)
                return null
            }
            entry.value
        }

    suspend fun put(
        key: K,
        value: V,
    ) {
        mutex.withLock { cache.put(key, Entry(value, System.currentTimeMillis() + ttlMillis)) }
    }

    suspend fun getOrPut(
        key: K,
        create: () -> V,
    ): V =
        mutex.withLock {
            val existing = cache.getIfAvailable(key)
            if (existing != null && System.currentTimeMillis() < existing.expiresAtMillis) {
                return existing.value
            }
            create().also { cache.put(key, Entry(it, System.currentTimeMillis() + ttlMillis)) }
        }

    suspend fun removeIf(matches: (K) -> Boolean): Int =
        mutex.withLock {
            val doomed = cache.getKeys().filter(matches)
            doomed.forEach { cache.remove(it) }
            doomed.size
        }

    suspend fun clear() {
        mutex.withLock { cache.clear() }
    }
}

internal data class SoftwareKeyStoreStateCacheInvalidationResult(
    val before: Int,
    val after: Int,
    val evicted: Int,
)
