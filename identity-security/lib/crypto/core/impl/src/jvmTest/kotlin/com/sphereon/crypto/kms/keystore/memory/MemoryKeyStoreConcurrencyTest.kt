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

package com.sphereon.crypto.kms.keystore.memory

import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ResolvedKeyInfo
import com.sphereon.crypto.core.jose.JwaCurve
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import kotlinx.coroutines.runBlocking
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.Callable
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class MemoryKeyStoreConcurrencyTest {
    @Test
    fun concurrentFirstAllocationReturnsOneCanonicalPartition() {
        val backing = MemoryKeyStoreBackingStorageImpl()
        val workers = 16
        val barrier = CyclicBarrier(workers)
        val executor = Executors.newFixedThreadPool(workers)
        try {
            val futures = (0 until workers).map {
                executor.submit(Callable {
                    (0 until 200).map { round ->
                        barrier.await(10, TimeUnit.SECONDS)
                        backing.getPartition(StoragePartitionKey.forTenant("shared-$round", "tenant"))
                    }
                })
            }
            val observed = futures.map { it.get(30, TimeUnit.SECONDS) }
            repeat(200) { round ->
                val canonical = backing.getPartition(StoragePartitionKey.forTenant("shared-$round", "tenant"))
                observed.forEach { assertSame(canonical, it[round]) }
            }
            assertEquals(200, backing.getPartitionCount())
            assertEquals(200, backing.getPartitionKeys().size)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun concurrentServiceInstancesKeepEveryDifferentAliasInSharedPartition() {
        val backing = MemoryKeyStoreBackingStorageImpl()
        val key = StoragePartitionKey.forTenant("shared", "tenant")
        val workers = 16
        val services = List(workers) { service(backing, key) }
        val barrier = CyclicBarrier(workers)
        val executor = Executors.newFixedThreadPool(workers)
        try {
            val futures = services.mapIndexed { worker, store ->
                executor.submit(Callable {
                    runBlocking {
                        barrier.await(10, TimeUnit.SECONDS)
                        repeat(100) { index ->
                            val alias = "$worker-$index"
                            store.storeKey(keyInfo(alias), "provider", alias, null)
                        }
                    }
                })
            }
            futures.forEach { it.get(30, TimeUnit.SECONDS) }
            runBlocking {
                assertEquals(workers * 100, services.first().listKeys().size)
                repeat(workers) { worker ->
                    repeat(100) { index ->
                        val alias = "$worker-$index"
                        assertEquals(alias, services.last().getKey(keyInfo(alias).copy(alias = alias)).alias)
                    }
                }
            }
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun overwriteDenialIsAtomicAcrossServiceInstances() {
        val partition = StoragePartition(keys = ConcurrentCheckMap())
        val backing = object : MemoryKeyStoreBackingStorage {
            override fun getPartition(partitionKey: StoragePartitionKey) = partition
            override fun removePartition(partitionKey: StoragePartitionKey) = false
            override fun clearAll() = Unit
            override fun getPartitionCount() = 1
            override fun getPartitionKeys() = emptySet<StoragePartitionKey>()
        }
        val key = StoragePartitionKey.forTenant("shared", "tenant")
        val executor = Executors.newFixedThreadPool(2)
        val start = CyclicBarrier(2)
        try {
            val results = List(2) { contender ->
                executor.submit(Callable {
                    start.await(10, TimeUnit.SECONDS)
                    runBlocking {
                        try {
                            service(backing, key).storeKey(keyInfo("key-$contender"), "provider", "same", null)
                            true
                        } catch (_: IllegalStateException) {
                            false
                        }
                    }
                })
            }.map { it.get(10, TimeUnit.SECONDS) }
            assertEquals(1, results.count { it })
            assertEquals(1, partition.keys.size)
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun tenantPartitionsAndDirectStoresRemainIsolated() = runBlocking {
        val backing = MemoryKeyStoreBackingStorageImpl()
        val first = service(backing, StoragePartitionKey.forTenant("shared", "first"))
        val second = service(backing, StoragePartitionKey.forTenant("shared", "second"))
        val direct = service(null, null)
        val anotherDirect = service(null, null)
        first.storeKey(keyInfo("first"), "provider", "same", null)
        second.storeKey(keyInfo("second"), "provider", "same", null)
        direct.storeKey(keyInfo("direct"), "provider", "same", null)
        assertEquals("first", first.getKey(keyInfo("request").copy(alias = "same")).key?.kid)
        assertEquals("second", second.getKey(keyInfo("request").copy(alias = "same")).key?.kid)
        assertEquals("direct", direct.getKey(keyInfo("request").copy(alias = "same")).key?.kid)
        assertTrue(anotherDirect.listKeys().isEmpty())
        val snapshot = backing.getPartitionKeys()
        assertTrue(backing.removePartition(StoragePartitionKey.forTenant("shared", "first")))
        assertFalse(backing.removePartition(StoragePartitionKey.forTenant("shared", "first")))
        assertEquals(2, snapshot.size)
        assertEquals(1, backing.getPartitionCount())
        backing.clearAll()
        assertEquals(0, backing.getPartitionCount())
        assertTrue(backing.getPartitionKeys().isEmpty())
    }

    private fun service(backing: MemoryKeyStoreBackingStorage?, key: StoragePartitionKey?) =
        MemoryKeyStoreService(
            MemoryKeyStoreConfig(id = "shared", keyVisibility = KeyVisibility.PUBLIC.keyVisibility, overwriteAlias = false),
            backing,
            key,
        )

    private val publicKey: Jwk = run {
        val key = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair().public as ECPublicKey
        fun coordinate(value: java.math.BigInteger): String {
            val bytes = value.toByteArray().takeLast(32).toByteArray()
            val fixed = ByteArray(32)
            bytes.copyInto(fixed, 32 - bytes.size)
            return Base64.getUrlEncoder().withoutPadding().encodeToString(fixed)
        }
        Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = coordinate(key.w.affineX), y = coordinate(key.w.affineY))
    }

    private fun keyInfo(kid: String) =
        ResolvedKeyInfo(key = publicKey.copy(kid = kid), keyVisibility = KeyVisibility.PUBLIC)

    /** Forces both unlocked check-then-write callers to observe absence before either writes. */
    private class ConcurrentCheckMap : LinkedHashMap<String, ManagedKeyInfoType<*>>() {
        private val checks = CountDownLatch(2)

        override fun containsKey(key: String): Boolean {
            val present = super.containsKey(key)
            checks.countDown()
            checks.await(250, TimeUnit.MILLISECONDS)
            return present
        }
    }
}
