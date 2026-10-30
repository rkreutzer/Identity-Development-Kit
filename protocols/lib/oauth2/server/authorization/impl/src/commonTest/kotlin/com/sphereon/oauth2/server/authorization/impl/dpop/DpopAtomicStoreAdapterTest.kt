/* © 2026 Sphereon International B.V. */
@file:OptIn(kotlin.time.ExperimentalTime::class)
package com.sphereon.oauth2.server.authorization.impl.dpop

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemorySingleUseObjectStore
import com.sphereon.oauth2.server.authorization.storage.SingleUseObjectStore
import com.sphereon.oauth2.server.authorization.storage.SingleUseObjectStoreError
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.time.Clock
import kotlin.time.Instant
import kotlin.time.Duration.Companion.seconds

/** Unit SPI delegation only; persistent multi-node acceptance is a separate database test. */
class DpopAtomicStoreAdapterTest {
    private val now = Instant.fromEpochSeconds(1_800_000_000)
    private val clock = object : Clock { override fun now() = this@DpopAtomicStoreAdapterTest.now }

    @Test fun unifiedStoreAtomicResultHasExactlyOneAcceptedReservation() = runTest {
        val store = InMemorySingleUseObjectStore(clock)
        val first = InMemoryDpopProofJtiCacheImpl(store)
        val second = InMemoryDpopProofJtiCacheImpl(store)
        val reservations = (0 until 32).map { index -> async {
            (if (index % 2 == 0) first else second).recordIfNew("verified-proof", now + 60.seconds)
        } }.awaitAll()
        assertEquals(1, reservations.count { it })
    }

    @Test fun unifiedStoreErrorCannotBecomeAnAcceptedProof() = runTest {
        assertFalse(InMemoryDpopProofJtiCacheImpl(unavailable()).recordIfNew("proof", now + 60.seconds))
    }

    @Test fun unifiedStoreCancellationIsPropagated() = runTest {
        assertFailsWith<CancellationException> {
            InMemoryDpopProofJtiCacheImpl(unavailable(cancel = true)).recordIfNew("proof", now + 60.seconds)
        }
    }

    private fun unavailable(cancel: Boolean = false) = object : SingleUseObjectStore {
        override suspend fun recordIfNew(namespace: String, key: String, expiresAt: Instant):
            IdkResult<Boolean, SingleUseObjectStoreError> {
            if (cancel) throw CancellationException("fixture store cancelled")
            return Err(SingleUseObjectStoreError.StorageFailure("recordIfNew", "fixture unavailable"))
        }
        override suspend fun isRecorded(namespace: String, key: String): IdkResult<Boolean, SingleUseObjectStoreError> =
            error("Atomic authentication cannot use a legacy peek")
        override suspend fun prune(now: Instant): IdkResult<Int, SingleUseObjectStoreError> = error("No prune in authentication")
        override suspend fun clear(): IdkResult<Unit, SingleUseObjectStoreError> = error("No clear in authentication")
    }
}
