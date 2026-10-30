package com.sphereon.oauth2.server.authorization.impl.storage.memory

import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKey
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKeyState
import com.sphereon.oauth2.server.authorization.storage.SigningKeyStoreError
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds
import kotlin.time.Instant

/** Exercises the real store's atomic mutation and public selection contract. */
class AppendSigningKeyPreservingDefaultTest {
    private val now = Instant.parse("2026-10-01T00:00:00Z")
    private val clock = object : Clock { override fun now(): Instant = now }
    private fun store() = InMemorySigningKeyStore(clock)
    private fun key(
        kid: String,
        algorithm: SignatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
        tenant: String = "tenant-a",
        priority: Int = 1,
        createdAt: Instant = now - 60.seconds,
        state: OAuth2SigningKeyState = OAuth2SigningKeyState.ACTIVE,
        notBefore: Instant = createdAt,
    ) = OAuth2SigningKey(
        tenantId = tenant,
        keyInfo = KeyInfo<KeyType>(kid = kid, alias = "alias-$kid", providerId = "provider",
            signatureAlgorithm = algorithm),
        state = state, priority = priority, createdAt = createdAt, notBefore = notBefore,
    )

    @Test
    fun addingRsaAndOtherEcAlgorithmsPreservesTheOriginalEsDefaultAndAllSigners() = runTest {
        val store = store()
        val original = key("default-es256")
        assertTrue(store.register(original).isOk)
        for ((index, algorithm) in listOf(SignatureAlgorithm.RSA_SHA256,
            SignatureAlgorithm.ECDSA_SHA384, SignatureAlgorithm.ECDSA_SHA512).withIndex()) {
            val result = store.appendPreservingDefault(key("additional-$index", algorithm,
                priority = Int.MAX_VALUE, createdAt = now))
            assertTrue(result.isOk, "Default-preserving append must accept another supported signing algorithm")
            assertTrue(result.value.priority < original.priority, "Caller priority must not replace the default")
            assertEquals(original, store.getActive("tenant-a").value)
        }
        val all = store.listAll("tenant-a").value
        assertEquals(4, all.size)
        assertTrue(all.all { it.state == OAuth2SigningKeyState.ACTIVE })
        assertEquals(setOf(SignatureAlgorithm.ECDSA_SHA256, SignatureAlgorithm.ECDSA_SHA384,
            SignatureAlgorithm.ECDSA_SHA512, SignatureAlgorithm.RSA_SHA256), all.map { it.algorithm }.toSet())
        assertEquals(all.map { it.kid }.toSet(), store.listPublishable("tenant-a").value.map { it.kid }.toSet())
    }

    @Test
    fun simultaneousAdditionsNeverReplaceTheDefaultOrLoseAnAcceptedKey() = runTest {
        val store = store()
        val original = key("default")
        assertTrue(store.register(original).isOk)
        val additions = (0 until 24).map { index -> async {
            store.appendPreservingDefault(key("parallel-$index", SignatureAlgorithm.RSA_SHA256,
                priority = Int.MAX_VALUE, createdAt = now))
        } }.awaitAll()
        assertTrue(additions.all { it.isOk })
        assertEquals(original, store.getActive("tenant-a").value)
        assertEquals(25, store.listAll("tenant-a").value.size)
        assertEquals(25L, store.contentRevision("tenant-a").value)
    }

    @Test
    fun duplicateKidRefusesWithoutChangingTheDescriptorDefaultOrRevision() = runTest {
        val store = store()
        val original = key("same-kid")
        assertTrue(store.register(original).isOk)
        val before = store.contentRevision("tenant-a").value
        val result = store.appendPreservingDefault(key("same-kid", SignatureAlgorithm.RSA_SHA256))
        assertTrue(result.isErr)
        assertTrue(result.error is SigningKeyStoreError.DuplicateKid)
        assertEquals(original, store.getActive("tenant-a").value)
        assertEquals(listOf(original), store.listAll("tenant-a").value)
        assertEquals(before, store.contentRevision("tenant-a").value)
    }

    @Test
    fun addingToOneTenantLeavesAnotherTenantsDefaultAndRevisionUntouched() = runTest {
        val store = store()
        val originalA = key("shared-kid")
        val originalB = key("shared-kid", tenant = "tenant-b")
        assertTrue(store.register(originalA).isOk)
        assertTrue(store.register(originalB).isOk)
        val result = store.appendPreservingDefault(key("rsa", SignatureAlgorithm.RSA_SHA256, createdAt = now))
        assertTrue(result.isOk)
        assertEquals(originalA, store.getActive("tenant-a").value)
        assertEquals(originalB, store.getActive("tenant-b").value)
        assertEquals(listOf(originalB), store.listAll("tenant-b").value)
        assertEquals(1L, store.contentRevision("tenant-b").value)
    }

    @Test
    fun missingEligibleDefaultCannotBeReplacedByAnAppend() = runTest {
        val store = store()
        val result = store.appendPreservingDefault(key("rsa", SignatureAlgorithm.RSA_SHA256))
        assertTrue(result.isErr)
        assertTrue(store.listAll("tenant-a").value.isEmpty())
        assertEquals(0L, store.contentRevision("tenant-a").value)
    }

    @Test
    fun invalidLifecycleAndFutureKeyRefuseWithoutMutatingTheCollection() = runTest {
        for (candidate in listOf(key("legacy", state = OAuth2SigningKeyState.LEGACY),
            key("disabled", state = OAuth2SigningKeyState.DISABLED), key("future", notBefore = now + 1.seconds))) {
            val store = store()
            val original = key("default")
            assertTrue(store.register(original).isOk)
            assertTrue(store.appendPreservingDefault(candidate).isErr)
            assertEquals(listOf(original), store.listAll("tenant-a").value)
            assertEquals(1L, store.contentRevision("tenant-a").value)
        }
    }

    @Test
    fun lowestPossibleDefaultPriorityRefusesWithoutOverflowOrChangingTheDefault() = runTest {
        val store = store()
        val original = key("default", priority = Int.MIN_VALUE)
        assertTrue(store.register(original).isOk)
        assertTrue(store.appendPreservingDefault(key("rsa", SignatureAlgorithm.RSA_SHA256, createdAt = now)).isErr)
        assertEquals(listOf(original), store.listAll("tenant-a").value)
        assertEquals(original, store.getActive("tenant-a").value)
        assertEquals(1L, store.contentRevision("tenant-a").value)
    }
}
