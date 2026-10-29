package com.sphereon.crypto.jose.jwe

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.ManagedKeyReference
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.command.EcdhDeriveCommand
import com.sphereon.crypto.jose.jwe.command.DecryptJweCommandImpl
import com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.CancellationException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class JweProviderBackedWrapTest {
    private val reference = ManagedKeyReference(providerId = "customer-provider", alias = "sealed-authority-kek", kid = "kek-v1")
    private val identifiers = mockk<MultiManagedIdentifierService>()
    private val keys = mockk<KeyManagerService>()
    private val command = DecryptJweCommandImpl(
        execution = mockk<SessionExecution>(relaxed = true), identifierService = identifiers,
        keyManagerService = keys, ecdhDeriveCommand = mockk<EcdhDeriveCommand>(),
    )

    private fun compact(algorithm: String) = JweCompact(
        header = JweHeader().apply { alg = algorithm; enc = "A256GCM" },
        encryptedKey = ByteArray(40) { 3 }, iv = ByteArray(12), ciphertext = ByteArray(16), authTag = ByteArray(16),
    )

    private fun formats(algorithm: String): List<Jwe> {
        val value = compact(algorithm)
        val parts = value.serialize().split('.')
        return listOf(
            value,
            JweJsonFlattened(protected = parts[0], encrypted_key = parts[1], iv = parts[2], ciphertext = parts[3], tag = parts[4]),
            JweJsonGeneral(protected = parts[0], recipients = arrayOf(JweRecipient(encrypted_key = parts[1])),
                iv = parts[2], ciphertext = parts[3], tag = parts[4]),
        )
    }

    private fun refuseMaterialResolution() {
        coEvery { identifiers.resolve(any<ManagedIdentifierOptsOrResult>()) } returns
            IdkResult.err(IdkError.FORBIDDEN_ERROR(message = "Private key export is forbidden"))
    }

    @Test
    fun providerBackedWrapPreservesExactReferenceWithoutPrivateExport() = runTest {
        refuseMaterialResolution()
        val plaintext = "opaque-provider-result".encodeToByteArray()
        coEvery { keys.unwrapKey(match { it === reference }, any(), any()) } returns ByteArray(32) { 7 }
        coEvery { keys.decrypt(any(), any(), any(), any(), any(), any()) } returns plaintext
        for (algorithm in listOf("A256KW", "RSA-OAEP-256")) {
            for (jwe in formats(algorithm)) {
                val result = command.execute(DecryptJweArgs(jwe = jwe, decryptor = ManagedOptsKeyInfo(identifier = reference)))
                assertTrue(result.isOk, "Provider unwrap must not require private material export")
                assertContentEquals(plaintext, result.value.plaintext)
            }
        }
        coVerify(exactly = 6) { keys.unwrapKey(match { it === reference }, any(), any()) }
        coVerify(exactly = 0) { identifiers.resolve(any<ManagedIdentifierOptsOrResult>()) }
    }

    @Test
    fun directEncryptionStillRequiresResolvedCekMaterial() = runTest {
        refuseMaterialResolution()
        val result = command.execute(DecryptJweArgs(jwe = compact("dir"), decryptor = ManagedOptsKeyInfo(identifier = reference)))
        assertTrue(result.isErr)
        coVerify(exactly = 1) { identifiers.resolve(any<ManagedIdentifierOptsOrResult>()) }
        coVerify(exactly = 0) { keys.unwrapKey(any(), any(), any()) }
    }

    @Test
    fun providerlessWrapStillUsesIdentifierResolution() = runTest {
        refuseMaterialResolution()
        val result = command.execute(DecryptJweArgs(
            jwe = compact("A256KW"), decryptor = ManagedOptsKeyInfo(identifier = KeyInfo<Nothing>(alias = "unbound-kek")),
        ))
        assertTrue(result.isErr)
        coVerify(exactly = 1) { identifiers.resolve(any<ManagedIdentifierOptsOrResult>()) }
        coVerify(exactly = 0) { keys.unwrapKey(any(), any(), any()) }
    }

    @Test
    fun redirectedLookupCannotUseOpaqueProviderUnwrap() = runTest {
        refuseMaterialResolution()
        val redirected = ManagedKeyReference(providerId = "different-provider", alias = "different-kek")
        val result = command.execute(DecryptJweArgs(
            jwe = compact("A256KW"), decryptor = ManagedOptsKeyInfo(identifier = reference, lookup = redirected),
        ))
        assertTrue(result.isErr)
        coVerify(exactly = 1) { identifiers.resolve(any<ManagedIdentifierOptsOrResult>()) }
        coVerify(exactly = 0) { keys.unwrapKey(any(), any(), any()) }
    }

    @Test
    fun cancelledProviderUnwrapPropagatesForEverySerialization() = runTest {
        refuseMaterialResolution()
        coEvery { keys.unwrapKey(any(), any(), any()) } throws CancellationException("cancelled")
        for (jwe in formats("A256KW")) {
            assertFailsWith<CancellationException> {
                command.execute(DecryptJweArgs(jwe = jwe, decryptor = ManagedOptsKeyInfo(identifier = reference)))
            }
        }
    }

    @Test
    fun providerUnwrapRefusalKeepsProviderDetailsPrivate() = runTest {
        refuseMaterialResolution()
        coEvery { keys.unwrapKey(any(), any(), any()) } throws IllegalStateException("private-provider-details")
        for (jwe in formats("A256KW")) {
            val result = command.execute(DecryptJweArgs(jwe = jwe, decryptor = ManagedOptsKeyInfo(identifier = reference)))
            assertTrue(result.isErr)
            assertEquals("Key unwrapping failed", result.error.message.defaultMessage)
        }
        coVerify(exactly = 3) { keys.unwrapKey(any(), any(), any()) }
        coVerify(exactly = 0) { identifiers.resolve(any<ManagedIdentifierOptsOrResult>()) }
    }
}
