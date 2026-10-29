/* Copyright 2026 Sphereon International B.V. */
package com.sphereon.crypto.kms.provider.software

import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.kms.provider.software.testutil.SoftwareKmsTestContext
import dev.whyoleg.cryptography.CryptographyProvider
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import kotlin.test.*

/** Actual provider operation, independently verified; does not claim hosted API advertises Ed448. */
class SoftwareEd448SignatureInteropTest {
    @Test fun inlineEd448ActualProviderSignatureVerifiesIndependently() = vector(false)
    @Test fun persistedEd448SelectorActualProviderSignatureVerifiesIndependently() = vector(true)
    private fun vector(selector: Boolean) = runBlocking<Unit> {
        val ctx = SoftwareKmsTestContext("ed448-preservation-$selector", this@SoftwareEd448SignatureInteropTest)
        try {
            val provider = ctx.softwareKmsProviderFactory.create(SoftwareKmsProviderConfig(
                id = "ed448-${java.util.UUID.randomUUID()}", cryptographyProvider = CryptographyProvider.Default.name,
                persistKeysDuringGeneration = true, autoCreateCertificate = false,
            ), ctx.session.sessionExecution)
            assertTrue(SignatureAlgorithm.ED448 in provider.supportedSignatureAlgorithms(),
                "Source provider catalog explicitly advertises this preserved algorithm")
            val generated = provider.generateKeyAsync(alias = "ed448-vector-${java.util.UUID.randomUUID()}", alg = SignatureAlgorithm.ED448)
            val input = "actual software provider Ed448 interoperability framed challenge".encodeToByteArray()
            val selected = if (selector) KeyInfo<Jwk>(alias = generated.alias, providerId = provider.id,
                keyVisibility = KeyVisibility.PRIVATE, signatureAlgorithm = SignatureAlgorithm.ED448)
                else generated.joseToManagedKeyInfo(visibility = KeyVisibility.PRIVATE)
            val signature = provider.createRawSignature(selected, input, requireX5Chain = false)
            val x = Base64.getUrlDecoder().decode(requireNotNull(generated.jose.publicJwk.x))
            assertEquals(57, x.size)
            val prefix = "3043300506032b6571033a00".chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val spki = prefix + x
            val public = KeyFactory.getInstance("Ed448").generatePublic(X509EncodedKeySpec(spki))
            assertEquals(114, signature.size)
            fun verify(message: ByteArray, bytes: ByteArray) = runCatching {
                Signature.getInstance("Ed448").run { initVerify(public); update(message); verify(bytes) }
            }.getOrDefault(false)
            assertTrue(verify(input, signature))
            assertFalse(verify(input + byteArrayOf(0), signature))
            assertFalse(verify(input, signature.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }))
            // Only public verification material is exported to captured test output for the owning
            // EDK verifier test. No private key, selector, authorization token or keystore is emitted.
            fun b64(bytes: ByteArray) = Base64.getEncoder().encodeToString(bytes)
            println("SOFTWARE_ED448_PUBLIC_VECTOR " + buildJsonObject {
                put("selector", selector); put("algorithm", "ED448"); put("publicKeySpkiBase64", b64(spki))
                put("inputBase64", b64(input)); put("signatureBase64", b64(signature))
            })
        } finally { ctx.destroy() }
    }
}
