/* © 2026 Sphereon International B.V. */
package com.sphereon.crypto.kms.provider.software

import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.kms.provider.software.testutil.SoftwareKmsTestContext
import dev.whyoleg.cryptography.CryptographyProvider
import kotlinx.coroutines.runBlocking
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Real provider key generation/signing with independent JCA verification; no mock cryptography. */
class SoftwareRawSignatureEncodingDeclarationTest {
    @Test fun es256InlineUsesFixedWidthP1363AndVerifiesIndependently() = vector(SignatureAlgorithm.ECDSA_SHA256, false)
    @Test fun es384InlineUsesFixedWidthP1363AndVerifiesIndependently() = vector(SignatureAlgorithm.ECDSA_SHA384, false)
    @Test fun es512InlineUsesFixedWidthP1363AndVerifiesIndependently() = vector(SignatureAlgorithm.ECDSA_SHA512, false)
    @Test fun rs256InlineUsesAtLeast2048BitRsaAndVerifiesIndependently() = vector(SignatureAlgorithm.RSA_SHA256, false)
    @Test fun es256PersistedSelectorUsesFixedWidthP1363AndVerifiesIndependently() = vector(SignatureAlgorithm.ECDSA_SHA256, true)
    @Test fun es384PersistedSelectorUsesFixedWidthP1363AndVerifiesIndependently() = vector(SignatureAlgorithm.ECDSA_SHA384, true)
    @Test fun es512PersistedSelectorUsesFixedWidthP1363AndVerifiesIndependently() = vector(SignatureAlgorithm.ECDSA_SHA512, true)
    @Test fun rs256PersistedSelectorUsesAtLeast2048BitRsaAndVerifiesIndependently() = vector(SignatureAlgorithm.RSA_SHA256, true)

    private fun vector(algorithm: SignatureAlgorithm, selector: Boolean) = runBlocking<Unit> {
        val ctx = SoftwareKmsTestContext("raw-interop-$algorithm-$selector", this@SoftwareRawSignatureEncodingDeclarationTest)
        try {
            val provider = ctx.softwareKmsProviderFactory.create(SoftwareKmsProviderConfig(
                id = "raw-interop-${java.util.UUID.randomUUID()}", cryptographyProvider = CryptographyProvider.Default.name,
                persistKeysDuringGeneration = true, autoCreateCertificate = false,
            ), ctx.session.sessionExecution)
            assertEquals(com.sphereon.crypto.core.kms.command.SignatureEncoding.RAW, provider.rawSignatureEncoding(algorithm))
            val generated = provider.generateKeyAsync(alias = "vector-${java.util.UUID.randomUUID()}", alg = algorithm)
            val publicJwk = generated.jose.publicJwk
            val input = "independent raw signature interoperability ✓".toByteArray(Charsets.UTF_8)
            val keyInfo = if (selector) KeyInfo<Jwk>(alias = generated.alias, providerId = provider.id,
                keyVisibility = KeyVisibility.PRIVATE, signatureAlgorithm = algorithm)
                else generated.joseToManagedKeyInfo(visibility = KeyVisibility.PRIVATE)
            val signature = provider.createRawSignature(keyInfo, input, requireX5Chain = false)
            val public = jcaPublicKey(publicJwk, algorithm)
            val verifier = when (algorithm) {
                SignatureAlgorithm.ECDSA_SHA256 -> "SHA256withECDSAinP1363Format"
                SignatureAlgorithm.ECDSA_SHA384 -> "SHA384withECDSAinP1363Format"
                SignatureAlgorithm.ECDSA_SHA512 -> "SHA512withECDSAinP1363Format"
                SignatureAlgorithm.RSA_SHA256 -> "SHA256withRSA"
                else -> error("Unexpected vector algorithm")
            }
            val expectedBytes = when (algorithm) {
                SignatureAlgorithm.ECDSA_SHA256 -> 64
                SignatureAlgorithm.ECDSA_SHA384 -> 96
                SignatureAlgorithm.ECDSA_SHA512 -> 132
                else -> (public as java.security.interfaces.RSAPublicKey).modulus.bitLength().let {
                    assertTrue(it >= 2048); (it + 7) / 8
                }
            }
            assertEquals(expectedBytes, signature.size, "Actual provider encoding is fixed-width P1363 for ECDSA, modulus width for RSA")
            assertTrue(verify(verifier, public, input, signature))
            val corruptedInput = input.copyOf().apply { this[0] = (this[0].toInt() xor 1).toByte() }
            assertFalse(verify(verifier, public, corruptedInput, signature))
            val corruptedSignature = signature.copyOf().apply { this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte() }
            assertFalse(verify(verifier, public, input, corruptedSignature))
        } finally { ctx.destroy() }
    }
    private fun verify(algorithm: String, public: PublicKey, input: ByteArray, signature: ByteArray): Boolean =
        runCatching { Signature.getInstance(algorithm).run { initVerify(public); update(input); verify(signature) } }.getOrDefault(false)

    private fun jcaPublicKey(jwk: Jwk, algorithm: SignatureAlgorithm): PublicKey {
        fun unsigned(value: String?) = BigInteger(1, Base64.getUrlDecoder().decode(requireNotNull(value)))
        if (algorithm == SignatureAlgorithm.RSA_SHA256)
            return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(unsigned(jwk.n), unsigned(jwk.e)))
        val curve = when (algorithm) {
            SignatureAlgorithm.ECDSA_SHA256 -> "secp256r1"
            SignatureAlgorithm.ECDSA_SHA384 -> "secp384r1"
            SignatureAlgorithm.ECDSA_SHA512 -> "secp521r1"
            else -> error("Unexpected EC vector algorithm")
        }
        val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec(curve)) }
            .getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(unsigned(jwk.x), unsigned(jwk.y)), parameters))
    }
}
