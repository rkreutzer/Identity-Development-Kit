/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0.
 */

package com.sphereon.mdoc.vical

import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.DER
import com.sphereon.cbor.CborByteString
import com.sphereon.core.api.decodeFromBase64
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.core.compat.LocalDateTimeKMP
import com.sphereon.crypto.core.CoseJoseKeyMappingService
import com.sphereon.crypto.core.CryptoServices
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.cose.CoseSign1CborCodecImpl
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.generic.X509DistinguishedNameElements
import com.sphereon.crypto.core.kms.CertificateService
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.X509CertificateExtensionSpec
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.mdoc.testutil.createMdocCryptoTestAppGraph
import com.sphereon.crypto.core.x509.Certificate
import com.sphereon.crypto.core.x509.X509ExtensionOids
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.di.context.PrincipalType
import dev.whyoleg.cryptography.CryptographyProvider
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Clock

class AuthenticatedVicalIacaValidatorTest {
    private val app = createMdocCryptoTestAppGraph(this)
    private val session = app.userContextManager.getAnonymous().sessionContextManager
        .createOrGetFromId("authenticated-vical-iaca", principalType = PrincipalType.USER)
    private lateinit var kms: KeyManagerService
    private lateinit var certificates: CertificateService
    private lateinit var validator: VicalValidatorImpl
    private lateinit var signer: VicalSignerImpl

    @BeforeTest
    fun setUp() {
        val factory = (app as SoftwareKmsProviderFactoryImpl.Graph).softwareKmsProvider
        kms = session.graph.asKeyManagerServiceGraph().keyManagerService
        kms.registerProvider(
            factory.create(
                SoftwareKmsProviderConfig(
                    id = "authenticated-vical-iaca-software",
                    cryptographyProvider = CryptographyProvider.Default.name,
                    autoCreateCertificate = true,
                ),
                session.asCoreApiServiceGraph().serviceExecution,
            ),
            makeDefaultKms = true,
        )
        certificates = (session.graph as CertificateService.Graph).certificateService
        val crypto = (session.graph as CryptoServices.Graph).cryptoServices
        val coseCodec = CoseSign1CborCodecImpl()
        val vicalCodec = VicalCborCodecImpl()
        signer = VicalSignerImpl(crypto.cose, coseCodec, vicalCodec)
        validator = VicalValidatorImpl(crypto.cose, coseCodec, vicalCodec, crypto.x509)
    }

    @Test
    fun authenticatedModeAcceptsIndependentSignerAndIacaWhileLegacyStillRejects() = runTest {
        val fixture = fixture()

        val authenticated = validator.validate(fixture.signedVical, fixture.policy())
        assertTrue(authenticated.isOk, if (authenticated.isErr) authenticated.error.message.defaultMessage else null)

        val legacy = validator.validate(
            fixture.signedVical,
            fixture.policy(embeddedIacaTrustMode = VicalEmbeddedIacaTrustMode.LEGACY_CONFIGURED_ISSUER_ANCHOR),
        )
        assertTrue(legacy.isErr, "legacy mode must not treat a signer anchor as an unrelated IACA anchor")
    }

    @Test
    fun authenticatedRestrictionsAreAdditionalAndEmptyIsFailClosed() = runTest {
        val fixture = fixture()
        assertTrue(validator.validate(fixture.signedVical, fixture.policy(restrictions = arrayOf(fixture.iaca.derToBase64()))).isOk)
        assertTrue(validator.validate(fixture.signedVical, fixture.policy(restrictions = emptyArray())).isErr)
        assertTrue(validator.validate(fixture.signedVical, fixture.policy(restrictions = arrayOf(fixture.signerAnchor))).isErr)
        assertFailsWith<IllegalArgumentException> {
            fixture.policy(
                embeddedIacaTrustMode = VicalEmbeddedIacaTrustMode.LEGACY_CONFIGURED_ISSUER_ANCHOR,
                restrictions = arrayOf(fixture.iaca.derToBase64()),
            )
        }
    }

    @Test
    fun authenticatedModeRejectsInvalidIacaSecurityMinimum() = runTest {
        val valid = iaca()
        val verificationTime = Clock.System.now().epochSeconds
        val cases = listOf(
            "ca false" to iaca(basicConstraints = byteArrayOf(0x30, 0x00)).der,
            "non-critical basic constraints" to iaca(basicConstraintsCritical = false).der,
            "missing path length" to iaca(basicConstraints = byteArrayOf(0x30, 0x03, 0x01, 0x01, 0xff.toByte())).der,
            "extra key usage" to iaca(keyUsage = byteArrayOf(0x03, 0x02, 0x01, 0x86.toByte())).der,
            "wrong key usage" to iaca(keyUsage = byteArrayOf(0x03, 0x02, 0x07, 0x80.toByte())).der,
            "non-critical key usage" to iaca(keyUsageCritical = false).der,
            "not yet valid" to iaca(notBefore = "2100-01-01T00:00:00", notAfter = "2101-01-01T00:00:00").der,
            "not self-issued" to iaca(subjectCommonName = "Different IACA subject").der,
            "unknown critical extension" to iaca(extraExtensions = listOf(X509CertificateExtensionSpec("1.2.3.4", true, byteArrayOf(0x05, 0x00)))).der,
            "duplicate extension" to iaca(extraExtensions = listOf(X509CertificateExtensionSpec(X509ExtensionOids.KEY_USAGE, true, byteArrayOf(0x03, 0x02, 0x01, 0x06)))).der,
            "expired" to iaca(notBefore = "2020-01-01T00:00:00", notAfter = "2021-01-01T00:00:00").der,
            "missing basic constraints" to valid.der.withoutExtension(X509ExtensionOids.BASIC_CONSTRAINTS),
            "missing key usage" to valid.der.withoutExtension(X509ExtensionOids.KEY_USAGE),
            "missing subject key identifier" to valid.der.withoutExtension(X509ExtensionOids.SUBJECT_KEY_IDENTIFIER),
        )
        cases.forEach { (name, certificateDer) ->
            val error = runCatching { AuthenticatedVicalIacaValidator.validate(certificateDer, verificationTime) }.exceptionOrNull()
            assertTrue(error is IllegalArgumentException, "$name must be rejected, got $error")
        }

        val tampered = valid.der.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertFailsWith<IllegalArgumentException> { AuthenticatedVicalIacaValidator.validate(tampered, verificationTime) }
        assertFailsWith<IllegalArgumentException> { AuthenticatedVicalIacaValidator.validate(valid.der + 0, verificationTime) }

        val wrongSki = valid.der.mutateByteAfter(byteArrayOf(0x04, 0x14) + valid.ski())
        assertFailsWith<IllegalArgumentException> { AuthenticatedVicalIacaValidator.validate(wrongSki, verificationTime) }

        val parsed = DER.decodeFromByteArray<X509Certificate>(valid.der)
        val otherAlgorithm = DER.decodeFromByteArray<X509Certificate>(iaca(algorithm = SignatureAlgorithm.ECDSA_SHA384).der).signatureAlgorithm
        val mismatchedAlgorithms = DER.encodeToByteArray(parsed.copy(signatureAlgorithm = otherAlgorithm))
        assertFailsWith<IllegalArgumentException> { AuthenticatedVicalIacaValidator.validate(mismatchedAlgorithms, verificationTime) }
        val nonMinimalSignature = parsed.signatureValue.rawBytes.withUnnecessaryIntegerPadding()
        val nonMinimalCertificate = DER.encodeToByteArray(parsed.copy(signatureValue = X509SignatureValue(nonMinimalSignature)))
        assertFailsWith<IllegalArgumentException> { AuthenticatedVicalIacaValidator.validate(nonMinimalCertificate, verificationTime) }
    }

    @Test
    fun authenticatedMinimumSupportsAllExistingEcIacaCurves() = runTest {
        val verificationTime = Clock.System.now().epochSeconds
        listOf(
            SignatureAlgorithm.ECDSA_SHA256,
            SignatureAlgorithm.ECDSA_SHA384,
            SignatureAlgorithm.ECDSA_SHA512,
        ).forEach { algorithm ->
            AuthenticatedVicalIacaValidator.validate(iaca(algorithm = algorithm).der, verificationTime)
        }
    }

    @Test
    fun signerAuthenticationFailsBeforeEmbeddedIacaAuthentication() = runTest {
        val fixture = fixture(embeddedIaca = iaca(basicConstraints = byteArrayOf(0x30, 0x00)))
        val codec = CoseSign1CborCodecImpl()
        val cose = codec.decode(fixture.signedVical).getOrThrow().value
        val tamperedSignature = cose.signature.value.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        val tampered = codec.encode(cose.copy(signature = CborByteString(tamperedSignature))).getOrThrow()

        val result = validator.validate(tampered, fixture.policy())
        assertTrue(result.isErr)
        assertTrue(result.error.message.defaultMessage.contains("COSE_Sign1 signature", ignoreCase = true), result.error.message.defaultMessage)
    }

    @Test
    fun nextUpdateCutoffIsExplicitLocalPolicy() = runTest {
        val fixture = fixture(nextUpdate = "2020-01-02T00:00:00Z")
        val strict = validator.validate(fixture.signedVical, fixture.policy())
        assertTrue(strict.isErr)
        assertTrue(strict.error.message.defaultMessage.contains("freshness cutoff"))

        val advisory = validator.validate(
            fixture.signedVical,
            fixture.policy().copy(rejectPastNextUpdate = false),
        )
        assertTrue(advisory.isOk, if (advisory.isErr) advisory.error.message.defaultMessage else null)

        // Requiring presence and rejecting a missed publication time are independent policies.
        assertTrue(validator.validate(fixture.signedVical, fixture.policy().copy(requireNextUpdate = false)).isErr)
    }

    @Test
    fun missingNextUpdateRequiresExplicitPolicyOptOut() = runTest {
        val fixture = fixture(nextUpdate = null)
        assertTrue(validator.validate(fixture.signedVical, fixture.policy()).isErr)
        assertTrue(validator.validate(fixture.signedVical, fixture.policy().copy(rejectPastNextUpdate = false)).isErr)
        assertTrue(validator.validate(fixture.signedVical, fixture.policy().copy(requireNextUpdate = false)).isOk)
    }

    @Test
    fun certificateMetadataMustEqualAuthenticatedDer() = runTest {
        val cases: List<Pair<String, (VicalCertificateInfo) -> VicalCertificateInfo>> = listOf(
            "notBefore" to { it.copy(notBefore = "2021-01-01T00:00:00Z") },
            "notAfter" to { it.copy(notAfter = "2099-01-01T00:00:00Z") },
            "issuer" to { it.copy(issuer = byteArrayOf(0x30, 0x00)) },
            "subject" to { it.copy(subject = byteArrayOf(0x30, 0x00)) },
        )
        for ((field, amend) in cases) {
            val fixture = fixture(amendEntry = amend)
            val result = validator.validate(fixture.signedVical, fixture.policy())
            assertTrue(result.isErr, "$field mismatch must be rejected")
            assertTrue(result.error.message.defaultMessage.contains("$field does not match certificate"), result.error.message.defaultMessage)
        }
    }

    @Test
    fun signerChainUsesPolicyVerificationTime() = runTest {
        val fixture = fixture()
        val result = validator.validate(fixture.signedVical, fixture.policy().copy(verificationTimeEpochSeconds = 0))
        assertTrue(result.isErr)
        assertTrue(result.error.message.defaultMessage.contains("signer certificate chain"), result.error.message.defaultMessage)
    }

    @Test
    fun profileFilteredSnapshotsAllowWithdrawalButConcreteLookupsStillRequireAMatch() = runTest {
        val policy = VicalValidationPolicy(
            trustedCerts = arrayOf(VicalSignerFixtures.root),
            verificationTimeEpochSeconds = kotlin.time.Instant.parse("2026-10-22T00:00:00Z").epochSeconds,
            embeddedIacaTrustMode = VicalEmbeddedIacaTrustMode.AUTHENTICATED_VICAL,
            signerCertificateProfile = VicalSignerCertificateProfile.ISO_18013_5_ANNEX_C,
            requiredCertificateProfiles = setOf("urn:example:issuer"),
        )
        val empty = validator.validate(VicalSignerFixtures.valid.decodeFromBase64(), policy)
        assertTrue(empty.isOk, if (empty.isErr) empty.error.message.defaultMessage else null)
        assertTrue(empty.value.matchingCertificateInfos.isEmpty())
        assertTrue(validator.validate(VicalSignerFixtures.valid.decodeFromBase64(), policy.copy(expectedDocType = "org.iso.18013.5.1.mDL")).isErr)
        val populated = fixture()
        val filtered = validator.validate(populated.signedVical, populated.policy().copy(requiredCertificateProfiles = setOf("urn:example:other")))
        assertTrue(filtered.isOk, if (filtered.isErr) filtered.error.message.defaultMessage else null)
        assertTrue(filtered.value.matchingCertificateInfos.isEmpty())
    }

    @Test
    fun dedicatedSignerProfileAcceptsIndependentCoseFixtureAndRejectsInvalidCertificates() = runTest {
        val policy = VicalValidationPolicy(
            trustedCerts = arrayOf(VicalSignerFixtures.root),
            verificationTimeEpochSeconds = kotlin.time.Instant.parse("2026-10-22T00:00:00Z").epochSeconds,
            embeddedIacaTrustMode = VicalEmbeddedIacaTrustMode.AUTHENTICATED_VICAL,
            signerCertificateProfile = VicalSignerCertificateProfile.ISO_18013_5_ANNEX_C,
        )
        val valid = validator.validate(VicalSignerFixtures.valid.decodeFromBase64(), policy)
        assertTrue(valid.isOk, if (valid.isErr) valid.error.message.defaultMessage else null)
        assertTrue(valid.value.matchingCertificateInfos.isEmpty(), "a valid empty VICAL removes all material")
        val invalid = mapOf(
            "wrong KU" to VicalSignerFixtures.wrongKeyUsage,
            "missing KU" to VicalSignerFixtures.missingKeyUsage,
            "wrong EKU" to VicalSignerFixtures.wrongEku,
            "missing EKU" to VicalSignerFixtures.missingEku,
            "validity" to VicalSignerFixtures.longValidity,
            "AKI" to VicalSignerFixtures.missingAki,
            "CRL" to VicalSignerFixtures.missingCrl,
            "subject" to VicalSignerFixtures.missingOrganization,
            "serial" to VicalSignerFixtures.shortSerial,
        )
        for ((name, encoded) in invalid) {
            assertTrue(validator.validate(encoded.decodeFromBase64(), policy).isErr, "$name must be rejected")
        }
        val tagged = validator.validate(byteArrayOf(0xd2.toByte()) + VicalSignerFixtures.valid.decodeFromBase64(), policy)
        assertTrue(tagged.isErr)
        assertTrue(tagged.error.message.defaultMessage.contains("untagged"))
    }

    private suspend fun fixture(
        embeddedIaca: Certificate? = null,
        nextUpdate: String? = "2100-01-01T00:00:00Z",
        amendEntry: (VicalCertificateInfo) -> VicalCertificateInfo = { it },
    ): Fixture {
        val iaca = embeddedIaca ?: iaca()
        val signerKey = kms.generateKey(alg = SignatureAlgorithm.ECDSA_SHA256, keyVisibility = KeyVisibility.PRIVATE)
        val signerAnchor = signerKey.jose.publicJwk.x5c?.singleOrNull() ?: fail("VICAL signer has no certificate")
        assertFalse(signerAnchor == iaca.derToBase64(), "VICAL signer and embedded IACA must be independent")
        val ski = iaca.ski()
        val verificationTime = Clock.System.now().epochSeconds
        val vical = Vical(
            vicalProvider = "https://vical.example.test",
            date = "2020-01-01T00:00:00Z",
            nextUpdate = nextUpdate,
            certificateInfos = listOf(
                amendEntry(VicalCertificateInfo(
                    certificate = iaca.der,
                    serialNumber = byteArrayOf(1),
                    ski = ski,
                    docTypes = listOf("org.iso.18013.5.1.mDL"),
                )),
            ),
        )
        val signed = signer.sign(vical, CoseJoseKeyMappingService.toCoseKeyInfo(signerKey.joseToManagedKeyInfo(KeyVisibility.PRIVATE)))
            .getOrElse { fail("sign real VICAL: $it") }
        return Fixture(signed, signerAnchor, iaca, verificationTime)
    }

    private suspend fun iaca(
        algorithm: SignatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
        basicConstraints: ByteArray = byteArrayOf(0x30, 0x06, 0x01, 0x01, 0xff.toByte(), 0x02, 0x01, 0x00),
        basicConstraintsCritical: Boolean = true,
        keyUsage: ByteArray = byteArrayOf(0x03, 0x02, 0x01, 0x06),
        keyUsageCritical: Boolean = true,
        extraExtensions: List<X509CertificateExtensionSpec> = emptyList(),
        notBefore: String = "2020-01-01T00:00:00",
        notAfter: String = "2100-01-01T00:00:00",
        subjectCommonName: String = "Authenticated VICAL test IACA",
    ): Certificate {
        val key = kms.generateKey(alg = algorithm, keyVisibility = KeyVisibility.PRIVATE)
            .joseToManagedKeyInfo(KeyVisibility.PRIVATE)
        val dn = X509DistinguishedNameElements(commonName = "Authenticated VICAL test IACA", country = "NL")
        return certificates.createCertificate(
            issuerKeyInfo = key,
            issuer = dn,
            subjectKeyInfo = key,
            subject = X509DistinguishedNameElements(commonName = subjectCommonName, country = "NL"),
            serialNumber = 1,
            extensions = listOf(
                X509CertificateExtensionSpec(X509ExtensionOids.BASIC_CONSTRAINTS, basicConstraintsCritical, basicConstraints),
                X509CertificateExtensionSpec(X509ExtensionOids.KEY_USAGE, keyUsageCritical, keyUsage),
            ) + extraExtensions,
            notBefore = LocalDateTimeKMP.fromString(notBefore),
            notAfter = LocalDateTimeKMP.fromString(notAfter),
        ).certificate
    }

    private fun Certificate.ski(): ByteArray {
        val x509 = com.sphereon.crypto.core.interop.x509CertificateFromDer(der)
        val raw = x509.tbsCertificate.extensions!!.single { it.oid.toString() == X509ExtensionOids.SUBJECT_KEY_IDENTIFIER }.value
        return (at.asitplus.awesn1.Asn1Element.parse(raw) as Asn1Primitive).content
    }

    private data class Fixture(
        val signedVical: ByteArray,
        val signerAnchor: String,
        val iaca: Certificate,
        val verificationTimeEpochSeconds: Long,
    ) {
        fun policy(
            embeddedIacaTrustMode: VicalEmbeddedIacaTrustMode = VicalEmbeddedIacaTrustMode.AUTHENTICATED_VICAL,
            restrictions: Array<String>? = null,
        ) = VicalValidationPolicy(
            trustedCerts = arrayOf(signerAnchor),
            verificationTimeEpochSeconds = verificationTimeEpochSeconds,
            embeddedIacaTrustMode = embeddedIacaTrustMode,
            authenticatedIacaRestrictions = restrictions,
        )
    }

    private fun ByteArray.withoutExtension(oid: String): ByteArray {
        val certificate = DER.decodeFromByteArray<X509Certificate>(this)
        val tbs = certificate.tbsCertificate
        val extensions = tbs.extensions.orEmpty().filterNot { it.oid.toString() == oid }
        // The public constructor accepts extensions; the serialized data-class copy
        // uses an internal explicitly-tagged representation, not that API.
        val modifiedTbs = X509TbsCertificate(
            version = tbs.version,
            serialNumber = tbs.serialNumber,
            signatureAlgorithm = tbs.signatureAlgorithm,
            issuerName = tbs.issuerName,
            subjectName = tbs.subjectName,
            validFrom = tbs.validity.validFrom,
            validUntil = tbs.validity.validUntil,
            subjectPublicKeyInfo = tbs.subjectPublicKeyInfo,
            extensions = extensions,
        )
        return DER.encodeToByteArray(
            certificate.copy(tbsCertificate = modifiedTbs),
        )
    }

    private fun ByteArray.mutateByteAfter(needle: ByteArray): ByteArray {
        val result = copyOf()
        val offset = indices.firstOrNull { index -> index + needle.size <= size && copyOfRange(index, index + needle.size).contentEquals(needle) }
            ?: fail("DER marker not found")
        result[offset + 2] = (result[offset + 2].toInt() xor 1).toByte()
        return result
    }

    private fun ByteArray.withUnnecessaryIntegerPadding(): ByteArray {
        require(size > 8 && this[0] == 0x30.toByte() && this[1].toInt() in 1..127 && this[2] == 0x02.toByte())
        val integerLength = this[3].toInt() and 0xff
        val body = copyOfRange(2, size)
        return byteArrayOf(0x30, (size - 2 + 1).toByte(), 0x02, (integerLength + 1).toByte(), 0x00) +
            body.copyOfRange(2, body.size)
    }

}
