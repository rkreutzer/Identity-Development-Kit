/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.mdoc.vical

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1Structure
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.DER
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.interop.getPublicKeyJwk
import com.sphereon.crypto.core.interop.toSignatureAlgorithm
import com.sphereon.crypto.core.x509.X509ExtensionOids
import com.sphereon.crypto.core.x509.certificateFromDer
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.SHA1
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray
import kotlin.time.Duration.Companion.days
import kotlin.time.Instant

/** Certificate-profile checks only. Chain authentication and COSE verification remain mandatory. */
internal object VicalSignerCertificateValidator {
    private const val VICAL_EKU = "1.0.18013.5.1.8"
    private const val AKI = "2.5.29.35"
    private const val CRL_DP = "2.5.29.31"
    private const val AIA = "1.3.6.1.5.5.7.1.1"

    @OptIn(DelicateCryptographyApi::class)
    suspend fun validate(chain: List<ByteArray>, issuerCandidates: List<ByteArray>, at: Long) {
        val der = chain.first()
        val parsed = DER.decodeFromByteArray<X509Certificate>(der)
        require(DER.encodeToByteArray(parsed).contentEquals(der)) { "VICAL signer certificate must be canonical DER" }
        val tbs = parsed.tbsCertificate
        require(tbs.version == X509TbsCertificate.Version.V3) { "VICAL signer certificate must be v3" }
        require(parsed.signatureAlgorithm == tbs.signatureAlgorithm) { "VICAL signer signature algorithms differ" }
        require(parsed.signatureAlgorithm.toSignatureAlgorithm() in setOf(
            SignatureAlgorithm.ECDSA_SHA256, SignatureAlgorithm.ECDSA_SHA384, SignatureAlgorithm.ECDSA_SHA512,
        )) { "VICAL signer certificate requires ECDSA SHA-256, SHA-384 or SHA-512" }
        val fields = ((Asn1Element.parse(der) as Asn1Sequence).children.first() as Asn1Sequence).children
        val serial = (fields[1] as Asn1Primitive).content
        // Entropy cannot be established from one certificate. Enforce the representable size;
        // CSPRNG generation and uniqueness remain obligations of the issuing CA.
        require(serial.size in 8..20 && serial.first().toInt() >= 0 && serial.any { it != 0.toByte() }) {
            "VICAL signer serial must be positive and contain 8 to 20 octets"
        }
        val certificate = certificateFromDer(der)
        val now = Instant.fromEpochSeconds(at)
        require(certificate.notBefore <= now && now < certificate.notAfter) { "VICAL signer certificate is not currently valid" }
        require(certificate.notAfter > certificate.notBefore && certificate.notAfter - certificate.notBefore <= 1187.days) {
            "VICAL signer validity exceeds 1187 days"
        }
        val subject = fields[5] as Asn1Sequence
        val attributes = subject.children.flatMap { (it as Asn1Structure).children }.map { (it as Asn1Sequence).children }
        for ((attributeOid, tag) in listOf("2.5.4.6" to 0x13, "2.5.4.10" to 0x0c, "2.5.4.3" to 0x0c)) {
            val value = attributes.singleOrNull { oid(it.first()) == attributeOid }?.getOrNull(1) as? Asn1Primitive
                ?: error("VICAL signer requires a unique country, organization and common name")
            require(value.derEncoded.first().toInt() == tag && value.content.decodeToString().isNotBlank()) {
                "VICAL signer subject attribute has an invalid encoding"
            }
            if (attributeOid == "2.5.4.6") require(value.content.size == 2 && value.content.all { it.toInt() in 65..90 }) {
                "VICAL signer country must be a two-letter uppercase code"
            }
        }
        val spki = tbs.subjectPublicKeyInfo
        require(spki.algorithmOid.toString() == "1.2.840.10045.2.1" && spki.subjectPublicKey.bitCarryingBytes.firstOrNull() == 0x04.toByte()) {
            "VICAL signer requires an uncompressed EC public key"
        }
        require(parsed.getPublicKeyJwk().crv?.value in setOf("P-256", "P-384", "P-521")) {
            "VICAL signer curve is unsupported"
        }
        val extensions = tbs.extensions.orEmpty()
        require(extensions.map { it.oid }.distinct().size == extensions.size) { "VICAL signer has duplicate extensions" }
        val byOid = extensions.associateBy { it.oid.toString() }
        val critical = setOf(X509ExtensionOids.KEY_USAGE, X509ExtensionOids.EXTENDED_KEY_USAGE)
        require(extensions.filter { it.critical }.all { it.oid.toString() in critical }) { "VICAL signer has an unsupported critical extension" }
        fun required(oid: String, isCritical: Boolean): ByteArray {
            val extension = requireNotNull(byOid[oid]) { "VICAL signer requires extension $oid" }
            require(extension.critical == isCritical) { "VICAL signer extension $oid has incorrect criticality" }
            return extension.value
        }
        require(required(X509ExtensionOids.KEY_USAGE, true).contentEquals(byteArrayOf(0x03, 0x02, 0x06, 0x40))) {
            "VICAL signer Key Usage must contain only nonRepudiation"
        }
        val eku = Asn1Element.parse(required(X509ExtensionOids.EXTENDED_KEY_USAGE, true)) as Asn1Sequence
        require(eku.children.map(::oid) == listOf(VICAL_EKU)) { "VICAL signer requires the dedicated mdlVICAL extended key usage" }
        val ski = (Asn1Element.parse(required(X509ExtensionOids.SUBJECT_KEY_IDENTIFIER, false)) as Asn1Primitive).content
        val expectedSki = CryptographyProvider.Default.get(SHA1).hasher().hash(spki.subjectPublicKey.bitCarryingBytes)
        require(ski.contentEquals(expectedSki)) { "VICAL signer SKI does not match its public key" }
        val aki = Asn1Element.parse(required(AKI, false)) as Asn1Sequence
        val keyId = aki.children.singleOrNull { it.derEncoded.first() == 0x80.toByte() } as? Asn1Primitive
            ?: error("VICAL signer AKI requires a key identifier")
        val issuers = (chain.drop(1) + issuerCandidates).map { DER.decodeFromByteArray<X509Certificate>(it) }
            .filter { it.tbsCertificate.subjectName == tbs.issuerName }
        require(issuers.any { issuer ->
            val issuerSki = issuer.tbsCertificate.extensions.orEmpty().singleOrNull { it.oid.toString() == X509ExtensionOids.SUBJECT_KEY_IDENTIFIER }
            issuerSki != null && (Asn1Element.parse(issuerSki.value) as Asn1Primitive).content.contentEquals(keyId.content)
        }) { "VICAL signer AKI does not identify an issuer certificate" }
        val points = Asn1Element.parse(required(CRL_DP, false)) as Asn1Sequence
        require(points.children.isNotEmpty()) { "VICAL signer CRL distribution points are empty" }
        points.children.forEach { point ->
            val names = (point as Asn1Sequence).children
            require(names.size == 1 && names.single().derEncoded.first() == 0xa0.toByte()) {
                "VICAL signer CRL point must contain only distributionPoint"
            }
            val name = (names.single() as Asn1Structure).children.single()
            require(name.derEncoded.first() == 0xa0.toByte()) { "VICAL signer CRL point requires fullName" }
            val uris = (name as Asn1Structure).children
            require(uris.isNotEmpty() && uris.all(::isUri)) { "VICAL signer CRL point requires URI names" }
        }
        byOid[AIA]?.let { extension ->
            require(!extension.critical) { "VICAL signer AIA must be non-critical" }
            val access = (Asn1Element.parse(extension.value) as Asn1Sequence).children
            require(access.isNotEmpty() && access.all {
                val description = (it as Asn1Sequence).children
                description.size == 2 && oid(description[0]) == "1.3.6.1.5.5.7.48.1" && isUri(description[1])
            }) { "VICAL signer AIA requires OCSP URI access descriptions" }
        }
    }

    private fun oid(element: Asn1Element): String = ObjectIdentifier.decodeFromTlv(element as Asn1Primitive).toString()
    private fun isUri(element: Asn1Element): Boolean = element is Asn1Primitive &&
        element.derEncoded.first() == 0x86.toByte() && element.content.all { it.toInt() in 33..126 } &&
        Regex("[A-Za-z][A-Za-z0-9+.-]*:.+").matches(element.content.decodeToString())
}
