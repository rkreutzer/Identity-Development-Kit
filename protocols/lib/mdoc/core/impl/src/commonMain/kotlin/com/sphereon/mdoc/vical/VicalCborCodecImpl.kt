/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.mdoc.vical

import com.sphereon.cbor.Cbor
import com.sphereon.cbor.CborArray
import com.sphereon.cbor.CborByteString
import com.sphereon.cbor.CborItem
import com.sphereon.cbor.CborMap
import com.sphereon.cbor.CborString
import com.sphereon.cbor.CborTagged
import com.sphereon.cbor.CborTDate
import com.sphereon.cbor.CborUInt
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.encoding.parse
import com.sphereon.core.api.IdkResult
import com.sphereon.crypto.core.cose.CoseSign1CborCodec
import com.sphereon.crypto.core.cose.CoseSign1Input
import com.sphereon.crypto.core.CoseCryptoService
import com.sphereon.crypto.core.cose.CoseKeyType
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.x509.X509VerificationProfile
import com.sphereon.crypto.core.x509.X509VerificationRequest
import com.sphereon.crypto.core.x509.X509VerifyService
import com.sphereon.crypto.core.interop.toX509Certificate
import com.sphereon.crypto.core.x509.certificateFromDer
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.coroutines.CancellationException
import kotlin.time.Instant
import com.sphereon.core.compat.LocalDateTimeKMP
import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime

/** Deterministic CBOR codec for the ISO/IEC 18013-5 VICAL payload. */
@Inject
@SingleIn(com.sphereon.di.session.SessionScope::class)
@ContributesBinding(com.sphereon.di.session.SessionScope::class, binding = binding<VicalCborCodec>())
class VicalCborCodecImpl : VicalCborCodec {
    override fun encode(value: Vical): ByteArray = Cbor.encode(encodeVical(value))

    override fun decode(bytes: ByteArray): Vical =
        try {
            val item = Cbor.tryDecode(bytes).getOrThrow()
            decodeVical(item)
        } catch (expected: IllegalArgumentException) {
            throw expected
        } catch (expected: Exception) {
            throw IllegalArgumentException("Invalid VICAL CBOR", expected)
        }

    private fun encodeVical(value: Vical): CborMap<CborString, CborItem<*>> {
        val fields = mutableMapOf<CborString, CborItem<*>>()
        fields[CborString("version")] = CborString(value.version)
        fields[CborString("vicalProvider")] = CborString(value.vicalProvider)
        value.vicalIssueId?.let { fields[CborString("vicalIssueID")] = encodeUnsigned(it) }
        fields[CborString("date")] = CborTDate(value.date)
        value.nextUpdate?.let { fields[CborString("nextUpdate")] = CborTDate(it) }
        value.notAfter?.let { fields[CborString("notAfter")] = CborTDate(it) }
        fields[CborString("certificateInfos")] =
            CborArray(value.certificateInfos.map { encodeCertificateInfo(it) }.toMutableList())
        value.extensions?.let { fields[CborString("extensions")] = encodeTextMap(it, "VICAL extensions") }
        value.vicalUrl?.let { fields[CborString("vicalURL")] = CborString(it) }
        return CborMap(fields)
    }

    private fun encodeCertificateInfo(value: VicalCertificateInfo): CborMap<CborString, CborItem<*>> {
        val fields = mutableMapOf<CborString, CborItem<*>>()
        fields[CborString("certificate")] = CborByteString(value.certificate)
        fields[CborString("serialNumber")] = encodeBigUnsigned(value.serialNumber)
        fields[CborString("ski")] = CborByteString(value.ski)
        fields[CborString("docType")] = CborArray(value.docTypes.map(::CborString).toMutableList())
        value.certificateProfiles?.let {
            fields[CborString("certificateProfile")] = CborArray(it.map(::CborString).toMutableList())
        }
        value.issuingAuthority?.let { fields[CborString("issuingAuthority")] = CborString(it) }
        value.issuingCountry?.let { fields[CborString("issuingCountry")] = CborString(it) }
        value.stateOrProvinceName?.let { fields[CborString("stateOrProvinceName")] = CborString(it) }
        value.issuer?.let { fields[CborString("issuer")] = CborByteString(it) }
        value.subject?.let { fields[CborString("subject")] = CborByteString(it) }
        value.notBefore?.let { fields[CborString("notBefore")] = CborTDate(it) }
        value.notAfter?.let { fields[CborString("notAfter")] = CborTDate(it) }
        value.extensions?.let { fields[CborString("extensions")] = encodeTextMap(it, "CertificateInfo extensions") }
        return CborMap(fields)
    }

    private fun decodeVical(item: CborItem<*>): Vical {
        val fields = textMap(item, "VICAL")
        return Vical(
            version = requiredText(fields, "version"),
            vicalProvider = requiredText(fields, "vicalProvider"),
            vicalIssueId = fields["vicalIssueID"]?.let(::decodeUnsigned),
            date = requiredDate(fields, "date"),
            nextUpdate = fields["nextUpdate"]?.let { decodeDate(it, "VICAL.nextUpdate") },
            notAfter = fields["notAfter"]?.let { decodeDate(it, "VICAL.notAfter") },
            certificateInfos =
                required(fields, "certificateInfos").asArray("VICAL.certificateInfos")
                    .map { decodeCertificateInfo(it) },
            extensions = fields["extensions"]?.let { textMap(it, "VICAL.extensions") },
            // The ballot CDDL names this field vicalURL; the structures overview in
            // the same draft uses vicalURI. Accept both on input and emit vicalURL.
            vicalUrl = (fields["vicalURL"] ?: fields["vicalURI"])?.let { it.asText("VICAL URL") },
        )
    }

    private fun decodeCertificateInfo(item: CborItem<*>): VicalCertificateInfo {
        val fields = textMap(item, "CertificateInfo")
        return VicalCertificateInfo(
            certificate = required(fields, "certificate").asBytes("CertificateInfo.certificate"),
            serialNumber = decodeBigUnsigned(required(fields, "serialNumber"), "CertificateInfo.serialNumber"),
            ski = required(fields, "ski").asBytes("CertificateInfo.ski"),
            docTypes = required(fields, "docType").asArray("CertificateInfo.docType").map { it.asText("CertificateInfo.docType entry") },
            certificateProfiles = fields["certificateProfile"]?.let { value -> value.asArray("CertificateInfo.certificateProfile").map { it.asText("CertificateInfo.certificateProfile entry") } },
            issuingAuthority = fields["issuingAuthority"]?.let { it.asText("CertificateInfo.issuingAuthority") },
            issuingCountry = fields["issuingCountry"]?.let { it.asText("CertificateInfo.issuingCountry") },
            stateOrProvinceName = fields["stateOrProvinceName"]?.let { it.asText("CertificateInfo.stateOrProvinceName") },
            issuer = fields["issuer"]?.let { it.asBytes("CertificateInfo.issuer") },
            subject = fields["subject"]?.let { it.asBytes("CertificateInfo.subject") },
            notBefore = fields["notBefore"]?.let { decodeDate(it, "CertificateInfo.notBefore") },
            notAfter = fields["notAfter"]?.let { decodeDate(it, "CertificateInfo.notAfter") },
            extensions = fields["extensions"]?.let { textMap(it, "CertificateInfo.extensions") },
        )
    }

    private fun encodeTextMap(values: Map<String, CborItem<*>>, typeName: String): CborMap<CborString, CborItem<*>> {
        require(values.keys.all { it.isNotBlank() }) { "$typeName keys must not be blank" }
        return CborMap(values.mapKeys { CborString(it.key) }.toMutableMap())
    }

    private fun textMap(item: CborItem<*>, typeName: String): Map<String, CborItem<*>> {
        val map = item as? CborMap<*, *> ?: error("$typeName must be a CBOR map")
        return map.value.entries.associate { (key, value) ->
            val textKey = key as? CborString ?: error("$typeName keys must be text")
            textKey.value to (value as? CborItem<*> ?: error("$typeName values must be CBOR items"))
        }
    }

    private fun required(fields: Map<String, CborItem<*>>, name: String): CborItem<*> =
        fields[name] ?: error("$name is required")

    private fun requiredText(fields: Map<String, CborItem<*>>, name: String): String =
        required(fields, name).asText(name)

    private fun requiredDate(fields: Map<String, CborItem<*>>, name: String): String =
        decodeDate(required(fields, name), "VICAL.$name")

    private fun decodeDate(item: CborItem<*>, name: String): String {
        val value =
            when (item) {
                is CborTDate -> item.value
                is CborTagged<*> -> {
                    require(item.tagNumber == CborTagged.DATE_TIME_STRING) { "$name must use CBOR tag 0" }
                    (item.taggedItem as? CborString)?.value ?: error("$name must contain a text date")
                }
                else -> error("$name must be a CBOR date-time")
            }
        return CborTDate(value).value
    }

    private fun encodeUnsigned(value: ULong): CborUInt = CborUInt(value.toLong())

    private fun decodeUnsigned(item: CborItem<*>): ULong =
        (item as? CborUInt)?.value?.toULong()
            ?: error("VICAL vicalIssueID must be an unsigned integer")

    private fun encodeBigUnsigned(value: ByteArray): CborItem<*> {
        val normalized = normalizeUnsigned(value)
        require(normalized.isNotEmpty()) { "biguint must not be zero" }
        if (normalized.size <= 8) {
            var result = 0L
            normalized.forEach { result = (result shl 8) or (it.toLong() and 0xff) }
            return CborUInt(result)
        }
        return CborTagged(2, CborByteString(normalized))
    }

    private fun decodeBigUnsigned(item: CborItem<*>, name: String): ByteArray =
        when (item) {
            is CborUInt -> {
                require(item.value != 0L) { "$name must be positive" }
                unsignedLongBytes(item.value)
            }
            is CborTagged<*> -> {
                require(item.tagNumber == 2) { "$name must be a uint or positive bignum" }
                val bytes = (item.taggedItem as? CborByteString)?.value ?: error("$name bignum must contain bytes")
                require(bytes.isNotEmpty() && bytes[0].toInt() != 0) { "$name bignum must be canonical and positive" }
                bytes.copyOf()
            }
            else -> error("$name must be a uint or positive bignum")
        }

    private fun unsignedLongBytes(value: Long): ByteArray {
        var current = value
        val result = ByteArray(8)
        for (index in 7 downTo 0) {
            result[index] = (current and 0xff).toByte()
            current = current ushr 8
        }
        return normalizeUnsigned(result)
    }

    private fun normalizeUnsigned(value: ByteArray): ByteArray {
        val first = value.indexOfFirst { it.toInt() != 0 }
        return if (first < 0) byteArrayOf() else value.copyOfRange(first, value.size)
    }

    private fun CborItem<*>.asText(name: String): String =
        (this as? CborString)?.value ?: error("$name must be text")

    private fun CborItem<*>.asBytes(name: String): ByteArray =
        (this as? CborByteString)?.value ?: error("$name must be a byte string")

    private fun CborItem<*>.asArray(name: String): List<CborItem<*>> {
        val array = this as? CborArray<*> ?: error("$name must be an array")
        return array.value.map { it as? CborItem<*> ?: error("$name entries must be CBOR items") }
    }
}

/** COSE_Sign1 VICAL signer. The x5chain is deliberately left unprotected per Annex C. */
@Inject
@SingleIn(com.sphereon.di.session.SessionScope::class)
@ContributesBinding(com.sphereon.di.session.SessionScope::class, binding = binding<VicalSigner>())
class VicalSignerImpl(
    private val coseCryptoService: CoseCryptoService,
    private val coseSign1CborCodec: CoseSign1CborCodec,
    private val vicalCborCodec: VicalCborCodec,
) : VicalSigner {
    override suspend fun sign(
        vical: Vical,
        keyInfo: KeyInfoType<CoseKeyType>?,
    ): IdkResult<ByteArray, com.sphereon.core.api.error.IdkError> =
        try {
            val signed =
                coseCryptoService.sign1<Any>(
                    input = CoseSign1Input.Builder().withPayload(vicalCborCodec.encode(vical)).build(),
                    keyInfo = keyInfo,
                    requireX5Chain = true,
                ).coseSign1
            require(signed.protectedHeader.x5chain == null) { "VICAL x5chain must be unprotected" }
            require(!signed.unprotectedHeader?.x5chain?.value.isNullOrEmpty()) { "VICAL signer x5chain is required" }
            coseSign1CborCodec.encode(signed)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (expected: Exception) {
            com.sphereon.core.api.Err(
                com.sphereon.core.api.error.IdkError.fromString(
                    code = "MDOC_VICAL_SIGN_FAILED",
                    message = "VICAL signing failed: ${expected.message}",
                    exception = expected,
                ),
            )
        }
}

/** Validates the VICAL signature, signer chain, freshness, entry metadata, and document selection. */
@Inject
@SingleIn(com.sphereon.di.session.SessionScope::class)
@ContributesBinding(com.sphereon.di.session.SessionScope::class, binding = binding<VicalValidator>())
class VicalValidatorImpl(
    private val coseCryptoService: CoseCryptoService,
    private val coseSign1CborCodec: CoseSign1CborCodec,
    private val vicalCborCodec: VicalCborCodec,
    private val x509VerifyService: X509VerifyService,
) : VicalValidator {
    override suspend fun validate(
        signedVical: ByteArray,
        policy: VicalValidationPolicy,
    ): IdkResult<VicalValidationResult, com.sphereon.core.api.error.IdkError> =
        try {
            require(policy.trustedCerts.isNotEmpty()) { "VICAL validation requires explicit trust anchors" }
            val wire = Cbor.tryDecode(signedVical).getOrThrow() as? CborArray<*>
                ?: error("VICAL COSE_Sign1 must be untagged")
            require(wire.value.size == 4) { "VICAL COSE_Sign1 must contain four elements" }
            val protectedBytes = wire.value[0] as? CborByteString ?: error("VICAL protected header must be a byte string")
            val protectedMap = Cbor.tryDecode(protectedBytes.value).getOrThrow() as? CborMap<*, *>
                ?: error("VICAL protected header must contain a map")
            val unprotectedMap = wire.value[1] as? CborMap<*, *> ?: error("VICAL unprotected header must be a map")
            require(protectedMap.value.keys.toList() == listOf(CborUInt(1))) { "VICAL protected header must contain only alg" }
            require(unprotectedMap.value.keys.toList() == listOf(CborUInt(33))) { "VICAL unprotected header must contain only x5chain" }
            val cose = coseSign1CborCodec.decode(signedVical).getOrThrow().value
            require(cose.payload != null) { "VICAL payload must not be detached" }
            require(cose.protectedHeader.x5chain == null) { "VICAL signer x5chain must be unprotected" }
            val chain = cose.unprotectedHeader?.x5chain?.value?.map { it.value } ?: error("VICAL signer x5chain is required")
            require(chain.isNotEmpty()) { "VICAL signer x5chain is empty" }
            require(cose.protectedHeader.alg != null) { "VICAL COSE_Sign1 alg must be protected" }
            require(cose.protectedHeader.crit == null && cose.protectedHeader.contentType == null &&
                cose.protectedHeader.kid == null && cose.protectedHeader.iv == null &&
                cose.protectedHeader.partialIv == null && cose.protectedHeader.typ == null
            ) { "VICAL protected header contains unsupported parameters" }
            val unprotected = cose.unprotectedHeader
            require(unprotected != null && unprotected.alg == null && unprotected.crit == null &&
                unprotected.contentType == null && unprotected.kid == null && unprotected.iv == null &&
                unprotected.partialIv == null && unprotected.typ == null
            ) { "VICAL unprotected header contains unsupported parameters" }

            val strictProfile = policy.signerCertificateProfile == VicalSignerCertificateProfile.ISO_18013_5_ANNEX_C
            val trustedCertificates = com.sphereon.crypto.core.x509.pemAndDerToCertificateChain(policy.trustedCerts, null)
            if (strictProfile) VicalSignerCertificateValidator.validate(chain, trustedCertificates.map { it.der }, policy.verificationTimeEpochSeconds)
            // Exact leaf pinning is explicit admission. The dedicated profile checks its
            // validity/extensions; COSE below proves possession. A generic mdoc leaf check
            // incorrectly requires digitalSignature instead of Annex C's nonRepudiation.
            val explicitlyPinned = strictProfile && trustedCertificates.any { it.der.contentEquals(chain.first()) }
            if (!explicitlyPinned) {
                val chainResult =
                x509VerifyService.verifyCertificateChain(
                    X509VerificationRequest(
                        enabled = true,
                        chainDER = chain.toTypedArray(),
                        trustedCerts = policy.trustedCerts,
                        verificationProfile = X509VerificationProfile.ISO_18013_5,
                        verificationTime = policy.verificationTime(),
                    ),
                )
            require(!chainResult.error && !chainResult.critical && chainResult.message != "X509 verification has been disabled") {
                "VICAL signer certificate chain is not trusted: ${chainResult.message}"
            }
            }
            val signature = coseCryptoService.verify1(cose, keyInfo = null, requireX5Chain = true)
            require(!signature.error && !signature.critical && !signature.message.orEmpty().contains("disabled", ignoreCase = true)) {
                "VICAL COSE_Sign1 signature is invalid: ${signature.message}"
            }

            val vical = vicalCborCodec.decode(cose.payload!!.value)
            validateDates(vical, policy)
            val matches = selectAndValidateEntries(vical, policy)
            // Snapshot ingestion may legitimately project zero roots (withdrawal or profile
            // filtering). Concrete certificate lookups still require a matching certificate.
            if (policy.expectedDocType != null || policy.expectedCertificateSerialNumber != null ||
                policy.expectedCertificateSki != null || (policy.requiredCertificateProfiles.isNotEmpty() &&
                    policy.embeddedIacaTrustMode != VicalEmbeddedIacaTrustMode.AUTHENTICATED_VICAL)
            ) {
                require(matches.isNotEmpty()) { "VICAL contains no certificate matching the requested selection" }
            }
            com.sphereon.core.api.Ok(
                VicalValidationResult(
                    vical = vical,
                    signerCertificateChain = chain,
                    matchingCertificateInfos = matches,
                ),
            )
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (expected: Exception) {
            com.sphereon.core.api.Err(
                com.sphereon.core.api.error.IdkError.fromString(
                    code = "MDOC_VICAL_VALIDATION_FAILED",
                    message = "VICAL validation failed: ${expected.message}",
                    exception = expected,
                ),
            )
        }

    private fun validateDates(vical: Vical, policy: VicalValidationPolicy) {
        val now = policy.verificationTimeEpochSeconds
        val issueDate = Instant.parse(vical.date).epochSeconds
        require(issueDate <= now + policy.clockSkewSeconds) { "VICAL issue date is in the future" }
        val nextUpdate = vical.nextUpdate?.let { Instant.parse(it).epochSeconds }
        if (policy.requireNextUpdate) {
            require(nextUpdate != null) { "VICAL nextUpdate is required by policy" }
        }
        require(!policy.rejectPastNextUpdate || nextUpdate == null || nextUpdate > now) {
            "VICAL nextUpdate freshness cutoff exceeded"
        }
        val vicalNotAfter = vical.notAfter
        require(vicalNotAfter == null || Instant.parse(vicalNotAfter).epochSeconds > now) { "VICAL notAfter has expired" }
    }

    private suspend fun selectAndValidateEntries(vical: Vical, policy: VicalValidationPolicy): List<VicalCertificateInfo> {
        val expectedDocType = policy.expectedDocType
        val expectedSerial = policy.expectedCertificateSerialNumber
        val expectedSki = policy.expectedCertificateSki
        return vical.certificateInfos.mapNotNull { info ->
            if (policy.embeddedIacaTrustMode == VicalEmbeddedIacaTrustMode.AUTHENTICATED_VICAL) {
                // An authenticated source snapshot must not carry unauthenticated IACAs merely
                // because a caller selected a different document type.
                validateEntryMetadata(info, policy)
            }
            val docTypeMatch = expectedDocType == null || expectedDocType in info.docTypes
            val serialMatch = expectedSerial == null || unsignedEquals(info.serialNumber, expectedSerial)
            val skiMatch = expectedSki == null || info.ski.contentEquals(expectedSki)
            val profileMatch =
                policy.requiredCertificateProfiles.isEmpty() ||
                    info.certificateProfiles.orEmpty().any { it in policy.requiredCertificateProfiles }
            if (!docTypeMatch || !serialMatch || !skiMatch || !profileMatch) return@mapNotNull null
            if (policy.embeddedIacaTrustMode == VicalEmbeddedIacaTrustMode.LEGACY_CONFIGURED_ISSUER_ANCHOR) {
                validateEntryMetadata(info, policy)
            }
            info
        }
    }

    private suspend fun validateEntryMetadata(info: VicalCertificateInfo, policy: VicalValidationPolicy) {
        val certificate = certificateFromDer(info.certificate)
        when (policy.embeddedIacaTrustMode) {
            VicalEmbeddedIacaTrustMode.LEGACY_CONFIGURED_ISSUER_ANCHOR -> {
                val issuerTrust =
                    x509VerifyService.verifyCertificateChain(
                        X509VerificationRequest(
                            enabled = true,
                            chainDER = arrayOf(info.certificate),
                            trustedCerts = policy.trustedIssuerCerts,
                            verificationProfile = X509VerificationProfile.ISO_18013_5,
                            verificationTime = policy.verificationTime(),
                        ),
                    )
                require(!issuerTrust.error && !issuerTrust.critical && issuerTrust.message != "X509 verification has been disabled") {
                    "VICAL embedded issuer certificate is not trusted: ${issuerTrust.message}"
                }
            }

            VicalEmbeddedIacaTrustMode.AUTHENTICATED_VICAL -> {
                AuthenticatedVicalIacaValidator.validate(info.certificate, policy.verificationTimeEpochSeconds)
                policy.authenticatedIacaRestrictions?.let { restrictions ->
                    require(restrictions.isNotEmpty()) { "Authenticated IACA restriction list must not be empty" }
                    val admitted = com.sphereon.crypto.core.x509.pemAndDerToCertificateChain(restrictions, null)
                        .any { it.der.contentEquals(info.certificate) }
                    require(admitted) { "VICAL embedded IACA is not admitted by the configured local restrictions" }
                }
            }
        }
        val actualSerial = certificate.serialNumber?.let { hexToBytes(it) }
        require(actualSerial != null && unsignedEquals(actualSerial, info.serialNumber)) { "VICAL certificate serialNumber does not match certificate" }
        val actualSki = subjectKeyIdentifier(certificate.toX509Certificate())
            ?: error("VICAL certificate does not contain a Subject Key Identifier extension")
        require(actualSki.contentEquals(info.ski)) { "VICAL certificate ski does not match certificate" }
        info.notBefore?.let { require(Instant.parse(it) == certificate.notBefore) { "VICAL certificate notBefore does not match certificate" } }
        info.notAfter?.let { require(Instant.parse(it) == certificate.notAfter) { "VICAL certificate notAfter does not match certificate" } }
        val fields = ((Asn1Element.parse(info.certificate) as Asn1Sequence).children.first() as Asn1Sequence).children
        val versionOffset = if (fields.first().derEncoded.first() == 0xa0.toByte()) 1 else 0
        info.issuer?.let { require(it.contentEquals(fields[versionOffset + 2].derEncoded)) { "VICAL certificate issuer does not match certificate" } }
        info.subject?.let { require(it.contentEquals(fields[versionOffset + 4].derEncoded)) { "VICAL certificate subject does not match certificate" } }
    }

    private fun VicalValidationPolicy.verificationTime(): LocalDateTimeKMP =
        Instant.fromEpochSeconds(verificationTimeEpochSeconds).toLocalDateTime(TimeZone.currentSystemDefault()).let {
            LocalDateTimeKMP(it.year, it.monthNumber, it.dayOfMonth, it.hour, it.minute, it.second, it.nanosecond)
        }

    private fun unsignedEquals(left: ByteArray, right: ByteArray): Boolean =
        normalize(left).contentEquals(normalize(right))

    private fun normalize(value: ByteArray): ByteArray {
        val first = value.indexOfFirst { it.toInt() != 0 }
        return if (first < 0) byteArrayOf() else value.copyOfRange(first, value.size)
    }

    private fun hexToBytes(value: String): ByteArray {
        val normalized = value.replace(":", "").trim()
        require(normalized.length % 2 == 0) { "certificate serialNumber is not valid hexadecimal" }
        return ByteArray(normalized.length / 2) { index -> normalized.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    private fun subjectKeyIdentifier(certificate: at.asitplus.awesn1.crypto.pki.X509Certificate): ByteArray? {
        val extension = certificate.tbsCertificate.extensions
            ?.firstOrNull { it.oid.toString() == "2.5.29.14" }
            ?: return null
        // The X.509 extnValue is an OCTET STRING whose contents are the DER encoding of
        // SubjectKeyIdentifier (itself an OCTET STRING). awesn1 exposes extnValue contents,
        // so parse the inner value instead of accepting a derived hash as a substitute.
        return (Asn1Element.parse(extension.value) as? Asn1Primitive)?.content
    }
}
