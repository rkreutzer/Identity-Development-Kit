/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.mdoc.vical

import com.sphereon.cbor.CborItem
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.cose.CoseKeyType
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Multibinds
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/** One CertificateInfo entry in an ISO/IEC 18013-5 VICAL. */
data class VicalCertificateInfo(
    val certificate: ByteArray,
    val serialNumber: ByteArray,
    val ski: ByteArray,
    val docTypes: List<String>,
    val certificateProfiles: List<String>? = null,
    val issuingAuthority: String? = null,
    val issuingCountry: String? = null,
    val stateOrProvinceName: String? = null,
    val issuer: ByteArray? = null,
    val subject: ByteArray? = null,
    val notBefore: String? = null,
    val notAfter: String? = null,
    val extensions: Map<String, CborItem<*>>? = null,
) {
    init {
        require(certificate.isNotEmpty()) { "VICAL certificate must not be empty" }
        require(serialNumber.isNotEmpty() && serialNumber.first().toInt() != 0 && serialNumber.any { it.toInt() != 0 }) {
            "VICAL serialNumber must be a canonical positive biguint"
        }
        require(ski.isNotEmpty()) { "VICAL ski must not be empty" }
        require(docTypes.isNotEmpty() && docTypes.all { it.isNotBlank() }) {
            "VICAL docTypes must contain at least one non-blank document type"
        }
        require(certificateProfiles == null || certificateProfiles.all(::isVicalProfileUrn)) {
            "VICAL certificateProfiles must be RFC 8141 URNs"
        }
    }

    override fun equals(other: Any?): Boolean =
        other is VicalCertificateInfo &&
            certificate.contentEquals(other.certificate) &&
            serialNumber.contentEquals(other.serialNumber) &&
            ski.contentEquals(other.ski) &&
            docTypes == other.docTypes &&
            certificateProfiles == other.certificateProfiles &&
            issuingAuthority == other.issuingAuthority &&
            issuingCountry == other.issuingCountry &&
            stateOrProvinceName == other.stateOrProvinceName &&
            issuer.contentEqualsNullable(other.issuer) &&
            subject.contentEqualsNullable(other.subject) &&
            notBefore == other.notBefore &&
            notAfter == other.notAfter &&
            extensions == other.extensions

    override fun hashCode(): Int {
        var result = certificate.contentHashCode()
        result = 31 * result + serialNumber.contentHashCode()
        result = 31 * result + ski.contentHashCode()
        result = 31 * result + docTypes.hashCode()
        result = 31 * result + (certificateProfiles?.hashCode() ?: 0)
        result = 31 * result + (issuingAuthority?.hashCode() ?: 0)
        result = 31 * result + (issuingCountry?.hashCode() ?: 0)
        result = 31 * result + (stateOrProvinceName?.hashCode() ?: 0)
        result = 31 * result + issuer.contentHashCodeNullable()
        result = 31 * result + subject.contentHashCodeNullable()
        result = 31 * result + (notBefore?.hashCode() ?: 0)
        result = 31 * result + (notAfter?.hashCode() ?: 0)
        result = 31 * result + (extensions?.hashCode() ?: 0)
        return result
    }
}

/** The payload covered by the VICAL COSE_Sign1 signature. */
data class Vical(
    val version: String = "1.0",
    val vicalProvider: String,
    /** Optional unsigned issue identifier; zero is valid in the ISO/IEC 18013-5 CDDL. */
    val vicalIssueId: ULong? = null,
    val date: String,
    val nextUpdate: String? = null,
    val notAfter: String? = null,
    val certificateInfos: List<VicalCertificateInfo>,
    val extensions: Map<String, CborItem<*>>? = null,
    val vicalUrl: String? = null,
) {
    init {
        require(version == "1.0") { "VICAL version must be '1.0'" }
        require(vicalProvider.isNotBlank()) { "VICAL provider must not be blank" }
        require(certificateInfos.all { it.docTypes.isNotEmpty() }) { "VICAL certificateInfos must be valid" }
        require(vicalUrl == null || vicalUrl.isNotBlank()) { "VICAL URL must not be blank" }
    }
}

/** CBOR codec for the untagged VICAL payload (not the surrounding COSE_Sign1). */
interface VicalCborCodec {
    fun encode(value: Vical): ByteArray

    fun decode(bytes: ByteArray): Vical
}

/** Explicit trust and selection policy for a signed VICAL. */
data class VicalValidationPolicy(
    val trustedCerts: Array<String>,
    /** Trust anchors for embedded issuer/IACA certificates; defaults to the configured VICAL trust. */
    val trustedIssuerCerts: Array<String> = trustedCerts,
    val verificationTimeEpochSeconds: Long = Clock.System.now().epochSeconds,
    val expectedDocType: String? = null,
    val expectedCertificateSerialNumber: ByteArray? = null,
    val expectedCertificateSki: ByteArray? = null,
    val requiredCertificateProfiles: Set<String> = emptySet(),
    /** Local policy requiring the otherwise optional expected publication time. */
    val requireNextUpdate: Boolean = true,
    val clockSkewSeconds: Long = 120,
    val embeddedIacaTrustMode: VicalEmbeddedIacaTrustMode = VicalEmbeddedIacaTrustMode.LEGACY_CONFIGURED_ISSUER_ANCHOR,
    val authenticatedIacaRestrictions: Array<String>? = null,
    /**
     * Local freshness cutoff, enabled by default for backwards compatibility.
     * ISO/IEC 18013-5 defines nextUpdate as an expected publication time, not an expiry.
     * Disabling this cutoff does not disable certificate validity or signature validation.
     */
    val rejectPastNextUpdate: Boolean = true,
    val signerCertificateProfile: VicalSignerCertificateProfile = VicalSignerCertificateProfile.LEGACY,
) {
    init {
        require(trustedCerts.isNotEmpty()) { "VICAL validation requires configured trust anchors" }
        require(embeddedIacaTrustMode != VicalEmbeddedIacaTrustMode.LEGACY_CONFIGURED_ISSUER_ANCHOR || trustedIssuerCerts.isNotEmpty()) {
            "Legacy VICAL validation requires configured issuer trust anchors"
        }
        require(embeddedIacaTrustMode != VicalEmbeddedIacaTrustMode.LEGACY_CONFIGURED_ISSUER_ANCHOR || authenticatedIacaRestrictions == null) {
            "Authenticated IACA restrictions require authenticated VICAL IACA trust mode"
        }
        require(embeddedIacaTrustMode != VicalEmbeddedIacaTrustMode.AUTHENTICATED_VICAL || trustedIssuerCerts.contentEquals(trustedCerts)) {
            "Authenticated VICAL IACA mode does not consume trustedIssuerCerts; use authenticatedIacaRestrictions for local restrictions"
        }
        require(clockSkewSeconds >= 0) { "VICAL clock skew must not be negative" }
        require(requiredCertificateProfiles.all(::isVicalProfileUrn)) { "VICAL required certificate profiles must be RFC 8141 URNs" }
    }
}

/** Explicitly adopted signer profile; Annex C is informative in ISO/IEC 18013-5. */
enum class VicalSignerCertificateProfile {
    /** Existing generic certificate-chain validation, without a dedicated VICAL leaf profile. */
    LEGACY,
    /** Annex C signer certificate checks, with the currently supported NIST EC curves. */
    ISO_18013_5_ANNEX_C,
}

/** How certificates embedded in an already authenticated VICAL become trusted IACAs. */
enum class VicalEmbeddedIacaTrustMode {
    /** Backwards-compatible behavior: every embedded certificate must chain to [VicalValidationPolicy.trustedIssuerCerts]. */
    LEGACY_CONFIGURED_ISSUER_ANCHOR,

    /** Apply the local authenticated-IACA security minimum; this is not a claim of full ISO/IEC 18013-5 profile validation. */
    AUTHENTICATED_VICAL,
}

data class VicalValidationResult(
    val vical: Vical,
    val signerCertificateChain: List<ByteArray>,
    val matchingCertificateInfos: List<VicalCertificateInfo>,
)

/** Signs a VICAL payload as an untagged COSE_Sign1 with an unprotected x5chain. */
interface VicalSigner {
    suspend fun sign(
        vical: Vical,
        keyInfo: KeyInfoType<CoseKeyType>? = null,
    ): IdkResult<ByteArray, IdkError>
}

/** Validates a signed VICAL and selects entries for a document ecosystem. */
interface VicalValidator {
    suspend fun validate(
        signedVical: ByteArray,
        policy: VicalValidationPolicy,
    ): IdkResult<VicalValidationResult, IdkError>
}

/** Retrieval policy for a tenant's remotely published VICAL. */
data class VicalFetchPolicy(
    val validation: VicalValidationPolicy,
    val requireHttps: Boolean = true,
    /** Requires canonical application/cbor or legacy application/cwt VICAL media. */
    val requireApplicationCwt: Boolean = true,
    val maxBodyBytes: Long = 10 * 1024 * 1024,
    val maxRedirects: Int = 3,
    val useCache: Boolean = true,
    val cacheTtl: Duration = 60.minutes,
) {
    init {
        require(maxBodyBytes > 0) { "VICAL maximum body size must be positive" }
        require(maxBodyBytes <= Int.MAX_VALUE.toLong()) { "VICAL maximum body size exceeds the supported in-memory limit" }
        require(maxRedirects >= 0) { "VICAL maximum redirects must not be negative" }
        require(cacheTtl.isPositive()) { "VICAL cache TTL must be positive" }
    }
}

data class VicalFetchResult(
    val validation: VicalValidationResult,
    val sourceUrl: String,
    val fetchedAtEpochSeconds: Long,
    val fromCache: Boolean,
)

/** Retrieves and validates a tenant-scoped VICAL publication. */
interface VicalFetcher {
    suspend fun fetch(
        url: String,
        policy: VicalFetchPolicy,
    ): IdkResult<VicalFetchResult, IdkError>
}

/**
 * Public DI seam for tenant-scoped VICAL consumers. Keeping this as an allow-empty multibinding
 * lets verifier and wallet products depend on the protocol API without making the HTTP/cache
 * implementation mandatory in every platform graph. A configured VICAL source must still fail
 * closed when this set is empty; the consumer owns that policy.
 */
@ContributesTo(SessionScope::class)
interface VicalFetcherMultibinds {
    @Multibinds(allowEmpty = true)
    fun vicalFetchers(): Set<VicalFetcher>
}

private fun ByteArray?.contentEqualsNullable(other: ByteArray?): Boolean =
    when {
        this == null || other == null -> this == null && other == null
        else -> contentEquals(other)
    }

private fun ByteArray?.contentHashCodeNullable(): Int = this?.contentHashCode() ?: 0

// RFC 8141 namestring grammar. Percent escapes must be complete; URI whitespace and
// non-ASCII characters must be percent encoded. Namespace registration is not inferred.
private val vicalUrnPchar = "(?:[A-Za-z0-9._~!$&'()*+,;=:@-]|%[0-9A-Fa-f]{2})"
private val vicalProfileUrn = Regex(
    "[uU][rR][nN]:[A-Za-z0-9][A-Za-z0-9-]{0,30}[A-Za-z0-9]:" +
        "$vicalUrnPchar(?:$vicalUrnPchar|/)*" +
        "(?:\\?\\+$vicalUrnPchar(?:$vicalUrnPchar|/|\\?(?!=))*)?" +
        "(?:\\?=$vicalUrnPchar(?:$vicalUrnPchar|/|\\?)*)?" +
        "(?:#(?:$vicalUrnPchar|/|\\?)*)?",
)
private fun isVicalProfileUrn(value: String): Boolean = vicalProfileUrn.matches(value)
