/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.wallet.unit.attestation

import com.sphereon.wallet.unit.EudiWalletTrustEvidence
import com.sphereon.wallet.unit.WalletAttestationStatusEvidence
import com.sphereon.wallet.unit.WalletAttestedKeyRef
import com.sphereon.wallet.unit.WalletKeystoreRef
import com.sphereon.wallet.unit.WalletPrivateKeyProtectionEvidence
import com.sphereon.wallet.unit.WalletProviderAttestationSignerRef
import com.sphereon.wallet.unit.WalletSecureComponentEvidence
import com.sphereon.wallet.unit.WalletSecureCryptographicApplicationRef
import com.sphereon.wallet.unit.WalletSecureCryptographicDeviceRef
import com.sphereon.wallet.unit.WalletSolutionRef
import com.sphereon.wallet.unit.WalletStatusMaintenancePeriod
import com.sphereon.wallet.unit.WalletStatusSubjectRef
import com.sphereon.wallet.unit.WalletUserAuthenticationEvidence
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlin.time.Instant

@Serializable
enum class WalletUnitAttestationKind {
    WUA,
    WIA,
    KA,
}

@Serializable
enum class WalletUnitAttestationProfile {
    LOCAL_EVALUATION_REFERENCE,
    TS03_JWT,
    OID4VCI_JWT,
}

@Serializable
enum class WalletUnitAttestationStatus {
    ACTIVE,
    REVOKED,
    CONSUMED,
}

@Serializable
enum class WalletUnitAttestationFormat {
    STORED_REF,
    JWT,
    SD_JWT_VC,
    SD_JWT_VC_PRESENTATION,
    KEY_ATTESTATION_JWT,
    MDOC_DEVICE_RESPONSE,
    MDOC_DOCUMENT,
    MDOC_ISSUER_SIGNED,
}

@Serializable
enum class WalletUnitAttestationEncoding {
    COMPACT,
    BASE64URL,
}

@Serializable
data class WalletUnitAttestationMaterial(
    val format: WalletUnitAttestationFormat,
    val value: String,
    val encoding: WalletUnitAttestationEncoding = WalletUnitAttestationEncoding.COMPACT,
)

@Serializable
data class WalletUnitAttestationTrustInput(
    val trustedJwks: JsonObject? = null,
    val trustedIssuers: List<String> = emptyList(),
    val x509TrustAnchorPaths: List<String> = emptyList(),
    val mdocTrustedCerts: List<String> = emptyList(),
    val walletProviderTrustEvidence: EudiWalletTrustEvidence? = null,
    val walletSolutionTrustEvidence: EudiWalletTrustEvidence? = null,
    val statusEvidence: WalletAttestationStatusEvidence? = null,
)

@Serializable
data class WalletUnitAttestationEvidence(
    val profile: WalletUnitAttestationProfile,
    val ts03Conformant: Boolean,
    val signer: WalletProviderAttestationSignerRef? = null,
    val walletSolution: WalletSolutionRef? = null,
    val secureApplication: WalletSecureCryptographicApplicationRef? = null,
    val secureDevice: WalletSecureCryptographicDeviceRef? = null,
    val secureComponent: WalletSecureComponentEvidence? = null,
    val keystore: WalletKeystoreRef? = null,
    val userAuthentication: WalletUserAuthenticationEvidence? = null,
    val privateKeyProtection: WalletPrivateKeyProtectionEvidence? = null,
    val trustEvidence: EudiWalletTrustEvidence? = null,
    val custom: Map<String, String> = emptyMap(),
)

@Serializable
data class WalletAttestationArtifactMetadata(
    val artifactHash: String,
    val statusSubject: WalletStatusSubjectRef? = null,
    val maintenancePeriod: WalletStatusMaintenancePeriod? = null,
    val signingEvidence: Map<String, String> = emptyMap(),
    val claimSummary: Map<String, String> = emptyMap(),
    val singleUse: Boolean = false,
    val consumedAt: Instant? = null,
)

@Serializable
data class WalletAttestationArtifact(
    val kind: WalletUnitAttestationKind,
    val profile: WalletUnitAttestationProfile,
    val material: WalletUnitAttestationMaterial,
    val issuedAt: Instant,
    val expiresAt: Instant? = null,
    val statusSubject: WalletStatusSubjectRef? = null,
    val evidence: WalletUnitAttestationEvidence,
    val metadata: WalletAttestationArtifactMetadata,
)

@Serializable
data class WalletInstanceAttestationValidationRequest(
    val material: WalletUnitAttestationMaterial,
    val expectedAudience: String,
    val expectedIssuer: String? = null,
    val trust: WalletUnitAttestationTrustInput = WalletUnitAttestationTrustInput(),
    val validationPolicy: Ts03WalletAttestationValidationPolicy = Ts03WalletAttestationValidationPolicy(),
    val validationTimeEpochSeconds: Long? = null,
    val clockSkewSeconds: Long = 300,
)

@Serializable
data class KeyAttestationValidationRequest(
    val material: WalletUnitAttestationMaterial,
    val expectedAudience: String,
    val expectedNonce: String,
    val expectedIssuer: String? = null,
    val requiredKeyStorage: List<String> = emptyList(),
    val requiredUserAuthentication: List<String> = emptyList(),
    val trust: WalletUnitAttestationTrustInput = WalletUnitAttestationTrustInput(),
    val validationPolicy: Ts03WalletAttestationValidationPolicy = Ts03WalletAttestationValidationPolicy(),
    val validationTimeEpochSeconds: Long? = null,
    val clockSkewSeconds: Long = 300,
)

@Serializable
data class Ts1194723ValidationResult(
    val valid: Boolean,
    val format: WalletUnitAttestationFormat,
    val evidence: Map<String, String> = emptyMap(),
    val errors: List<String> = emptyList(),
)

interface WalletUnitAttestationMaterialValidator {
    suspend fun validateWalletInstanceAttestation(request: WalletInstanceAttestationValidationRequest): com.sphereon.core.api.IdkResult<Ts1194723ValidationResult, com.sphereon.core.api.error.IdkError>

    suspend fun validateKeyAttestation(request: KeyAttestationValidationRequest): com.sphereon.core.api.IdkResult<Ts1194723ValidationResult, com.sphereon.core.api.error.IdkError>
}

/**
 * D10 (WIA binding hygiene): the wallet instance identity a WIA attests to is never
 * caller-supplied. It is always resolved server-side from the wallet unit's authoritative
 * instance association (the unit-instance pair minted at provisioning). Earlier versions of
 * this request carried a caller-supplied `walletInstance: WalletInstanceRef`, but the issuer
 * only ever consumed its `id`; none of `holderBindingRef`, `integrityEvidenceRef`, or
 * `evidence` were read on the issue path, so the ref was dropped entirely rather than kept
 * around as a partially-used input. [expectedWalletInstanceId] replaces it as an optional,
 * validation-only precondition: callers that already know which instance they expect can
 * assert it, and issuance is rejected if it disagrees with the resolved authoritative id.
 */
@Serializable
data class WalletInstanceAttestationIssueRequest(
    val walletUnitId: String,
    val walletAccountId: String,
    /** Exact attended operation authorized to use the WSCA signer. */
    val operationBinding: String,
    val profile: WalletUnitAttestationProfile,
    val requestedFormat: WalletUnitAttestationFormat = WalletUnitAttestationFormat.JWT,
    val expectedWalletInstanceId: String? = null,
    val walletSolution: WalletSolutionRef,
    val secureApplication: WalletSecureCryptographicApplicationRef? = null,
    val secureDevice: WalletSecureCryptographicDeviceRef? = null,
    val keystore: WalletKeystoreRef? = null,
    val signer: WalletProviderAttestationSignerRef? = null,
    val statusSubject: WalletStatusSubjectRef? = null,
    val audience: String,
    val expiresAt: Instant,
    val proofBinding: Map<String, String> = emptyMap(),
    val evidence: Map<String, String> = emptyMap(),
) {
    init {
        require(operationBinding.isNotBlank()) { "wallet_instance_attestation_operation_binding_blank" }
    }
}

@Serializable
data class WalletInstanceAttestationIssueResult(
    val walletUnitId: String,
    val walletAccountId: String,
    val attestationRef: String,
    val artifact: WalletAttestationArtifact,
    val statusRef: String? = artifact.statusSubject?.statusListUri,
    val issuedAt: Instant,
    val expiresAt: Instant,
)

@Serializable
data class KeyAttestationIssueRequest(
    val walletUnitId: String,
    val walletAccountId: String,
    /** Exact attended operation authorized to use the WSCA signer. */
    val operationBinding: String,
    val profile: WalletUnitAttestationProfile,
    val requestedFormat: WalletUnitAttestationFormat = WalletUnitAttestationFormat.KEY_ATTESTATION_JWT,
    val attestedKeys: List<WalletAttestedKeyRef>,
    val secureApplication: WalletSecureCryptographicApplicationRef? = null,
    val secureDevice: WalletSecureCryptographicDeviceRef? = null,
    val keystore: WalletKeystoreRef? = null,
    val userAuthentication: WalletUserAuthenticationEvidence? = null,
    val privateKeyProtection: WalletPrivateKeyProtectionEvidence? = null,
    val signer: WalletProviderAttestationSignerRef? = null,
    val statusSubject: WalletStatusSubjectRef? = null,
    val audience: String,
    val nonce: String,
    val expiresAt: Instant? = null,
    val singleUse: Boolean = true,
    val evidence: Map<String, String> = emptyMap(),
) {
    init {
        require(operationBinding.isNotBlank()) { "key_attestation_operation_binding_blank" }
    }
}

@Serializable
data class KeyAttestationIssueResult(
    val walletUnitId: String,
    val walletAccountId: String,
    val attestationRef: String,
    val artifact: WalletAttestationArtifact,
    val nonce: String,
    val audience: String,
)

@Serializable
data class WalletInstanceAttestationRecord(
    val walletUnitId: String,
    val walletAccountId: String,
    val attestationRef: String,
    val audience: String,
    val status: WalletUnitAttestationStatus = WalletUnitAttestationStatus.ACTIVE,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val artifact: WalletAttestationArtifact,
)

@Serializable
data class KeyAttestationRecord(
    val walletUnitId: String,
    val walletAccountId: String,
    val attestationRef: String,
    val audience: String,
    val nonce: String,
    val status: WalletUnitAttestationStatus = WalletUnitAttestationStatus.ACTIVE,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val artifact: WalletAttestationArtifact,
)

@Serializable
data class WalletUnitAttestationTombstoneResult(
    val walletUnitId: String,
    val walletAccountId: String? = null,
    val walletInstanceAttestations: Int,
    val keyAttestations: Int,
    val tombstonedAt: Instant,
    val reason: String,
)

interface WalletUnitAttestationStore {
    suspend fun saveWalletInstanceAttestation(record: WalletInstanceAttestationRecord): com.sphereon.core.api.IdkResult<WalletInstanceAttestationRecord, com.sphereon.core.api.error.IdkError>

    suspend fun findWalletInstanceAttestation(attestationRef: String): com.sphereon.core.api.IdkResult<WalletInstanceAttestationRecord?, com.sphereon.core.api.error.IdkError>

    suspend fun listWalletInstanceAttestations(
        walletUnitId: String,
        walletAccountId: String? = null,
    ): com.sphereon.core.api.IdkResult<List<WalletInstanceAttestationRecord>, com.sphereon.core.api.error.IdkError>

    suspend fun saveKeyAttestation(record: KeyAttestationRecord): com.sphereon.core.api.IdkResult<KeyAttestationRecord, com.sphereon.core.api.error.IdkError>

    suspend fun findKeyAttestation(attestationRef: String): com.sphereon.core.api.IdkResult<KeyAttestationRecord?, com.sphereon.core.api.error.IdkError>

    suspend fun listKeyAttestations(
        walletUnitId: String,
        walletAccountId: String? = null,
    ): com.sphereon.core.api.IdkResult<List<KeyAttestationRecord>, com.sphereon.core.api.error.IdkError>

    suspend fun tombstoneWalletUnitAttestations(
        walletUnitId: String,
        walletAccountId: String? = null,
        tombstonedAt: Instant,
        reason: String,
    ): com.sphereon.core.api.IdkResult<WalletUnitAttestationTombstoneResult, com.sphereon.core.api.error.IdkError>
}

interface WalletInstanceAttestationIssuer {
    suspend fun issue(request: WalletInstanceAttestationIssueRequest): com.sphereon.core.api.IdkResult<WalletInstanceAttestationIssueResult, com.sphereon.core.api.error.IdkError>
}

interface KeyAttestationIssuer {
    suspend fun issue(request: KeyAttestationIssueRequest): com.sphereon.core.api.IdkResult<KeyAttestationIssueResult, com.sphereon.core.api.error.IdkError>
}

interface Ts1194723ServerValidationService {
    suspend fun validateWalletInstanceAttestation(
        attestationRef: String,
        expectedAudience: String
    ): com.sphereon.core.api.IdkResult<Boolean, com.sphereon.core.api.error.IdkError>

    suspend fun validateKeyAttestation(
        attestationRef: String,
        expectedAudience: String,
        expectedNonce: String
    ): com.sphereon.core.api.IdkResult<Boolean, com.sphereon.core.api.error.IdkError>

    suspend fun validateWalletInstanceAttestation(request: WalletInstanceAttestationValidationRequest): com.sphereon.core.api.IdkResult<Ts1194723ValidationResult, com.sphereon.core.api.error.IdkError>

    suspend fun validateKeyAttestation(request: KeyAttestationValidationRequest): com.sphereon.core.api.IdkResult<Ts1194723ValidationResult, com.sphereon.core.api.error.IdkError>
}
