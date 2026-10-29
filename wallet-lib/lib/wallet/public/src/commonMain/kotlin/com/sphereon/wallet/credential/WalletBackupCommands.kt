/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.wallet.credential

import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.ActionType
import com.sphereon.core.api.service.ServiceCommand
import kotlinx.serialization.Serializable

/**
 * Authenticated deletion evidence emitted by a wallet-specific credential store.
 *
 * Tenant authority is deliberately absent. The command implementation derives it from the
 * current session and binds the evidence to the authoritative managed-wallet registration.
 */
@Serializable
data class WalletCredentialDeletionManifestEvidence(
    val walletUnitId: String,
    val credentialRecordId: String,
    val tombstoneDocumentRef: String,
    val tombstoneDocumentVersion: Long,
    val tombstoneDigest: String,
    val erasedBodyDocumentRefs: Set<String>,
    val deletedAtEpochSeconds: Long,
    /** Encrypted auxiliary secrets erased with the credential, separate from instance bodies. */
    val erasedSecretDocumentRefs: Set<String> = emptySet(),
) {
    init {
        require(walletUnitId.isNotBlank() && credentialRecordId.isNotBlank()) {
            "wallet_credential_deletion_manifest_identity_invalid"
        }
        require(tombstoneDocumentRef.isNotBlank() && tombstoneDocumentVersion > 0) {
            "wallet_credential_deletion_manifest_tombstone_invalid"
        }
        require(tombstoneDigest.startsWith("sha256:") && tombstoneDigest.length > "sha256:".length) {
            "wallet_credential_deletion_manifest_digest_invalid"
        }
        require(
            erasedBodyDocumentRefs.none(String::isBlank) &&
                erasedSecretDocumentRefs.none(String::isBlank) &&
                erasedSecretDocumentRefs.intersect(erasedBodyDocumentRefs).isEmpty() &&
                deletedAtEpochSeconds > 0,
        ) {
            "wallet_credential_deletion_manifest_evidence_invalid"
        }
    }
}

@Serializable
data class WalletCredentialDeletionManifestReceipt(
    val walletUnitId: String,
    val credentialRecordId: String,
    val manifestVersion: Long,
    val tombstoneDigest: String,
) {
    init {
        require(walletUnitId.isNotBlank() && credentialRecordId.isNotBlank() && manifestVersion > 0) {
            "wallet_credential_deletion_manifest_receipt_invalid"
        }
        require(tombstoneDigest.startsWith("sha256:")) {
            "wallet_credential_deletion_manifest_receipt_digest_invalid"
        }
    }
}

interface RecordWalletCredentialDeletionManifestServiceCommand :
    ServiceCommand<WalletCredentialDeletionManifestEvidence, WalletCredentialDeletionManifestReceipt, IdkError> {
    override val actionType: ActionType get() = ActionType.UPDATE

    companion object {
        const val COMMAND_ID = "wallet.backup.record-credential-deletion"
    }
}

/** Narrow wallet-store port whose enterprise adapter delegates to the registered command. */
interface WalletCredentialDeletionManifestRecorder {
    suspend fun recordDeletion(
        evidence: WalletCredentialDeletionManifestEvidence,
    ): com.sphereon.core.api.IdkResult<WalletCredentialDeletionManifestReceipt, IdkError>
}
