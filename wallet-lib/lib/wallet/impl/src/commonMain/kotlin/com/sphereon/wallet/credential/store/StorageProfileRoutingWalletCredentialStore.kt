/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.sphereon.wallet.credential.store

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.di.session.SessionScope
import com.sphereon.wallet.credential.CredentialMetadata
import com.sphereon.wallet.credential.CredentialMetadataFilter
import com.sphereon.wallet.credential.CredentialRecord
import com.sphereon.wallet.credential.CredentialTypeRef
import com.sphereon.wallet.credential.HybridWalletCredentialStoreDelegate
import com.sphereon.wallet.credential.LocalWalletCredentialStore
import com.sphereon.wallet.credential.RemoteWalletCredentialStore
import com.sphereon.wallet.credential.StorageProfile
import com.sphereon.wallet.credential.WalletCredentialStore
import com.sphereon.wallet.credential.WalletStorageMode
import com.sphereon.wallet.credential.WalletStorageProfileResolver

/**
 * Routes wallet credential operations through the store selected by [StorageProfile].
 *
 * The delegates remain ordinary [WalletCredentialStore] implementations: local is typically the
 * blob-backed store, remote is typically the vault-backed store, and hybrid composes both. This
 * keeps routing rooted in the existing blob/vault abstractions instead of introducing another
 * credential persistence concept.
 */
class StorageProfileRoutingWalletCredentialStore(
    private val storageProfileResolver: WalletStorageProfileResolver,
    private val localStore: LocalWalletCredentialStore,
    private val remoteStore: RemoteWalletCredentialStore,
    private val hybridStore: HybridWalletCredentialStoreDelegate,
) : WalletCredentialStore {
    override suspend fun putCredential(
        walletUnitId: String,
        record: CredentialRecord,
    ): IdkResult<CredentialRecord, IdkError> = delegateFor(walletUnitId).flatMap { it.putCredential(walletUnitId, record) }

    override suspend fun getCredential(
        walletUnitId: String,
        credentialRecordId: String,
    ): IdkResult<CredentialRecord?, IdkError> = delegateFor(walletUnitId).flatMap { it.getCredential(walletUnitId, credentialRecordId) }

    override suspend fun getCredentialEnvelope(
        walletUnitId: String,
        credentialRecordId: String,
    ): IdkResult<CredentialRecord?, IdkError> = delegateFor(walletUnitId).flatMap { it.getCredentialEnvelope(walletUnitId, credentialRecordId) }

    override suspend fun updateCredentialEnvelope(
        walletUnitId: String,
        credentialRecordId: String,
        transform: (CredentialRecord) -> CredentialRecord,
    ): IdkResult<CredentialRecord?, IdkError> = delegateFor(walletUnitId).flatMap { it.updateCredentialEnvelope(walletUnitId, credentialRecordId, transform) }

    override suspend fun getMetadata(
        walletUnitId: String,
        credentialRecordId: String,
    ): IdkResult<CredentialMetadata?, IdkError> = delegateFor(walletUnitId).flatMap { it.getMetadata(walletUnitId, credentialRecordId) }

    override suspend fun listMetadata(
        walletUnitId: String,
        filter: CredentialMetadataFilter,
    ): IdkResult<List<CredentialMetadata>, IdkError> = delegateFor(walletUnitId).flatMap { it.listMetadata(walletUnitId, filter) }

    override suspend fun findByCredentialTypeRef(
        walletUnitId: String,
        ref: CredentialTypeRef,
    ): IdkResult<List<CredentialMetadata>, IdkError> = delegateFor(walletUnitId).flatMap { it.findByCredentialTypeRef(walletUnitId, ref) }

    override suspend fun deleteCredential(
        walletUnitId: String,
        credentialRecordId: String,
    ): IdkResult<Boolean, IdkError> = delegateFor(walletUnitId).flatMap { it.deleteCredential(walletUnitId, credentialRecordId) }

    private suspend fun delegateFor(walletUnitId: String): IdkResult<WalletCredentialStore, IdkError> {
        val profileResult = storageProfileResolver.resolveStorageProfile(walletUnitId)
        if (profileResult.isErr) return Err(profileResult.error)

        val profile = profileResult.value
        val validationError = profile.validationError(walletUnitId)
        if (validationError != null) return Err(validationError)

        return Ok(
            when (profile.mode) {
                WalletStorageMode.LOCAL -> localStore
                WalletStorageMode.REMOTE -> remoteStore
                WalletStorageMode.HYBRID -> hybridStore
            },
        )
    }

    private fun StorageProfile.validationError(walletUnitId: String): IdkError? {
        if (this.walletUnitId != walletUnitId) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "StorageProfile.walletUnitId must match walletUnitId")
        }
        return when (mode) {
            WalletStorageMode.LOCAL -> {
                if (localStoreRef == null) {
                    IdkError.ILLEGAL_ARGUMENT_ERROR(message = "LOCAL storage profile '$id' requires localStoreRef")
                } else {
                    null
                }
            }

            WalletStorageMode.REMOTE -> {
                if (remoteVaultRef == null) {
                    IdkError.ILLEGAL_ARGUMENT_ERROR(message = "REMOTE storage profile '$id' requires remoteVaultRef")
                } else {
                    null
                }
            }

            WalletStorageMode.HYBRID -> {
                if (localStoreRef == null || remoteVaultRef == null) {
                    IdkError.ILLEGAL_ARGUMENT_ERROR(message = "HYBRID storage profile '$id' requires localStoreRef and remoteVaultRef")
                } else {
                    null
                }
            }
        }
    }
}

private suspend inline fun <T, R> IdkResult<T, IdkError>.flatMap(crossinline block: suspend (T) -> IdkResult<R, IdkError>): IdkResult<R, IdkError> = if (isOk) block(value) else Err(error)
