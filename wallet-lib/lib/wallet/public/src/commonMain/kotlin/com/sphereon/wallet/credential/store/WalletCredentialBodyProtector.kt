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

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import kotlinx.serialization.Serializable

@Serializable
enum class WalletCredentialProtectedDocumentRole {
    CREDENTIAL_INSTANCE_BODY,
    CREDENTIAL_RECORD_ENVELOPE,
    CREDENTIAL_TOMBSTONE,
    ISSUANCE_SESSION,
    DEFERRED_ACCESS_TOKEN,
    ISSUANCE_SESSION_TOMBSTONE,
    REFRESH_TOKEN,
}

interface WalletCredentialBodyProtector {
    suspend fun protect(
        walletUnitId: String,
        credentialRecordId: String,
        credentialInstanceId: String,
        plaintext: ByteArray,
        documentRole: WalletCredentialProtectedDocumentRole = WalletCredentialProtectedDocumentRole.CREDENTIAL_INSTANCE_BODY,
    ): IdkResult<ByteArray, IdkError>

    suspend fun open(
        walletUnitId: String,
        credentialRecordId: String,
        credentialInstanceId: String,
        protectedBody: ByteArray,
        documentRole: WalletCredentialProtectedDocumentRole = WalletCredentialProtectedDocumentRole.CREDENTIAL_INSTANCE_BODY,
    ): IdkResult<ByteArray, IdkError>

    /** Validates envelope structure and exact context binding without returning plaintext. */
    suspend fun validate(
        walletUnitId: String,
        credentialRecordId: String,
        credentialInstanceId: String,
        protectedBody: ByteArray,
        documentRole: WalletCredentialProtectedDocumentRole = WalletCredentialProtectedDocumentRole.CREDENTIAL_INSTANCE_BODY,
    ): IdkResult<Unit, IdkError> = open(
        walletUnitId,
        credentialRecordId,
        credentialInstanceId,
        protectedBody,
        documentRole,
    ).map { plaintext ->
        plaintext.fill(0)
        Unit
    }
}
