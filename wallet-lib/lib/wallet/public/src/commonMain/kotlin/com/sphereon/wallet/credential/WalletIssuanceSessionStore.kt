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

package com.sphereon.wallet.credential

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError

/**
 * Policy gate for copying deferred access-token secrets between local blob storage and a remote
 * vault while using hybrid issuance-session storage.
 *
 * The default policy denies remote secret mirroring. Applications that intentionally support
 * remote deferred-issuance resume can inject or construct an allowing policy without changing the
 * issuance-session store API.
 */
interface WalletDeferredAccessTokenRemoteMirrorPolicy {
    suspend fun allowRemoteMirror(request: WalletDeferredAccessTokenRemoteMirrorRequest): Boolean

    companion object {
        val deny: WalletDeferredAccessTokenRemoteMirrorPolicy =
            object : WalletDeferredAccessTokenRemoteMirrorPolicy {
                override suspend fun allowRemoteMirror(request: WalletDeferredAccessTokenRemoteMirrorRequest): Boolean = false
            }

        val allow: WalletDeferredAccessTokenRemoteMirrorPolicy =
            object : WalletDeferredAccessTokenRemoteMirrorPolicy {
                override suspend fun allowRemoteMirror(request: WalletDeferredAccessTokenRemoteMirrorRequest): Boolean = true
            }
    }
}

data class WalletDeferredAccessTokenRemoteMirrorRequest(
    val walletUnitId: String,
    val issuanceSessionId: String,
    val operation: WalletDeferredAccessTokenRemoteMirrorOperation,
)

enum class WalletDeferredAccessTokenRemoteMirrorOperation {
    STORE_REMOTE_COPY,
    READ_REMOTE_COPY,
}

/**
 * Persistence for resumable wallet-side issuance state.
 *
 * Implementations store [IssuanceSession] metadata separately from any access-token secret so
 * list/get session APIs can resume workflows without exposing credential bodies or token material.
 */
interface WalletIssuanceSessionStore {
    suspend fun putSession(
        walletUnitId: String,
        session: IssuanceSession,
    ): IdkResult<IssuanceSession, IdkError>

    suspend fun getSession(
        walletUnitId: String,
        issuanceSessionId: String,
    ): IdkResult<IssuanceSession?, IdkError>

    suspend fun listSessions(
        walletUnitId: String,
        statuses: Set<IssuanceSessionStatus> = emptySet(),
    ): IdkResult<List<IssuanceSession>, IdkError>

    suspend fun storeDeferredAccessToken(
        walletUnitId: String,
        issuanceSessionId: String,
        accessToken: String,
    ): IdkResult<SecretRef, IdkError>

    suspend fun getDeferredAccessToken(
        walletUnitId: String,
        issuanceSessionId: String,
    ): IdkResult<String?, IdkError>

    /**
     * Persists the OAuth2 refresh token for a credential record and returns a [SecretRef] to it for
     * later silent replenishment (ARF ISSU_45/65). The default returns
     * `WALLET_REFRESH_TOKEN_PERSISTENCE_UNSUPPORTED`; callers must handle that error rather than
     * assuming a token was stored.
     */
    suspend fun storeRefreshToken(
        walletUnitId: String,
        credentialRecordId: String,
        refreshToken: String,
    ): IdkResult<SecretRef, IdkError> = Err(IdkError.fromString(code = "WALLET_REFRESH_TOKEN_PERSISTENCE_UNSUPPORTED", message = "This wallet issuance session store does not persist refresh tokens"))

    /** Reads back a refresh token stored by [storeRefreshToken]. Default returns null (none available). */
    suspend fun getRefreshToken(
        walletUnitId: String,
        credentialRecordId: String,
    ): IdkResult<String?, IdkError> = Ok(null)

    suspend fun deleteSession(
        walletUnitId: String,
        issuanceSessionId: String,
    ): IdkResult<Boolean, IdkError>
}

/**
 * Local issuance-session delegate backed by the platform blob abstraction.
 */
interface LocalWalletIssuanceSessionStore : WalletIssuanceSessionStore

/**
 * Remote issuance-session delegate backed by the platform vault abstraction.
 */
interface RemoteWalletIssuanceSessionStore : WalletIssuanceSessionStore

/**
 * Hybrid issuance-session delegate that composes local blob and remote vault delegates.
 */
interface HybridWalletIssuanceSessionStoreDelegate : WalletIssuanceSessionStore
