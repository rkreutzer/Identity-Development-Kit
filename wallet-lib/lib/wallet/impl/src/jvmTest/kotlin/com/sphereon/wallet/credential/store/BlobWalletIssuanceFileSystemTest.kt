/* Copyright 2026 Sphereon International B.V. SPDX-License-Identifier: Apache-2.0 */
package com.sphereon.wallet.credential.store

import com.sphereon.data.store.blob.BlobInfo
import com.sphereon.data.store.blob.fs.FileSystemBlobStore
import com.sphereon.data.store.party.model.IdentifierType
import com.sphereon.wallet.credential.IdentifierRef
import com.sphereon.wallet.credential.IssuanceSession
import com.sphereon.wallet.credential.IssuanceSessionStatus
import com.sphereon.wallet.credential.walletIssuanceSessionPath
import java.nio.file.Files
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Instant

class BlobWalletIssuanceFileSystemTest {
    @Test
    fun failedLegacyFileSystemSessionCanBeDeletedAndItsIdReused() = runTest {
        val root = Files.createTempDirectory("wallet-issuance-legacy").toString()
        val blobs = createWalletUnitBlobService(FileSystemBlobStore(root))
        val path = walletIssuanceSessionPath("unit", "session")
        assertTrue(blobs.storeBlob(BlobInfo(path = "$path/access-token"), "old-access".encodeToByteArray()).isOk)
        assertTrue(blobs.storeBlob(BlobInfo(path = path), "session-record".encodeToByteArray()).isErr)
        val store = BlobWalletIssuanceSessionStore(blobs)
        val deleted = store.deleteSession("unit", "session")
        assertTrue(deleted.isOk, deleted.toString())
        assertTrue(deleted.value)
        assertTrue(blobs.storeBlob(BlobInfo(path = path), "new-session-record".encodeToByteArray()).isOk)
        assertTrue(store.storeDeferredAccessToken("unit", "session", "new-access").isOk)
        assertEquals("new-access", store.getDeferredAccessToken("unit", "session").value)
    }

    @Test
    fun sessionAndItsSecretsCoexistOnDiskAndCanBeReadAfterReopening() = runTest {
        val root = Files.createTempDirectory("wallet-issuance-storage").toString()
        fun open() = BlobWalletIssuanceSessionStore(createWalletUnitBlobService(FileSystemBlobStore(root)))
        val store = open()
        val session = IssuanceSession(
            id = "same-session-and-record-id",
            walletUnitId = "unit",
            issuerRef = IdentifierRef(IdentifierType.DID, "did:example:issuer"),
            credentialIssuerUrl = "https://issuer.example",
            credentialConfigurationId = "credential",
            status = IssuanceSessionStatus.DEFERRED,
            createdAt = Instant.fromEpochSeconds(100),
            updatedAt = Instant.fromEpochSeconds(100),
        )
        assertTrue(store.storeDeferredAccessToken("unit", session.id, "synthetic-access-token").isOk)
        assertTrue(store.storeRefreshToken("unit", session.id, "synthetic-refresh-token").isOk)
        val put = store.putSession("unit", session)
        assertTrue(put.isOk, put.toString())
        assertEquals(listOf(session), store.listSessions("unit", emptySet()).value)
        val reopened = open()
        assertEquals(session, reopened.getSession("unit", session.id).value)
        assertEquals("synthetic-access-token", reopened.getDeferredAccessToken("unit", session.id).value)
        assertEquals("synthetic-refresh-token", reopened.getRefreshToken("unit", session.id).value)
        assertTrue(reopened.deleteSession("unit", session.id).value)
        assertEquals(null, reopened.getSession("unit", session.id).value)
        assertEquals(null, reopened.getDeferredAccessToken("unit", session.id).value)
        assertEquals("synthetic-refresh-token", reopened.getRefreshToken("unit", session.id).value)
    }

    @Test
    fun existingKeyValueSecretsRemainReadableAndNewValuesTakePrecedence() = runTest {
        val blobs = createWalletUnitBlobService()
        val legacy = walletIssuanceSessionPath("unit", "session")
        assertTrue(blobs.storeBlob(BlobInfo(path = "$legacy/access-token"), "old-access".encodeToByteArray()).isOk)
        assertTrue(blobs.storeBlob(BlobInfo(path = "$legacy/refresh-token"), "old-refresh".encodeToByteArray()).isOk)
        val store = BlobWalletIssuanceSessionStore(blobs)
        assertEquals("old-access", store.getDeferredAccessToken("unit", "session").value)
        assertEquals("old-refresh", store.getRefreshToken("unit", "session").value)
        assertTrue(store.storeDeferredAccessToken("unit", "session", "new-access").isOk)
        assertEquals("new-access", store.getDeferredAccessToken("unit", "session").value)
        assertTrue(store.deleteSession("unit", "session").isOk)
        assertEquals(null, store.getDeferredAccessToken("unit", "session").value)
    }
}
