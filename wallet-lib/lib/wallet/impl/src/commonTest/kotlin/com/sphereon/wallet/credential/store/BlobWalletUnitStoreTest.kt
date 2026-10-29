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
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.data.store.blob.InMemoryBlobStoreConfig
import com.sphereon.data.store.blob.BlobInfoType
import com.sphereon.data.store.blob.BlobService
import com.sphereon.data.store.blob.ResolvedBlobInfo
import com.sphereon.data.store.blob.impl.BlobStoreService
import com.sphereon.data.store.blob.impl.DefaultBlobService
import com.sphereon.data.store.blob.impl.DefaultRetentionPolicyService
import com.sphereon.data.store.blob.impl.KvBlobMetadataIndex
import com.sphereon.data.store.blob.memory.InMemoryBlobBackingStorageImpl
import com.sphereon.data.store.blob.memory.InMemoryBlobStoreFactoryImpl
import com.sphereon.data.store.kv.InMemoryKvStoreConfig
import com.sphereon.data.store.kv.KvStoreScopeBinding
import com.sphereon.data.store.kv.memory.InMemoryKvBackingStorageImpl
import com.sphereon.data.store.kv.memory.InMemoryKvStoreFactoryImpl
import com.sphereon.data.store.party.model.IdentifierType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.wallet.credential.IdentifierRef
import com.sphereon.wallet.credential.StorageProfile
import com.sphereon.wallet.credential.StoreRef
import com.sphereon.wallet.credential.WalletUnitProfile
import com.sphereon.wallet.credential.WalletProfilePurpose
import com.sphereon.wallet.credential.WalletStorageMode
import com.sphereon.wallet.credential.WalletHolderIdentifierKind
import com.sphereon.wallet.credential.WalletHolderVerificationMethod
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

private const val INSTANCE_WALLET_A = "wallet-unit-a"
private const val INSTANCE_WALLET_B = "wallet-unit-b"
private val INSTANCE_NOW = Instant.fromEpochSeconds(1_800_000_000)

private class WalletUnitBlobStoreService(
    private val store: com.sphereon.data.store.blob.BlobStore,
) : BlobStoreService {
    override fun getStoreIds(): Array<String> = arrayOf("memory")

    override fun getStoreConfig(storeId: String) = InMemoryBlobStoreConfig(id = storeId)

    override fun getStore(storeId: String) = store
}

private class WalletUnitKvStoreService(
    private val store: com.sphereon.data.store.kv.KvStore,
) : com.sphereon.data.store.kv.impl.KvStoreService {
    override fun getStoreIds(): Array<String> = arrayOf(KvBlobMetadataIndex.STORE_ID)

    override fun getStoreConfig(storeId: String) = InMemoryKvStoreConfig(id = storeId, scopeBinding = KvStoreScopeBinding.APP)

    override fun getStore(storeId: String) = store
}

private class WalletUnitSessionExecution : com.sphereon.core.api.context.SessionExecution {
    override val sessionContext: com.sphereon.di.session.SessionContext = com.sphereon.di.context.NoOpSessionContext
    override val sessionContextManager: com.sphereon.di.session.SessionContextManager
        get() = throw NotImplementedError("Not needed for unit tests")
    override val log: com.sphereon.core.api.log.SessionLogService = WalletUnitNoOpLogService(sessionContext)
    override val conf: com.sphereon.core.api.context.ContextConfig
        get() = throw NotImplementedError("Not needed for unit tests")
}

private class WalletUnitNoOpLogService(
    override val sessionContext: com.sphereon.di.session.SessionContext,
) : com.sphereon.core.api.log.SessionLogService {
    override val id: String = "wallet-unit-store-test-log"
    override val isEnabled: Boolean = false
    override val scope = com.sphereon.core.api.context.IdkScope.SESSION
    override val logManager: com.sphereon.core.api.log.SessionLogManager
        get() = throw NotImplementedError("Not needed for unit tests")

    override suspend fun setConfig(config: com.sphereon.core.api.log.LoggerConfig): com.sphereon.core.api.log.LogService = this

    override fun executeAsync(message: com.sphereon.core.api.log.LogMessage): IdkResult<Unit, com.sphereon.core.api.error.IdkErrorType> = Ok(Unit)

    override fun toAsync(): com.sphereon.core.api.log.AsyncLogService = throw NotImplementedError("Not needed for unit tests")
}

private class WalletUnitEventService : com.sphereon.core.events.SessionEventService {
    private val hub =
        com.sphereon.core.events.impl
            .EventHubImpl()
    override val scope: com.sphereon.core.api.context.IdkScope = com.sphereon.core.api.context.IdkScope.SESSION
    override val eventHub: com.sphereon.core.events.EventHub = hub
    override val parent: com.sphereon.core.events.UserEventService get() = throw NotImplementedError("Not needed for unit tests")
    override val sessionContext: com.sphereon.di.session.SessionContext = com.sphereon.di.context.NoOpSessionContext

    override suspend fun emit(event: com.sphereon.core.events.Event) {
        hub.publish(event)
    }

    override suspend fun emit(
        event: com.sphereon.core.events.Event,
        sign: Boolean,
        encrypt: Boolean,
        keyAlias: String?,
        encryptionKeyAlias: String?,
        encryptParts: Set<com.sphereon.core.events.EncryptedPart>,
    ) {
        hub.publish(event)
    }

    override fun eventBuilder(): com.sphereon.core.events.EventBuilder =
        com.sphereon.core.events.impl
            .DefaultEventBuilder(com.sphereon.core.api.context.IdkScope.SESSION)
}

internal fun createWalletUnitBlobService(store: com.sphereon.data.store.blob.BlobStore? = null): DefaultBlobService {
    val blobBackingStorage = InMemoryBlobBackingStorageImpl()
    val blobFactory = InMemoryBlobStoreFactoryImpl(blobBackingStorage)
    val memoryStore = blobFactory.create(InMemoryBlobStoreConfig(id = "memory"))

    val kvBackingStorage = InMemoryKvBackingStorageImpl()
    val kvFactory = InMemoryKvStoreFactoryImpl(kvBackingStorage)
    val kvStore = kvFactory.create(InMemoryKvStoreConfig(id = KvBlobMetadataIndex.STORE_ID, scopeBinding = KvStoreScopeBinding.APP))

    return DefaultBlobService(
        blobStoreService = WalletUnitBlobStoreService(store ?: memoryStore),
        metadataIndex = KvBlobMetadataIndex(WalletUnitKvStoreService(kvStore)),
        retentionPolicyService = DefaultRetentionPolicyService(),
        tempUrlPolicy =
            com.sphereon.data.store.blob
                .DefaultTempUrlPolicy(),
        eventService = WalletUnitEventService(),
        execution = WalletUnitSessionExecution(),
    )
}

private class RacingWalletUnitBlobService(
    private val delegate: BlobService,
    private val walletUnitId: String,
) : BlobService by delegate {
    private val mutex = Mutex()
    private val release = CompletableDeferred<Unit>()
    private var arrivals = 0

    override suspend fun getBlob(info: BlobInfoType): IdkResult<ResolvedBlobInfo, IdkError> {
        val result = delegate.getBlob(info)
        val shouldWait =
            mutex.withLock {
                if (info.path != com.sphereon.wallet.credential.walletUnitPath(walletUnitId) || release.isCompleted) {
                    false
                } else {
                    arrivals += 1
                    if (arrivals == 2) release.complete(Unit)
                    true
                }
            }
        if (shouldWait) release.await()
        return result
    }
}

class BlobWalletUnitStoreTest {
    @Test
    fun putWalletUnitPersistsStorageProfileAndResolverUsesIt() =
        runTest {
            val store = BlobWalletUnitStore(createWalletUnitBlobService())
            val instance = walletInstance(INSTANCE_WALLET_A, WalletProfilePurpose.WORK, storageProfileId = "work-hybrid")
            val profile =
                StorageProfile(
                    id = "work-hybrid",
                    walletUnitId = INSTANCE_WALLET_A,
                    mode = WalletStorageMode.HYBRID,
                    localStoreRef = StoreRef(id = "local-blob", type = "blob"),
                    remoteVaultRef = StoreRef(id = "work-vault", type = "vault"),
                    encryptionPolicyId = "work-managed-encryption",
                    syncPolicyId = "work-sync",
                )

            val put = store.putWalletUnit(instance, profile)

            assertTrue(put.isOk)
            assertEquals(instance, store.getWalletUnit(INSTANCE_WALLET_A).value)
            assertEquals(profile, store.getStorageProfile(INSTANCE_WALLET_A).value)
            assertEquals(profile, store.resolveStorageProfile(INSTANCE_WALLET_A).value)
        }

    @Test
    fun resolveStorageProfileCreatesStandaloneLocalBlobProfileWhenMissing() =
        runTest {
            val store = BlobWalletUnitStore(createWalletUnitBlobService())

            val profile = store.resolveStorageProfile(INSTANCE_WALLET_A).value

            assertEquals(INSTANCE_WALLET_A, profile.walletUnitId)
            assertEquals(WalletStorageMode.LOCAL, profile.mode)
            assertEquals(StoreRef(id = "memory", type = "blob"), profile.localStoreRef)
            assertNotNull(store.getWalletUnit(INSTANCE_WALLET_A).value)
            assertEquals(profile, store.getStorageProfile(INSTANCE_WALLET_A).value)
        }

    @Test
    fun archiveWalletUnitHidesItFromDefaultListButPreservesProfile() =
        runTest {
            val store = BlobWalletUnitStore(createWalletUnitBlobService())
            store.resolveStorageProfile(INSTANCE_WALLET_A)
            store.resolveStorageProfile(INSTANCE_WALLET_B)

            val archived = store.archiveWalletUnit(INSTANCE_WALLET_A, INSTANCE_NOW).value

            assertEquals(INSTANCE_NOW, archived?.archivedAt)
            assertEquals(listOf(INSTANCE_WALLET_B), store.listWalletUnits().value.map { it.id })
            assertEquals(
                setOf(INSTANCE_WALLET_A, INSTANCE_WALLET_B),
                store
                    .listWalletUnits(includeArchived = true)
                    .value
                    .map { it.id }
                    .toSet()
            )
            assertEquals(INSTANCE_WALLET_A, store.getStorageProfile(INSTANCE_WALLET_A).value?.walletUnitId)
        }

    @Test
    fun putWalletUnitRejectsMismatchedStorageProfile() =
        runTest {
            val store = BlobWalletUnitStore(createWalletUnitBlobService())
            val instance = walletInstance(INSTANCE_WALLET_A, WalletProfilePurpose.PERSONAL, storageProfileId = "profile-a")
            val profile =
                StorageProfile(
                    id = "profile-a",
                    walletUnitId = INSTANCE_WALLET_B,
                    mode = WalletStorageMode.LOCAL,
                    localStoreRef = StoreRef(id = "memory", type = "blob"),
                    encryptionPolicyId = "wallet-local-default",
                )

            val result = store.putWalletUnit(instance, profile)

            assertTrue(result.isErr)
            assertNull(store.getWalletUnit(INSTANCE_WALLET_A).value)
        }

    @Test
    fun registerHolderVerificationMethodPersistsExactTypedMetadataAndRejectsConflicts() =
        runTest {
            val store = BlobWalletUnitStore(createWalletUnitBlobService())
            store.resolveStorageProfile(INSTANCE_WALLET_A)
            val method =
                WalletHolderVerificationMethod(
                    value = "https://wallet.example/jwks#holder-key-1",
                    controller = "https://wallet.example/holders/alice",
                    kind = WalletHolderIdentifierKind.JWKS_KID,
                    signingAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                )

            val registered = store.registerHolderVerificationMethod(INSTANCE_WALLET_A, "opaque-key-1", method)
            val repeated = store.registerHolderVerificationMethod(INSTANCE_WALLET_A, "opaque-key-1", method)
            val conflicting =
                store.registerHolderVerificationMethod(
                    INSTANCE_WALLET_A,
                    "opaque-key-1",
                    method.copy(kind = WalletHolderIdentifierKind.MANAGED_KID),
                )

            assertTrue(registered.isOk)
            assertTrue(repeated.isOk, "identical registration must be idempotent")
            assertTrue(conflicting.isErr)
            assertEquals(method, store.getWalletUnit(INSTANCE_WALLET_A).value?.holderVerificationMethods?.get("opaque-key-1"))
        }

    @Test
    fun concurrentRegistrationsAcrossStoreInstancesConvergeWithoutLosingEitherKey() =
        runTest {
            val delegate = createWalletUnitBlobService()
            BlobWalletUnitStore(delegate).resolveStorageProfile(INSTANCE_WALLET_A)
            val racingService = RacingWalletUnitBlobService(delegate, INSTANCE_WALLET_A)
            val firstStore = BlobWalletUnitStore(racingService)
            val secondStore = BlobWalletUnitStore(racingService)
            val first =
                WalletHolderVerificationMethod(
                    value = "https://wallet.example/jwks#first",
                    controller = "https://wallet.example/holders/alice",
                    kind = WalletHolderIdentifierKind.JWKS_KID,
                    signingAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                )
            val second = first.copy(value = "https://wallet.example/jwks#second")

            val results =
                coroutineScope {
                    listOf(
                        async { firstStore.registerHolderVerificationMethod(INSTANCE_WALLET_A, "opaque-first", first) },
                        async { secondStore.registerHolderVerificationMethod(INSTANCE_WALLET_A, "opaque-second", second) },
                    ).awaitAll()
                }

            assertTrue(results.all { it.isOk })
            assertEquals(
                mapOf("opaque-first" to first, "opaque-second" to second),
                firstStore.getWalletUnit(INSTANCE_WALLET_A).value?.holderVerificationMethods,
            )
        }

    private fun walletInstance(
        id: String,
        purpose: WalletProfilePurpose,
        storageProfileId: String,
    ): WalletUnitProfile =
        WalletUnitProfile(
            id = id,
            ownerSubjectRef = IdentifierRef(type = IdentifierType.DID, value = "did:example:owner:$id"),
            label = id,
            purpose = purpose,
            storageProfileId = storageProfileId,
            defaultHolderKeyPolicyId = "holder-key-default",
            createdAt = INSTANCE_NOW,
            updatedAt = INSTANCE_NOW,
        )
}
