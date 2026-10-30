/*
 * Copyright 2023-2026 Sphereon International B.V.
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

package com.sphereon.data.store.asset.impl

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.AppConfigService
import com.sphereon.core.api.conf.ConfigLevel
import com.sphereon.core.api.conf.ConfigService
import com.sphereon.core.api.conf.PrincipalConfigService
import com.sphereon.core.api.conf.TenantConfigService
import com.sphereon.core.api.context.ContextConfig
import com.sphereon.core.api.context.IdkScope
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.log.AsyncLogService
import com.sphereon.core.api.log.LogMessage
import com.sphereon.core.api.log.LoggerConfig
import com.sphereon.core.api.log.SessionLogManager
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.core.events.EncryptedPart
import com.sphereon.core.events.Event
import com.sphereon.core.events.EventBuilder
import com.sphereon.core.events.EventHub
import com.sphereon.core.events.SessionEventService
import com.sphereon.core.events.UserEventService
import com.sphereon.core.events.impl.DefaultEventBuilder
import com.sphereon.core.events.impl.EventHubImpl
import com.sphereon.data.store.blob.BlobDescriptor
import com.sphereon.data.store.blob.BlobInfo
import com.sphereon.data.store.blob.BlobService
import com.sphereon.data.store.blob.BlobStore
import com.sphereon.data.store.blob.BlobStoreConfigBase
import com.sphereon.data.store.blob.DefaultTempUrlPolicy
import com.sphereon.data.store.blob.InMemoryBlobStoreConfig
import com.sphereon.data.store.blob.PutOptions
import com.sphereon.data.store.blob.impl.BlobStoreService
import com.sphereon.data.store.blob.impl.DefaultBlobService
import com.sphereon.data.store.blob.impl.DefaultRetentionPolicyService
import com.sphereon.data.store.blob.impl.KvBlobMetadataIndex
import com.sphereon.data.store.blob.memory.InMemoryBlobBackingStorageImpl
import com.sphereon.data.store.blob.memory.InMemoryBlobStoreFactoryImpl
import com.sphereon.data.store.kv.InMemoryKvStoreConfig
import com.sphereon.data.store.kv.KvStore
import com.sphereon.data.store.kv.KvStoreConfigBase
import com.sphereon.data.store.kv.KvStoreScopeBinding
import com.sphereon.data.store.kv.impl.KvStoreService
import com.sphereon.data.store.kv.memory.InMemoryKvBackingStorageImpl
import com.sphereon.data.store.kv.memory.InMemoryKvStoreFactoryImpl
import com.sphereon.di.context.NoOpSessionContext
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionContextManager

/**
 * Test-only [BlobStoreService] that resolves all store IDs to the same in-memory blob store.
 */
class TestBlobStoreService(
    private val store: BlobStore,
    private val storeId: String = "memory",
) : BlobStoreService {
    override fun getStoreIds(): Array<String> = arrayOf(storeId)

    override fun getStoreConfig(storeId: String): BlobStoreConfigBase = InMemoryBlobStoreConfig(id = storeId)

    override fun getStore(storeId: String): BlobStore = store
}

/**
 * Test-only [KvStoreService] that resolves all store IDs to the same in-memory KV store.
 */
class TestKvStoreService(
    private val store: KvStore,
) : KvStoreService {
    override fun getStoreIds(): Array<String> = arrayOf(KvBlobMetadataIndex.STORE_ID)

    override fun getStoreConfig(storeId: String): KvStoreConfigBase = InMemoryKvStoreConfig(id = storeId, scopeBinding = KvStoreScopeBinding.APP)

    override fun getStore(storeId: String): KvStore = store
}

private class NoOpSessionLogService(
    override val sessionContext: SessionContext = NoOpSessionContext,
) : SessionLogService {
    override val id: String = "test-asset-log"
    override val isEnabled: Boolean = false
    override val scope = IdkScope.SESSION
    override val logManager: SessionLogManager
        get() = throw NotImplementedError("Not needed for unit tests")

    override suspend fun setConfig(config: LoggerConfig): com.sphereon.core.api.log.LogService = this

    override fun executeAsync(message: LogMessage): IdkResult<Unit, IdkErrorType> = Ok(Unit)

    override fun toAsync(): AsyncLogService = throw NotImplementedError("Not needed for unit tests")
}

/**
 * Minimal [SessionExecution] for unit tests.
 */
class TestSessionExecution(
    override val sessionContext: SessionContext = NoOpSessionContext,
) : SessionExecution {
    override val sessionContextManager: SessionContextManager
        get() = throw NotImplementedError("Not needed for unit tests")
    override val log: SessionLogService = NoOpSessionLogService(sessionContext)
    override val conf: ContextConfig = object : ContextConfig {
        override val app: AppConfigService
            get() = error("Unexpected application configuration read")
        override val tenant: TenantConfigService
            get() = error("Unexpected tenant configuration read")
        override val principal: PrincipalConfigService
            get() = error("Unexpected principal configuration read")

        override fun conf(level: ConfigLevel): ConfigService = error("Unexpected configuration read at $level")
    }
}

/**
 * [SessionEventService] over a plain in-process hub for unit tests.
 */
class TestSessionEventService : SessionEventService {
    private val hub = EventHubImpl()
    override val scope: IdkScope = IdkScope.SESSION
    override val eventHub: EventHub = hub
    override val parent: UserEventService get() = throw NotImplementedError("Not needed for unit tests")
    override val sessionContext: SessionContext = NoOpSessionContext

    override suspend fun emit(event: Event) {
        hub.publish(event)
    }

    override suspend fun emit(
        event: Event,
        sign: Boolean,
        encrypt: Boolean,
        keyAlias: String?,
        encryptionKeyAlias: String?,
        encryptParts: Set<EncryptedPart>,
    ) {
        hub.publish(event)
    }

    override fun eventBuilder(): EventBuilder = DefaultEventBuilder(IdkScope.SESSION)
}

/**
 * Delegating [BlobService] that counts writes, so dedup tests can assert that identical bytes
 * are stored exactly once while everything else runs through the REAL blob service.
 */
class CountingBlobService(
    private val delegate: BlobService,
) : BlobService by delegate {
    var storeCount: Int = 0
        private set

    override suspend fun storeBlob(
        target: BlobInfo,
        data: ByteArray,
        options: PutOptions,
    ): IdkResult<BlobDescriptor, IdkError> {
        storeCount++
        return delegate.storeBlob(target, data, options)
    }
}

/**
 * Creates a REAL [DefaultBlobService] backed by in-memory blob and KV stores, the same
 * collaborator wiring the production graph uses (modulo the in-memory backends).
 */
fun createTestBlobService(): DefaultBlobService {
    val blobBackingStorage = InMemoryBlobBackingStorageImpl()
    val blobFactory = InMemoryBlobStoreFactoryImpl(blobBackingStorage)
    val blobConfig = InMemoryBlobStoreConfig(id = "memory")
    val memoryStore = blobFactory.create(blobConfig)

    val kvBackingStorage = InMemoryKvBackingStorageImpl()
    val kvFactory = InMemoryKvStoreFactoryImpl(kvBackingStorage)
    val kvConfig = InMemoryKvStoreConfig(id = KvBlobMetadataIndex.STORE_ID, scopeBinding = KvStoreScopeBinding.APP)
    val kvStore = kvFactory.create(kvConfig)

    val kvStoreService = TestKvStoreService(kvStore)
    val metadataIndex = KvBlobMetadataIndex(kvStoreService)
    val blobStoreService = TestBlobStoreService(memoryStore)

    return DefaultBlobService(
        blobStoreService = blobStoreService,
        metadataIndex = metadataIndex,
        retentionPolicyService = DefaultRetentionPolicyService(),
        tempUrlPolicy = DefaultTempUrlPolicy(),
        eventService = TestSessionEventService(),
        execution = TestSessionExecution(),
    )
}
