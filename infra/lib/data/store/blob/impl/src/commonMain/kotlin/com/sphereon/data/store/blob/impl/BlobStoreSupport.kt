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

package com.sphereon.data.store.blob.impl

import com.sphereon.core.api.conf.CamelCaseKeyDenormalizerImpl
import com.sphereon.core.api.conf.ConfigService
import com.sphereon.core.api.conf.DefaultPolymorphicConfigBinder
import com.sphereon.core.api.conf.PrincipalConfigService
import com.sphereon.core.api.conf.PropertyKeyNormalizerImpl
import com.sphereon.core.api.conf.TypeSuffixEntryDetection
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.log.AppLogManager
import com.sphereon.data.store.blob.BlobStore
import com.sphereon.data.store.blob.BlobStoreConfigBase
import com.sphereon.data.store.blob.BlobStoreFactory
import com.sphereon.data.store.blob.BlobStoreJsonSupport
import com.sphereon.data.store.blob.BlobStoreRegistry
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

// ================================================================================================
// BlobStoreConfigBinder (polymorphic, using DefaultPolymorphicConfigBinder)
// ================================================================================================

@OptIn(ExperimentalObjCName::class)
@ObjCName("BlobStoreConfigBinder", exact = true)
interface BlobStoreConfigBinder {
    fun getBlobStoreIds(configService: ConfigService): Array<String>

    fun getBlobStoreConfig(
        configService: ConfigService,
        storeId: String,
    ): BlobStoreConfigBase

    fun getBlobStoreConfigs(configService: ConfigService): Array<BlobStoreConfigBase>

    @ContributesTo(AppScope::class)
    interface Graph {
        val blobStoreConfigBinder: BlobStoreConfigBinder
    }

    companion object {
        const val BLOB_STORES_PREFIX: String = "blob.stores"
    }
}

/**
 * Property name aliases for relaxed config binding.
 * Maps normalized (lowercased, dot-separated) property names to their canonical camelCase field names.
 */
private val BlobStorePropertyNameAliases =
    mapOf(
        "scopebinding" to "scopeBinding",
        "rootdir" to "rootDir",
        "root.dir" to "rootDir",
        "autocreatedirs" to "autoCreateDirs",
        "auto.create.dirs" to "autoCreateDirs",
        "maxentries" to "maxEntries",
        "max.entries" to "maxEntries",
        "kvstoreid" to "kvStoreId",
        "kv.store.id" to "kvStoreId",
        "maxblobsizebytes" to "maxBlobSizeBytes",
        "max.blob.size.bytes" to "maxBlobSizeBytes",
    )

@Inject
@SingleIn(AppScope::class)
@ContributesBinding(AppScope::class, binding = binding<BlobStoreConfigBinder>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("BlobStoreConfigBinderImpl", exact = true)
class BlobStoreConfigBinderImpl(
    appLogManager: AppLogManager,
) : BlobStoreConfigBinder {
    private val log = appLogManager.withTag("BlobStoreConfigBinder")
    private val keyNormalizer = PropertyKeyNormalizerImpl.Default

    private fun buildPrefixes(configService: ConfigService) = setOf(BlobStoreConfigBinder.BLOB_STORES_PREFIX)

    private fun createPolymorphicBinder(prefix: String) =
        DefaultPolymorphicConfigBinder(
            prefix = prefix,
            baseClass = BlobStoreConfigBase::class,
            json = BlobStoreJsonSupport.serializer,
            entryDetection = TypeSuffixEntryDetection(excludedSuffixes = setOf(".auth.type")),
            idFieldName = "id",
            keyNormalizer = keyNormalizer,
            keyDenormalizer = CamelCaseKeyDenormalizerImpl(),
            nestedPrefixAliases = mapOf("auth" to "auth", "ui" to "ui"),
            propertyNameAliases = BlobStorePropertyNameAliases,
        )

    override fun getBlobStoreIds(configService: ConfigService): Array<String> {
        val prefixes = buildPrefixes(configService)
        val allIds = mutableSetOf<String>()
        for (prefix in prefixes) {
            val binder = createPolymorphicBinder(prefix)
            val configsResult = binder.getEntryConfigsAsMapResult(configService, strict = true)
            require(configsResult.isOk) {
                "Failed to bind blob store configs for prefix '$prefix': ${configsResult.error.message.defaultMessage}"
            }
            val configs = configsResult.value
            if (configs.isNotEmpty()) {
                allIds.addAll(configs.values.map { it.id })
            } else {
                allIds.addAll(binder.getEntryIds(configService))
            }
        }

        return allIds.toTypedArray().also {
            log.debug("Found ${it.size} blob stores: ${it.joinToString(",")}")
        }
    }

    override fun getBlobStoreConfig(
        configService: ConfigService,
        storeId: String,
    ): BlobStoreConfigBase {
        val prefixes = buildPrefixes(configService)
        val notFoundCode = "NOT_FOUND_ERROR"

        for (prefix in prefixes) {
            val binder = createPolymorphicBinder(prefix)
            val configResult = binder.getEntryConfigResult(configService, storeId)
            if (configResult.isOk) {
                log.debug("Blob store configuration bound successfully")
                return configResult.value
            }
            if (configResult.error.code != notFoundCode) {
                log.warn("BLOB_STORE_CONFIG_RESOLUTION_FAILED stage=configuration-binding")
                throw IllegalArgumentException(
                    "Failed to bind blob store config for '$storeId' under prefix '$prefix': ${configResult.error.message.defaultMessage}",
                )
            }
        }

        log.warn("BLOB_STORE_CONFIG_RESOLUTION_FAILED stage=lookup code=NOT_FOUND_ERROR")
        throw IllegalArgumentException("Blob store config not found for store ID: $storeId")
    }

    override fun getBlobStoreConfigs(configService: ConfigService): Array<BlobStoreConfigBase> {
        val prefixes = buildPrefixes(configService)
        val allConfigs = mutableMapOf<String, BlobStoreConfigBase>()
        for (prefix in prefixes) {
            val binder = createPolymorphicBinder(prefix)
            val configsResult = binder.getEntryConfigsAsMapResult(configService, strict = true)
            require(configsResult.isOk) {
                "Failed to bind blob store configs for prefix '$prefix': ${configsResult.error.message.defaultMessage}"
            }
            allConfigs.putAll(configsResult.value)
        }

        return allConfigs.values
            .filter { it.enabled }
            .toTypedArray()
    }
}

// ================================================================================================
// BlobStoreManager
// ================================================================================================

@OptIn(ExperimentalObjCName::class)
@ObjCName("BlobStoreManager", exact = true)
interface BlobStoreManager : BlobStoreRegistry {
    fun createFromBlobStoreConfig(config: BlobStoreConfigBase): BlobStore

    fun createFromBlobStoreConfig(
        config: BlobStoreConfigBase,
        execution: SessionExecution?,
    ): BlobStore

    fun createFromProperties(
        configService: ConfigService,
        execution: SessionExecution?,
    ): Set<BlobStore>

    @ContributesTo(AppScope::class)
    interface Graph {
        val blobStoreManager: BlobStoreManager
    }
}

@Inject
@SingleIn(AppScope::class)
@ContributesBinding(AppScope::class, binding = binding<BlobStoreManager>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("BlobStoreManagerImpl", exact = true)
class BlobStoreManagerImpl(
    factories: Set<BlobStoreFactory>,
    private val binder: BlobStoreConfigBinder,
) : BlobStoreManager {
    private val factories = factories.filter { it.backendId != NoOpBlobStoreFactoryImpl.BACKEND_ID }.toSet()

    override fun createFromBlobStoreConfig(config: BlobStoreConfigBase): BlobStore = createFromBlobStoreConfig(config, null)

    override fun createFromBlobStoreConfig(
        config: BlobStoreConfigBase,
        execution: SessionExecution?,
    ): BlobStore {
        require(factories.isNotEmpty()) {
            "No BlobStoreFactory implementations found. Add at least one blob backend module (memory, filesystem, etc)."
        }
        val factory =
            factories.firstOrNull { it.backendId.equals(config.backendId, ignoreCase = true) }
                ?: throw IllegalArgumentException(
                    "No BlobStoreFactory found for backendId '${config.backendId}'. Available: ${factories.map { it.backendId }.distinct().sorted()}",
                )
        return factory.create(config, execution)
    }

    override fun createFromProperties(
        configService: ConfigService,
        execution: SessionExecution?,
    ): Set<BlobStore> =
        binder
            .getBlobStoreConfigs(configService)
            .map {
                createFromBlobStoreConfig(it, execution)
            }.toSet()

    override fun resolve(config: BlobStoreConfigBase): BlobStore = createFromBlobStoreConfig(config)

    override fun availableBackends(): List<String> = factories.map { it.backendId }.distinct().sorted()
}

// ================================================================================================
// BlobStoreService (session-scoped)
// ================================================================================================

@OptIn(ExperimentalObjCName::class)
@ObjCName("BlobStoreService", exact = true)
interface BlobStoreService {
    fun getStoreIds(): Array<String>

    fun getStoreConfig(storeId: String): BlobStoreConfigBase

    fun getStore(storeId: String): BlobStore

    @OptIn(ExperimentalObjCName::class)
    @ObjCName("BlobStoreServiceGraph", exact = true)
    @ContributesTo(scope = SessionScope::class)
    interface Graph {
        val blobStoreService: BlobStoreService
    }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<BlobStoreService>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("BlobStoreServiceImpl", exact = true)
class BlobStoreServiceImpl(
    private val config: PrincipalConfigService,
    private val binder: BlobStoreConfigBinder,
    private val manager: BlobStoreManager,
    private val execution: SessionExecution,
) : BlobStoreService {
    override fun getStoreIds(): Array<String> = binder.getBlobStoreIds(config)

    override fun getStoreConfig(storeId: String): BlobStoreConfigBase = binder.getBlobStoreConfig(config, storeId)

    override fun getStore(storeId: String): BlobStore {
        val storeConfig = getStoreConfig(storeId)
        return manager.createFromBlobStoreConfig(storeConfig, execution)
    }
}

// ================================================================================================
// NoOp factory (keeps multibinding stable)
// ================================================================================================

@Inject
@SingleIn(AppScope::class)
@ContributesIntoSet(AppScope::class, binding = binding<BlobStoreFactory>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("NoOpBlobStoreFactoryImpl", exact = true)
class NoOpBlobStoreFactoryImpl : BlobStoreFactory {
    override val backendId: String = BACKEND_ID

    override fun create(
        config: BlobStoreConfigBase,
        execution: SessionExecution?,
    ): BlobStore = throw IllegalArgumentException("No BlobStoreFactory found. Add a blob backend module (memory, filesystem, etc) to your app.")

    companion object {
        const val BACKEND_ID: String = "___NO_OP___"
    }
}
