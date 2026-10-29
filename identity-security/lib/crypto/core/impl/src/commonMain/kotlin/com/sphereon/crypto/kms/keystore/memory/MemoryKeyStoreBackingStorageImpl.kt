/*
 * © 2026 Sphereon International B.V.
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
 *
 */

package com.sphereon.crypto.kms.keystore.memory

import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * App-scoped backing storage for MemoryKeyStore.
 *
 * This singleton maintains separate storage partitions based on StoragePartitionKey.
 * It enables multi-tenant support where keys and certificates are isolated by:
 * - tenant only (for REST APIs)
 * - tenant + principal (for user-specific data)
 * - tenant + principal + session (for session-specific data)
 * - or app-wide (single shared storage)
 *
 * Partition allocation and lifecycle operations are synchronized across callers.
 */
@Inject
@SingleIn(AppScope::class)
@ContributesBinding(AppScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("MemoryKeyStoreBackingStorageImpl", exact = true)
class MemoryKeyStoreBackingStorageImpl : MemoryKeyStoreBackingStorage {
    private val monitor = SynchronizedObject()
    private val partitions = mutableMapOf<StoragePartitionKey, StoragePartition>()

    /**
     * Gets or creates a storage partition for the given key.
     * Concurrent callers for the same key receive the same partition instance.
     */
    override fun getPartition(partitionKey: StoragePartitionKey): StoragePartition =
        synchronized(monitor) { partitions.getOrPut(partitionKey) { StoragePartition() } }

    /**
     * Removes a storage partition, clearing all associated keys and certificates.
     * Useful for cleanup when a session ends or a tenant is removed.
     */
    override fun removePartition(partitionKey: StoragePartitionKey): Boolean =
        synchronized(monitor) { partitions.remove(partitionKey) != null }

    /**
     * Clears all storage partitions. Use with caution - typically only for testing or shutdown.
     */
    override fun clearAll() {
        synchronized(monitor) { partitions.clear() }
    }

    /**
     * Returns the number of active storage partitions.
     */
    override fun getPartitionCount(): Int = synchronized(monitor) { partitions.size }

    /**
     * Returns all partition keys (useful for diagnostics/monitoring).
     */
    override fun getPartitionKeys(): Set<StoragePartitionKey> = synchronized(monitor) { partitions.keys.toSet() }
}
