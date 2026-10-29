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

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.encodeToBase64
import com.sphereon.core.api.encodeToHex
import com.sphereon.core.api.error.IdkError
import com.sphereon.data.store.blob.digest.DigestAlg
import com.sphereon.data.store.blob.digest.hash
import com.sphereon.data.store.asset.PublicAssetPaths
import com.sphereon.data.store.asset.TenantAssetService
import com.sphereon.data.store.asset.model.AssetInfo
import com.sphereon.data.store.asset.model.AssetNamespace
import com.sphereon.data.store.asset.model.AssetReference
import com.sphereon.data.store.asset.model.ResolvedAsset
import com.sphereon.data.store.asset.model.UploadAssetInput
import com.sphereon.data.store.blob.BlobDescriptor
import com.sphereon.data.store.blob.BlobInfo
import com.sphereon.data.store.blob.BlobService
import com.sphereon.data.store.blob.ListOptions
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

/**
 * Default IDK implementation of [TenantAssetService]: a content-addressed layer over
 * [BlobService].
 *
 * Identical bytes collapse to ONE hash (and ONE public URL) within a tenant and namespace, so
 * clients download byte-identical images exactly once. Tenants stay isolated: the blob path
 * carries the tenant segment and dedup never crosses tenants.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<TenantAssetService>())
@ContributesBinding(SessionScope::class, binding = binding<TenantAssetService?>())
class DefaultTenantAssetService(
    private val blobService: BlobService,
) : TenantAssetService {
    override suspend fun uploadAsset(
        tenantId: String,
        input: UploadAssetInput,
    ): IdkResult<AssetReference, IdkError> {
        val digest = hash(input.data, DigestAlg.SHA256)
        val hexHash = digest.encodeToHex()
        val b64 = digest.encodeToBase64()

        val blobPath = assetBlobPath(tenantId, input.namespace, hexHash)

        // Dedup with putIfAbsent semantics: only write when this content is not already stored
        // for the tenant and namespace. The content type is persisted with the blob so it can be
        // served back later by hash.
        val existing = blobService.getBlobInfo(BlobInfo(path = blobPath, tenantId = tenantId))
        if (existing.isErr) {
            val storeResult =
                blobService.storeBlob(
                    target = BlobInfo(path = blobPath, tenantId = tenantId, contentType = input.contentType),
                    data = input.data,
                )
            if (storeResult.isErr) return Err(storeResult.error)
        }

        // The asset URI is stored RELATIVE (content-addressed under PublicAssetPaths.BASE_PATH).
        // The absolute host is applied at SERVE time from the per-tenant external base
        // (PublicAssetPaths.toAbsolute), so in multi-tenant gateway mode each tenant's asset URI
        // carries that tenant's host rather than one static configured host.
        val publicUri = PublicAssetPaths.assetPath(tenantId, input.namespace, hexHash, input.contentType)

        return Ok(
            AssetReference(
                uri = publicUri,
                integrity = "sha256-$b64",
                contentType = input.contentType,
                localBlob = BlobInfo(path = blobPath, tenantId = tenantId),
            ),
        )
    }

    override suspend fun listAssets(
        tenantId: String,
        namespace: AssetNamespace,
        contentType: String?,
    ): IdkResult<List<AssetInfo>, IdkError> {
        // The blob list is filtered by PREFIX (the per-tenant, per-namespace content-addressed
        // asset directory). The blob service scopes the prefix under the tenant and unscopes the
        // returned paths, so each descriptor.path comes back as
        // "assets/$tenantId/$namespace/by-hash/<hash>".
        val byHashPrefix = assetBlobPath(tenantId, namespace, "")
        val listResult =
            blobService.listBlobs(
                info = BlobInfo(tenantId = tenantId),
                options = ListOptions(prefix = byHashPrefix, recursive = true),
            )
        if (listResult.isErr) return Err(listResult.error)

        val assets =
            listResult.value.descriptors
                .mapNotNull { descriptor -> descriptor.toAssetInfo(tenantId, namespace) }
                .filter { asset -> matchesContentTypeFilter(asset, contentType) }
        return Ok(assets)
    }

    override suspend fun getAsset(
        tenantId: String,
        namespace: AssetNamespace,
        hash: String,
    ): IdkResult<AssetInfo, IdkError> {
        if (!PublicAssetPaths.isCanonicalHash(hash)) {
            return Err(IdkError.NOT_FOUND_ERROR(message = "Asset not found"))
        }
        val blobPath = assetBlobPath(tenantId, namespace, hash)
        val infoResult = blobService.getBlobInfo(BlobInfo(path = blobPath, tenantId = tenantId))
        if (infoResult.isErr) {
            return Err(IdkError.NOT_FOUND_ERROR(message = "Asset not found for hash: $hash"))
        }

        val descriptor = infoResult.value
        return Ok(
            AssetInfo(
                uri = PublicAssetPaths.assetPath(tenantId, namespace, hash, descriptor.contentType),
                contentType = descriptor.contentType ?: "application/octet-stream",
                hash = hash,
                sizeBytes = descriptor.sizeBytes,
                createdAt = descriptor.createdAt,
            ),
        )
    }

    override suspend fun getAssetContent(
        tenantId: String,
        namespace: AssetNamespace,
        hash: String,
    ): IdkResult<ResolvedAsset, IdkError> {
        if (!PublicAssetPaths.isCanonicalHash(hash)) {
            return Err(IdkError.NOT_FOUND_ERROR(message = "Asset not found"))
        }
        val blobPath = assetBlobPath(tenantId, namespace, hash)
        val blobResult = blobService.getBlob(BlobInfo(path = blobPath, tenantId = tenantId))
        if (blobResult.isErr) {
            return Err(IdkError.NOT_FOUND_ERROR(message = "Asset not found for hash: $hash"))
        }

        val resolved = blobResult.value
        val contentType = resolved.contentType ?: "application/octet-stream"
        return Ok(
            ResolvedAsset(
                data = resolved.data,
                contentType = contentType,
                info =
                    AssetInfo(
                        uri = PublicAssetPaths.assetPath(tenantId, namespace, hash, resolved.contentType),
                        contentType = contentType,
                        hash = hash,
                        sizeBytes = resolved.data.size.toLong(),
                    ),
            ),
        )
    }

    override suspend fun deleteAsset(
        tenantId: String,
        namespace: AssetNamespace,
        hash: String,
    ): IdkResult<Unit, IdkError> {
        if (!PublicAssetPaths.isCanonicalHash(hash)) {
            return Err(IdkError.NOT_FOUND_ERROR(message = "Asset not found"))
        }
        val blobPath = assetBlobPath(tenantId, namespace, hash)
        val deleteResult = blobService.deleteBlob(BlobInfo(path = blobPath, tenantId = tenantId))
        if (deleteResult.isErr) return Err(deleteResult.error)
        if (!deleteResult.value) {
            return Err(IdkError.NOT_FOUND_ERROR(message = "Asset not found for hash: $hash"))
        }
        return Ok(Unit)
    }

    /**
     * Content-addressed, tenant-and-namespace-scoped blob path. Identical bytes dedup within a
     * tenant and namespace; tenants stay isolated by the `$tenantId` segment.
     */
    private fun assetBlobPath(
        tenantId: String,
        namespace: AssetNamespace,
        hash: String,
    ): String = "assets/$tenantId/${namespace.value}/by-hash/$hash"

    /**
     * Maps a content-addressed asset blob descriptor to an [AssetInfo], or `null` when the blob's
     * leaf is not a valid SHA-256 hash (defensive: the by-hash directory only holds hash-named
     * blobs).
     */
    private fun BlobDescriptor.toAssetInfo(
        tenantId: String,
        namespace: AssetNamespace,
    ): AssetInfo? {
        val hashLeaf = PublicAssetPaths.hashFromLeaf(path.substringAfterLast('/'))
        if (!PublicAssetPaths.isCanonicalHash(hashLeaf)) return null
        return AssetInfo(
            uri = PublicAssetPaths.assetPath(tenantId, namespace, hashLeaf, contentType),
            contentType = contentType ?: "application/octet-stream",
            hash = hashLeaf,
            sizeBytes = sizeBytes,
            createdAt = createdAt,
        )
    }

    /** [contentTypeFilter] is matched as a case-insensitive content-type prefix. */
    private fun matchesContentTypeFilter(
        asset: AssetInfo,
        contentTypeFilter: String?,
    ): Boolean {
        if (contentTypeFilter == null) return true
        val mediaType =
            asset.contentType
                .substringBefore(';')
                .trim()
                .lowercase()
        return mediaType.startsWith(contentTypeFilter.substringBefore(';').trim().lowercase())
    }
}
