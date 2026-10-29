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

package com.sphereon.data.store.asset.model

import com.sphereon.core.api.Base64Serializer
import com.sphereon.core.compat.JsExportCompat
import kotlinx.serialization.Serializable

/**
 * Raw-byte upload into a tenant's asset library. The asset is content-addressed by the
 * SHA-256 of [data] and deduplicated per tenant and [namespace]: uploading identical bytes
 * again returns a reference to the already-stored asset.
 */
@JsExportCompat
@Serializable
data class UploadAssetInput(
    val namespace: AssetNamespace,
    val data: ByteArray,
    val contentType: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other !is UploadAssetInput) {
            return false
        }
        return namespace == other.namespace && data.contentEquals(other.data) && contentType == other.contentType
    }

    override fun hashCode(): Int {
        var result = namespace.hashCode()
        result = 31 * result + data.contentHashCode()
        result = 31 * result + contentType.hashCode()
        return result
    }
}

/**
 * A stored asset resolved to its raw bytes, used by the public hosting surface that serves
 * `/public/assets/{tenantId}/{namespace}/{hash}.{ext}` and returned by the tenant asset content command.
 *
 * The bytes serialize as a base64 string. A plain `ByteArray` becomes a JSON array of numbers, about three and a half
 * characters per byte of image data, which this type carries across the command transport.
 */
@JsExportCompat
@Serializable
data class ResolvedAsset(
    @Serializable(with = Base64Serializer::class)
    val data: ByteArray,
    val contentType: String,
    val info: AssetInfo,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }
        if (other !is ResolvedAsset) {
            return false
        }
        return data.contentEquals(other.data) && contentType == other.contentType && info == other.info
    }

    override fun hashCode(): Int {
        var result = data.contentHashCode()
        result = 31 * result + contentType.hashCode()
        result = 31 * result + info.hashCode()
        return result
    }
}
