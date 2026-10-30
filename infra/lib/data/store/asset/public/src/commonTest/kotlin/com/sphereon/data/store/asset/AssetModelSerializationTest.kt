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

package com.sphereon.data.store.asset

import com.sphereon.data.store.asset.model.AssetInfo
import com.sphereon.data.store.asset.model.AssetNamespace
import com.sphereon.data.store.asset.model.AssetReference
import com.sphereon.data.store.asset.model.ResolvedAsset
import com.sphereon.data.store.blob.BlobInfo
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Guards the wire shapes frozen in `asset-components.yml`: lowercase [AssetNamespace] values and
 * the [AssetReference]/[AssetInfo] property names.
 */
class AssetModelSerializationTest {
    private val json = Json { encodeDefaults = false }

    @Test
    fun assetNamespace_serializesToLowercaseWireValues() {
        assertEquals("\"brand\"", json.encodeToString(AssetNamespace.serializer(), AssetNamespace.BRAND))
        assertEquals("\"design\"", json.encodeToString(AssetNamespace.serializer(), AssetNamespace.DESIGN))
        assertEquals(AssetNamespace.BRAND, json.decodeFromString(AssetNamespace.serializer(), "\"brand\""))
        assertEquals(AssetNamespace.DESIGN, json.decodeFromString(AssetNamespace.serializer(), "\"design\""))
    }

    @Test
    fun assetReference_roundTripsWithSpecPropertyNames() {
        val reference =
            AssetReference(
                uri = "/public/assets/acme/brand/abc.png",
                integrity = "sha256-AAAA",
                altText = "Logo",
                contentType = "image/png",
                localBlob = BlobInfo(path = "assets/acme/brand/by-hash/abc", tenantId = "acme"),
            )
        val encoded = json.encodeToString(AssetReference.serializer(), reference)
        val decoded = json.decodeFromString(AssetReference.serializer(), encoded)
        assertEquals(reference, decoded)
        assertEquals(
            reference,
            json.decodeFromString(
                AssetReference.serializer(),
                """{"uri":"/public/assets/acme/brand/abc.png","integrity":"sha256-AAAA","altText":"Logo",""" +
                    """"contentType":"image/png","localBlob":{"path":"assets/acme/brand/by-hash/abc","tenantId":"acme"}}""",
            ),
        )
    }

    @Test
    fun shouldSerializeResolvedAssetBytesAsBase64Text() {
        val asset =
            ResolvedAsset(
                data = byteArrayOf(1, 2, 3),
                contentType = "image/png",
                info =
                    AssetInfo(
                        uri = "/public/assets/acme/brand/abc.png",
                        contentType = "image/png",
                        hash = "abc",
                        sizeBytes = 3L,
                    ),
            )
        val encoded = json.encodeToString(ResolvedAsset.serializer(), asset)
        assertEquals(
            """{"data":"AQID","contentType":"image/png","info":{"uri":"/public/assets/acme/brand/abc.png","contentType":"image/png","hash":"abc","sizeBytes":3}}""",
            encoded,
        )
        assertEquals(asset, json.decodeFromString(ResolvedAsset.serializer(), encoded))
    }

    @Test
    fun assetInfo_roundTripsWithSpecPropertyNames() {
        val info =
            AssetInfo(
                uri = "/public/assets/acme/brand/abc.png",
                contentType = "image/png",
                hash = "abc",
                sizeBytes = 4L,
            )
        val encoded = json.encodeToString(AssetInfo.serializer(), info)
        val decoded = json.decodeFromString(AssetInfo.serializer(), encoded)
        assertEquals(info, decoded)
        assertEquals(
            info,
            json.decodeFromString(
                AssetInfo.serializer(),
                """{"uri":"/public/assets/acme/brand/abc.png","contentType":"image/png","hash":"abc","sizeBytes":4}""",
            ),
        )
    }
}
