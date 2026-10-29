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

import com.sphereon.data.store.asset.model.AssetNamespace
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PublicAssetPathsTest {
    private val tenantId = "acme"
    private val hash = "0f4636c78f65d3639ece5a064b5ae753e3408614a14fb18ab4d7540d2c248543"

    @Test
    fun assetPath_buildsTenantScopedNamespacedPathWithExtension() {
        assertEquals(
            "/public/assets/acme/brand/$hash.png",
            PublicAssetPaths.assetPath(tenantId, AssetNamespace.BRAND, hash, "image/png"),
        )
        assertEquals(
            "/public/assets/acme/design/$hash.pdf",
            PublicAssetPaths.assetPath(tenantId, AssetNamespace.DESIGN, hash, "application/pdf"),
        )
    }

    @Test
    fun assetPath_unknownOrMissingContentType_hasNoExtension() {
        assertEquals(
            "/public/assets/acme/brand/$hash",
            PublicAssetPaths.assetPath(tenantId, AssetNamespace.BRAND, hash),
        )
        assertEquals(
            "/public/assets/acme/brand/$hash",
            PublicAssetPaths.assetPath(tenantId, AssetNamespace.BRAND, hash, "application/octet-stream"),
        )
    }

    @Test
    fun assetPath_leafRoundTripsThroughHashFromLeaf() {
        val withExt = PublicAssetPaths.assetPath(tenantId, AssetNamespace.BRAND, hash, "image/svg+xml")
        assertEquals(hash, PublicAssetPaths.hashFromLeaf(withExt.substringAfterLast('/')))

        val withoutExt = PublicAssetPaths.assetPath(tenantId, AssetNamespace.DESIGN, hash)
        assertEquals(hash, PublicAssetPaths.hashFromLeaf(withoutExt.substringAfterLast('/')))
    }

    @Test
    fun shouldAcceptOnlyLowercaseHexOfARegisteredDigestLengthAsCanonicalHash() {
        assertTrue(PublicAssetPaths.isCanonicalHash(hash))
        assertTrue(PublicAssetPaths.isCanonicalHash("a".repeat(64)))
        assertTrue(PublicAssetPaths.isCanonicalHash("0".repeat(64)))
        assertTrue(PublicAssetPaths.isCanonicalHash("a".repeat(96)))
        assertTrue(PublicAssetPaths.isCanonicalHash("f".repeat(128)))
        assertFalse(PublicAssetPaths.isCanonicalHash(""))
        assertFalse(PublicAssetPaths.isCanonicalHash("a".repeat(32)))
        assertFalse(PublicAssetPaths.isCanonicalHash("a".repeat(40)))
        assertFalse(PublicAssetPaths.isCanonicalHash("a".repeat(129)))
        assertFalse(PublicAssetPaths.isCanonicalHash(hash.dropLast(1)))
        assertFalse(PublicAssetPaths.isCanonicalHash("${hash}0"))
        assertFalse(PublicAssetPaths.isCanonicalHash(hash.uppercase()))
        assertFalse(PublicAssetPaths.isCanonicalHash("g" + hash.drop(1)))
        assertFalse(PublicAssetPaths.isCanonicalHash("$hash\n"))
        assertFalse(PublicAssetPaths.isCanonicalHash(" $hash"))
        assertFalse(PublicAssetPaths.isCanonicalHash("$hash.png"))
    }

    @Test
    fun extensionForContentType_stripsParametersAndIgnoresCase() {
        assertEquals("png", PublicAssetPaths.extensionForContentType("image/PNG"))
        assertEquals("png", PublicAssetPaths.extensionForContentType("image/png; charset=utf-8"))
        assertEquals("jpg", PublicAssetPaths.extensionForContentType("image/jpeg"))
        assertEquals("jpg", PublicAssetPaths.extensionForContentType("image/jpg"))
        assertEquals("svg", PublicAssetPaths.extensionForContentType("image/svg+xml"))
        assertEquals("webp", PublicAssetPaths.extensionForContentType("image/webp"))
        assertEquals("ico", PublicAssetPaths.extensionForContentType("image/x-icon"))
        assertEquals("pdf", PublicAssetPaths.extensionForContentType("application/pdf"))
        assertNull(PublicAssetPaths.extensionForContentType(null))
        assertNull(PublicAssetPaths.extensionForContentType("text/plain"))
    }

    @Test
    fun toAbsolute_joinsBaseUrlAndPath() {
        val relative = PublicAssetPaths.assetPath(tenantId, AssetNamespace.BRAND, hash, "image/png")
        assertEquals(
            "https://acme.example.com/public/assets/acme/brand/$hash.png",
            PublicAssetPaths.toAbsolute(relative, "https://acme.example.com"),
        )
        // Trailing slash on the base is normalized away.
        assertEquals(
            "https://acme.example.com/public/assets/acme/brand/$hash.png",
            PublicAssetPaths.toAbsolute(relative, "https://acme.example.com/"),
        )
    }

    @Test
    fun toAbsolute_isNoOpForAbsoluteForeignOrBlankInputs() {
        val absolute = "https://cdn.example.com/logo.png"
        assertEquals(absolute, PublicAssetPaths.toAbsolute(absolute, "https://acme.example.com"))
        assertEquals("/other/path", PublicAssetPaths.toAbsolute("/other/path", "https://acme.example.com"))
        val relative = PublicAssetPaths.assetPath(tenantId, AssetNamespace.BRAND, hash)
        assertEquals(relative, PublicAssetPaths.toAbsolute(relative, null))
        assertEquals(relative, PublicAssetPaths.toAbsolute(relative, " "))
        assertNull(PublicAssetPaths.toAbsolute(null, "https://acme.example.com"))
    }

    @Test
    fun assetNamespace_fromValueResolvesWireValuesAndNames() {
        assertEquals(AssetNamespace.BRAND, AssetNamespace.fromValue("brand"))
        assertEquals(AssetNamespace.DESIGN, AssetNamespace.fromValue("design"))
        assertEquals(AssetNamespace.BRAND, AssetNamespace.fromValue("BRAND"))
        assertNull(AssetNamespace.fromValue("unknown"))
    }
}
