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
import com.sphereon.data.store.blob.digest.MultihashAlgorithm

/**
 * Canonical public-asset path constants for the tenant asset library, shared between the IDK
 * impl layer (which builds the URI returned from [TenantAssetService.uploadAsset]) and the EDK
 * rest hosting adapter (which mounts the public GET endpoints under the same root).
 *
 * Tenant asset URLs are tenant scoped and host independent:
 *
 * ```
 * /public/assets/{tenantId}/{namespace}/{hash}.{ext}
 * ```
 *
 * Because the tenant id is in the path, the URL resolves identically whether assets are served
 * from the tenant's own domain or from the platform domain. The asset id is the SHA-256 content
 * hash and is stable across hosts and re-uploads of the same bytes, hence the deliberately
 * UNVERSIONED `/public/` prefix.
 *
 * Credential design keeps its own `/public/assets/design/{hash}.{ext}` scheme
 * (`PublicDesignAssetPaths`): those URLs are embedded in issued credentials and must stay
 * byte-stable.
 */
object PublicAssetPaths {
    /** Root mount for the PUBLIC, unauthenticated tenant-asset hosting surface. */
    const val BASE_PATH = "/public/assets"

    private val LOWERCASE_HEX = Regex("[0-9a-f]+")

    /**
     * The lengths, in hexadecimal characters, of the digests of the algorithms the blob module registers for content
     * addressing ([MultihashAlgorithm]). The format check follows that registry instead of one hard-coded width.
     */
    private val DIGEST_HEX_LENGTHS: Set<Int> = MultihashAlgorithm.entries.map { it.digestLength * 2 }.toSet()

    /**
     * Returns the tenant-and-namespace directory of the public hosting surface,
     * e.g. `"/public/assets/acme/brand"`.
     */
    fun namespacePath(
        tenantId: String,
        namespace: AssetNamespace,
    ): String = "$BASE_PATH/$tenantId/${namespace.value}"

    /**
     * Returns the CONTENT-ADDRESSED relative public path for an asset, identified solely by the
     * SHA-256 hash of its bytes, with an optional file extension derived from the content-type.
     *
     * Content addressing collapses byte-identical assets onto a SINGLE stable URL per tenant and
     * namespace, so clients download and cache the bytes exactly once. The hash also yields the
     * subresource-integrity value for free.
     *
     * The extension is a CLIENT HINT for CDNs/browsers that key off file extensions. It is NOT
     * part of the hash: the server recovers the hash via [hashFromLeaf] by stripping the
     * extension, then looks up `(tenant, namespace, hash)` in the blob store. Same bytes + same
     * content-type always produce the same URI.
     *
     * @param tenantId tenant the asset belongs to
     * @param namespace asset namespace (`brand` / `design`)
     * @param hash lowercase hex SHA-256 digest (64 chars) of the asset bytes
     * @param contentType optional MIME type; mapped to a file extension and appended when known
     * @return full relative path, e.g. `"/public/assets/acme/brand/<64-hex>.png"`
     */
    fun assetPath(
        tenantId: String,
        namespace: AssetNamespace,
        hash: String,
        contentType: String? = null,
    ): String {
        val ext = extensionForContentType(contentType)
        val base = "${namespacePath(tenantId, namespace)}/$hash"
        return if (ext != null) "$base.$ext" else base
    }

    /**
     * Maps a MIME content-type string to a well-known file extension, or returns `null` for
     * unrecognised types. The mapping is intentionally small — only image formats and PDF that
     * are expected as branding/design assets.
     *
     * Matching is case-insensitive. Any `; charset=...` (or other) parameters are stripped
     * before matching, so `"image/PNG"` and `"image/png; charset=utf-8"` both map to `"png"`.
     *
     * @param contentType raw Content-Type header value, may be null or include parameters
     * @return lowercase file extension without leading dot, or `null` if unrecognised
     */
    fun extensionForContentType(contentType: String?): String? {
        if (contentType == null) return null
        val mediaType = contentType.substringBefore(';').trim().lowercase()
        return when (mediaType) {
            "image/png" -> "png"
            "image/jpeg", "image/jpg" -> "jpg"
            "image/svg+xml" -> "svg"
            "image/gif" -> "gif"
            "image/webp" -> "webp"
            "image/avif" -> "avif"
            "image/x-icon", "image/vnd.microsoft.icon" -> "ico"
            "application/pdf" -> "pdf"
            else -> null
        }
    }

    /**
     * Recovers the bare SHA-256 hash from the leaf segment of a content-addressed asset URL.
     *
     * The leaf is the last path segment of the request URL, e.g. `"<64-hex>.png"` or simply
     * `"<64-hex>"` (no extension). The hash is everything before the first dot; if there is no
     * dot the full leaf is returned unchanged.
     *
     * Used by the EDK hosting route to extract the lookup key from `{asset}` path parameters.
     *
     * @param leaf the last path segment, e.g. `"abc123.png"` or `"abc123"`
     * @return the hash portion, e.g. `"abc123"`
     */
    fun hashFromLeaf(leaf: String): String = leaf.substringBefore('.')

    /**
     * Whether [hash] is a canonical asset hash: the lowercase hexadecimal digest of the asset bytes, which is what
     * [assetPath] takes and [hashFromLeaf] recovers. Its length has to be that of a digest algorithm the blob module
     * registers ([MultihashAlgorithm]). The library computes SHA-256, so its own hashes are 64 characters, but the check
     * does not fix that width. The whole string has to match, so a trailing newline, surrounding whitespace or an
     * upper-case digit is refused.
     */
    fun isCanonicalHash(hash: String): Boolean = hash.length in DIGEST_HEX_LENGTHS && hash.matches(LOWERCASE_HEX)

    /**
     * Resolves a stored asset [uri] to an ABSOLUTE URL using a per-request/per-tenant
     * [externalBaseUrl], so the host embedded in served content matches the host the request
     * arrived on (multi-tenant gateway: `acme.example.com` vs `bob.example.com`).
     *
     * Asset URIs are stored RELATIVE (content-addressed under [BASE_PATH]) precisely so the
     * host can be supplied at SERVE time from the per-tenant external base. This keeps
     * content-addressing intact — only the host/base differs, the hash/path is untouched.
     *
     * Returns [uri] unchanged (a no-op) when:
     *  - [uri] is null or blank,
     *  - [externalBaseUrl] is null or blank,
     *  - [uri] already looks absolute (contains `"://"`), or
     *  - [uri] is not a public asset path (does not start with [BASE_PATH]).
     *
     * @param uri the stored (relative) asset URI, e.g. `"/public/assets/acme/brand/<hash>.png"`
     * @param externalBaseUrl the per-tenant external origin, e.g. `"https://acme.example.com"`
     * @return the absolute URL, e.g. `"https://acme.example.com/public/assets/acme/brand/<hash>.png"`
     */
    fun toAbsolute(
        uri: String?,
        externalBaseUrl: String?,
    ): String? {
        if (uri.isNullOrBlank()) return uri
        if (externalBaseUrl.isNullOrBlank()) return uri
        if (uri.contains("://")) return uri
        if (!uri.startsWith(BASE_PATH)) return uri
        return externalBaseUrl.trimEnd('/') + uri
    }
}
