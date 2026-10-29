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
 */

package com.sphereon.openid.oid4vci.common

/**
 * URL construction utilities for OID4VCI endpoints.
 */
object Oid4vciUrls {
    /**
     * Builds the `.well-known/openid-credential-issuer` URL per OID4VCI 1.0 Final Section 12.2.2.
     *
     * The `.well-known` segment is inserted between the host (including port) and any path:
     * - `https://issuer.example.com`        → `https://issuer.example.com/.well-known/openid-credential-issuer`
     * - `https://issuer.example.com/tenant1` → `https://issuer.example.com/.well-known/openid-credential-issuer/tenant1`
     */
    fun buildWellKnownUrl(issuerUrl: String): String {
        // OID4VCI 12.2.2 inserts the well-known segment without changing the issuer path.
        // OAuth AS discovery has different terminating-slash rules and uses its own helper.
        val normalized = issuerUrl.trim()
        if (normalized.contains(WELL_KNOWN_PATH)) {
            return normalized
        }
        val schemeEnd = normalized.indexOf("://") + SCHEME_SEPARATOR_LENGTH
        val pathStart = normalized.indexOf('/', schemeEnd)
        return if (pathStart < 0) {
            "$normalized$WELL_KNOWN_PATH"
        } else {
            val host = normalized.substring(0, pathStart)
            val path = normalized.substring(pathStart)
            "$host$WELL_KNOWN_PATH$path"
        }
    }

    /**
     * Returns the issuer identifier represented by either an issuer URL or a full metadata URL.
     *
     * OID4VCI inserts `/.well-known/openid-credential-issuer` between host and issuer path, so the
     * reverse operation removes that segment and preserves the suffix as the issuer path.
     */
    fun buildIssuerUrl(issuerOrWellKnownUrl: String): String {
        val normalized = issuerOrWellKnownUrl.trim()
        val schemeEnd = normalized.indexOf("://") + SCHEME_SEPARATOR_LENGTH
        val wellKnownStart = normalized.indexOf(WELL_KNOWN_PATH, schemeEnd)
        if (wellKnownStart < 0) {
            return normalized
        }
        val host = normalized.substring(0, wellKnownStart)
        val issuerPath = normalized.substring(wellKnownStart + WELL_KNOWN_PATH.length)
        return "$host$issuerPath"
    }

    const val WELL_KNOWN_PATH = "/.well-known/openid-credential-issuer"

    private const val SCHEME_SEPARATOR_LENGTH = 3

}
