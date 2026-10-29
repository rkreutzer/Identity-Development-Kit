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

package com.sphereon.openid.oid4vci.rest

import com.sphereon.core.compat.JsExportCompat
import kotlinx.serialization.Serializable

/**
 * Configuration for the OID4VCI backend REST API.
 */
@JsExportCompat
@Serializable
data class Oid4vciRestConfig(
    /**
     * External base URL for building status URIs and offer URIs.
     * E.g., "https://issuer.example.com"
     */
    val externalBaseUrl: String? = null,
    /**
     * Whether a single process serves the deployment. Correlation ids that make a call idempotent are claimed on the KV store `oid4vci.rest.sessions`, and
     * a claim on a process-local backend (`memory`, `kottage`) is refused unless this is set, because two replicas could
     * each claim the same key. Read from `oid4vci.rest.requests.allowProcessLocalStore`.
     */
    val allowProcessLocalRequestStore: Boolean = false,
) {
    companion object {
        const val CONFIG_PREFIX = "oid4vci.rest"
    }
}

/**
 * Provider interface for OID4VCI REST configuration.
 */
@JsExportCompat
interface Oid4vciRestConfigProvider {
    fun getConfig(): Oid4vciRestConfig
}
