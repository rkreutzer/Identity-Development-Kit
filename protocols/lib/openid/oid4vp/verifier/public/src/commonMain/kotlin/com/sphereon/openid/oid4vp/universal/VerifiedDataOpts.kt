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

package com.sphereon.openid.oid4vp.universal

import com.sphereon.core.compat.JsExportCompat
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * The way verified data is represented in a callback, per the FIDES Universal OID4VP spec.
 *
 * @see <a href="https://github.com/FIDEScommunity/universal-oid4vp">Universal OID4VP spec</a>
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifiedDataMode", exact = true)
@Serializable
@JsExportCompat
enum class VerifiedDataMode {
    @SerialName("authorization_response")
    AUTHORIZATION_RESPONSE,

    @SerialName("vp_token")
    VP_TOKEN,

    @SerialName("credential_claims_deserialized")
    CREDENTIAL_CLAIMS_DESERIALIZED,
}

/**
 * Controls which verified data representations a callback carries. Only applies to the
 * `authorization_response_verified` status. Omitting it, or leaving [modes] empty, carries none.
 *
 * @see <a href="https://github.com/FIDEScommunity/universal-oid4vp">Universal OID4VP spec</a>
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifiedDataOpts", exact = true)
@JsExportCompat
@Serializable
data class VerifiedDataOpts(
    val modes: List<VerifiedDataMode> = emptyList(),
)
