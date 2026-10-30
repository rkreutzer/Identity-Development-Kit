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

package com.sphereon.openid.oid4vp.verifier.callback

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.callback.CallbackSigningAlgorithm
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Dispatches the Universal OID4VP status response of an authorization session to an external callback URL (webhook).
 *
 * Implementations should be best-effort: callback delivery failures must not break the main OID4VP flows.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("AuthorizationSessionCallbackDispatcher", exact = true)
interface AuthorizationSessionCallbackDispatcher {
    suspend fun dispatch(
        url: String,
        status: GetAuthorizationRequestStatusOutput,
    ): IdkResult<Unit, IdkError>

    /**
     * Dispatch with signing metadata. Legacy implementers remain source-compatible: unsigned
     * calls delegate to [dispatch], while signed calls fail closed until this overload is
     * explicitly implemented.
     */
    suspend fun dispatch(
        url: String,
        status: GetAuthorizationRequestStatusOutput,
        signing: AuthorizationSessionCallbackSigning?,
    ): IdkResult<Unit, IdkError> =
        if (signing == null) {
            dispatch(url, status)
        } else {
            com.sphereon.core.api.Err(
                IdkError.fromString(message = "Signed authorization session callback is unsupported"),
            )
        }
}

/** Secret reference and algorithm selected for one callback delivery. */
data class AuthorizationSessionCallbackSigning(
    val secretRef: String?,
    val algorithm: CallbackSigningAlgorithm?,
)
