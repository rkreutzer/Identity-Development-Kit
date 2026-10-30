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

package com.sphereon.sdjwt.vc

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The type claims of an SD-JWT VC payload, read in one place.
 *
 * `vct` and `vct#integrity` are plain claims: SD-JWT VC does not allow them to be selectively disclosable,
 * so they are present in the issuer-signed JWT payload of every presentation.
 */
object SdJwtVcClaims {
    const val VCT = "vct"
    const val VCT_INTEGRITY = "vct#integrity"

    /** The `vct` of [payload], or null when it is absent, not a string or blank. */
    fun vct(payload: JsonObject): String? = (payload[VCT] as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotBlank() }

    /**
     * The `vct#integrity` expression of [payload]: Ok(null) when the claim is absent, Ok(expression) when it
     * is a non-blank string, and an error when it is present in any other shape. A malformed pin is never
     * the same as no pin.
     */
    fun vctIntegrity(payload: JsonObject): IdkResult<String?, IdkError> {
        val claim = payload[VCT_INTEGRITY] ?: return Ok(null)
        val expression = (claim as? JsonPrimitive)?.takeIf { it.isString }?.content?.takeIf { it.isNotBlank() }
        return expression?.let { Ok(it) } ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The $VCT_INTEGRITY claim must be a non-blank string"))
    }
}
