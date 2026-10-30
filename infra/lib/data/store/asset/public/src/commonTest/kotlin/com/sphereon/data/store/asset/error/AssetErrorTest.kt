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

package com.sphereon.data.store.asset.error

import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.validation.ValidationErrorDetail
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AssetErrorTest {
    @Test
    fun shouldClassifyValidationErrorAsValidationAndJoinEveryDetail() {
        val error =
            AssetError.ValidationError(
                listOf(
                    ValidationErrorDetail(path = ".hash", message = "must be a digest"),
                    ValidationErrorDetail(path = ".namespace", message = "is unknown"),
                ),
            )

        assertEquals("ASSET_VALIDATION_ERROR", error.code)
        assertEquals(ErrorCategory.VALIDATION, error.category)
        assertEquals(IdkError.Severity.ERROR, error.severity)
        assertTrue(error.message.defaultMessage.contains(".hash: must be a digest"))
        assertTrue(error.message.defaultMessage.contains(".namespace: is unknown"))
    }

    @Test
    fun shouldConvertToIdkErrorKeepingCodeAndCategory() {
        val details = listOf(ValidationErrorDetail(path = ".hash", message = "must be a digest"))

        val error = AssetError.ValidationError(details)
        val converted = IdkError.fromDTO(error)

        assertEquals(details, error.errors)
        assertEquals(ErrorCategory.VALIDATION, converted.category)
        assertEquals("ASSET_VALIDATION_ERROR", converted.code)
    }
}
