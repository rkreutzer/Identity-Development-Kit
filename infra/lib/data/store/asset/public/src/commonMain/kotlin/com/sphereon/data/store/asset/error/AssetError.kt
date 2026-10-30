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
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.validation.ValidationErrorDetail

/**
 * Errors the tenant asset commands report themselves, as opposed to the ones the asset library returns.
 */
sealed interface AssetError : IdkErrorType {
    /**
     * A request failed validation before the asset library was asked for anything.
     *
     * @property errors the path and message of every failed constraint
     */
    data class ValidationError(
        val errors: List<ValidationErrorDetail>,
        override val code: String = "ASSET_VALIDATION_ERROR",
        override val message: IdkError.Message =
            IdkError.Message(
                i18nKey = "assets.error.validation_error",
                defaultMessage = "Asset request validation failed: ${errors.joinToString { "${it.path}: ${it.message}" }}",
            ),
        override val category: ErrorCategory = ErrorCategory.VALIDATION,
        override val severity: IdkError.Severity = IdkError.Severity.ERROR,
        override val exception: Throwable? = null,
        override val causes: List<IdkErrorType> = emptyList(),
        override val meta: Map<String, Any?> = emptyMap(),
    ) : AssetError
}
