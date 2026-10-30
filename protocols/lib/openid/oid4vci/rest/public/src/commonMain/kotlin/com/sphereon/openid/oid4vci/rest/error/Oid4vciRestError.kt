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

package com.sphereon.openid.oid4vci.rest.error

import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.validation.ValidationErrorDetail

/** Errors of the OID4VCI backend REST commands that carry structure of their own. */
sealed interface Oid4vciRestError : IdkErrorType {
    /** The input of a command violates a rule of its type, with one detail per violation. */
    data class ValidationError(
        val errors: List<ValidationErrorDetail>,
        override val code: String = "OID4VCI_REST_VALIDATION_ERROR",
        override val message: IdkError.Message =
            IdkError.Message(
                i18nKey = "oid4vci.rest.error.validation_error",
                defaultMessage = "OID4VCI request validation failed: ${errors.joinToString { it.message }}",
            ),
        override val severity: IdkError.Severity = IdkError.Severity.ERROR,
        override val category: ErrorCategory = ErrorCategory.VALIDATION,
        override val exception: Throwable? = null,
        override val causes: List<IdkErrorType> = emptyList(),
        override val meta: Map<String, Any?> = emptyMap(),
    ) : Oid4vciRestError
}
