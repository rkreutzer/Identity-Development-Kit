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
import com.sphereon.core.api.decodeFromBase64
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash

/**
 * Verifies a W3C subresource integrity expression against the original octets of a type metadata document.
 *
 * Several whitespace separated expressions may be supplied. Only the strongest supported algorithm present is
 * considered, and the document is accepted when one expression of that algorithm matches. The digest is taken
 * over the retrieved octets and never over a re-serialized form.
 */
internal object TypeMetadataIntegrity {
    private val strengthOrder: List<Pair<String, DigestAlg>> =
        listOf(
            "sha512" to DigestAlg.SHA512,
            "sha384" to DigestAlg.SHA384,
            "sha256" to DigestAlg.SHA256,
        )

    fun verify(
        document: ByteArray,
        integrity: String,
    ): IdkResult<Unit, IdkError> {
        val expressions = integrity.split(' ', '\t', '\n', '\r').filter { it.isNotEmpty() }
        if (expressions.isEmpty()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The integrity expression is empty"))
        }
        val parsed =
            expressions.map { expression ->
                val separator = expression.indexOf('-')
                if (separator <= 0 || separator == expression.length - 1) {
                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The integrity expression '$expression' is malformed"))
                }
                val algorithm = expression.substring(0, separator).lowercase()
                val digest = expression.substring(separator + 1).substringBefore('?')
                algorithm to digest
            }
        val (algorithmName, algorithm) =
            strengthOrder.firstOrNull { (name, _) -> parsed.any { it.first == name } }
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "No supported hash algorithm in integrity expression '$integrity'"))
        val actual = hash(document, algorithm)
        for ((name, digest) in parsed) {
            if (name != algorithmName) continue
            val expected =
                try {
                    digest.decodeFromBase64()
                } catch (invalid: IllegalArgumentException) {
                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The integrity digest '$digest' is not valid base64", throwable = invalid))
                }
            if (expected.contentEquals(actual)) {
                return Ok(Unit)
            }
        }
        return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The type metadata document does not match its $algorithmName integrity digest"))
    }
}
