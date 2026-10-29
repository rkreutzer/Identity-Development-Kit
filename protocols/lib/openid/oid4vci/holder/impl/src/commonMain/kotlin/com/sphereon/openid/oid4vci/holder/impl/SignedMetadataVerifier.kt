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

package com.sphereon.openid.oid4vci.holder.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.jose.jws.JwsCompact
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vci.common.Oid4vciJson
import com.sphereon.openid.oid4vci.common.model.CredentialIssuerMetadata
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn

@Inject
@SingleIn(SessionScope::class)
class SignedMetadataVerifier(
    private val verifyJwsCommand: VerifyJwsCommand,
) {
    suspend fun verifyAndExtract(
        jwtString: String,
        expectedIssuer: String,
    ): IdkResult<CredentialIssuerMetadata, IdkError> {
        val verifyArgs = VerifyJwsArgs(jws = JwsCompact(jwtString))
        val result = verifyJwsCommand.execute(verifyArgs).getOrElse { return Err(it) }

        if (!result.isValid) {
            return Err(
                IdkError.fromString(
                    message = "Signed issuer metadata verification failed: ${result.errorMessages.joinToString()}",
                    code = "SIGNED_METADATA_VERIFICATION_FAILED",
                ),
            )
        }

        val metadata =
            try {
                Oid4vciJson.lenient.decodeFromJsonElement(CredentialIssuerMetadata.serializer(), result.parsedPayload)
            } catch (expected: Exception) {
                return Err(
                    IdkError.fromString(
                        message = "Failed to parse issuer metadata from JWT payload: ${expected.message}",
                        code = "SIGNED_METADATA_PARSE_FAILED",
                        exception = expected,
                    ),
                )
            }

        // OID4VCI 12.2.4 requires simple string comparison without normalization.
        if (metadata.credentialIssuer != expectedIssuer) {
            return Err(
                IdkError.fromString(
                    message = "Signed metadata credential_issuer (${metadata.credentialIssuer}) does not match expected ($expectedIssuer)",
                    code = "SIGNED_METADATA_ISSUER_MISMATCH",
                ),
            )
        }

        return Ok(metadata)
    }

    companion object {
        private const val JWT_PART_COUNT = 3

        fun isJwtResponse(body: String): Boolean {
            val trimmed = body.trim()
            if (trimmed.isEmpty() || trimmed.startsWith("{")) {
                return false
            }
            val parts = trimmed.split('.')
            return parts.size == JWT_PART_COUNT &&
                parts.all { part ->
                    part.isNotEmpty() && part.all { c -> c.isLetterOrDigit() || c == '-' || c == '_' || c == '=' }
                }
        }
    }
}
