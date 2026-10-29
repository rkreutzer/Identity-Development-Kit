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
import com.sphereon.di.session.SessionScope
import com.sphereon.sdjwt.vc.command.ResolveTypeMetadataCommand
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn

/**
 * Follows the `extends` chain of the type metadata that [resolveTypeMetadataCommand] resolves, validating the
 * name, integrity pin and loop freedom of every document it consults.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class)
class SdJwtVcTypeMatcherImpl(
    private val resolveTypeMetadataCommand: ResolveTypeMetadataCommand,
) : SdJwtVcTypeMatcher {
    override suspend fun matches(
        vct: String,
        acceptedVcts: List<String>,
        vctIntegrity: String?,
    ): IdkResult<Boolean, IdkError> {
        if (vct.isBlank()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The credential vct must not be blank"))
        }
        if (acceptedVcts.isEmpty()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "At least one accepted vct is required"))
        }
        if (vct in acceptedVcts) {
            return Ok(true)
        }

        val visited = mutableSetOf<String>()
        var matched = false
        var current: String? = vct
        var pin: String? = vctIntegrity
        while (current != null) {
            if (!visited.add(current)) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Type metadata extends chain closes a loop at '$current': ${visited.joinToString(" -> ")}"))
            }
            val resolved = resolveTypeMetadataCommand.execute(ResolveTypeMetadataArgs(vct = current)).getOrElse { return Err(it) }
            val success =
                when (resolved) {
                    is TypeMetadataResolutionResult.Success -> resolved
                    is TypeMetadataResolutionResult.Failure -> return Err(resolutionError(current, resolved.error))
                }
            val metadata = success.metadata
            if (metadata.vct != current) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Type metadata resolved for '$current' names vct '${metadata.vct}'"))
            }
            if (pin != null) {
                val document =
                    success.rawDocument
                        ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Type metadata for '$current' carries no original document to verify its integrity against"))
                TypeMetadataIntegrity.verify(document, pin).getOrElse {
                    return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Integrity check of type metadata for '$current' failed: ${it.message.defaultMessage}"))
                }
            }
            val parent = metadata.extends
            if (parent != null && parent in acceptedVcts) {
                matched = true
            }
            current = parent
            pin = metadata.extendsIntegrity
        }
        return Ok(matched)
    }

    private fun resolutionError(
        vct: String,
        error: TypeMetadataResolutionError,
    ): IdkError =
        when (error) {
            is TypeMetadataResolutionError.NetworkError ->
                IdkError.UNKNOWN_ERROR(message = "Type metadata for '$vct' could not be fetched: ${error.message}", exception = error.cause)
            is TypeMetadataResolutionError.InvalidFormat ->
                IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Type metadata for '$vct' is invalid: ${error.message}")
            TypeMetadataResolutionError.NotFound ->
                IdkError.NOT_FOUND_ERROR(message = "Type metadata for '$vct' was not found")
            is TypeMetadataResolutionError.UnsupportedVct ->
                IdkError.ILLEGAL_ARGUMENT_ERROR(message = "No resolver supports vct '${error.vct}'")
            is TypeMetadataResolutionError.CircularDependency ->
                IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Type metadata extends chain closes a loop at '${error.vct}'")
        }
}
