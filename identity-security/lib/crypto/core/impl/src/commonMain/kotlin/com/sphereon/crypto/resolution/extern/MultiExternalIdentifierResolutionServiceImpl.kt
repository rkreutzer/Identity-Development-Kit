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
 *
 */

package com.sphereon.crypto.resolution.extern

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.asErrorResult
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<MultiExternalIdentifierService>())
class MultiExternalIdentifierResolutionServiceImpl(
    execution: SessionExecution,
    val external: Set<ExternalIdentifierService>,
) : ExternalIdentifierServiceAdapter<ExternalIdentifierResult>(
        supportedIdentifierMethods = external.flatMap { it.supportedIdentifierMethods }.toSet().toList(),
        execution = execution,
        commandId = COMMAND_ID,
    ),
    MultiExternalIdentifierService {
    @Suppress("MagicNumber")
    override suspend fun doExecute(
        args: ExternalIdentifierOptsOrResult,
        applyDuring: (ExternalIdentifierOptsOrResult) -> ExternalIdentifierOptsOrResult,
    ): IdkResult<ExternalIdentifierResult, IdkErrorType> {
        external.firstOrNull { it.isSupportedOpts(args) }?.let {
            log.debug(
                "Using external identifier resolution service: ${it::class.simpleName} for identifier method: ${args.method?.methodName ?: "not specified"}",
            )
            val result = it.resolve(args)
            if (result.isErr) {
                val code = result.error.code.takeIf { value -> value.matches(Regex("[A-Za-z0-9_.:-]{1,160}")) } ?: "unavailable"
                log.warn("EXTERNAL_IDENTIFIER_RESOLUTION_REFUSED stage=resolver-result code=$code")
            }
            return result
        }

        // Log detailed information about why no resolver was found
        val identifierType = args.identifier::class.simpleName ?: "Unknown"
        val identifierMethod = args.method?.methodName ?: "not specified"
        val argsType = args::class.simpleName ?: "Unknown"
        val availableResolvers = external.map { it::class.simpleName }.joinToString(", ")
        val supportedMethods = external.flatMap { it.supportedIdentifierMethods }.map { it.methodName }.joinToString(", ")

        log.warn("EXTERNAL_IDENTIFIER_RESOLUTION_REFUSED stage=resolver-selection reason=unsupported_identifier")

        return IdkError
            .COMMAND_ARG_NOT_SUPPORTED_ERROR(
                message =
                    "External identifier opts or result not supported: $argsType (method: $identifierMethod, identifier type: $identifierType). " +
                        "Available resolvers: [$availableResolvers], supported methods: [$supportedMethods]",
            ).asErrorResult()
    }

    override suspend fun resolve(opts: ExternalIdentifierOptsOrResult): IdkResult<ExternalIdentifierResult, IdkErrorType> = execute(opts)

    override suspend fun isSupportedIdentifier(identifier: Any): Boolean = external.any { it.isSupportedIdentifier(identifier) }

    companion object {
        const val COMMAND_ID = "crypto.resolution.external"
    }
}
