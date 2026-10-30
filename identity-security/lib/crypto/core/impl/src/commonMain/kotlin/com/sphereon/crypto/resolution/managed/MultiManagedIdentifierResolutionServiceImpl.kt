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

package com.sphereon.crypto.resolution.managed

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.asErrorResult
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.log.Log
import com.sphereon.crypto.core.KeyType
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<MultiManagedIdentifierService>())
@ContributesBinding(SessionScope::class, binding = binding<ManagedIdentifierService>())
class MultiManagedIdentifierResolutionServiceImpl(
    execution: SessionExecution,
    val managedIdentifierServices: Set<ManagedIdentifierService>,
) : ManagedIdentifierServiceAdapter<ManagedIdentifierResult<KeyType>>(
        supportedIdentifierMethods = managedIdentifierServices.flatMap { it.supportedIdentifierMethods }.toSet().toList(),
        execution = execution,
        commandId = COMMAND_ID,
    ),
    MultiManagedIdentifierService {
    override suspend fun doExecute(
        args: ManagedIdentifierOptsOrResult,
        applyDuring: (ManagedIdentifierOptsOrResult) -> ManagedIdentifierOptsOrResult,
    ): IdkResult<ManagedIdentifierResult<KeyType>, IdkErrorType> {
        managedIdentifierServices.firstOrNull { it.isSupportedIdentifier(args.identifier) }?.let {
            return it.resolve(args)
        }

        return IdkError
            .COMMAND_ARG_NOT_SUPPORTED_ERROR(message = "Managed identifier opts or result not supported : ${args::class.simpleName}, id: ${args.identifier}")
            .asErrorResult()
    }

    override suspend fun resolve(opts: ManagedIdentifierOptsOrResult): IdkResult<ManagedIdentifierResult<KeyType>, IdkErrorType> {
        // Capture static method names before suspension loses the caller. Never include an
        // exception message, arguments, key references, filesystem paths or raw stack traces.
        val callerPath = Regex("com\\.sphereon\\.[A-Za-z0-9_.$]+")
            .findAll(Throwable().stackTraceToString()).map { it.value }
            .filterNot { it.contains("MultiManagedIdentifierResolutionServiceImpl") }
            .distinct().take(4).joinToString(">").take(512).ifEmpty { "unavailable" }
        val result = execute(opts)
        if (result.isErr) {
            val kind = when (opts) {
                is ManagedOptsKeyInfo -> if (opts.identifier.key == null) "key-reference" else "supplied-key"
                is ManagedOptsJwk -> "supplied-jwk"
                else -> "other"
            }
            val code = result.error.code.takeIf { it.matches(Regex("[A-Za-z0-9_.:-]{1,160}")) } ?: "unavailable"
            Log.app().withTag("ManagedKeyResolution").warn("Managed key resolution refused stage=command input_kind=$kind code=$code caller_path=$callerPath")
        }
        return result
    }

    override suspend fun isSupportedIdentifier(identifier: Any): Boolean = managedIdentifierServices.any { it.isSupportedIdentifier(identifier) }

    companion object {
        const val COMMAND_ID = "crypto.resolution.managed"
    }
}
