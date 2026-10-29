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

package com.sphereon.core.api.session

import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.compat.JsExportCompat

/**
 * Standard error mapper interface for commands.
 * Provides consistent error creation across all command implementations.
 *
 * @param E The error type (typically IdkError or a subtype)
 */
@JsExportCompat
interface CommandErrorMapper<E : IdkErrorType> {
    /**
     * Creates an error for unsupported arguments.
     */
    fun unsupportedArg(
        command: Any,
        arg: Any,
    ): E

    /**
     * Creates an error when a command is disabled.
     */
    fun commandDisabled(commandId: String): E

    /**
     * Creates an error when command execution is intentionally skipped.
     */
    fun commandSkipped(
        commandId: String,
        reason: String? = null,
    ): E = unknown(message = "Command '$commandId' was skipped${reason?.let { ": $it" } ?: ""}")

    /**
     * Creates an error when authorization fails.
     */
    fun notAuthorized(
        commandId: CommandId,
        reason: String,
    ): E

    /**
     * Creates an error when a lifecycle interceptor denied the command, or failed (then [denialCode] is
     * `INTERCEPTOR_ERROR`). Mappers that can carry it keep [interceptorName] and [denialCode] on the error
     * (see [CommandErrors.DENIED_BY_INTERCEPTOR_META]); the default drops them and delegates to [notAuthorized],
     * so existing implementers keep compiling and behave as before.
     */
    fun notAuthorizedByInterceptor(
        commandId: CommandId,
        reason: String,
        interceptorName: String,
        denialCode: String,
    ): E = notAuthorized(commandId, reason)

    /**
     * Creates an error for unknown/unexpected failures.
     */
    fun unknown(
        message: String,
        cause: Throwable? = null,
    ): E

    /**
     * Creates an error when all handlers in a chain have failed.
     */
    fun allHandlersFailed(errors: List<E>): E

    /**
     * Creates an error when a command cannot be found in the active context.
     */
    fun commandNotFound(commandId: String): E = unknown(message = "Command '$commandId' not found")

    /**
     * Creates an error when a command ID format is invalid.
     */
    fun invalidCommandId(commandId: String): E
}

/**
 * Default implementation of CommandErrorMapper for IdkError.
 */
object IdkErrorCommandErrorMapper : CommandErrorMapper<IdkError> {
    override fun unsupportedArg(
        command: Any,
        arg: Any,
    ): IdkError = CommandErrors.unsupportedArg(command = command as? BaseCommand<*, *, *>, arg = arg)

    override fun commandDisabled(commandId: String): IdkError = CommandErrors.commandDisabled(commandId = commandId)

    override fun commandSkipped(
        commandId: String,
        reason: String?,
    ): IdkError = CommandErrors.commandSkipped(commandId = commandId, reason = reason)

    override fun notAuthorized(
        commandId: CommandId,
        reason: String,
    ): IdkError = CommandErrors.notAuthorized(commandId, reason)

    override fun notAuthorizedByInterceptor(
        commandId: CommandId,
        reason: String,
        interceptorName: String,
        denialCode: String,
    ): IdkError = CommandErrors.notAuthorizedByInterceptor(commandId, reason, interceptorName, denialCode)

    override fun unknown(
        message: String,
        cause: Throwable?,
    ): IdkError = IdkError.UNKNOWN_ERROR(message = message, exception = cause)

    override fun allHandlersFailed(errors: List<IdkError>): IdkError = CommandErrors.allHandlersFailed(errors)

    override fun commandNotFound(commandId: String): IdkError = CommandErrors.commandNotFound(commandId)

    override fun invalidCommandId(commandId: String): IdkError = CommandErrors.invalidCommandId(commandId)
}

/**
 * Convenience mapper for APIs that expose IdkErrorType while using IdkError implementations.
 */
object IdkErrorTypeCommandErrorMapper : CommandErrorMapper<IdkErrorType> {
    override fun unsupportedArg(
        command: Any,
        arg: Any,
    ): IdkErrorType = IdkErrorCommandErrorMapper.unsupportedArg(command, arg)

    override fun commandDisabled(commandId: String): IdkErrorType = IdkErrorCommandErrorMapper.commandDisabled(commandId)

    override fun commandSkipped(
        commandId: String,
        reason: String?,
    ): IdkErrorType = IdkErrorCommandErrorMapper.commandSkipped(commandId, reason)

    override fun notAuthorized(
        commandId: CommandId,
        reason: String,
    ): IdkErrorType = IdkErrorCommandErrorMapper.notAuthorized(commandId, reason)

    override fun notAuthorizedByInterceptor(
        commandId: CommandId,
        reason: String,
        interceptorName: String,
        denialCode: String,
    ): IdkErrorType = IdkErrorCommandErrorMapper.notAuthorizedByInterceptor(commandId, reason, interceptorName, denialCode)

    override fun unknown(
        message: String,
        cause: Throwable?,
    ): IdkErrorType = IdkErrorCommandErrorMapper.unknown(message, cause)

    override fun allHandlersFailed(errors: List<IdkErrorType>): IdkErrorType =
        CommandErrors.allHandlersFailed(
            errors.map { error ->
                when (error) {
                    is IdkError -> error
                    else -> IdkError.UNKNOWN_ERROR(message = error.message.defaultMessage)
                }
            },
        )

    override fun commandNotFound(commandId: String): IdkErrorType = IdkErrorCommandErrorMapper.commandNotFound(commandId)

    override fun invalidCommandId(commandId: String): IdkErrorType = IdkErrorCommandErrorMapper.invalidCommandId(commandId)
}
