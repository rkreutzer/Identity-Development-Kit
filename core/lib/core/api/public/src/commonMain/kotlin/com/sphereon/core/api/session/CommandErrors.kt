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

/**
 * Canonical command-domain error constructors.
 *
 * Centralizing command errors prevents ad-hoc string-coded error construction in command paths.
 */
object CommandErrors {
    const val COMMAND_NOT_AUTHORIZED_CODE = "COMMAND_NOT_AUTHORIZED"

    /**
     * Error meta key holding the [CommandLifecycleInterceptor.name] of the interceptor whose denial (or failure)
     * produced a [COMMAND_NOT_AUTHORIZED_CODE] error. Absent when the error did not come from an interceptor.
     */
    const val DENIED_BY_INTERCEPTOR_META = "deniedByInterceptor"

    /**
     * Error meta key holding the [InterceptorVerdict.Deny.errorCode] of the denial, or `INTERCEPTOR_ERROR`
     * when the interceptor threw. Always present together with [DENIED_BY_INTERCEPTOR_META].
     */
    const val DENIAL_CODE_META = "denialCode"

    /** The [DENIAL_CODE_META] value when the interceptor threw instead of returning a verdict. */
    const val INTERCEPTOR_ERROR_DENIAL_CODE = "INTERCEPTOR_ERROR"

    fun unsupportedArg(
        command: BaseCommand<*, *, *>? = null,
        arg: Any? = null,
    ): IdkError = IdkError.COMMAND_ARG_NOT_SUPPORTED_ERROR(command = command, arg = arg)

    fun commandDisabled(commandId: String): IdkError = IdkError.COMMAND_DISABLED_ERROR(commandId = commandId)

    fun commandSkipped(
        commandId: String,
        reason: String? = null,
    ): IdkError = IdkError.COMMAND_SKIPPED_ERROR(commandId = commandId, reason = reason)

    fun notAuthorized(
        commandId: CommandId,
        reason: String,
        actor: String? = null,
    ): IdkError = IdkError.COMMAND_NOT_AUTHORIZED_ERROR(commandId = commandId.value, reason = reason, actor = actor)

    /**
     * A [notAuthorized] error that also names the interceptor behind it, in [DENIED_BY_INTERCEPTOR_META],
     * and the denial's error code, in [DENIAL_CODE_META]. Code, message and the other meta are those of [notAuthorized].
     */
    fun notAuthorizedByInterceptor(
        commandId: CommandId,
        reason: String,
        interceptorName: String,
        denialCode: String,
        actor: String? = null,
    ): IdkError {
        val base = notAuthorized(commandId, reason, actor)
        return IdkError(
            code = base.code,
            message = base.message,
            severity = base.severity,
            category = base.category,
            causes = base.causes,
            meta = base.meta + mapOf(DENIED_BY_INTERCEPTOR_META to interceptorName, DENIAL_CODE_META to denialCode),
            exception = base.exception,
        )
    }

    fun allHandlersFailed(errors: List<IdkError>): IdkError = IdkError.ALL_HANDLERS_FAILED_ERROR(errors = errors)

    fun commandNotFound(commandId: String): IdkError =
        IdkError.NOT_FOUND_ERROR(
            resource = "command:$commandId",
            message = "Command not found: $commandId",
        )

    fun invalidCommandId(commandId: String): IdkError =
        IdkError.ILLEGAL_ARGUMENT_ERROR(
            message = "Invalid command ID format: $commandId. Must match format: module.service.command",
        )

    fun isAuthorizationFailure(error: IdkErrorType): Boolean = error.code == COMMAND_NOT_AUTHORIZED_CODE
}
