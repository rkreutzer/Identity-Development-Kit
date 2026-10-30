/*
 * (c) 2026 Sphereon International B.V.
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

package com.sphereon.core.api.session

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import kotlinx.coroutines.test.runTest
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CommandDenialMetaTest {
    @Test
    fun denyFromNamedInterceptorCarriesInterceptorNameAndDenialCode() = runTest {
        val interceptor =
            object : CommandLifecycleInterceptor {
                override val name: String = "policy-gate"

                override suspend fun beforeExecute(
                    context: CommandExecutionContext,
                    args: Any,
                ): InterceptorVerdict = InterceptorVerdict.Deny(reason = "not allowed", errorCode = "POLICY_DENIED")
            }
        var executed = false
        val command = DenialTestCommand(chainOf(interceptor)) { executed = true }

        val error = command.execute(Unit).error

        assertFalse(executed)
        assertEquals(CommandErrors.COMMAND_NOT_AUTHORIZED_CODE, error.code)
        assertTrue(error.message.defaultMessage.contains("not allowed"))
        assertEquals("policy-gate", error.meta[CommandErrors.DENIED_BY_INTERCEPTOR_META])
        assertEquals("POLICY_DENIED", error.meta[CommandErrors.DENIAL_CODE_META])
        assertEquals("not allowed", error.meta["reason"])
    }

    @Test
    fun denyWithDefaultErrorCodeCarriesDefaultDenialCode() = runTest {
        val interceptor =
            object : CommandLifecycleInterceptor {
                override val name: String = "license"

                override suspend fun beforeExecute(
                    context: CommandExecutionContext,
                    args: Any,
                ): InterceptorVerdict = InterceptorVerdict.Deny("expired")
            }

        val error = DenialTestCommand(chainOf(interceptor)).execute(Unit).error

        assertEquals(CommandErrors.COMMAND_NOT_AUTHORIZED_CODE, error.code)
        assertEquals("license", error.meta[CommandErrors.DENIED_BY_INTERCEPTOR_META])
        assertEquals("INTERCEPTOR_DENIED", error.meta[CommandErrors.DENIAL_CODE_META])
    }

    @Test
    fun beforeExecuteExceptionCarriesInterceptorNameAndInterceptorErrorCode() = runTest {
        val interceptor =
            object : CommandLifecycleInterceptor {
                override val name: String = "flaky"

                override suspend fun beforeExecute(
                    context: CommandExecutionContext,
                    args: Any,
                ): InterceptorVerdict = throw IllegalStateException("store down")
            }

        val error = DenialTestCommand(chainOf(interceptor)).execute(Unit).error

        assertEquals(CommandErrors.COMMAND_NOT_AUTHORIZED_CODE, error.code)
        assertTrue(error.message.defaultMessage.contains("Interceptor 'flaky' failed: store down"))
        assertEquals("flaky", error.meta[CommandErrors.DENIED_BY_INTERCEPTOR_META])
        assertEquals("INTERCEPTOR_ERROR", error.meta[CommandErrors.DENIAL_CODE_META])
    }

    @Test
    fun contextSetupExceptionCarriesInterceptorNameAndInterceptorErrorCode() = runTest {
        val interceptor =
            object : CommandLifecycleInterceptor {
                override val name: String = "ctx-setup"

                override fun executionCoroutineContext(
                    context: CommandExecutionContext,
                    args: Any,
                ): CoroutineContext = throw IllegalStateException("no context")
            }

        val error = DenialTestCommand(chainOf(interceptor)).execute(Unit).error

        assertEquals(CommandErrors.COMMAND_NOT_AUTHORIZED_CODE, error.code)
        assertEquals("ctx-setup", error.meta[CommandErrors.DENIED_BY_INTERCEPTOR_META])
        assertEquals("INTERCEPTOR_ERROR", error.meta[CommandErrors.DENIAL_CODE_META])
    }

    @Test
    fun firstDenyWinsWhenSeveralInterceptorsDeny() = runTest {
        val first = denying(name = "first", order = 1, code = "FIRST_CODE")
        val second = denying(name = "second", order = 2, code = "SECOND_CODE")

        val error = DenialTestCommand(chainOf(second, first)).execute(Unit).error

        assertEquals("first", error.meta[CommandErrors.DENIED_BY_INTERCEPTOR_META])
        assertEquals("FIRST_CODE", error.meta[CommandErrors.DENIAL_CODE_META])
    }

    @Test
    fun plainNotAuthorizedHasNoDenialMeta() {
        val error = IdkErrorCommandErrorMapper.notAuthorized(CommandId("a.b.c"), "nope")

        assertEquals(CommandErrors.COMMAND_NOT_AUTHORIZED_CODE, error.code)
        assertNull(error.meta[CommandErrors.DENIED_BY_INTERCEPTOR_META])
        assertNull(error.meta[CommandErrors.DENIAL_CODE_META])
    }

    @Test
    fun deniedByInterceptorOverloadOfBothBuiltInMappersCarriesMeta() {
        val idkError =
            IdkErrorCommandErrorMapper.notAuthorizedByInterceptor(CommandId("a.b.c"), "nope", "gate", "GATE_CODE")
        val typedError =
            IdkErrorTypeCommandErrorMapper.notAuthorizedByInterceptor(CommandId("a.b.c"), "nope", "gate", "GATE_CODE")

        for (error in listOf(idkError, typedError)) {
            assertEquals(CommandErrors.COMMAND_NOT_AUTHORIZED_CODE, error.code)
            assertEquals("gate", error.meta[CommandErrors.DENIED_BY_INTERCEPTOR_META])
            assertEquals("GATE_CODE", error.meta[CommandErrors.DENIAL_CODE_META])
        }
    }

    @Test
    fun legacyMapperWithoutOverrideFallsBackToNotAuthorized() {
        val mapper =
            object : CommandErrorMapper<IdkError> {
                override fun unsupportedArg(
                    command: Any,
                    arg: Any,
                ): IdkError = IdkError.UNKNOWN_ERROR(message = "unsupported")

                override fun commandDisabled(commandId: String): IdkError = IdkError.UNKNOWN_ERROR(message = "disabled")

                override fun notAuthorized(
                    commandId: CommandId,
                    reason: String,
                ): IdkError = IdkError.UNKNOWN_ERROR(message = "legacy: $reason")

                override fun unknown(
                    message: String,
                    cause: Throwable?,
                ): IdkError = IdkError.UNKNOWN_ERROR(message = message)

                override fun allHandlersFailed(errors: List<IdkError>): IdkError = IdkError.UNKNOWN_ERROR(message = "all")

                override fun invalidCommandId(commandId: String): IdkError = IdkError.UNKNOWN_ERROR(message = "invalid")
            }

        val error = mapper.notAuthorizedByInterceptor(CommandId("a.b.c"), "nope", "gate", "X")

        assertEquals("legacy: nope", error.message.defaultMessage)
    }
}

private fun denying(
    name: String,
    order: Int,
    code: String,
): CommandLifecycleInterceptor =
    object : CommandLifecycleInterceptor {
        override val name: String = name
        override val order: Int = order

        override suspend fun beforeExecute(
            context: CommandExecutionContext,
            args: Any,
        ): InterceptorVerdict = InterceptorVerdict.Deny(reason = "denied by $name", errorCode = code)
    }

private fun chainOf(vararg interceptors: CommandLifecycleInterceptor): CommandLifecycleInterceptorChain =
    object : CommandLifecycleInterceptorChain {
        override val interceptors: List<CommandLifecycleInterceptor> = interceptors.toList()
    }

private class DenialTestCommand(
    interceptorChain: CommandLifecycleInterceptorChain,
    private val onExecute: () -> Unit = {},
) : CommandAdapter<Unit, String, IdkError>(
        id = "test.denial.meta",
        interceptorChain = interceptorChain,
    ) {
    override suspend fun doExecute(
        args: Unit,
        applyDuring: (Unit) -> Unit,
    ): IdkResult<String, IdkError> {
        applyDuring(args)
        onExecute()
        return IdkResult.ok("ok")
    }
}
