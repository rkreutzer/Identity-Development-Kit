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
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * A hook that runs before a command enters its lifecycle (an execution guard) must be able to see the
 * invocation context that command will run in, so it applies the same root and boundary rules as the
 * lifecycle interceptors.
 */
class CommandInvocationContextEntryTest {
    @Test
    fun enteredFromMatchesTheContextTheCommandRunsIn() = runTest {
        val parents: List<CommandInvocationContext?> =
            listOf(
                null,
                CommandInvocationContext.externalBoundary(),
                CommandInvocationContext.externalCommand(),
            )
        for (parent in parents) {
            val predicted = CommandInvocationContext.enteredFrom(parent)
            val observed =
                if (parent == null) observedInvocation() else withContext(parent) { observedInvocation() }
            assertEquals(observed.boundary, predicted.boundary, "boundary for parent $parent")
            assertEquals(observed.commandDepth, predicted.commandDepth, "depth for parent $parent")
        }
    }

    @Test
    fun externalBoundaryEntersTheDispatchedCommandAsAnExternalRoot() {
        val entered = CommandInvocationContext.enteredFrom(CommandInvocationContext.externalBoundary())
        assertEquals(CommandInvocationBoundary.EXTERNAL, entered.boundary)
        assertEquals(true, entered.isRootCommand)
    }

    @Test
    fun commandsInvokedByTheDispatchedCommandAreNotRoots() {
        val nested =
            CommandInvocationContext.enteredFrom(
                CommandInvocationContext.enteredFrom(CommandInvocationContext.externalBoundary()),
            )
        assertEquals(CommandInvocationBoundary.EXTERNAL, nested.boundary)
        assertEquals(false, nested.isRootCommand)
    }

    private suspend fun observedInvocation(): CommandInvocationContext {
        var seen: CommandInvocationContext? = null
        val interceptor =
            object : CommandLifecycleInterceptor {
                override val name: String = "invocation-probe"

                override suspend fun beforeExecute(
                    context: CommandExecutionContext,
                    args: Any,
                ): InterceptorVerdict {
                    seen = currentCoroutineContext()[CommandInvocationContext]
                    return InterceptorVerdict.Continue
                }
            }
        ProbeCommand(
            object : CommandLifecycleInterceptorChain {
                override val interceptors: List<CommandLifecycleInterceptor> = listOf(interceptor)
            },
        ).execute(Unit)
        return assertNotNull(seen)
    }
}

private class ProbeCommand(
    interceptorChain: CommandLifecycleInterceptorChain,
) : CommandAdapter<Unit, String, IdkError>(
        id = "test.invocation.probe",
        interceptorChain = interceptorChain,
    ) {
    override suspend fun doExecute(
        args: Unit,
        applyDuring: (Unit) -> Unit,
    ): IdkResult<String, IdkError> = IdkResult.ok("ok")
}
