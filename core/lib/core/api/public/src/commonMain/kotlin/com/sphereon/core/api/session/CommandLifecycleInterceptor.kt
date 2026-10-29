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
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Provides
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.EmptyCoroutineContext

private const val DEFAULT_INTERCEPTOR_ORDER = 100

/** Identifies whether the current command tree began at a transport boundary or in-process. */
enum class CommandInvocationBoundary {
    EXTERNAL,
    INTERNAL,
}

/**
 * Typed coroutine-owned command nesting state.
 *
 * External HTTP/gRPC adapters install [externalBoundary] before dispatch. [CommandAdapter]
 * replaces that marker with depth zero for the first service command and increments the depth for
 * every command invoked from its coroutine. A new external boundary resets the depth. This keeps
 * lifecycle policy request-local without a thread local or process-wide mutable registry.
 */
class CommandInvocationContext private constructor(
    val boundary: CommandInvocationBoundary,
    val commandDepth: Int,
) : AbstractCoroutineContextElement(Key) {
    init {
        require(commandDepth >= BOUNDARY_MARKER_DEPTH) { "Command invocation depth is invalid" }
    }

    val isRootCommand: Boolean get() = commandDepth == 0

    internal fun enterCommand(): CommandInvocationContext =
        CommandInvocationContext(
            boundary = boundary,
            commandDepth = commandDepth + 1,
        )

    companion object Key : CoroutineContext.Key<CommandInvocationContext> {
        private const val BOUNDARY_MARKER_DEPTH: Int = -1

        /** Installs a fresh external service boundary; the first command enters at depth zero. */
        fun externalBoundary(): CommandInvocationContext =
            CommandInvocationContext(
                boundary = CommandInvocationBoundary.EXTERNAL,
                commandDepth = BOUNDARY_MARKER_DEPTH,
            )

        /**
         * Marks execution already owned by an external streaming command whose API does not use
         * [CommandAdapter]. Regular commands invoked while collecting that stream enter at depth
         * one and are therefore treated as internal invocations.
         */
        fun externalCommand(): CommandInvocationContext =
            CommandInvocationContext(
                boundary = CommandInvocationBoundary.EXTERNAL,
                commandDepth = 0,
            )

        internal fun internalRoot(): CommandInvocationContext =
            CommandInvocationContext(
                boundary = CommandInvocationBoundary.INTERNAL,
                commandDepth = 0,
            )

        /**
         * The context a command entered from [parent] runs in: one level below [parent], or an
         * internal root when no invocation is active. Hooks that run before a command enters its
         * lifecycle use this to apply the same root and boundary rules as lifecycle interceptors.
         */
        fun enteredFrom(parent: CommandInvocationContext?): CommandInvocationContext =
            parent?.enterCommand() ?: internalRoot()
    }
}

/**
 * Context passed to interceptors during command lifecycle.
 *
 * @property commandId The hierarchical command ID (e.g., "did.manager.resolve")
 * @property parsedCommandId Parsed CommandId, or null if not a valid 3-segment ID
 * @property subsystem The event subsystem this command belongs to
 * @property tenantId The tenant associated with the active command execution, if available
 * @property principalId The principal associated with the active command execution, if available
 * @property correlationId The correlation identifier associated with the active command execution, if available
 */
@JsExportCompat
data class CommandExecutionContext(
    val commandId: String,
    val parsedCommandId: CommandId?,
    val subsystem: String?,
    val tenantId: String? = null,
    val principalId: String? = null,
    val correlationId: String? = null,
)

/**
 * Verdict returned by [CommandLifecycleInterceptor.beforeExecute].
 *
 * Interceptors return [Continue] to allow execution or [Deny] to prevent it.
 * All interceptors in the chain are always called regardless of denials --
 * this allows audit interceptors to always emit STARTED events.
 */
@JsExportCompat
sealed class InterceptorVerdict {
    data object Continue : InterceptorVerdict()

    data class Deny(
        val reason: String,
        val errorCode: String = "INTERCEPTOR_DENIED",
    ) : InterceptorVerdict()
}

/**
 * Generic lifecycle hook for cross-cutting concerns around command execution.
 *
 * IDK defines only this generic interface. Concrete interceptors for policy,
 * audit, telemetry, etc. are provided by downstream layers via DI replacement
 * of [DefaultInterceptorChainGraph].
 *
 * Interceptors are called in [order] ascending for [beforeExecute] and
 * descending for [afterExecute].
 */
@JsExportCompat
interface CommandLifecycleInterceptor {
    val name: String
    val order: Int get() = DEFAULT_INTERCEPTOR_ORDER

    /**
     * Called before command execution.
     *
     * Return [InterceptorVerdict.Continue] to allow execution or
     * [InterceptorVerdict.Deny] to prevent it. All interceptors are still
     * called even if a prior interceptor denied -- this lets downstream
     * interceptors (e.g., audit) observe the denial.
     */
    suspend fun beforeExecute(
        context: CommandExecutionContext,
        args: Any,
    ): InterceptorVerdict = InterceptorVerdict.Continue

    /**
     * Contributes execution-local coroutine context that remains active for the
     * command body and the matching [afterExecute] callbacks.
     *
     * Implementations must not retain thread-local scopes in [beforeExecute];
     * use a [kotlinx.coroutines.ThreadContextElement] here instead.
     */
    fun executionCoroutineContext(
        context: CommandExecutionContext,
        args: Any,
    ): CoroutineContext = EmptyCoroutineContext

    /**
     * Called after command execution (or denial). Always runs, even on exceptions.
     *
     * @param context The command execution context
     * @param args The original command arguments
     * @param result The command result, or null if execution was skipped/threw
     * @param denied The first denial verdict if any interceptor denied, or null
     * @param durationMs Monotonic elapsed duration in milliseconds
     */
    suspend fun afterExecute(
        context: CommandExecutionContext,
        args: Any,
        result: IdkResult<Any, IdkErrorType>?,
        denied: InterceptorVerdict.Deny?,
        durationMs: Long,
    ) {
    }
}

/**
 * Ordered chain of [CommandLifecycleInterceptor] instances.
 *
 * IDK provides [EmptyInterceptorChain] by default via [DefaultInterceptorChainGraph].
 * Downstream layers replace this with a chain containing concrete interceptors.
 */
@JsExportCompat
interface CommandLifecycleInterceptorChain {
    val interceptors: List<CommandLifecycleInterceptor>
}

/**
 * Empty interceptor chain for IDK standalone usage.
 * No cross-cutting concerns are applied.
 */
object EmptyInterceptorChain : CommandLifecycleInterceptorChain {
    override val interceptors: List<CommandLifecycleInterceptor> = emptyList()
}

/**
 * Default DI binding for [CommandLifecycleInterceptorChain] in IDK.
 *
 * Provides [EmptyInterceptorChain] which applies no cross-cutting concerns.
 * Downstream layers replace this graph to inject real interceptors:
 * ```kotlin
 * @ContributesTo(SessionScope::class, replaces = [DefaultInterceptorChainGraph::class])
 * interface MyInterceptorChainGraph {
 *     @Provides
 *     fun provideInterceptorChain(...): CommandLifecycleInterceptorChain = ...
 * }
 * ```
 */
@ContributesTo(SessionScope::class)
interface DefaultInterceptorChainGraph {
    @Provides
    fun provideInterceptorChain(): CommandLifecycleInterceptorChain = EmptyInterceptorChain
}
