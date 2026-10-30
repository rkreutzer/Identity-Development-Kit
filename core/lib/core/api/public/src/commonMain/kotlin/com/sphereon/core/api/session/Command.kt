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

import com.sphereon.core.api.HasId
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.context.ContextConfig
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.events.EventSubsystem
import com.sphereon.core.api.events.EventSubsystems
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.core.compat.JsExportCompat
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.withContext
import software.amazon.app.platform.scope.Scope
import software.amazon.app.platform.scope.Scoped
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.TimeSource

fun interface CommandSupports {
    suspend fun supports(args: Any): Boolean
}

@Suppress("UNCHECKED_CAST")
private fun <E : IdkErrorType> defaultCommandErrorMapper(): CommandErrorMapper<E> = IdkErrorTypeCommandErrorMapper as CommandErrorMapper<E>

/**
 * Represents a generic command interface that defines the structure for executing a specific piece of logic.
 *
 * This interface is designed to provide a consistent approach for implementing commands
 * with support for checking argument compatibility and executing the command logic.
 *
 * @param Arg The type of the input argument that the `execute` method expects.
 * @param SuccessResult The type of the result produced by the `execute` method.
 */
fun interface BaseCommand<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType> {
    /**
     * Determines whether the provided arguments are supported by this command.
     *
     * @param args The arguments to check for support. These are on purpose of type Any, so we can pass anything in.
     *   Do not change args type to Arg!
     * @return True if the arguments are supported, false otherwise.
     */
    suspend fun supports(args: Any): Boolean = true

    /**
     * Executes the command using the provided argument and produces a result.
     *
     * @param args The argument required to execute the command.
     * @return The result produced after executing the command.
     */
    suspend fun execute(args: Arg): IdkResult<SuccessResult, ErrorResult>

    /**
     * Extract the success value or return a default.
     */
    fun <SuccessResult : Any, ErrorResult : IdkErrorType> IdkResult<SuccessResult, ErrorResult>.getOrElse(default: SuccessResult): SuccessResult =
        if (isOk) {
            this.value
        } else {
            default
        }

    /**
     * Feed a successful value into the next command.
     */
    suspend fun <Arg : Any, NextSuccess : Any, ErrorResult : IdkErrorType> IdkResult<Arg, ErrorResult>.andThenCommand(
        nextCommand: BaseCommand<Arg, NextSuccess, ErrorResult>,
    ): IdkResult<NextSuccess, ErrorResult> =
        if (this.isOk) {
            nextCommand.execute(this.value)
        } else {
            IdkResult.err<NextSuccess, ErrorResult>(this.error)
        }

    /**
     * Compose two commands into one that runs them in sequence.
     */
    @Suppress("UNCHECKED_CAST")
    fun <FirstArg : Any, FirstSuccessResult : Any, NextSuccessResult : Any, ErrorResult : IdkErrorType> BaseCommand<FirstArg, FirstSuccessResult, ErrorResult>.andThen(
        next: BaseCommand<FirstSuccessResult, NextSuccessResult, ErrorResult>,
        errorMapper: CommandErrorMapper<ErrorResult>,
    ): BaseCommand<FirstArg, NextSuccessResult, ErrorResult> =
        object : BaseCommand<FirstArg, NextSuccessResult, ErrorResult> {
            override suspend fun supports(args: Any): Boolean =
                this@andThen.supports(args) &&
                    ((args as? FirstArg)?.let { next.supports(it) } ?: false)

            override suspend fun execute(args: FirstArg): IdkResult<NextSuccessResult, ErrorResult> {
                val firstResult = this@andThen.execute(args)
                if (!firstResult.isOk) {
                    return IdkResult.err<NextSuccessResult, ErrorResult>(firstResult.error)
                }

                val supportResult = next.supportsOrError(firstResult.value, errorMapper)
                if (supportResult.isErr) {
                    return IdkResult.err(supportResult.error)
                }
                return next.execute(firstResult.value)
            }
        }

    /**
     * Convenience overload for IdkError-based command chains.
     */
    fun <FirstArg : Any, FirstSuccessResult : Any, NextSuccessResult : Any> BaseCommand<FirstArg, FirstSuccessResult, IdkError>.andThen(
        next: BaseCommand<FirstSuccessResult, NextSuccessResult, IdkError>,
    ): BaseCommand<FirstArg, NextSuccessResult, IdkError> = andThen(next = next, errorMapper = IdkErrorCommandErrorMapper)
}

/**
 * Represents a command that is part of a chain of commands, extending the generic `ISureCommand` interface.
 *
 * This interface introduces support for chaining commands by specifying a reference to the next command
 * in the chain and a configuration object that dictates the command's execution behavior within the chain.
 * The fist command in the
 *
 * @param Arg The type of the input argument required for execution.
 * @param Result The type of the result produced by the command upon execution.
 */
@JsExportCompat
interface BaseChainCommand<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType> : BaseCommand<Arg, SuccessResult, ErrorResult> {
    /**
     * Represents the next command in a sequence of commands.
     * This variable holds an optional reference to an `ISureCommand` that
     * can be executed after the current command.
     *
     * @property Arg The type of the argument required by the command.
     * @property Result The type of the result produced by the command.
     */
    val next: BaseCommand<Arg, SuccessResult, ErrorResult>?

    /**
     * Provides the configuration for a chain command.
     *
     * This configuration implements the `IChainCommandConfig` interface and specifies
     * the maximum number of executions allowed for the chain command, with a default
     * value of `1`.
     */
    val config: IChainCommandConfig
        get() =
            object : IChainCommandConfig {
                /**
                 * Represents the maximum number of times the command can be executed.
                 *
                 * If null, the command may be executed an unlimited number of times.
                 * This property is intended to serve as an upper limit configuration for chained command execution.
                 */
                override val maxExecutions: Int?
                    get() = 1
            }
}

/**
 * Represents the configuration details for a chain command, defining the behavior of the
 * command execution flow, particularly the minimum and maximum number of allowed executions
 * for the command.
 */
@JsExportCompat
interface IChainCommandConfig {
    /**
     * Represents the minimum number of times a command in a chain must be executed.
     * It is a required value set to ensure that commands adhere to a baseline execution count.
     * The default value is 1.
     */
    val minExecutions: Int
        get() = 1

    /**
     * The maximum number of times a chain command is allowed to execute.
     * This value is optional and can be null, indicating no specific upper limit.
     */
    val maxExecutions: Int?
}

/**
 * Represents a pipeline command that executes a series of commands in sequence.
 *
 * This interface extends `ISureCommand` by adding support for managing
 * and organizing multiple commands as part of a processing pipeline.
 *
 * The PipeLine command's execute function itself is responsible for executing the delegates/filters in the commands property
 * The implementation itself defines whether it really acts like a pipe and filter design pattern, where outputs from one command are the input of the next command, or whether it acts more like a chain of responsibility (minus the commands themselves creating the chain), where the same input is passed on to the individual commands for processing.
 *
 * @param Arg The type of the input argument that the pipeline expects.
 * @param Result The type of the result produced by the pipeline after executing the commands.
 */
@JsExportCompat
interface BasePipelineCommand<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType> : BaseCommand<Arg, SuccessResult, ErrorResult> {
    /**
     * An array of commands that can be executed as part of a pipeline.
     *
     * Each command in the array implements the ISureCommand interface and can define
     * specific logic to execute and conditions for execution compatibility.
     */
    val commands: MutableList<out BaseCommand<*, *, *>>

    /**
     * Adds a command to the pipeline.
     *
     * @param filter The command to be added. It should implement the ISureCommand interface, and is used as a step in the pipeline.
     * @return The current instance of ISurePipelineCommand with the new command added.
     */
    fun addCommand(filter: BaseCommand<*, *, *>): BasePipelineCommand<Arg, SuccessResult, ErrorResult>

    /**
     * Removes the specified command from the pipeline.
     *
     * @param filter The command to be removed from the pipeline.
     * @return The current pipeline command instance after the specified command has been removed.
     */
    fun removeCommand(filter: BaseCommand<*, *, *>): BasePipelineCommand<Arg, SuccessResult, ErrorResult>

    // The execute function is the process function normally found in a pipeline
}

/**
 * Represents a command interface that provides a mechanism to execute operations
 * using a specific argument and return a result.
 *
 * This interface extends the `ISureCommand` interface, inheriting its core functionality
 * while adding unique properties useful for command-oriented implementations.
 *
 * @param Arg The type of the input argument expected by the command.
 * @param Result The type of the result produced by executing the command.
 */
@JsExportCompat
interface Command<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType> :
    HasId,
    BaseCommand<Arg, SuccessResult, ErrorResult> {
    /**
     * A unique identifier for a command implementing the ISureCommand interface.
     *
     * This identifier is used to distinguish between different commands within the application,
     * enabling consistent identification and referencing within the application.
     *
     */
    override val id: String

    /**
     * Indicates whether the command is currently enabled or not.
     *
     * This property is used to manage the active state of the command, allowing
     * clients to check if operations associated with the command can be executed.
     *
     * A value of `true` denotes that the command is active and can accept operations,
     * while a value of `false` signifies that the command is inactive.
     */
    val isEnabled: Boolean

    /**
     * The subsystem that this command belongs to.
     *
     * Used by the event system to automatically tag events emitted from this command.
     * Commands can override this to provide a more specific subsystem.
     *
     * @see EventSubsystem
     * @see EventSubsystems
     */
    val subsystem: EventSubsystem
        get() = EventSubsystems.CUSTOM
}

/**
 * Represents a chainable command interface that combines the functionality of ISureService and ISureChainCommand.
 *
 * This interface is useful for creating services that implement command execution logic
 * with support for chaining multiple commands together. It extends the capabilities
 * of ISureService and ISureChainCommand, providing features such as enabling/disabling
 * functionality, identifying the command, and specifying chained command configurations.
 *
 * @param Arg The input argument type required for the execution of the commands.
 * @param Result The output result type produced by the commands upon execution.
 */
@JsExportCompat
interface ChainCommand<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType> :
    Command<Arg, SuccessResult, ErrorResult>,
    BaseChainCommand<Arg, SuccessResult, ErrorResult>

/**
 * Represents a command interface that combines the functionalities of a generic command and
 * a pipeline command, allowing for a structured and extensible way to define a pipeline of
 * commands that can be executed in sequence.
 *
 * This interface extends both `ISureService` and `ISurePipelineCommand`, inheriting their
 * properties and behaviors. It can be used to create services that not only execute core
 * logic but also manage and process a sequence of commands in a pipeline.
 *
 * @param Arg The type of the input argument required by the command and commands.
 * @param Result The type of the result produced by the command and commands.
 */
@JsExportCompat
interface PipelineCommand<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType> :
    Command<Arg, SuccessResult, ErrorResult>,
    BasePipelineCommand<Arg, SuccessResult, ErrorResult>

/**
 * Represents a multi-command interface that extends `ISurePipelineService` and provides utility methods
 * to manage and retrieve individual services by their unique identifiers.
 *
 * This interface is part of a broader pipeline-based command architecture and is designed to allow
 * composition of multiple services (`ISureService`) while providing enhanced command management functionalities.
 *
 * @param Arg The type of input the command operates on.
 * @param Result The type of result the command produces.
 */
@JsExportCompat
interface MultiService<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType> : PipelineCommand<Arg, SuccessResult, ErrorResult> {
    /**
     * An array of commands that are part of the multi-command execution pipeline.
     *
     * Each command in the array is an instance of `ISureService` that represents
     * a specific piece of functionality to be executed within the multi-command context.
     * The commands collectively define the steps or stages in the execution flow.
     */
    override val commands: MutableList<Command<Arg, SuccessResult, ErrorResult>>

    fun hasId(id: String): Boolean = getById(id) != null

    /**
     * Retrieves an `ISureService` instance with the specified identifier.
     *
     * This method searches among the available services to find a matching command
     * with the given `id`. If a matching command is found, it is returned; otherwise,
     * null is returned.
     *
     * @param id The identifier of the command to retrieve.
     * @return The `ISureService` instance matching the provided identifier, or null if no match is found.
     */
    fun getById(id: String): Command<Arg, SuccessResult, ErrorResult>?
}

@JsExportCompat
interface ICommandInitExtension<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType> {
    fun beforeInit(service: Command<Arg, SuccessResult, ErrorResult>) {}

    fun afterInit(service: Command<Arg, SuccessResult, ErrorResult>) {}
}

@JsExportCompat
enum class CommandExecutionPhase {
    BEFORE,
    DURING,
    AFTER,
}

@JsExportCompat
interface ICommandExecutionExtension<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType> {
    fun beforeExecute(
        service: Command<Arg, SuccessResult, ErrorResult>,
        args: Arg,
    ) {}

    fun duringExecute(
        service: Command<Arg, SuccessResult, ErrorResult>,
        args: Arg,
    ): Arg = args

    fun afterExecute(
        service: Command<Arg, SuccessResult, ErrorResult>,
        args: Arg,
        result: IdkResult<SuccessResult, ErrorResult>,
    ) {
    }
}

@JsExportCompat
interface ICommandExecutionListener<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType> {
    fun onBeforeExecute(
        serviceId: String,
        args: Arg,
    ) {}

    fun onDuringExecute(
        serviceId: String,
        args: Arg,
    ): Arg = args

    fun onAfterExecute(
        serviceId: String,
        args: Arg,
        result: IdkResult<SuccessResult, ErrorResult>,
    ) {}
}

@JsExportCompat
abstract class MultiCommandAdapter<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType>(
    id: String,
    isEnabled: Boolean,
    initExtensions: Array<ICommandInitExtension<Arg, SuccessResult, ErrorResult>> = emptyArray(),
    executionExtensions: Array<ICommandExecutionExtension<Arg, SuccessResult, ErrorResult>> = emptyArray(),
    commands: MutableList<Command<Arg, SuccessResult, ErrorResult>>,
    errorMapper: CommandErrorMapper<ErrorResult> = defaultCommandErrorMapper(),
) : CommandAdapter<Arg, SuccessResult, ErrorResult>(id, isEnabled, initExtensions, executionExtensions, errorMapper = errorMapper),
    MultiService<Arg, SuccessResult, ErrorResult> {
    override val commands: MutableList<Command<Arg, SuccessResult, ErrorResult>> = commands.filter { it.isEnabled }.toMutableList()

    override fun getById(id: String): Command<Arg, SuccessResult, ErrorResult>? = commands.firstOrNull { it.id == id }

    @Suppress("UNCHECKED_CAST")
    override fun addCommand(filter: BaseCommand<*, *, *>): BasePipelineCommand<Arg, SuccessResult, ErrorResult> = apply { this.commands.add(filter as Command<Arg, SuccessResult, ErrorResult>) }

    @Suppress("UNCHECKED_CAST")
    override fun removeCommand(filter: BaseCommand<*, *, *>): BasePipelineCommand<Arg, SuccessResult, ErrorResult> =
        apply {
            this.commands.remove(filter as Command<Arg, SuccessResult, ErrorResult>)
        }
}

@JsExportCompat
abstract class CommandAdapter<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType>(
    override val id: String,
    /**
     * Command enabled state. Defaults to true (permissive).
     */
    override val isEnabled: Boolean = true,
    initExtensions: Array<ICommandInitExtension<Arg, SuccessResult, ErrorResult>> = emptyArray(),
    private val executionExtensions: Array<ICommandExecutionExtension<Arg, SuccessResult, ErrorResult>> = emptyArray(),
    private val errorMapper: CommandErrorMapper<ErrorResult> = defaultCommandErrorMapper(),
    /**
     * Enhanced execution extensions with suspend support and short-circuit capability.
     * These are processed alongside regular extensions but support async operations
     * and can short-circuit command execution (e.g., for policy enforcement).
     */
    private val enhancedExecutionExtensions: Array<IEnhancedCommandExecutionExtension<Arg, SuccessResult, ErrorResult>> = emptyArray(),
    /**
     * Interceptor chain for cross-cutting concerns (policy, audit, telemetry, etc.).
     *
     * IDK provides [EmptyInterceptorChain] by default, which applies no cross-cutting logic.
     * Downstream layers (EDK/VDX) replace [DefaultInterceptorChainGraph] via DI to inject
     * concrete interceptors for policy enforcement, audit logging, and telemetry.
     */
    private val interceptorChain: CommandLifecycleInterceptorChain = EmptyInterceptorChain,
) : Command<Arg, SuccessResult, ErrorResult> {
    init {
        if (isEnabled) {

            initExtensions.forEach { it.beforeInit(this) }
            doInitialize()
            initExtensions.forEach { it.afterInit(this) }
        }
    }

    protected fun doInitialize() {}

    // The abstract doExecute method receives a lambda to apply "during" callbacks.
    protected abstract suspend fun doExecute(
        args: Arg,
        applyDuring: (Arg) -> Arg,
    ): IdkResult<SuccessResult, ErrorResult>

    protected open fun commandExecutionContext(): CommandExecutionContext =
        CommandExecutionContext(
            commandId = id,
            parsedCommandId = CommandId.tryParse(id),
            subsystem = subsystem?.value,
        )

    @Suppress("UNCHECKED_CAST")
    override suspend fun execute(args: Arg): IdkResult<SuccessResult, ErrorResult> {
        // Return errors instead of throwing exceptions (IdkResult-based error handling)
        if (!isEnabled) {
            return IdkResult.err(
                errorMapper.commandDisabled(commandId = id),
            )
        }

        // Supports checks must not be influenced by caller-provided context.
        if (!supports(args)) {
            return IdkResult.err(
                errorMapper.unsupportedArg(command = this, arg = args),
            )
        }

        // Structural input validation when args implements ValidatableInput.
        if (args is com.sphereon.core.api.service.ValidatableInput) {
            val validationResult = (args as com.sphereon.core.api.service.ValidatableInput).validate()
            if (validationResult.isErr) {
                @Suppress("UNCHECKED_CAST")
                return IdkResult.err(validationResult.error as ErrorResult)
            }
        }

        // Command-level validation for ServiceCommand input.
        if (this is com.sphereon.core.api.service.ServiceCommand<*, *, *>) {
            @Suppress("UNCHECKED_CAST")
            val svc = this as com.sphereon.core.api.service.ServiceCommand<Arg, *, IdkErrorType>
            val ctxValidation = svc.validateInput(args)
            if (ctxValidation.isErr) {
                @Suppress("UNCHECKED_CAST")
                return IdkResult.err(ctxValidation.error as ErrorResult)
            }
        }

        val interceptors = interceptorChain.interceptors.sortedBy { it.order }
        val context = commandExecutionContext()

        val startMark = TimeSource.Monotonic.markNow()
        var commandResult: IdkResult<SuccessResult, ErrorResult>? = null
        var firstDenial: InterceptorVerdict.Deny? = null
        var firstDenialInterceptor: String? = null
        var executionCoroutineContext: CoroutineContext = EmptyCoroutineContext
        var contextSetupCancellation: CancellationException? = null

        // Phase 1: compose the invocation context before entering the lifecycle.
        for (interceptor in interceptors) {
            try {
                executionCoroutineContext += interceptor.executionCoroutineContext(context, args)
            } catch (cancelled: CancellationException) {
                contextSetupCancellation = cancelled
                break
            } catch (expected: Exception) {
                if (firstDenial == null) {
                    firstDenialInterceptor = interceptor.name
                    firstDenial =
                        InterceptorVerdict.Deny(
                            reason = "Interceptor '${interceptor.name}' failed: ${expected.message ?: "unknown error"}",
                            errorCode = CommandErrors.INTERCEPTOR_ERROR_DENIAL_CODE,
                        )
                }
            }
        }

        suspend fun executeBody(): IdkResult<SuccessResult, ErrorResult> {
            val denial = firstDenial
            if (denial != null) {
                val deniedResult: IdkResult<SuccessResult, ErrorResult> =
                    IdkResult.err(
                        errorMapper.notAuthorizedByInterceptor(
                            commandId = CommandId(id),
                            reason = denial.reason,
                            interceptorName = firstDenialInterceptor.orEmpty(),
                            denialCode = denial.errorCode,
                        ),
                    )
                commandResult = deniedResult
                return deniedResult
            }

            // Process enhanced extensions first because they can short-circuit.
            var currentArgs = args
            for (ext in enhancedExecutionExtensions) {
                when (val beforeResult = ext.beforeExecute(this, currentArgs)) {
                    is BeforeExecuteResult.Continue -> {
                        currentArgs = beforeResult.args
                    }

                    is BeforeExecuteResult.Skip -> {
                        val skippedResult: IdkResult<SuccessResult, ErrorResult> =
                            IdkResult.err(
                                errorMapper.commandSkipped(commandId = id),
                            )
                        commandResult = skippedResult
                        return skippedResult
                    }

                    is BeforeExecuteResult.ShortCircuit<*, *> -> {
                        val shortCircuitResult = beforeResult.result as IdkResult<SuccessResult, ErrorResult>
                        // Still call afterExecute for short-circuited results.
                        var finalResult = shortCircuitResult
                        for (afterExt in enhancedExecutionExtensions.reversed()) {
                            finalResult = afterExt.afterExecute(this, args, finalResult)
                        }
                        commandResult = finalResult
                        return finalResult
                    }
                }
            }

            // Process regular synchronous extensions beforeExecute.
            executionExtensions.forEach { it.beforeExecute(this, currentArgs) }

            // Execute the command with during callbacks.
            val result =
                doExecute(currentArgs) { argDuring ->
                    var modified = argDuring
                    // Apply regular extensions during execution.
                    executionExtensions.forEach { modified = it.duringExecute(this, modified) }
                    modified
                }

            // Process regular extensions afterExecute.
            executionExtensions.forEach { it.afterExecute(this, currentArgs, result) }

            // Process enhanced extensions afterExecute in reverse order.
            var finalResult = result
            for (ext in enhancedExecutionExtensions.reversed()) {
                finalResult = ext.afterExecute(this, args, finalResult)
            }

            commandResult = finalResult
            return finalResult
        }

        val parentInvocation = currentCoroutineContext()[CommandInvocationContext]
        val commandInvocation = CommandInvocationContext.enteredFrom(parentInvocation)
        return withContext(executionCoroutineContext + commandInvocation) {
            var lifecycleFailure: Throwable? = null
            var lifecycleResult: IdkResult<SuccessResult, ErrorResult>? = null
            try {
                val setupCancellation = contextSetupCancellation
                if (setupCancellation != null) {
                    throw setupCancellation
                }

                // Phase 2: run all before hooks in the invocation context.
                for (interceptor in interceptors) {
                    var verdict: InterceptorVerdict? = null
                    var beforeFailure: Throwable? = null
                    try {
                        verdict = interceptor.beforeExecute(context, args)
                    } catch (failure: Throwable) {
                        beforeFailure = failure
                    }
                    val failure = beforeFailure
                    if (failure is CancellationException || (failure != null && failure !is Exception)) {
                        throw failure
                    }
                    if (failure is Exception) {
                        // Interceptor errors fail closed to prevent silent policy bypass.
                        if (firstDenial == null) {
                            firstDenialInterceptor = interceptor.name
                            firstDenial =
                                InterceptorVerdict.Deny(
                                    reason = "Interceptor '${interceptor.name}' failed: ${failure.message ?: "unknown error"}",
                                    errorCode = CommandErrors.INTERCEPTOR_ERROR_DENIAL_CODE,
                                )
                        }
                    } else if (verdict is InterceptorVerdict.Deny && firstDenial == null) {
                        firstDenialInterceptor = interceptor.name
                        firstDenial = verdict
                    }
                }

                lifecycleResult = executeBody()
            } catch (failure: Throwable) {
                lifecycleFailure = failure
            }

            // Phase 3: attempt every after hook in reverse order.
            val durationMs = startMark.elapsedNow().inWholeMilliseconds.coerceAtLeast(0L)
            var afterCancellation: CancellationException? = null
            for (interceptor in interceptors.asReversed()) {
                var afterFailure: Throwable? = null
                try {
                    interceptor.afterExecute(
                        context = context,
                        args = args,
                        result = commandResult as? IdkResult<Any, IdkErrorType>,
                        denied = firstDenial,
                        durationMs = durationMs,
                    )
                } catch (failure: Throwable) {
                    afterFailure = failure
                }
                val failure = afterFailure
                when {
                    failure is CancellationException && afterCancellation == null -> {
                        afterCancellation = failure
                    }

                    failure != null && failure !is Exception -> throw failure
                    else -> {
                        // Ordinary observational failures do not replace the command result.
                    }
                }
            }

            val originalFailure = lifecycleFailure
            if (originalFailure != null) {
                throw originalFailure
            }
            val observationalCancellation = afterCancellation
            if (observationalCancellation != null) {
                throw observationalCancellation
            }
            requireNotNull(lifecycleResult) { "Command lifecycle produced no result" }
        }
    }
}

@JsExportCompat
abstract class ExecutionScopedAdapter<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType>(
    override val id: String,
    /**
     * Command enabled state. Defaults to true (permissive).
     */
    override val isEnabled: Boolean = true,
    initExtensions: Array<ICommandInitExtension<Arg, SuccessResult, ErrorResult>> = emptyArray(),
    executionExtensions: Array<ICommandExecutionExtension<Arg, SuccessResult, ErrorResult>> = emptyArray(),
    protected val execution: SessionExecution,
    protected val log: SessionLogService = execution.log,
    protected val conf: ContextConfig = execution.conf,
    errorMapper: CommandErrorMapper<ErrorResult> = defaultCommandErrorMapper(),
    /**
     * Enhanced execution extensions with suspend support and short-circuit capability.
     * These are processed alongside regular extensions but support async operations
     * and can short-circuit command execution (e.g., for policy enforcement).
     */
    enhancedExecutionExtensions: Array<IEnhancedCommandExecutionExtension<Arg, SuccessResult, ErrorResult>> = emptyArray(),
) : CommandAdapter<Arg, SuccessResult, ErrorResult>(
        id = id,
        isEnabled = isEnabled,
        initExtensions = initExtensions,
        executionExtensions = executionExtensions,
        errorMapper = errorMapper,
        enhancedExecutionExtensions = enhancedExecutionExtensions,
        interceptorChain = execution.interceptorChain,
    ),
    Scoped {
    override suspend fun execute(args: Arg): IdkResult<SuccessResult, ErrorResult> = super.execute(args)

    override fun commandExecutionContext(): CommandExecutionContext =
        CommandExecutionContext(
            commandId = id,
            parsedCommandId = CommandId.tryParse(id),
            subsystem = subsystem?.value,
            tenantId = execution.tenantId,
            principalId = execution.principalId,
            correlationId = execution.correlationId,
        )

    /**
     * This is a little trick to have any subclasses that implement scoped use this function. This class also implements scoped, but
     * will not be triggered, as we construct this class manually from the subclass
     *
     * Whenever a subclass implements scoped it can override this method. If nothing is done it will be auto registered as session in the session scope.
     */
    override fun onEnterScope(scope: Scope) {
        val activeSession = execution.sessionContextManager.getActive()
        activeSession.addService(this.id, this)
    }
    /*
    init {
        execution.getSessionContextManager().addService(id, this)
    }*/
}

/**
 * Session-scoped adapter for executable commands.
 *
 * Unlike non-command session adapters, every instance must carry a canonical
 * [CommandId]. Validation happens while the superclass arguments are evaluated,
 * before the adapter can be initialized or registered in a session scope.
 */
@JsExportCompat
abstract class ExecutionScopedCommandAdapter<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType>(
    id: String,
    isEnabled: Boolean = true,
    initExtensions: Array<ICommandInitExtension<Arg, SuccessResult, ErrorResult>> = emptyArray(),
    executionExtensions: Array<ICommandExecutionExtension<Arg, SuccessResult, ErrorResult>> = emptyArray(),
    execution: SessionExecution,
    log: SessionLogService = execution.log,
    conf: ContextConfig = execution.conf,
    errorMapper: CommandErrorMapper<ErrorResult> = defaultCommandErrorMapper(),
    enhancedExecutionExtensions: Array<IEnhancedCommandExecutionExtension<Arg, SuccessResult, ErrorResult>> = emptyArray(),
) : ExecutionScopedAdapter<Arg, SuccessResult, ErrorResult>(
        id = CommandId(id).value,
        isEnabled = isEnabled,
        initExtensions = initExtensions,
        executionExtensions = executionExtensions,
        execution = execution,
        log = log,
        conf = conf,
        errorMapper = errorMapper,
        enhancedExecutionExtensions = enhancedExecutionExtensions,
    )
