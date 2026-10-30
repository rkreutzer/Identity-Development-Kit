/*
 * Copyright (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sphereon.core.events.impl

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.events.EventCategories
import com.sphereon.core.api.events.EventTypes
import com.sphereon.core.api.session.BeforeExecuteResult
import com.sphereon.core.api.session.Command
import com.sphereon.core.api.session.IEnhancedCommandExecutionExtension
import com.sphereon.core.events.CommandEventConfig
import com.sphereon.core.events.EncryptedPart
import com.sphereon.core.events.Event
import com.sphereon.core.events.SessionEventService
import com.sphereon.core.events.SilentCommand
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.time.Clock
import kotlin.time.Instant

/**
 * Command execution extension that emits lifecycle events for commands.
 *
 * This extension automatically emits events when commands:
 * - Start execution (COMMAND_STARTED)
 * - Complete successfully (COMMAND_COMPLETED)
 * - Fail with an error (COMMAND_FAILED)
 *
 * ## Silent Commands
 *
 * Commands implementing [SilentCommand] are skipped to prevent
 * infinite loops (e.g., StoreEventCommand emitting events about itself).
 *
 * ## Configuration
 *
 * Use [CommandEventConfig] to:
 * - Enable/disable event emission globally
 * - Include/exclude commands by pattern
 * - Override behavior for specific commands
 * - Configure signing and encryption
 *
 * ## Usage
 *
 * Register this extension with commands:
 *
 * ```kotlin
 * class MyCommandImpl(
 *     execution: SessionExecution,
 *     eventExtension: EventCommandExtension<*, *, *>
 * ) : ExecutionScopedCommandAdapter<Args, Result, IdkError>(
 *     id = "my.command",
 *     execution = execution,
 *     executionExtensions = arrayOf(eventExtension)
 * )
 * ```
 *
 * @see SilentCommand for commands that should not emit events
 * @see CommandEventConfig for configuration options
 */
class EventCommandExtension<Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType>(
    private val eventServiceProvider: () -> SessionEventService,
    private val config: CommandEventConfig = CommandEventConfig.DEFAULT,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
) : IEnhancedCommandExecutionExtension<Arg, SuccessResult, ErrorResult> {
    // Track start time for duration calculation
    private val startTimes = mutableMapOf<String, Instant>()

    override suspend fun beforeExecute(
        service: Command<Arg, SuccessResult, ErrorResult>,
        args: Arg,
    ): BeforeExecuteResult<Arg, SuccessResult, ErrorResult> {
        // Skip silent commands (event system commands)
        if (service is SilentCommand<*, *, *>) {
            return BeforeExecuteResult.Continue(args)
        }

        // Skip if not configured to emit for this command
        if (!config.shouldEmitStart(service.id)) {
            return BeforeExecuteResult.Continue(args)
        }

        // Record start time
        startTimes[service.id] = Clock.System.now()

        // Emit started event (fire-and-forget in background)
        scope.launch {
            val eventService = eventServiceProvider()
            val event =
                eventService
                    .eventBuilder()
                    .type(EventTypes.COMMAND_STARTED)
                    .origin(service.id)
                    .subsystem(service.subsystem)
                    .category(EventCategories.LIFECYCLE)
                    .payload(buildStartPayload(service, args))
                    .build()

            emitEvent(eventService, event)
        }

        return BeforeExecuteResult.Continue(args)
    }

    override suspend fun afterExecute(
        service: Command<Arg, SuccessResult, ErrorResult>,
        args: Arg,
        result: IdkResult<SuccessResult, ErrorResult>,
    ): IdkResult<SuccessResult, ErrorResult> {
        // Skip silent commands (event system commands)
        if (service is SilentCommand<*, *, *>) {
            return result
        }

        // Calculate duration
        val startTime = startTimes.remove(service.id)
        val durationMs =
            if (startTime != null) {
                Clock.System.now().toEpochMilliseconds() - startTime.toEpochMilliseconds()
            } else {
                0L
            }

        // Determine event type based on result
        val (eventType, shouldEmit) =
            if (result.isOk) {
                EventTypes.COMMAND_COMPLETED to config.shouldEmitSuccess(service.id)
            } else {
                EventTypes.COMMAND_FAILED to config.shouldEmitFailure(service.id)
            }

        if (!shouldEmit) {
            return result
        }

        // Emit completion event (fire-and-forget in background)
        scope.launch {
            val eventService = eventServiceProvider()
            val event =
                eventService
                    .eventBuilder()
                    .type(eventType)
                    .origin(service.id)
                    .subsystem(service.subsystem)
                    .category(
                        if (result.isOk) {
                            EventCategories.LIFECYCLE
                        } else {
                            EventCategories.ERROR
                        }
                    ).payload(buildCompletionPayload(service, result, durationMs))
                    .build()

            emitEvent(eventService, event)
        }

        return result
    }

    private suspend fun emitEvent(
        eventService: SessionEventService,
        event: Event,
    ) {
        val encryptParts =
            if (config.encryptPayload) {
                setOf(EncryptedPart.PAYLOAD)
            } else {
                emptySet()
            }

        eventService.emit(
            event = event,
            sign = config.signEvents,
            encrypt = config.encryptPayload,
            keyAlias = config.signingKeyAlias,
            encryptionKeyAlias = config.encryptionKeyAlias,
            encryptParts = encryptParts,
        )
    }

    private fun buildStartPayload(
        service: Command<Arg, SuccessResult, ErrorResult>,
        args: Arg,
    ): JsonObject =
        buildJsonObject {
            put("commandId", service.id)
            put("isEnabled", service.isEnabled)
            // Note: We don't serialize args to avoid exposing sensitive data
            // and to keep payload sizes reasonable
        }

    private fun buildCompletionPayload(
        service: Command<Arg, SuccessResult, ErrorResult>,
        result: IdkResult<SuccessResult, ErrorResult>,
        durationMs: Long,
    ): JsonObject =
        buildJsonObject {
            put("commandId", service.id)
            put("durationMs", durationMs)
            put("success", result.isOk)

            if (!result.isOk) {
                // Include error code/type but not full message (may be sensitive)
                val error = result.error
                if (error is IdkErrorType) {
                    // We can't easily serialize the error here without more context
                    put("errorType", error::class.simpleName ?: "Unknown")
                }
            }
        }

    companion object {
        /**
         * Create an extension with default configuration.
         */
        fun <Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType> create(
            eventServiceProvider: () -> SessionEventService,
            scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
        ): EventCommandExtension<Arg, SuccessResult, ErrorResult> = EventCommandExtension(eventServiceProvider, scope = scope)

        /**
         * Create an extension with custom configuration.
         */
        fun <Arg : Any, SuccessResult : Any, ErrorResult : IdkErrorType> create(
            eventServiceProvider: () -> SessionEventService,
            config: CommandEventConfig,
            scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
        ): EventCommandExtension<Arg, SuccessResult, ErrorResult> = EventCommandExtension(eventServiceProvider, config, scope)
    }
}
