/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.client.rest

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.HttpAdapter
import com.sphereon.core.api.http.command.CommandBackedHttpAdapter
import com.sphereon.core.api.http.command.HttpEndpointCommandRegistry
import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.core.api.http.command.HttpEndpointCommandAdapter
import com.sphereon.core.api.http.command.TenantPathPolicy
import com.sphereon.core.api.http.command.headerIgnoreCase
import com.sphereon.core.api.http.command.optionalIntQueryParam
import com.sphereon.core.api.http.command.requireJsonBody
import com.sphereon.core.api.http.command.requirePathParam
import com.sphereon.core.api.http.describe.HttpAdapterDescription
import com.sphereon.core.api.http.describe.HttpAdapterDescriptorProvider
import com.sphereon.core.api.http.describe.HttpAdapterMount
import com.sphereon.core.api.http.describe.HttpEndpointDescriptor
import com.sphereon.core.api.http.describe.HttpMethod
import com.sphereon.core.api.http.describe.MediaType
import com.sphereon.core.api.http.describe.OpenApiHints
import com.sphereon.di.session.SessionScope
import com.sphereon.wallet.interaction.CancelWalletInteractionArgs
import com.sphereon.wallet.interaction.ConsumeWalletInteractionAuthorizationHandoffCommand
import com.sphereon.wallet.interaction.ConsumeWalletInteractionCompletionHandoffCommand
import com.sphereon.wallet.interaction.ConsumeWalletInteractionHandoffArgs
import com.sphereon.wallet.interaction.ConsumeWalletInteractionHandoffRequest
import com.sphereon.wallet.interaction.ConsumeWalletInteractionHandoffResult
import com.sphereon.wallet.interaction.CancelWalletInteractionCommand
import com.sphereon.wallet.interaction.CancelWalletInteractionResult
import com.sphereon.wallet.interaction.DispatchWalletInteractionActionBody
import com.sphereon.wallet.interaction.GetWalletInteractionEventsArgs
import com.sphereon.wallet.interaction.GetWalletInteractionEventsCommand
import com.sphereon.wallet.interaction.GetWalletInteractionStateArgs
import com.sphereon.wallet.interaction.GetWalletInteractionStateCommand
import com.sphereon.wallet.interaction.ListWalletInteractionActivityArgs
import com.sphereon.wallet.interaction.ListWalletInteractionActivityCommand
import com.sphereon.wallet.interaction.ListWalletInteractionActivityResult
import com.sphereon.wallet.interaction.ListWalletInteractionTasksArgs
import com.sphereon.wallet.interaction.ListWalletInteractionTasksCommand
import com.sphereon.wallet.interaction.ListWalletInteractionTasksResult
import com.sphereon.wallet.interaction.RegisterWalletInteractionSensitiveInputArgs
import com.sphereon.wallet.interaction.RegisterWalletInteractionSensitiveInputCommand
import com.sphereon.wallet.interaction.RegisterWalletInteractionSensitiveInputRequest
import com.sphereon.wallet.interaction.RegisterWalletInteractionSensitiveInputResult
import com.sphereon.wallet.interaction.ResumeWalletInteractionArgs
import com.sphereon.wallet.interaction.ResumeWalletInteractionCommand
import com.sphereon.wallet.interaction.StartWalletInteractionBody
import com.sphereon.wallet.interaction.StartWalletInteractionCommand
import com.sphereon.wallet.interaction.SubmitWalletInteractionActionArgs
import com.sphereon.wallet.interaction.SubmitWalletInteractionActionCommand
import com.sphereon.wallet.interaction.WalletInteractionApiConstants
import com.sphereon.wallet.interaction.WalletInteractionClientFrame
import com.sphereon.wallet.interaction.WalletInteractionClientFrameType
import com.sphereon.wallet.interaction.WalletInteractionFailureCodes
import com.sphereon.wallet.interaction.WalletInteractionRevisionConflict
import com.sphereon.wallet.interaction.WalletInteractionServerFrame
import com.sphereon.wallet.interaction.WalletInteractionServerFrameType
import com.sphereon.wallet.interaction.WalletInteractionSessionEnvelope
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletInteractionStateEnvelope
import com.sphereon.wallet.interaction.WalletInteractionStateEvent
import com.sphereon.wallet.interaction.classifiedWalletInteractionError
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesIntoMap
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.StringKey
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.KSerializer
import kotlinx.serialization.json.Json

private const val PARAM_WALLET_UNIT_ID = "walletUnitId"
private const val PARAM_SESSION_ID = "sessionId"
private const val PARAM_AFTER_SEQUENCE = "afterSequence"
private const val PARAM_LIMIT = "limit"
private const val ACTIVITY_LIMIT_MIN = 1
private const val ACTIVITY_LIMIT_MAX = 500
private const val WALLET_INTERACTION_TAG = "wallet-interaction"

/** Answer to a conditional dispatch the session has already moved past. Nothing was applied. */
private const val HTTP_CONFLICT = 409
private val JSON_MEDIA = setOf(MediaType.ApplicationJson)
private val SSE_MEDIA = setOf(MediaType.Custom("text/event-stream"))
private val JSON_HEADERS = mapOf("Content-Type" to "application/json")
private val SSE_HEADERS =
    mapOf(
        "Content-Type" to "text/event-stream",
        "Cache-Control" to "no-cache",
        "Connection" to "keep-alive",
    )

interface StartWalletInteractionHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = WalletInteractionApiConstants.EndpointCommands.START
        val ENDPOINT: HttpEndpointDescriptor =
            walletInteractionEndpoint(
                method = HttpMethod.POST,
                pathPattern = WalletInteractionApiConstants.Paths.INTERACTIONS,
                consumes = JSON_MEDIA,
                produces = JSON_MEDIA,
                operationId = "startWalletInteraction",
                commandId = COMMAND_ID,
            )
    }
}

interface ResumeWalletInteractionHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = WalletInteractionApiConstants.EndpointCommands.RESUME
        val ENDPOINT: HttpEndpointDescriptor =
            walletInteractionEndpoint(
                method = HttpMethod.POST,
                pathPattern = WalletInteractionApiConstants.Paths.RESUME,
                produces = JSON_MEDIA,
                operationId = "resumeWalletInteraction",
                commandId = COMMAND_ID,
            )
    }
}

interface DispatchWalletInteractionActionHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = WalletInteractionApiConstants.EndpointCommands.DISPATCH_ACTION
        val ENDPOINT: HttpEndpointDescriptor =
            walletInteractionEndpoint(
                method = HttpMethod.POST,
                pathPattern = WalletInteractionApiConstants.Paths.ACTIONS,
                consumes = JSON_MEDIA,
                produces = JSON_MEDIA,
                operationId = "dispatchWalletInteractionAction",
                commandId = COMMAND_ID,
            )
    }
}

interface CancelWalletInteractionHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = WalletInteractionApiConstants.EndpointCommands.CANCEL
        val ENDPOINT: HttpEndpointDescriptor =
            walletInteractionEndpoint(
                method = HttpMethod.DELETE,
                pathPattern = WalletInteractionApiConstants.Paths.INTERACTION,
                produces = JSON_MEDIA,
                operationId = "cancelWalletInteraction",
                commandId = COMMAND_ID,
            )
    }
}

interface GetWalletInteractionStateHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = WalletInteractionApiConstants.EndpointCommands.GET_STATE
        val ENDPOINT: HttpEndpointDescriptor =
            walletInteractionEndpoint(
                method = HttpMethod.GET,
                pathPattern = WalletInteractionApiConstants.Paths.STATE,
                produces = JSON_MEDIA,
                operationId = "getWalletInteractionState",
                commandId = COMMAND_ID,
            )
    }
}

interface GetWalletInteractionEventsHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = WalletInteractionApiConstants.EndpointCommands.GET_EVENTS
        val ENDPOINT: HttpEndpointDescriptor =
            walletInteractionEndpoint(
                method = HttpMethod.GET,
                pathPattern = WalletInteractionApiConstants.Paths.EVENTS,
                produces = SSE_MEDIA,
                operationId = "getWalletInteractionEvents",
                commandId = COMMAND_ID,
            )
    }
}

interface HandleWalletInteractionFrameHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = WalletInteractionApiConstants.EndpointCommands.FRAME
        val ENDPOINT: HttpEndpointDescriptor =
            walletInteractionEndpoint(
                method = HttpMethod.POST,
                pathPattern = WalletInteractionApiConstants.Paths.FRAMES,
                consumes = JSON_MEDIA,
                produces = JSON_MEDIA,
                operationId = "handleWalletInteractionFrame",
                commandId = WalletInteractionApiConstants.Commands.FRAME,
                handlerCommandId = COMMAND_ID,
            )
    }
}

interface ConsumeWalletInteractionAuthorizationHandoffHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = WalletInteractionApiConstants.EndpointCommands.CONSUME_AUTHORIZATION_HANDOFF
        val ENDPOINT: HttpEndpointDescriptor =
            walletInteractionEndpoint(
                method = HttpMethod.POST,
                pathPattern = WalletInteractionApiConstants.Paths.AUTHORIZATION_HANDOFF,
                consumes = JSON_MEDIA,
                produces = JSON_MEDIA,
                operationId = "consumeWalletInteractionAuthorizationHandoff",
                commandId = WalletInteractionApiConstants.Commands.CONSUME_AUTHORIZATION_HANDOFF,
                handlerCommandId = COMMAND_ID,
            )
    }
}

interface ConsumeWalletInteractionCompletionHandoffHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = WalletInteractionApiConstants.EndpointCommands.CONSUME_COMPLETION_HANDOFF
        val ENDPOINT: HttpEndpointDescriptor =
            walletInteractionEndpoint(
                method = HttpMethod.POST,
                pathPattern = WalletInteractionApiConstants.Paths.COMPLETION_HANDOFF,
                consumes = JSON_MEDIA,
                produces = JSON_MEDIA,
                operationId = "consumeWalletInteractionCompletionHandoff",
                commandId = WalletInteractionApiConstants.Commands.CONSUME_COMPLETION_HANDOFF,
                handlerCommandId = COMMAND_ID,
            )
    }
}

interface RegisterWalletInteractionSensitiveInputHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = WalletInteractionApiConstants.EndpointCommands.REGISTER_SENSITIVE_INPUT
        val ENDPOINT: HttpEndpointDescriptor =
            walletInteractionEndpoint(
                method = HttpMethod.POST,
                pathPattern = WalletInteractionApiConstants.Paths.SENSITIVE_INPUTS,
                consumes = JSON_MEDIA,
                produces = JSON_MEDIA,
                operationId = "registerWalletInteractionSensitiveInput",
                commandId = WalletInteractionApiConstants.Commands.REGISTER_SENSITIVE_INPUT,
                handlerCommandId = COMMAND_ID,
            )
    }
}

interface ListWalletInteractionActivityHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = WalletInteractionApiConstants.EndpointCommands.LIST_ACTIVITY
        val ENDPOINT: HttpEndpointDescriptor =
            walletInteractionEndpoint(
                method = HttpMethod.GET,
                pathPattern = WalletInteractionApiConstants.Paths.ACTIVITY,
                produces = JSON_MEDIA,
                operationId = "listWalletInteractionActivity",
                commandId = WalletInteractionApiConstants.Commands.LIST_ACTIVITY,
                handlerCommandId = COMMAND_ID,
            )
    }
}

interface ListWalletInteractionTasksHttpEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID: String = WalletInteractionApiConstants.EndpointCommands.LIST_TASKS
        val ENDPOINT: HttpEndpointDescriptor =
            walletInteractionEndpoint(
                method = HttpMethod.GET,
                pathPattern = WalletInteractionApiConstants.Paths.TASKS,
                produces = JSON_MEDIA,
                operationId = "listWalletInteractionTasks",
                commandId = WalletInteractionApiConstants.Commands.LIST_TASKS,
                handlerCommandId = COMMAND_ID,
            )
    }
}

/**
 * Public REST adapter for wallet interaction sessions.
 *
 * This adapter exposes request/response HTTP resources and bounded event replay.
 * It does not provide the internal routed command transport; live event streams
 * remain available through the neutral server-streaming command.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpAdapter>())
@StringKey(WalletInteractionHttpAdapter.ADAPTER_ID)
class WalletInteractionHttpAdapter(
    execution: SessionExecution,
    endpointCommandRegistry: HttpEndpointCommandRegistry,
) : CommandBackedHttpAdapter(
        id = ADAPTER_ID,
        execution = execution,
        endpointCommandRegistry = endpointCommandRegistry,
        mount = HttpAdapterMount(serverPrefix = "", adapterBasePath = BASE_PATH),
        tenantPathPolicy = TenantPathPolicy.None,
    ) {

    companion object {
        const val ADAPTER_ID: String = "wallet.interaction.http"
        const val BASE_PATH: String = WalletInteractionApiConstants.BASE_PATH
    }
}

@Inject
@SingleIn(AppScope::class)
@ContributesIntoSet(AppScope::class, binding = binding<HttpAdapterDescriptorProvider>())
class WalletInteractionHttpAdapterDescriptorProvider : HttpAdapterDescriptorProvider {
    override val id: String = WalletInteractionHttpAdapter.ADAPTER_ID

    override fun describe(): HttpAdapterDescription =
        HttpAdapterDescription(
            id = id,
            mount =
                HttpAdapterMount(
                    serverPrefix = "",
                    adapterBasePath = WalletInteractionHttpAdapter.BASE_PATH,
                ),
            endpoints =
                WalletInteractionHttpEndpoints.relative.map { endpoint ->
                    endpoint.copy(
                        pathPatterns = endpoint.pathPatterns.map { pattern -> WalletInteractionHttpAdapter.BASE_PATH + pattern },
                    )
                },
            openApiHints =
                OpenApiHints(
                    tags = setOf(WALLET_INTERACTION_TAG),
                    operationIdPrefix = "walletInteraction",
                ),
        )
}

object WalletInteractionHttpEndpoints {
    val relative: List<HttpEndpointDescriptor> =
        listOf(
            StartWalletInteractionHttpEndpointCommand.ENDPOINT,
            ResumeWalletInteractionHttpEndpointCommand.ENDPOINT,
            DispatchWalletInteractionActionHttpEndpointCommand.ENDPOINT,
            CancelWalletInteractionHttpEndpointCommand.ENDPOINT,
            GetWalletInteractionStateHttpEndpointCommand.ENDPOINT,
            GetWalletInteractionEventsHttpEndpointCommand.ENDPOINT,
            HandleWalletInteractionFrameHttpEndpointCommand.ENDPOINT,
            RegisterWalletInteractionSensitiveInputHttpEndpointCommand.ENDPOINT,
            ConsumeWalletInteractionAuthorizationHandoffHttpEndpointCommand.ENDPOINT,
            ConsumeWalletInteractionCompletionHandoffHttpEndpointCommand.ENDPOINT,
            ListWalletInteractionActivityHttpEndpointCommand.ENDPOINT,
            ListWalletInteractionTasksHttpEndpointCommand.ENDPOINT,
        )
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(StartWalletInteractionHttpEndpointCommand.COMMAND_ID)
class StartWalletInteractionHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val command: StartWalletInteractionCommand,
) : WalletInteractionHttpEndpointCommandAdapter(
        id = StartWalletInteractionHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = StartWalletInteractionHttpEndpointCommand.ENDPOINT,
    ),
    StartWalletInteractionHttpEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> =
        runWalletInteractionEndpoint {
            val request = applyDuring(args)
            val walletUnitId = request.walletUnitId().orAbort()
            val body = request.requireJsonBody<StartWalletInteractionBody>(json).orAbort()
            if (body.input.walletUnitId != walletUnitId) {
                abort(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "wallet_interaction_start_wallet_mismatch"))
            }
            WalletInteractionSessionEnvelope(
                command.execute(body.input).orAbort(),
            ).json(WalletInteractionSessionEnvelope.serializer(), statusCode = 201)
        }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(ResumeWalletInteractionHttpEndpointCommand.COMMAND_ID)
class ResumeWalletInteractionHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val command: ResumeWalletInteractionCommand,
) : WalletInteractionHttpEndpointCommandAdapter(
        id = ResumeWalletInteractionHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = ResumeWalletInteractionHttpEndpointCommand.ENDPOINT,
    ),
    ResumeWalletInteractionHttpEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> =
        runWalletInteractionEndpoint {
            val request = applyDuring(args)
            WalletInteractionSessionEnvelope(
                command
                    .execute(
                        ResumeWalletInteractionArgs(
                            walletUnitId = request.walletUnitId().orAbort(),
                            sessionId = request.sessionId().orAbort(),
                        ),
                    ).orAbort(),
            ).json(WalletInteractionSessionEnvelope.serializer())
        }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(DispatchWalletInteractionActionHttpEndpointCommand.COMMAND_ID)
class DispatchWalletInteractionActionHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val command: SubmitWalletInteractionActionCommand,
    private val stateCommand: GetWalletInteractionStateCommand,
) : WalletInteractionHttpEndpointCommandAdapter(
        id = DispatchWalletInteractionActionHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = DispatchWalletInteractionActionHttpEndpointCommand.ENDPOINT,
    ),
    DispatchWalletInteractionActionHttpEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> =
        runWalletInteractionEndpoint {
            val request = applyDuring(args)
            val walletUnitId = request.walletUnitId().orAbort()
            val sessionId = request.sessionId().orAbort()
            val body = request.requireJsonBody<DispatchWalletInteractionActionBody>(json).orAbort()
            // Conditional write. A dispatch that names the revision it was decided against is
            // refused outright when the session has moved on, so an approval given on a screen
            // the user is no longer looking at never reaches the state machine. The check reads
            // the state immediately before dispatching: it deterministically refuses the
            // stale-render case, and the managed deployment's action authority is what turns
            // two dispatches racing at the same revision into a single atomic claim.
            val conflict = revisionConflict(walletUnitId, sessionId, body.expectedRevision)
            if (conflict != null) {
                conflict.json(WalletInteractionRevisionConflict.serializer(), statusCode = HTTP_CONFLICT)
            } else {
                WalletInteractionStateEnvelope(
                    command
                        .execute(
                            SubmitWalletInteractionActionArgs(
                                walletUnitId = walletUnitId,
                                sessionId = sessionId,
                                action = body.action,
                                expectedProcessRevision = body.expectedRevision,
                                idempotencyKey = body.idempotencyKey,
                            ),
                        ).orAbort(),
                ).json(WalletInteractionStateEnvelope.serializer())
            }
        }

    /**
     * The refusal describing why this dispatch must not be applied, or null when the session is
     * at the stated revision or the caller stated none.
     */
    private suspend fun revisionConflict(
        walletUnitId: String,
        sessionId: WalletInteractionSessionId,
        expectedRevision: Long?,
    ): WalletInteractionRevisionConflict? {
        if (expectedRevision == null) return null
        val current =
            stateCommand
                .execute(GetWalletInteractionStateArgs(walletUnitId = walletUnitId, sessionId = sessionId))
                .orAbort()
        if (current.revision == expectedRevision) return null
        return WalletInteractionRevisionConflict(
            sessionId = sessionId,
            expectedRevision = expectedRevision,
            currentRevision = current.revision,
            state = current,
        )
    }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(CancelWalletInteractionHttpEndpointCommand.COMMAND_ID)
class CancelWalletInteractionHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val command: CancelWalletInteractionCommand,
) : WalletInteractionHttpEndpointCommandAdapter(
        id = CancelWalletInteractionHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = CancelWalletInteractionHttpEndpointCommand.ENDPOINT,
    ),
    CancelWalletInteractionHttpEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> =
        runWalletInteractionEndpoint {
            val request = applyDuring(args)
            command
                .execute(
                    CancelWalletInteractionArgs(
                        walletUnitId = request.walletUnitId().orAbort(),
                        sessionId = request.sessionId().orAbort(),
                    ),
                ).orAbort()
                .json(CancelWalletInteractionResult.serializer())
        }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(GetWalletInteractionStateHttpEndpointCommand.COMMAND_ID)
class GetWalletInteractionStateHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val command: GetWalletInteractionStateCommand,
) : WalletInteractionHttpEndpointCommandAdapter(
        id = GetWalletInteractionStateHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = GetWalletInteractionStateHttpEndpointCommand.ENDPOINT,
    ),
    GetWalletInteractionStateHttpEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> =
        runWalletInteractionEndpoint {
            val request = applyDuring(args)
            WalletInteractionStateEnvelope(
                command
                    .execute(
                        GetWalletInteractionStateArgs(
                            walletUnitId = request.walletUnitId().orAbort(),
                            sessionId = request.sessionId().orAbort(),
                        ),
                    ).orAbort(),
            ).json(WalletInteractionStateEnvelope.serializer())
        }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(GetWalletInteractionEventsHttpEndpointCommand.COMMAND_ID)
class GetWalletInteractionEventsHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val command: GetWalletInteractionEventsCommand,
) : WalletInteractionHttpEndpointCommandAdapter(
        id = GetWalletInteractionEventsHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = GetWalletInteractionEventsHttpEndpointCommand.ENDPOINT,
    ),
    GetWalletInteractionEventsHttpEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> =
        runWalletInteractionEndpoint {
            val request = applyDuring(args)
            val afterRevision = request.afterRevision().orAbort()
            val events =
                command
                    .execute(
                        GetWalletInteractionEventsArgs(
                            walletUnitId = request.walletUnitId().orAbort(),
                            sessionId = request.sessionId().orAbort(),
                            afterRevision = afterRevision,
                        ),
                    ).orAbort()
                    .events
            val body = events.joinToString(separator = "") { event -> encodeSseEvent(event) }
            GenericHttpResponse(statusCode = 200, headers = SSE_HEADERS, body = body)
        }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(HandleWalletInteractionFrameHttpEndpointCommand.COMMAND_ID)
class HandleWalletInteractionFrameHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val resumeCommand: ResumeWalletInteractionCommand,
    private val submitActionCommand: SubmitWalletInteractionActionCommand,
    private val cancelCommand: CancelWalletInteractionCommand,
    private val stateCommand: GetWalletInteractionStateCommand,
) : WalletInteractionHttpEndpointCommandAdapter(
        id = HandleWalletInteractionFrameHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = HandleWalletInteractionFrameHttpEndpointCommand.ENDPOINT,
    ),
    HandleWalletInteractionFrameHttpEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> =
        runWalletInteractionEndpoint {
            val request = applyDuring(args)
            val pathSessionId = request.sessionId().orAbort()
            val frame = request.requireJsonBody<WalletInteractionClientFrame>(json).orAbort()
            if (frame.sessionId != pathSessionId) {
                abort(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "wallet_interaction_frame_session_mismatch"))
            }
            val walletUnitId = request.walletUnitId().orAbort()
            // Same conditional write as the actions endpoint, on the transport that already
            // carries the precondition in its body. Only DISPATCH_ACTION advances the state
            // machine on the client's behalf, so only DISPATCH_ACTION is gated.
            val staleAgainst =
                if (frame.type == WalletInteractionClientFrameType.DISPATCH_ACTION) {
                    frameRevisionConflict(walletUnitId, frame.sessionId, frame.lastRevision)
                } else {
                    null
                }
            if (staleAgainst != null) {
                return@runWalletInteractionEndpoint staleAgainst.json(
                    WalletInteractionServerFrame.serializer(),
                    statusCode = HTTP_CONFLICT,
                )
            }
            val state =
                when (frame.type) {
                    WalletInteractionClientFrameType.RESUME -> {
                        resumeCommand
                            .execute(ResumeWalletInteractionArgs(walletUnitId, frame.sessionId))
                            .orAbort()
                            .state
                    }

                    WalletInteractionClientFrameType.DISPATCH_ACTION -> {
                        submitActionCommand
                            .execute(
                                SubmitWalletInteractionActionArgs(
                                    walletUnitId = walletUnitId,
                                    sessionId = frame.sessionId,
                                    action = requireNotNull(frame.action) { "wallet_interaction_frame_action_missing" },
                                ),
                            ).orAbort()
                    }

                    WalletInteractionClientFrameType.CANCEL -> {
                        cancelCommand
                            .execute(CancelWalletInteractionArgs(walletUnitId, frame.sessionId))
                            .orAbort()
                            .state
                    }

                    WalletInteractionClientFrameType.PING -> {
                        null
                    }
                }
            val response =
                if (state == null) {
                    WalletInteractionServerFrame(
                        type = WalletInteractionServerFrameType.PONG,
                        sessionId = frame.sessionId,
                    )
                } else {
                    WalletInteractionServerFrame(
                        type = WalletInteractionServerFrameType.STATE,
                        sessionId = frame.sessionId,
                        revision = state.revision,
                        state = state,
                    )
                }
            response.json(WalletInteractionServerFrame.serializer())
        }

    /**
     * The ERROR server frame refusing a DISPATCH_ACTION frame whose stated revision is not the
     * one the session is at, or null when it matches or the frame stated none. The current state
     * rides along so the client can re-render without a second round trip.
     */
    private suspend fun frameRevisionConflict(
        walletUnitId: String,
        sessionId: WalletInteractionSessionId,
        lastRevision: Long?,
    ): WalletInteractionServerFrame? {
        if (lastRevision == null) return null
        val current =
            stateCommand
                .execute(GetWalletInteractionStateArgs(walletUnitId = walletUnitId, sessionId = sessionId))
                .orAbort()
        if (current.revision == lastRevision) return null
        return WalletInteractionServerFrame(
            type = WalletInteractionServerFrameType.ERROR,
            sessionId = sessionId,
            revision = current.revision,
            state = current,
            error =
                classifiedWalletInteractionError(
                    code = WalletInteractionFailureCodes.REVISION_CONFLICT,
                    messageKey = WalletInteractionApiConstants.Errors.REVISION_CONFLICT_MESSAGE_KEY,
                    arguments =
                        mapOf(
                            "expectedRevision" to lastRevision.toString(),
                            "currentRevision" to current.revision.toString(),
                        ),
                ),
        )
    }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(RegisterWalletInteractionSensitiveInputHttpEndpointCommand.COMMAND_ID)
class RegisterWalletInteractionSensitiveInputHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val command: RegisterWalletInteractionSensitiveInputCommand,
) : WalletInteractionHttpEndpointCommandAdapter(
        id = RegisterWalletInteractionSensitiveInputHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = RegisterWalletInteractionSensitiveInputHttpEndpointCommand.ENDPOINT,
    ),
    RegisterWalletInteractionSensitiveInputHttpEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> =
        runWalletInteractionEndpoint {
            val request = applyDuring(args)
            val body = request.sensitiveInputBody(json).orAbort()
            command
                .execute(
                    RegisterWalletInteractionSensitiveInputArgs(
                        walletUnitId = request.walletUnitId().orAbort(),
                        sessionId = request.sessionId().orAbort(),
                        purpose = body.purpose,
                        value = body.value,
                    ),
                ).orAbort()
                .json(RegisterWalletInteractionSensitiveInputResult.serializer(), statusCode = 201)
        }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(ConsumeWalletInteractionAuthorizationHandoffHttpEndpointCommand.COMMAND_ID)
class ConsumeWalletInteractionAuthorizationHandoffHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val command: ConsumeWalletInteractionAuthorizationHandoffCommand,
) : WalletInteractionHttpEndpointCommandAdapter(
        id = ConsumeWalletInteractionAuthorizationHandoffHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = ConsumeWalletInteractionAuthorizationHandoffHttpEndpointCommand.ENDPOINT,
    ),
    ConsumeWalletInteractionAuthorizationHandoffHttpEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> =
        runWalletInteractionEndpoint {
            val request = applyDuring(args)
            val body = request.requireJsonBody<ConsumeWalletInteractionHandoffRequest>(json).orAbort()
            command
                .execute(
                    ConsumeWalletInteractionHandoffArgs(
                        walletUnitId = request.walletUnitId().orAbort(),
                        sessionId = request.sessionId().orAbort(),
                        ref = body.ref,
                    ),
                ).orAbort()
                .json(ConsumeWalletInteractionHandoffResult.serializer())
        }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(ConsumeWalletInteractionCompletionHandoffHttpEndpointCommand.COMMAND_ID)
class ConsumeWalletInteractionCompletionHandoffHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val command: ConsumeWalletInteractionCompletionHandoffCommand,
) : WalletInteractionHttpEndpointCommandAdapter(
        id = ConsumeWalletInteractionCompletionHandoffHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = ConsumeWalletInteractionCompletionHandoffHttpEndpointCommand.ENDPOINT,
    ),
    ConsumeWalletInteractionCompletionHandoffHttpEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> =
        runWalletInteractionEndpoint {
            val request = applyDuring(args)
            val body = request.requireJsonBody<ConsumeWalletInteractionHandoffRequest>(json).orAbort()
            command
                .execute(
                    ConsumeWalletInteractionHandoffArgs(
                        walletUnitId = request.walletUnitId().orAbort(),
                        sessionId = request.sessionId().orAbort(),
                        ref = body.ref,
                    ),
                ).orAbort()
                .json(ConsumeWalletInteractionHandoffResult.serializer())
        }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(ListWalletInteractionActivityHttpEndpointCommand.COMMAND_ID)
class ListWalletInteractionActivityHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val command: ListWalletInteractionActivityCommand,
) : WalletInteractionHttpEndpointCommandAdapter(
        id = ListWalletInteractionActivityHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = ListWalletInteractionActivityHttpEndpointCommand.ENDPOINT,
    ),
    ListWalletInteractionActivityHttpEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> =
        runWalletInteractionEndpoint {
            val request = applyDuring(args)
            val walletUnitId = request.walletUnitId().orAbort()
            val afterSequence = request.afterSequence().orAbort()
            val limit =
                request
                    .optionalIntQueryParam(PARAM_LIMIT, min = ACTIVITY_LIMIT_MIN, max = ACTIVITY_LIMIT_MAX)
                    .orAbort()
            val listArgs =
                ListWalletInteractionActivityArgs(
                    walletUnitId = walletUnitId,
                    afterSequence = afterSequence,
                ).let { base -> if (limit == null) base else base.copy(limit = limit) }
            command
                .execute(listArgs)
                .orAbort()
                .json(ListWalletInteractionActivityResult.serializer())
        }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(ListWalletInteractionTasksHttpEndpointCommand.COMMAND_ID)
class ListWalletInteractionTasksHttpEndpointCommandImpl(
    execution: SessionExecution,
    private val command: ListWalletInteractionTasksCommand,
) : WalletInteractionHttpEndpointCommandAdapter(
        id = ListWalletInteractionTasksHttpEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = ListWalletInteractionTasksHttpEndpointCommand.ENDPOINT,
    ),
    ListWalletInteractionTasksHttpEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> =
        runWalletInteractionEndpoint {
            val request = applyDuring(args)
            val walletUnitId = request.walletUnitId().orAbort()
            val limit =
                request
                    .optionalIntQueryParam(PARAM_LIMIT, min = ACTIVITY_LIMIT_MIN, max = ACTIVITY_LIMIT_MAX)
                    .orAbort()
            val listArgs =
                ListWalletInteractionTasksArgs(walletUnitId = walletUnitId)
                    .let { base -> if (limit == null) base else base.copy(limit = limit) }
            command
                .execute(listArgs)
                .orAbort()
                .json(ListWalletInteractionTasksResult.serializer())
        }
}

abstract class WalletInteractionHttpEndpointCommandAdapter(
    id: String,
    execution: SessionExecution,
    endpoint: HttpEndpointDescriptor,
) : HttpEndpointCommandAdapter(id = id, execution = execution, endpoint = endpoint) {
    protected val json: Json = defaultWalletInteractionJson

    protected suspend fun runWalletInteractionEndpoint(block: suspend () -> GenericHttpResponse,): IdkResult<GenericHttpResponse, IdkError> =
        try {
            Ok(block())
        } catch (abort: WalletInteractionHttpAbort) {
            Err(abort.error)
        } catch (expected: IllegalArgumentException) {
            Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = expected.message ?: "wallet_interaction_request_invalid",
                    throwable = expected,
                ),
            )
        }

    protected fun <T> T.json(
        serializer: KSerializer<T>,
        statusCode: Int = 200,
    ): GenericHttpResponse =
        GenericHttpResponse(
            statusCode = statusCode,
            headers = JSON_HEADERS,
            body = json.encodeToString(serializer, this),
        )

    protected fun <T> IdkResult<T, IdkError>.orAbort(): T = getOrElse { abort(it) }

    protected fun abort(error: IdkError): Nothing = throw WalletInteractionHttpAbort(error)

    protected fun encodeSseEvent(event: WalletInteractionStateEvent): String =
        "id: ${event.revision}\n" +
            "event: ${WalletInteractionApiConstants.Sse.EVENT_STATE}\n" +
            "data: ${json.encodeToString(WalletInteractionStateEvent.serializer(), event)}\n\n"
}

private class WalletInteractionHttpAbort(
    val error: IdkError,
) : RuntimeException(error.toString())

private fun GenericHttpRequest.walletUnitId(): IdkResult<String, IdkError> = requirePathParam(PARAM_WALLET_UNIT_ID)

private fun GenericHttpRequest.sessionId(): IdkResult<WalletInteractionSessionId, IdkError> = requirePathParam(PARAM_SESSION_ID).map { raw -> WalletInteractionSessionId(raw) }

private fun GenericHttpRequest.afterRevision(): IdkResult<Long?, IdkError> {
    val raw = headerIgnoreCase(WalletInteractionApiConstants.Sse.LAST_EVENT_ID_HEADER) ?: return Ok(null)
    val revision =
        raw.toLongOrNull()
            ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "wallet_interaction_last_event_id_invalid"))
    return Ok(revision)
}

/**
 * Reads the sensitive-input body without letting the decoder speak.
 *
 * The generic JSON body helper reports failures as "Invalid request body: <decoder message>", and a
 * kotlinx decoding message ends with the offending JSON document. On this one endpoint that
 * document IS the sensitive value, so the generic helper would put a transaction code or an
 * authorization callback into a 400 response body and into every log line that renders the error.
 * The failure is therefore reported as a fixed key, and the cause is deliberately not attached.
 */
private fun GenericHttpRequest.sensitiveInputBody(json: Json): IdkResult<RegisterWalletInteractionSensitiveInputRequest, IdkError> {
    val text = body ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "wallet_interaction_sensitive_input_body_missing"))
    return try {
        Ok(json.decodeFromString(RegisterWalletInteractionSensitiveInputRequest.serializer(), text))
    } catch (expected: Exception) {
        Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "wallet_interaction_sensitive_input_body_invalid"))
    }
}

private fun GenericHttpRequest.afterSequence(): IdkResult<Long?, IdkError> {
    val raw = queryParams[PARAM_AFTER_SEQUENCE] ?: return Ok(null)
    val sequence =
        raw.toLongOrNull()?.takeIf { it >= 0 }
            ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "wallet_interaction_activity_after_sequence_invalid"))
    return Ok(sequence)
}

private fun walletInteractionEndpoint(
    method: HttpMethod,
    pathPattern: String,
    consumes: Set<MediaType> = emptySet(),
    produces: Set<MediaType>,
    operationId: String,
    commandId: String,
    handlerCommandId: String = commandId,
): HttpEndpointDescriptor =
    HttpEndpointDescriptor(
        method = method,
        pathPattern = pathPattern,
        consumes = consumes,
        produces = produces,
        operationId = operationId,
        commandId = commandId,
        handlerCommandId = handlerCommandId,
        tags = setOf(WALLET_INTERACTION_TAG),
    )
