/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.wallet.interaction.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.ServiceCommand
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.di.session.SessionScope
import com.sphereon.wallet.interaction.CancelWalletInteractionArgs
import com.sphereon.wallet.interaction.CancelWalletInteractionCommand
import com.sphereon.wallet.interaction.CancelWalletInteractionResult
import com.sphereon.wallet.interaction.CapturedInteractionClient
import com.sphereon.wallet.interaction.CapturedInteractionInput
import com.sphereon.wallet.interaction.ConsumeWalletInteractionAuthorizationHandoffCommand
import com.sphereon.wallet.interaction.ConsumeWalletInteractionCompletionHandoffCommand
import com.sphereon.wallet.interaction.ConsumeWalletInteractionHandoffArgs
import com.sphereon.wallet.interaction.ConsumeWalletInteractionHandoffResult
import com.sphereon.wallet.interaction.EnsureWalletClientRegistrationKeyArgs
import com.sphereon.wallet.interaction.EnsureWalletClientRegistrationKeyCommand
import com.sphereon.wallet.interaction.GetWalletInteractionEventsArgs
import com.sphereon.wallet.interaction.GetWalletInteractionEventsCommand
import com.sphereon.wallet.interaction.GetWalletInteractionEventsResult
import com.sphereon.wallet.interaction.GetWalletInteractionStateArgs
import com.sphereon.wallet.interaction.GetWalletInteractionStateCommand
import com.sphereon.wallet.interaction.ListWalletInteractionActivityArgs
import com.sphereon.wallet.interaction.ListWalletInteractionActivityCommand
import com.sphereon.wallet.interaction.ListWalletInteractionActivityResult
import com.sphereon.wallet.interaction.ListWalletInteractionTasksArgs
import com.sphereon.wallet.interaction.ListWalletInteractionTasksCommand
import com.sphereon.wallet.interaction.ListWalletInteractionTasksResult
import com.sphereon.wallet.interaction.ObserveWalletInteractionEventsCommand
import com.sphereon.wallet.interaction.RegisterWalletInteractionSensitiveInputArgs
import com.sphereon.wallet.interaction.RegisterWalletInteractionSensitiveInputCommand
import com.sphereon.wallet.interaction.RegisterWalletInteractionSensitiveInputResult
import com.sphereon.wallet.interaction.ResolveWalletCounterpartyEncounterCommand
import com.sphereon.wallet.interaction.ResumeWalletInteractionArgs
import com.sphereon.wallet.interaction.ResumeWalletInteractionCommand
import com.sphereon.wallet.interaction.StartWalletInteractionCommand
import com.sphereon.wallet.interaction.StartCapturedWalletInteractionCommand
import com.sphereon.wallet.interaction.SubmitWalletInteractionActionArgs
import com.sphereon.wallet.interaction.SubmitWalletInteractionActionCommand
import com.sphereon.wallet.interaction.WalletInteractionClient
import com.sphereon.wallet.interaction.WalletCounterpartyEncounterRegistry
import com.sphereon.wallet.interaction.WalletCounterpartyEncounterRequest
import com.sphereon.wallet.interaction.WalletCounterpartyEncounterResult
import com.sphereon.wallet.interaction.WalletInteractionActionAuthority
import com.sphereon.wallet.interaction.WalletInteractionActionPermit
import com.sphereon.wallet.interaction.WalletInteractionInput
import com.sphereon.wallet.interaction.WalletInteractionSession
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionStateEvent
import com.sphereon.wallet.interaction.WalletInteractionStateEventSource
import com.sphereon.wallet.interaction.WalletInteractionPrivateSessionStore
import com.sphereon.wallet.interaction.WalletInteractionSensitiveInputAuthority
import com.sphereon.wallet.interaction.WalletInteractionSensitiveInputPurpose
import com.sphereon.wallet.interaction.consumeOpenableAuthorizationHandoff
import com.sphereon.wallet.interaction.WalletClientRegistrationKey
import com.sphereon.wallet.unit.SecureComponentUsage
import com.sphereon.wallet.wsca.Wsca
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.IntoMap
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.StringKey
import dev.zacsweers.metro.binding
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.onEach

@Inject
@SingleIn(SessionScope::class)
class EnsureWalletClientRegistrationKeyCommandImpl(
    execution: SessionExecution,
    private val wsca: Wsca,
) : TypedServiceCommandAdapter<EnsureWalletClientRegistrationKeyArgs, WalletClientRegistrationKey, IdkError>(
        commandId = EnsureWalletClientRegistrationKeyCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<EnsureWalletClientRegistrationKeyArgs>(),
        outputTypeToken = typeToken<WalletClientRegistrationKey>(),
    ),
    EnsureWalletClientRegistrationKeyCommand {
    override val commandId: String get() = EnsureWalletClientRegistrationKeyCommand.COMMAND_ID

    override suspend fun doExecute(
        args: EnsureWalletClientRegistrationKeyArgs,
        applyDuring: (EnsureWalletClientRegistrationKeyArgs) -> EnsureWalletClientRegistrationKeyArgs,
    ): IdkResult<WalletClientRegistrationKey, IdkError> {
        val input = applyDuring(args)
        val key =
            wsca
                .ensureKey(
                    walletUnitId = input.walletUnitId,
                    usage = SecureComponentUsage.OAUTH_CLIENT_AUTHENTICATION,
                    algorithm = SignatureAlgorithm.ECDSA_SHA256,
                ).getOrElse { return Err(it) }
        val publicJwk =
            key.publicKeyJwk
                ?: return Err(IdkError.INVALID_STATE(message = "wallet_client_registration_public_jwk_missing"))
        return Ok(WalletClientRegistrationKey(keyId = key.keyId, algorithm = key.algorithm, publicJwk = publicJwk))
    }
}

@Inject
@SingleIn(SessionScope::class)
class StartWalletInteractionCommandImpl(
    execution: SessionExecution,
    private val client: WalletInteractionClient,
) : TypedServiceCommandAdapter<WalletInteractionInput, WalletInteractionSession, IdkError>(
        commandId = StartWalletInteractionCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<WalletInteractionInput>(),
        outputTypeToken = typeToken<WalletInteractionSession>(),
    ),
    StartWalletInteractionCommand {
    override val commandId: String get() = StartWalletInteractionCommand.COMMAND_ID

    override suspend fun doExecute(
        args: WalletInteractionInput,
        applyDuring: (WalletInteractionInput) -> WalletInteractionInput,
    ): IdkResult<WalletInteractionSession, IdkError> =
        walletInteractionCommand {
            val input = applyDuring(args)
            client.start(input).also { session -> session.state.requireWallet(input.walletUnitId) }
        }
}

@Inject
@SingleIn(SessionScope::class)
class StartCapturedWalletInteractionCommandImpl(
    execution: SessionExecution,
    private val client: CapturedInteractionClient,
) : TypedServiceCommandAdapter<CapturedInteractionInput, WalletInteractionSession, IdkError>(
        commandId = StartCapturedWalletInteractionCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CapturedInteractionInput>(),
        outputTypeToken = typeToken<WalletInteractionSession>(),
    ),
    StartCapturedWalletInteractionCommand {
    override val commandId: String get() = StartCapturedWalletInteractionCommand.COMMAND_ID

    override suspend fun doExecute(
        args: CapturedInteractionInput,
        applyDuring: (CapturedInteractionInput) -> CapturedInteractionInput,
    ): IdkResult<WalletInteractionSession, IdkError> =
        walletInteractionCommand {
            val input = applyDuring(args)
            client.startCaptured(input)
        }
}

/**
 * The app-side protocol engine calls this only after it has classified and resolved the
 * counterparty from an OID4 interaction. The configured backend authority owns Party persistence;
 * raw offers, authorization requests, credentials, and keys never cross this command boundary.
 */
@Inject
@SingleIn(SessionScope::class)
class ResolveWalletCounterpartyEncounterCommandImpl(
    execution: SessionExecution,
    private val counterpartyEncounterRegistry: WalletCounterpartyEncounterRegistry,
) : TypedServiceCommandAdapter<WalletCounterpartyEncounterRequest, WalletCounterpartyEncounterResult, IdkError>(
        commandId = ResolveWalletCounterpartyEncounterCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<WalletCounterpartyEncounterRequest>(),
        outputTypeToken = typeToken<WalletCounterpartyEncounterResult>(),
    ),
    ResolveWalletCounterpartyEncounterCommand {
    override val commandId: String get() = ResolveWalletCounterpartyEncounterCommand.COMMAND_ID

    override suspend fun doExecute(
        args: WalletCounterpartyEncounterRequest,
        applyDuring: (WalletCounterpartyEncounterRequest) -> WalletCounterpartyEncounterRequest,
    ): IdkResult<WalletCounterpartyEncounterResult, IdkError> =
        walletInteractionCommand { counterpartyEncounterRegistry.encounter(applyDuring(args)) }
}

@Inject
@SingleIn(SessionScope::class)
class ResumeWalletInteractionCommandImpl(
    execution: SessionExecution,
    private val client: WalletInteractionClient,
) : TypedServiceCommandAdapter<ResumeWalletInteractionArgs, WalletInteractionSession, IdkError>(
        commandId = ResumeWalletInteractionCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<ResumeWalletInteractionArgs>(),
        outputTypeToken = typeToken<WalletInteractionSession>(),
    ),
    ResumeWalletInteractionCommand {
    override val commandId: String get() = ResumeWalletInteractionCommand.COMMAND_ID

    override suspend fun doExecute(
        args: ResumeWalletInteractionArgs,
        applyDuring: (ResumeWalletInteractionArgs) -> ResumeWalletInteractionArgs,
    ): IdkResult<WalletInteractionSession, IdkError> =
        walletInteractionCommand {
            val input = applyDuring(args)
            client.resume(input.sessionId).also { session -> session.state.requireWallet(input.walletUnitId) }
        }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoSet(SessionScope::class, binding = binding<WalletInteractionActionAuthority>())
class LocalWalletInteractionActionAuthority : WalletInteractionActionAuthority {
    override val priority: Int = 0

    override suspend fun authorize(
        args: SubmitWalletInteractionActionArgs,
        currentState: WalletInteractionState,
    ): IdkResult<WalletInteractionActionPermit, IdkError> =
        Ok(WalletInteractionActionPermit.Proceed("local:${currentState.sessionId.value}:${currentState.revision}"))

    override suspend fun complete(
        permit: WalletInteractionActionPermit.Proceed,
        state: WalletInteractionState,
    ): IdkResult<Unit, IdkError> = Ok(Unit)

    override suspend fun abort(permit: WalletInteractionActionPermit.Proceed): IdkResult<Unit, IdkError> = Ok(Unit)
}

@Inject
@SingleIn(SessionScope::class)
class SubmitWalletInteractionActionCommandImpl(
    execution: SessionExecution,
    private val client: WalletInteractionClient,
    private val actionAuthorities: Set<WalletInteractionActionAuthority> = setOf(LocalWalletInteractionActionAuthority()),
) : TypedServiceCommandAdapter<SubmitWalletInteractionActionArgs, WalletInteractionState, IdkError>(
        commandId = SubmitWalletInteractionActionCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<SubmitWalletInteractionActionArgs>(),
        outputTypeToken = typeToken<WalletInteractionState>(),
    ),
    SubmitWalletInteractionActionCommand {
    override val commandId: String get() = SubmitWalletInteractionActionCommand.COMMAND_ID

    override suspend fun doExecute(
        args: SubmitWalletInteractionActionArgs,
        applyDuring: (SubmitWalletInteractionActionArgs) -> SubmitWalletInteractionActionArgs,
    ): IdkResult<WalletInteractionState, IdkError> {
        val input = applyDuring(args)
        val current =
            walletInteractionCommand {
                client.load(input.sessionId).state.also { state -> state.requireWallet(input.walletUnitId) }
            }.getOrElse { return Err(it) }
        val highestPriority = actionAuthorities.maxOfOrNull(WalletInteractionActionAuthority::priority)
            ?: return Err(IdkError.INVALID_STATE(message = "wallet_interaction_action_authority_missing"))
        val selected = actionAuthorities.filter { it.priority == highestPriority }
        if (selected.size != 1) {
            return Err(IdkError.INVALID_STATE(message = "wallet_interaction_action_authority_ambiguous"))
        }
        val permit = selected.single().authorize(input, current).getOrElse { return Err(it) }
        if (permit is WalletInteractionActionPermit.Replay) {
            permit.state.requireWallet(input.walletUnitId)
            return Ok(permit.state)
        }
        permit as WalletInteractionActionPermit.Proceed
        val executionResult =
            walletInteractionCommand {
                client.dispatch(input.sessionId, input.action)
                client.load(input.sessionId).state.also { value -> value.requireWallet(input.walletUnitId) }
            }
        val state = executionResult.getOrElse { error ->
            selected.single().abort(permit).getOrElse { return Err(it) }
            return Err(error)
        }
        selected.single().complete(permit, state).getOrElse { return Err(it) }
        return Ok(state)
    }
}

@Inject
@SingleIn(SessionScope::class)
class CancelWalletInteractionCommandImpl(
    execution: SessionExecution,
    private val client: WalletInteractionClient,
) : TypedServiceCommandAdapter<CancelWalletInteractionArgs, CancelWalletInteractionResult, IdkError>(
        commandId = CancelWalletInteractionCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CancelWalletInteractionArgs>(),
        outputTypeToken = typeToken<CancelWalletInteractionResult>(),
    ),
    CancelWalletInteractionCommand {
    override val commandId: String get() = CancelWalletInteractionCommand.COMMAND_ID

    override suspend fun doExecute(
        args: CancelWalletInteractionArgs,
        applyDuring: (CancelWalletInteractionArgs) -> CancelWalletInteractionArgs,
    ): IdkResult<CancelWalletInteractionResult, IdkError> =
        walletInteractionCommand {
            val input = applyDuring(args)
            client.load(input.sessionId).state.requireWallet(input.walletUnitId)
            client.cancel(input.sessionId)
            CancelWalletInteractionResult(
                sessionId = input.sessionId,
                state = client.load(input.sessionId).state.also { state -> state.requireWallet(input.walletUnitId) },
            )
        }
}

@Inject
@SingleIn(SessionScope::class)
class GetWalletInteractionStateCommandImpl(
    execution: SessionExecution,
    private val client: WalletInteractionClient,
) : TypedServiceCommandAdapter<GetWalletInteractionStateArgs, WalletInteractionState, IdkError>(
        commandId = GetWalletInteractionStateCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<GetWalletInteractionStateArgs>(),
        outputTypeToken = typeToken<WalletInteractionState>(),
    ),
    GetWalletInteractionStateCommand {
    override val commandId: String get() = GetWalletInteractionStateCommand.COMMAND_ID

    override suspend fun doExecute(
        args: GetWalletInteractionStateArgs,
        applyDuring: (GetWalletInteractionStateArgs) -> GetWalletInteractionStateArgs,
    ): IdkResult<WalletInteractionState, IdkError> =
        walletInteractionCommand {
            val input = applyDuring(args)
            client.load(input.sessionId).state.also { state -> state.requireWallet(input.walletUnitId) }
        }
}

@Inject
@SingleIn(SessionScope::class)
class GetWalletInteractionEventsCommandImpl(
    execution: SessionExecution,
    private val client: WalletInteractionClient,
) : TypedServiceCommandAdapter<GetWalletInteractionEventsArgs, GetWalletInteractionEventsResult, IdkError>(
        commandId = GetWalletInteractionEventsCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<GetWalletInteractionEventsArgs>(),
        outputTypeToken = typeToken<GetWalletInteractionEventsResult>(),
    ),
    GetWalletInteractionEventsCommand {
    override val commandId: String get() = GetWalletInteractionEventsCommand.COMMAND_ID

    override suspend fun doExecute(
        args: GetWalletInteractionEventsArgs,
        applyDuring: (GetWalletInteractionEventsArgs) -> GetWalletInteractionEventsArgs,
    ): IdkResult<GetWalletInteractionEventsResult, IdkError> =
        walletInteractionCommand {
            val input = applyDuring(args)
            val current = client.load(input.sessionId).state.also { state -> state.requireWallet(input.walletUnitId) }
            val afterRevision = input.afterRevision
            val events =
                if (client is WalletInteractionStateEventSource) {
                    client
                        .events(input.sessionId, afterRevision)
                        .also { replay -> replay.forEach { event -> event.state.requireWallet(input.walletUnitId) } }
                } else if (afterRevision == null || current.revision > afterRevision) {
                    listOf(current.toEvent())
                } else {
                    emptyList()
                }
            GetWalletInteractionEventsResult(events)
        }
}

@Inject
@SingleIn(SessionScope::class)
class ObserveWalletInteractionEventsCommandImpl(
    execution: SessionExecution,
    private val client: WalletInteractionClient,
) : TypedServiceCommandAdapter<GetWalletInteractionEventsArgs, WalletInteractionStateEvent, IdkError>(
        commandId = ObserveWalletInteractionEventsCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<GetWalletInteractionEventsArgs>(),
        outputTypeToken = typeToken<WalletInteractionStateEvent>(),
    ),
    ObserveWalletInteractionEventsCommand {
    override val commandId: String get() = ObserveWalletInteractionEventsCommand.COMMAND_ID

    override suspend fun execute(args: GetWalletInteractionEventsArgs): IdkResult<WalletInteractionStateEvent, IdkError> =
        Err(
            IdkError.UNSUPPORTED_OPERATION_ERROR(
                operation = commandId,
                reason = "wallet_interaction_observe_events_requires_streaming_transport",
            ),
        )

    override suspend fun doExecute(
        args: GetWalletInteractionEventsArgs,
        applyDuring: (GetWalletInteractionEventsArgs) -> GetWalletInteractionEventsArgs,
    ): IdkResult<WalletInteractionStateEvent, IdkError> =
        Err(
            IdkError.UNSUPPORTED_OPERATION_ERROR(
                operation = commandId,
                reason = "wallet_interaction_observe_events_requires_streaming_transport",
            ),
        )

    override suspend fun executeStream(args: GetWalletInteractionEventsArgs): IdkResult<Flow<WalletInteractionStateEvent>, IdkError> {
        walletInteractionCommand { client.load(args.sessionId).state.requireWallet(args.walletUnitId) }
            .getOrElse { return Err(it) }
        val source =
            client as? WalletInteractionStateEventSource
                ?: return Err(
                    IdkError.UNSUPPORTED_OPERATION_ERROR(
                        operation = commandId,
                        reason = "wallet_interaction_live_event_source_unavailable",
                    ),
                )
        return Ok(
            source
                .observeEvents(args.sessionId, args.afterRevision)
                .onEach { event -> event.state.requireWallet(args.walletUnitId) },
        )
    }
}

@Inject
@SingleIn(SessionScope::class)
class RegisterWalletInteractionSensitiveInputCommandImpl(
    execution: SessionExecution,
    private val client: WalletInteractionClient,
    private val sensitiveInputAuthority: WalletInteractionSensitiveInputAuthority,
) : TypedServiceCommandAdapter<RegisterWalletInteractionSensitiveInputArgs, RegisterWalletInteractionSensitiveInputResult, IdkError>(
        commandId = RegisterWalletInteractionSensitiveInputCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<RegisterWalletInteractionSensitiveInputArgs>(),
        outputTypeToken = typeToken<RegisterWalletInteractionSensitiveInputResult>(),
    ),
    RegisterWalletInteractionSensitiveInputCommand {
    override val commandId: String get() = RegisterWalletInteractionSensitiveInputCommand.COMMAND_ID

    override suspend fun doExecute(
        args: RegisterWalletInteractionSensitiveInputArgs,
        applyDuring: (RegisterWalletInteractionSensitiveInputArgs) -> RegisterWalletInteractionSensitiveInputArgs,
    ): IdkResult<RegisterWalletInteractionSensitiveInputResult, IdkError> =
        walletInteractionCommand {
            val input = applyDuring(args)
            client.load(input.sessionId).state.requireWallet(input.walletUnitId)
            RegisterWalletInteractionSensitiveInputResult(
                sensitiveInputAuthority.register(input.sessionId, input.purpose, input.value),
            )
        }
}

@Inject
@SingleIn(SessionScope::class)
class ConsumeWalletInteractionAuthorizationHandoffCommandImpl(
    execution: SessionExecution,
    private val client: WalletInteractionClient,
    private val sensitiveInputAuthority: WalletInteractionSensitiveInputAuthority,
) : TypedServiceCommandAdapter<ConsumeWalletInteractionHandoffArgs, ConsumeWalletInteractionHandoffResult, IdkError>(
        commandId = ConsumeWalletInteractionAuthorizationHandoffCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<ConsumeWalletInteractionHandoffArgs>(),
        outputTypeToken = typeToken<ConsumeWalletInteractionHandoffResult>(),
    ),
    ConsumeWalletInteractionAuthorizationHandoffCommand {
    override val commandId: String get() = ConsumeWalletInteractionAuthorizationHandoffCommand.COMMAND_ID

    override suspend fun doExecute(
        args: ConsumeWalletInteractionHandoffArgs,
        applyDuring: (ConsumeWalletInteractionHandoffArgs) -> ConsumeWalletInteractionHandoffArgs,
    ): IdkResult<ConsumeWalletInteractionHandoffResult, IdkError> =
        walletInteractionCommand {
            val input = applyDuring(args)
            client.load(input.sessionId).state.requireWallet(input.walletUnitId)
            val value =
                sensitiveInputAuthority.consumeOpenableAuthorizationHandoff(
                    input.sessionId,
                    input.ref,
                ) ?: throw NoSuchElementException("wallet_interaction_authorization_handoff_unknown")
            ConsumeWalletInteractionHandoffResult(value)
        }
}

@Inject
@SingleIn(SessionScope::class)
class ConsumeWalletInteractionCompletionHandoffCommandImpl(
    execution: SessionExecution,
    private val client: WalletInteractionClient,
    private val sensitiveInputAuthority: WalletInteractionSensitiveInputAuthority,
    private val privateSessionStore: WalletInteractionPrivateSessionStore,
) : TypedServiceCommandAdapter<ConsumeWalletInteractionHandoffArgs, ConsumeWalletInteractionHandoffResult, IdkError>(
        commandId = ConsumeWalletInteractionCompletionHandoffCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<ConsumeWalletInteractionHandoffArgs>(),
        outputTypeToken = typeToken<ConsumeWalletInteractionHandoffResult>(),
    ),
    ConsumeWalletInteractionCompletionHandoffCommand {
    override val commandId: String get() = ConsumeWalletInteractionCompletionHandoffCommand.COMMAND_ID

    override suspend fun doExecute(
        args: ConsumeWalletInteractionHandoffArgs,
        applyDuring: (ConsumeWalletInteractionHandoffArgs) -> ConsumeWalletInteractionHandoffArgs,
    ): IdkResult<ConsumeWalletInteractionHandoffResult, IdkError> =
        walletInteractionCommand {
            val input = applyDuring(args)
            client.load(input.sessionId).state.requireWallet(input.walletUnitId)
            val value =
                sensitiveInputAuthority.consume(
                    input.sessionId,
                    WalletInteractionSensitiveInputPurpose.PROTOCOL_COMPLETION_HANDOFF,
                    input.ref,
                ) ?: throw NoSuchElementException("wallet_interaction_completion_handoff_unknown")
            sensitiveInputAuthority.clear(input.sessionId)
            privateSessionStore.removeSession(input.sessionId)
            ConsumeWalletInteractionHandoffResult(value)
        }
}

@Inject
@SingleIn(SessionScope::class)
class ListWalletInteractionActivityCommandImpl(
    execution: SessionExecution,
    private val engine: DefaultWalletInteractionEngine,
) : TypedServiceCommandAdapter<ListWalletInteractionActivityArgs, ListWalletInteractionActivityResult, IdkError>(
        commandId = ListWalletInteractionActivityCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<ListWalletInteractionActivityArgs>(),
        outputTypeToken = typeToken<ListWalletInteractionActivityResult>(),
    ),
    ListWalletInteractionActivityCommand {
    override val commandId: String get() = ListWalletInteractionActivityCommand.COMMAND_ID

    override suspend fun doExecute(
        args: ListWalletInteractionActivityArgs,
        applyDuring: (ListWalletInteractionActivityArgs) -> ListWalletInteractionActivityArgs,
    ): IdkResult<ListWalletInteractionActivityResult, IdkError> =
        walletInteractionCommand {
            val input = applyDuring(args)
            ListWalletInteractionActivityResult(
                engine.listActivity(input.walletUnitId, input.afterSequence, input.limit),
            )
        }
}

@Inject
@SingleIn(SessionScope::class)
class ListWalletInteractionTasksCommandImpl(
    execution: SessionExecution,
    private val engine: DefaultWalletInteractionEngine,
) : TypedServiceCommandAdapter<ListWalletInteractionTasksArgs, ListWalletInteractionTasksResult, IdkError>(
        commandId = ListWalletInteractionTasksCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<ListWalletInteractionTasksArgs>(),
        outputTypeToken = typeToken<ListWalletInteractionTasksResult>(),
    ),
    ListWalletInteractionTasksCommand {
    override val commandId: String get() = ListWalletInteractionTasksCommand.COMMAND_ID

    override suspend fun doExecute(
        args: ListWalletInteractionTasksArgs,
        applyDuring: (ListWalletInteractionTasksArgs) -> ListWalletInteractionTasksArgs,
    ): IdkResult<ListWalletInteractionTasksResult, IdkError> =
        walletInteractionCommand {
            val input = applyDuring(args)
            ListWalletInteractionTasksResult(engine.listTasks(input.walletUnitId, input.limit))
        }
}

@ContributesTo(SessionScope::class)
interface WalletInteractionCommandDescriptors {
    @Provides
    @IntoMap
    @StringKey(EnsureWalletClientRegistrationKeyCommand.COMMAND_ID)
    fun ensureWalletClientRegistrationKey(impl: EnsureWalletClientRegistrationKeyCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(StartWalletInteractionCommand.COMMAND_ID)
    fun startWalletInteraction(impl: StartWalletInteractionCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(ResolveWalletCounterpartyEncounterCommand.COMMAND_ID)
    fun resolveWalletCounterpartyEncounter(
        impl: ResolveWalletCounterpartyEncounterCommandImpl,
    ): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(ResumeWalletInteractionCommand.COMMAND_ID)
    fun resumeWalletInteraction(impl: ResumeWalletInteractionCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(SubmitWalletInteractionActionCommand.COMMAND_ID)
    fun submitWalletInteractionAction(impl: SubmitWalletInteractionActionCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(CancelWalletInteractionCommand.COMMAND_ID)
    fun cancelWalletInteraction(impl: CancelWalletInteractionCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(GetWalletInteractionStateCommand.COMMAND_ID)
    fun getWalletInteractionState(impl: GetWalletInteractionStateCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(GetWalletInteractionEventsCommand.COMMAND_ID)
    fun getWalletInteractionEvents(impl: GetWalletInteractionEventsCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(ObserveWalletInteractionEventsCommand.COMMAND_ID)
    fun observeWalletInteractionEvents(impl: ObserveWalletInteractionEventsCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(RegisterWalletInteractionSensitiveInputCommand.COMMAND_ID)
    fun registerWalletInteractionSensitiveInput(impl: RegisterWalletInteractionSensitiveInputCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(ConsumeWalletInteractionAuthorizationHandoffCommand.COMMAND_ID)
    fun consumeWalletInteractionAuthorizationHandoff(impl: ConsumeWalletInteractionAuthorizationHandoffCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(ConsumeWalletInteractionCompletionHandoffCommand.COMMAND_ID)
    fun consumeWalletInteractionCompletionHandoff(impl: ConsumeWalletInteractionCompletionHandoffCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(ListWalletInteractionActivityCommand.COMMAND_ID)
    fun listWalletInteractionActivity(impl: ListWalletInteractionActivityCommandImpl): ServiceCommand<*, *, *> = impl

    @Provides
    @IntoMap
    @StringKey(ListWalletInteractionTasksCommand.COMMAND_ID)
    fun listWalletInteractionTasks(impl: ListWalletInteractionTasksCommandImpl): ServiceCommand<*, *, *> = impl
}

private suspend fun <T : Any> walletInteractionCommand(block: suspend () -> T): IdkResult<T, IdkError> =
    try {
        Ok(block())
    } catch (expected: IllegalArgumentException) {
        Err(
            IdkError.ILLEGAL_ARGUMENT_ERROR(
                message = expected.message ?: "wallet_interaction_command_invalid",
                throwable = expected,
            ),
        )
    } catch (expected: NoSuchElementException) {
        Err(
            IdkError.NOT_FOUND_ERROR(
                message = expected.message ?: "wallet_interaction_session_unknown",
                throwable = expected,
            ),
        )
    } catch (expected: IllegalStateException) {
        Err(
            IdkError.INVALID_STATE(
                message = expected.message ?: "wallet_interaction_command_invalid_state",
                throwable = expected,
            ),
        )
    }

private fun WalletInteractionState.requireWallet(walletUnitId: String) {
    require(this.walletUnitId == walletUnitId) {
        "wallet_interaction_session_wallet_mismatch"
    }
}

private fun WalletInteractionState.toEvent(): WalletInteractionStateEvent =
    WalletInteractionStateEvent(
        sessionId = sessionId,
        revision = revision,
        state = this,
    )
