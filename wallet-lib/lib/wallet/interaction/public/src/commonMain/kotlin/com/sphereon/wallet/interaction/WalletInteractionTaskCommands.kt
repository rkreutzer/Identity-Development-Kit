/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.wallet.interaction

import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.ActionType
import com.sphereon.core.api.service.ServiceCommand
import com.sphereon.core.api.service.SessionScopedCommandRegistry
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Provides
import kotlinx.serialization.Serializable

/** What an unfinished holder interaction is waiting for, as a task a person can pick up. */
@Serializable
enum class WalletInteractionTaskKind {
    /** A credential offer, its issuer, a transaction code or an authorization step needs the holder's decision. */
    OfferReview,

    /** A presentation request needs the holder to select credentials or consent to the disclosure. */
    DisclosureReview,

    /** The wallet needs an unlock or key authorization before the interaction can continue. */
    UnlockRequired,

    /** The issuer accepted the request and issues later; the wallet retrieves the credential when it is ready. */
    DeferredIssuance,

    /** Protocol work is running; nobody needs to act. */
    InProgress,
}

/** Who the task is currently waiting on. */
@Serializable
enum class WalletInteractionTaskParty { HOLDER, COUNTERPARTY, WALLET }

/**
 * One unfinished holder interaction of a wallet unit, projected as a task.
 *
 * The engine owns the projection: hosts render [kind], [waitingOn] and [actions] and never derive
 * them from [status] themselves. Acting on a task uses the existing interaction commands: resume
 * or continue through the interaction itself, [WalletInteractionActionType.RETRY_DEFERRED_RETRIEVAL]
 * through submit-action, and cancel.
 */
@Serializable
data class WalletInteractionTaskProjection(
    val sessionId: String,
    val walletUnitId: String,
    val flowKind: WalletInteractionFlowKind? = null,
    val protocol: WalletProtocol? = null,
    val status: WalletInteractionStatus,
    val kind: WalletInteractionTaskKind,
    val waitingOn: WalletInteractionTaskParty,
    val revision: Long,
    val openedAtEpochSeconds: Long,
    val updatedAtEpochSeconds: Long,
    val counterparty: WalletCounterpartySummary? = null,
    val deferred: WalletDeferredRetrievalSummary? = null,
    val actions: List<WalletInteractionTaskAction> = emptyList(),
) {
    init {
        require(sessionId.isNotBlank()) { "wallet_interaction_task_session_blank" }
        require(walletUnitId.isNotBlank()) { "wallet_interaction_task_wallet_unit_blank" }
        require(updatedAtEpochSeconds >= openedAtEpochSeconds) { "wallet_interaction_task_time_invalid" }
    }
}

/** An action a host may offer for a task. */
@Serializable
enum class WalletInteractionTaskAction {
    /** Open the interaction and continue where it stopped. */
    CONTINUE,

    /** Ask the issuer again for a deferred credential now. */
    RETRY_DEFERRED_RETRIEVAL,

    /** Stop the interaction. */
    CANCEL,
}

@Serializable
data class ListWalletInteractionTasksArgs(
    val walletUnitId: String,
    val limit: Int = 100,
) {
    init {
        require(walletUnitId.isNotBlank()) { "wallet_interaction_tasks_wallet_unit_blank" }
        require(limit in 1..500) { "wallet_interaction_tasks_limit_invalid" }
    }
}

/** The open tasks of a wallet unit, most recently updated first. */
@Serializable
data class ListWalletInteractionTasksResult(
    val tasks: List<WalletInteractionTaskProjection>,
)

interface ListWalletInteractionTasksCommand :
    ServiceCommand<ListWalletInteractionTasksArgs, ListWalletInteractionTasksResult, IdkError> {
    override val commandId: String get() = COMMAND_ID
    override val actionType: ActionType get() = ActionType.READ

    companion object { const val COMMAND_ID = "wallet.interaction.list-tasks" }
}

@ContributesTo(SessionScope::class)
interface WalletInteractionTaskCommandBindings {
    @Provides
    fun listWalletInteractionTasks(registry: SessionScopedCommandRegistry): ListWalletInteractionTasksCommand =
        registry.get(ListWalletInteractionTasksCommand.COMMAND_ID) as? ListWalletInteractionTasksCommand
            ?: error("No binding for ${ListWalletInteractionTasksCommand.COMMAND_ID}")
}

/**
 * The task projection of a non-terminal state, or null for a terminal one.
 *
 * [openedAtEpochSeconds] is when the task first appeared and [nowEpochSeconds] when this state was
 * recorded; both come from the store that records the state, never from the state itself.
 */
fun WalletInteractionState.taskProjection(
    openedAtEpochSeconds: Long,
    nowEpochSeconds: Long,
): WalletInteractionTaskProjection? {
    if (terminal || status in TERMINAL_TASK_STATUSES) return null
    val kind = when (status) {
        WalletInteractionStatus.DeferredRetrievalPending -> WalletInteractionTaskKind.DeferredIssuance
        WalletInteractionStatus.SecurityUnlockRequired -> WalletInteractionTaskKind.UnlockRequired
        WalletInteractionStatus.ResolvingEntryPoint,
        WalletInteractionStatus.Sharing,
        -> WalletInteractionTaskKind.InProgress
        else -> when (flowKind) {
            WalletInteractionFlowKind.CredentialReceive -> WalletInteractionTaskKind.OfferReview
            WalletInteractionFlowKind.CredentialPresent,
            WalletInteractionFlowKind.AttendedPresent,
            -> WalletInteractionTaskKind.DisclosureReview
            null -> WalletInteractionTaskKind.OfferReview.takeIf { status in RECEIVE_STATUSES }
                ?: WalletInteractionTaskKind.DisclosureReview.takeIf { status in PRESENT_STATUSES }
                ?: WalletInteractionTaskKind.InProgress
        }
    }
    val waitingOn = when (kind) {
        WalletInteractionTaskKind.DeferredIssuance -> WalletInteractionTaskParty.COUNTERPARTY
        WalletInteractionTaskKind.InProgress -> WalletInteractionTaskParty.WALLET
        else -> WalletInteractionTaskParty.HOLDER
    }
    val actions = buildList {
        if (kind != WalletInteractionTaskKind.InProgress) add(WalletInteractionTaskAction.CONTINUE)
        if (kind == WalletInteractionTaskKind.DeferredIssuance && deferred?.resumable != false) {
            add(WalletInteractionTaskAction.RETRY_DEFERRED_RETRIEVAL)
        }
        add(WalletInteractionTaskAction.CANCEL)
    }
    return WalletInteractionTaskProjection(
        sessionId = sessionId.value,
        walletUnitId = walletUnitId,
        flowKind = flowKind,
        protocol = protocol,
        status = status,
        kind = kind,
        waitingOn = waitingOn,
        revision = revision,
        openedAtEpochSeconds = openedAtEpochSeconds,
        updatedAtEpochSeconds = maxOf(openedAtEpochSeconds, nowEpochSeconds),
        counterparty = counterparty,
        deferred = deferred,
        actions = actions,
    )
}

private val TERMINAL_TASK_STATUSES = setOf(
    WalletInteractionStatus.Completed,
    WalletInteractionStatus.Cancelled,
    WalletInteractionStatus.Failed,
    WalletInteractionStatus.UnsupportedEntryPoint,
)

private val RECEIVE_STATUSES = setOf(
    WalletInteractionStatus.CredentialOfferReview,
    WalletInteractionStatus.AuthorizationRequired,
    WalletInteractionStatus.TxCodeRequired,
    WalletInteractionStatus.CredentialPreview,
)

private val PRESENT_STATUSES = setOf(
    WalletInteractionStatus.CredentialSelection,
    WalletInteractionStatus.DisclosureConsent,
)
