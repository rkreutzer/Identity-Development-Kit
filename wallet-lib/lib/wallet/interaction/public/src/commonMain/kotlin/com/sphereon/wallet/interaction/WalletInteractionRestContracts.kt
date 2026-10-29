/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction

import kotlinx.serialization.Serializable

/**
 * Public REST projection for wallet interaction sessions.
 *
 * These endpoint commands adapt the neutral wallet interaction commands to HTTP
 * resources. They are not the internal backend command transport. `/events`
 * is a bounded replay/SSE projection; live updates use
 * [WalletInteractionApiConstants.Commands.OBSERVE_EVENTS] over command
 * streaming.
 */
object WalletInteractionApiConstants {
    const val BASE_PATH: String = "/api/wallet/interaction/v1"

    object Paths {
        const val INTERACTIONS: String = "/wallets/{walletUnitId}/interactions"
        const val INTERACTION: String = "/wallets/{walletUnitId}/interactions/{sessionId}"
        const val RESUME: String = "/wallets/{walletUnitId}/interactions/{sessionId}/resume"
        const val ACTIONS: String = "/wallets/{walletUnitId}/interactions/{sessionId}/actions"
        const val STATE: String = "/wallets/{walletUnitId}/interactions/{sessionId}/state"
        const val EVENTS: String = "/wallets/{walletUnitId}/interactions/{sessionId}/events"
        const val FRAMES: String = "/wallets/{walletUnitId}/interactions/{sessionId}/frames"
        const val SENSITIVE_INPUTS: String = "/wallets/{walletUnitId}/interactions/{sessionId}/sensitive-inputs"
        const val AUTHORIZATION_HANDOFF: String = "/wallets/{walletUnitId}/interactions/{sessionId}/authorization-handoff"
        const val COMPLETION_HANDOFF: String = "/wallets/{walletUnitId}/interactions/{sessionId}/completion-handoff"
        const val ACTIVITY: String = "/wallets/{walletUnitId}/activity"
        const val TASKS: String = "/wallets/{walletUnitId}/tasks"
    }

    object Commands {
        const val START: String = "wallet.interaction.start"
        const val RESUME: String = "wallet.interaction.resume"
        const val DISPATCH_ACTION: String = "wallet.interaction.submit-action"
        const val CANCEL: String = "wallet.interaction.cancel"
        const val GET_STATE: String = "wallet.interaction.get-state"
        const val GET_EVENTS: String = "wallet.interaction.get-events"
        const val OBSERVE_EVENTS: String = "wallet.interaction.observe-events"

        /**
         * Authorization identity of the multiplexed frame transport. There is no dedicated
         * neutral service command behind it; the frame handler dispatches [RESUME],
         * [DISPATCH_ACTION], and [CANCEL] under their own ids.
         */
        const val FRAME: String = "wallet.interaction.frame"

        /**
         * Neutral service command ids the sensitive-input and activity endpoints authorize as.
         * Taken from the command declarations rather than repeated as literals so a rename cannot
         * leave the REST projection authorizing under an id no policy knows.
         */
        const val REGISTER_SENSITIVE_INPUT: String = RegisterWalletInteractionSensitiveInputCommand.COMMAND_ID
        const val CONSUME_AUTHORIZATION_HANDOFF: String = ConsumeWalletInteractionAuthorizationHandoffCommand.COMMAND_ID
        const val CONSUME_COMPLETION_HANDOFF: String = ConsumeWalletInteractionCompletionHandoffCommand.COMMAND_ID
        const val LIST_ACTIVITY: String = ListWalletInteractionActivityCommand.COMMAND_ID
        const val LIST_TASKS: String = ListWalletInteractionTasksCommand.COMMAND_ID
    }

    object EndpointCommands {
        const val START: String = "wallet.interaction-http.start"
        const val RESUME: String = "wallet.interaction-http.resume"
        const val DISPATCH_ACTION: String = "wallet.interaction-http.submit-action"
        const val CANCEL: String = "wallet.interaction-http.cancel"
        const val GET_STATE: String = "wallet.interaction-http.get-state"
        const val GET_EVENTS: String = "wallet.interaction-http.get-events"
        const val FRAME: String = "wallet.interaction-http.frame"
        const val REGISTER_SENSITIVE_INPUT: String = "wallet.interaction-http.register-sensitive-input"
        const val CONSUME_AUTHORIZATION_HANDOFF: String = "wallet.interaction-http.consume-authorization-handoff"
        const val CONSUME_COMPLETION_HANDOFF: String = "wallet.interaction-http.consume-completion-handoff"
        const val LIST_ACTIVITY: String = "wallet.interaction-http.list-activity"
        const val LIST_TASKS: String = "wallet.interaction-http.list-tasks"
    }

    object Sse {
        const val EVENT_STATE: String = "wallet-interaction-state"
        const val LAST_EVENT_ID_HEADER: String = "Last-Event-ID"
    }

    object Errors {
        /**
         * Refusal code of a conditional dispatch whose stated revision is not the revision the
         * session is at. Carried by [WalletInteractionRevisionConflict] on the actions endpoint
         * and by the ERROR server frame on the frame transport, both under HTTP 409.
         */
        const val REVISION_CONFLICT: String = "wallet_interaction_revision_conflict"

        /** Localization key paired with [REVISION_CONFLICT]. */
        const val REVISION_CONFLICT_MESSAGE_KEY: String = "wallet.interaction.error.revision_conflict"
    }
}

@Serializable
data class StartWalletInteractionBody(
    val input: WalletInteractionInput,
)

/**
 * Request body of the actions endpoint.
 *
 * [expectedRevision] makes the dispatch a conditional write. The endpoint reads the session
 * state first and refuses with 409 and a [WalletInteractionRevisionConflict] unless the session
 * is still at exactly that revision, so an approval decided against a screen the user is no
 * longer looking at is never applied. It is carried in the body rather than in a header because
 * the frame transport already carries the same precondition as
 * [WalletInteractionClientFrame.lastRevision], and because a body member cannot be stripped by
 * an intermediary the way an unrecognized header can.
 *
 * [idempotencyKey] names one dispatch attempt for the [WalletInteractionActionAuthority] that
 * arbitrates the session. The managed-wallet authority keys an action receipt on it and replays
 * the recorded state for a repeat of the same action; the local authority does not deduplicate,
 * and there it is [expectedRevision] that stops a retry of an already applied action.
 */
@Serializable
data class DispatchWalletInteractionActionBody(
    val action: WalletInteractionAction,
    val expectedRevision: Long? = null,
    val idempotencyKey: String? = null,
) {
    init {
        require(expectedRevision == null || expectedRevision >= 0) {
            "wallet_interaction_expected_revision_invalid"
        }
        require(idempotencyKey == null || idempotencyKey.isNotBlank()) {
            "wallet_interaction_action_idempotency_key_blank"
        }
    }
}

/**
 * Body of the 409 answer to a conditional dispatch that was refused. Nothing was applied. The
 * current [state] travels with the refusal so the client can re-render and let the user decide
 * again without a second round trip; [currentRevision] is always `state.revision`.
 */
@Serializable
data class WalletInteractionRevisionConflict(
    val sessionId: WalletInteractionSessionId,
    val expectedRevision: Long,
    val currentRevision: Long,
    val state: WalletInteractionState,
)

/**
 * Request body for registering client-supplied sensitive protocol input. The wallet unit and
 * session come from the path. The value is stored only in the private session store, is never
 * echoed back in any response or interaction state, and is never logged.
 */
@Serializable
data class RegisterWalletInteractionSensitiveInputRequest(
    val purpose: WalletInteractionSensitiveInputPurpose,
    val value: String,
) {
    init {
        require(value.isNotBlank()) { "wallet_interaction_sensitive_input_blank" }
    }

    override fun toString(): String = "RegisterWalletInteractionSensitiveInputRequest(purpose=$purpose, value=[redacted])"
}

@Serializable
data class WalletInteractionSessionEnvelope(
    val session: WalletInteractionSession,
)

@Serializable
data class WalletInteractionStateEnvelope(
    val state: WalletInteractionState,
)

@Serializable
data class CancelWalletInteractionResult(
    val sessionId: WalletInteractionSessionId,
    val state: WalletInteractionState,
)

/**
 * One client frame of the request/response frame transport.
 *
 * On a [WalletInteractionClientFrameType.DISPATCH_ACTION] frame, [lastRevision] is the same
 * conditional-write precondition as [DispatchWalletInteractionActionBody.expectedRevision]: the
 * frame is refused with 409 and an ERROR server frame carrying the current state unless the
 * session is still at that revision. It is ignored on RESUME, CANCEL, and PING, which do not
 * advance the state machine on the client's behalf.
 */
@Serializable
data class WalletInteractionClientFrame(
    val type: WalletInteractionClientFrameType,
    val sessionId: WalletInteractionSessionId,
    val action: WalletInteractionAction? = null,
    val lastRevision: Long? = null,
) {
    init {
        require(lastRevision == null || lastRevision >= 0) {
            "wallet_interaction_expected_revision_invalid"
        }
    }
}

@Serializable
enum class WalletInteractionClientFrameType {
    RESUME,
    DISPATCH_ACTION,
    CANCEL,
    PING,
}

@Serializable
data class WalletInteractionServerFrame(
    val type: WalletInteractionServerFrameType,
    val sessionId: WalletInteractionSessionId,
    val revision: Long? = null,
    val state: WalletInteractionState? = null,
    val error: WalletInteractionError? = null,
)

@Serializable
enum class WalletInteractionServerFrameType {
    STATE,
    ACK,
    ERROR,
    PONG,
}

fun WalletInteractionApiConstants.interactionsPath(walletUnitId: String): String = "${WalletInteractionApiConstants.BASE_PATH}/wallets/$walletUnitId/interactions"

fun WalletInteractionApiConstants.interactionPath(
    walletUnitId: String,
    sessionId: WalletInteractionSessionId,
): String = "${interactionsPath(walletUnitId)}/${sessionId.value}"

fun WalletInteractionApiConstants.resumePath(
    walletUnitId: String,
    sessionId: WalletInteractionSessionId,
): String = "${interactionPath(walletUnitId, sessionId)}/resume"

fun WalletInteractionApiConstants.actionsPath(
    walletUnitId: String,
    sessionId: WalletInteractionSessionId,
): String = "${interactionPath(walletUnitId, sessionId)}/actions"

fun WalletInteractionApiConstants.statePath(
    walletUnitId: String,
    sessionId: WalletInteractionSessionId,
): String = "${interactionPath(walletUnitId, sessionId)}/state"

fun WalletInteractionApiConstants.eventsPath(
    walletUnitId: String,
    sessionId: WalletInteractionSessionId,
): String = "${interactionPath(walletUnitId, sessionId)}/events"

fun WalletInteractionApiConstants.framePath(
    walletUnitId: String,
    sessionId: WalletInteractionSessionId,
): String = "${interactionPath(walletUnitId, sessionId)}/frames"

fun WalletInteractionApiConstants.sensitiveInputsPath(
    walletUnitId: String,
    sessionId: WalletInteractionSessionId,
): String = "${interactionPath(walletUnitId, sessionId)}/sensitive-inputs"

fun WalletInteractionApiConstants.authorizationHandoffPath(
    walletUnitId: String,
    sessionId: WalletInteractionSessionId,
): String = "${interactionPath(walletUnitId, sessionId)}/authorization-handoff"

fun WalletInteractionApiConstants.activityPath(walletUnitId: String): String = "${WalletInteractionApiConstants.BASE_PATH}/wallets/$walletUnitId/activity"
