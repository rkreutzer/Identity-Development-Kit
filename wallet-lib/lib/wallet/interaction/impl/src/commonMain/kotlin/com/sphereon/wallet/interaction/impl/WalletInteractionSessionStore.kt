/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.impl

import com.sphereon.wallet.interaction.WalletInteractionInput
import com.sphereon.wallet.interaction.WalletInteractionActivityProjection
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionStateEvent
import com.sphereon.wallet.interaction.WalletInteractionTaskProjection
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.filter
import kotlinx.serialization.Serializable

@Serializable
data class WalletInteractionStoredSession(
    val sessionId: WalletInteractionSessionId,
    val input: WalletInteractionInput,
    val adapterId: String?,
    val state: WalletInteractionState,
)

interface WalletInteractionSessionStore {
    suspend fun save(session: WalletInteractionStoredSession)

    suspend fun load(sessionId: WalletInteractionSessionId): WalletInteractionStoredSession?

    suspend fun events(
        sessionId: WalletInteractionSessionId,
        afterRevision: Long? = null,
    ): List<WalletInteractionStateEvent>

    fun observeEvents(
        sessionId: WalletInteractionSessionId,
        afterRevision: Long? = null,
    ): Flow<WalletInteractionStateEvent>

    suspend fun remove(sessionId: WalletInteractionSessionId)

    suspend fun listActivity(
        walletUnitId: String,
        afterSequence: Long? = null,
        limit: Int = 100,
    ): List<WalletInteractionActivityProjection> = emptyList()

    /** Open holder tasks of [walletUnitId], most recently updated first. */
    suspend fun listTasks(
        walletUnitId: String,
        limit: Int = 100,
    ): List<WalletInteractionTaskProjection> = emptyList()
}

interface WalletInteractionLiveEventBus {
    suspend fun publish(event: WalletInteractionStateEvent)

    fun observeEvents(
        sessionId: WalletInteractionSessionId,
        afterRevision: Long? = null,
    ): Flow<WalletInteractionStateEvent>
}

class ProcessLocalWalletInteractionLiveEventBus(
    extraBufferCapacity: Int = 64,
) : WalletInteractionLiveEventBus {
    private val liveEvents = MutableSharedFlow<WalletInteractionStateEvent>(extraBufferCapacity = extraBufferCapacity)

    override suspend fun publish(event: WalletInteractionStateEvent) {
        liveEvents.emit(event)
    }

    override fun observeEvents(
        sessionId: WalletInteractionSessionId,
        afterRevision: Long?,
    ): Flow<WalletInteractionStateEvent> =
        liveEvents.filter { event ->
            event.sessionId == sessionId && (afterRevision == null || event.revision > afterRevision)
        }
}

internal fun WalletInteractionState.activityProjection(
    sequence: Long,
    recordedAtEpochSeconds: Long? = null,
): WalletInteractionActivityProjection {
    val effectiveRecordedAt = recordedAtEpochSeconds
        ?: activity?.metadata?.get("recordedAtEpochSeconds")?.toLongOrNull()
        ?: kotlin.time.Clock.System.now().epochSeconds
    return WalletInteractionActivityProjection(
        sequence = sequence,
        recordedAtEpochSeconds = effectiveRecordedAt,
        sessionId = sessionId.value,
        walletUnitId = walletUnitId,
        flowKind = flowKind,
        status = status,
        counterparty = counterparty,
        credentialRecordIds = when (flowKind) {
            com.sphereon.wallet.interaction.WalletInteractionFlowKind.CredentialReceive -> receivedCredentialPreview.mapTo(linkedSetOf()) { it.id }
            com.sphereon.wallet.interaction.WalletInteractionFlowKind.CredentialPresent,
            com.sphereon.wallet.interaction.WalletInteractionFlowKind.AttendedPresent,
            -> disclosure?.selectedCredentialIds.orEmpty().toSet()
            null -> emptySet()
        },
        authorizationDecision = activity?.authorizationDecision,
    )
}
