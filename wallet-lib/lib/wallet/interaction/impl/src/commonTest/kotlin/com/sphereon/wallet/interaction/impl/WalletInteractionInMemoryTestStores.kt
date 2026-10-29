/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.impl

import com.sphereon.wallet.interaction.WalletInteractionActivityProjection
import com.sphereon.wallet.interaction.WalletInteractionPrivateSessionData
import com.sphereon.wallet.interaction.WalletInteractionPrivateSessionStore
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionStateEvent
import com.sphereon.wallet.interaction.WalletInteractionTaskProjection
import com.sphereon.wallet.interaction.taskProjection
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.flow

class InMemoryWalletInteractionPrivateSessionStore : WalletInteractionPrivateSessionStore {
    private val sessions = mutableMapOf<WalletInteractionSessionId, MutableMap<String, WalletInteractionPrivateSessionData>>()

    override suspend fun put(sessionId: WalletInteractionSessionId, data: WalletInteractionPrivateSessionData) {
        sessions.getOrPut(sessionId) { linkedMapOf() }[data.namespace] = data
    }

    override suspend fun get(sessionId: WalletInteractionSessionId, namespace: String): WalletInteractionPrivateSessionData? =
        sessions[sessionId]?.get(namespace)

    override suspend fun remove(sessionId: WalletInteractionSessionId, namespace: String) {
        sessions[sessionId]?.remove(namespace)
        if (sessions[sessionId]?.isEmpty() == true) sessions.remove(sessionId)
    }

    override suspend fun removeSession(sessionId: WalletInteractionSessionId) {
        sessions.remove(sessionId)
    }
}

class InMemoryWalletInteractionSessionStore(
    private val liveEventBus: WalletInteractionLiveEventBus = ProcessLocalWalletInteractionLiveEventBus(),
) : WalletInteractionSessionStore {
    private val sessions = mutableMapOf<WalletInteractionSessionId, WalletInteractionStoredSession>()
    private val eventHistory = mutableMapOf<WalletInteractionSessionId, MutableList<WalletInteractionStateEvent>>()
    private val activityHistory = mutableMapOf<WalletInteractionSessionId, WalletInteractionActivityProjection>()
    private val activitySequenceByWalletUnit = mutableMapOf<String, Long>()
    private val tasks = mutableMapOf<WalletInteractionSessionId, WalletInteractionTaskProjection>()

    override suspend fun save(session: WalletInteractionStoredSession) {
        sessions[session.sessionId] = session
        val now = kotlin.time.Clock.System.now().epochSeconds
        val task = session.state.taskProjection(tasks[session.sessionId]?.openedAtEpochSeconds ?: now, now)
        if (task == null) tasks.remove(session.sessionId) else tasks[session.sessionId] = task
        val event = session.state.toEvent()
        val events = eventHistory.getOrPut(session.sessionId) { mutableListOf() }
        if (events.lastOrNull()?.revision != event.revision || events.lastOrNull()?.state != event.state) {
            events.add(event)
            liveEventBus.publish(event)
        }
        if (session.state.terminal && activityHistory[session.sessionId]?.status != session.state.status) {
            val sequence = (activitySequenceByWalletUnit[session.state.walletUnitId] ?: 0L) + 1L
            activitySequenceByWalletUnit[session.state.walletUnitId] = sequence
            activityHistory[session.sessionId] = session.state.activityProjection(sequence)
        }
    }

    override suspend fun load(sessionId: WalletInteractionSessionId): WalletInteractionStoredSession? = sessions[sessionId]

    override suspend fun events(sessionId: WalletInteractionSessionId, afterRevision: Long?): List<WalletInteractionStateEvent> =
        eventHistory[sessionId].orEmpty().filter { event -> afterRevision == null || event.revision > afterRevision }

    override fun observeEvents(sessionId: WalletInteractionSessionId, afterRevision: Long?): Flow<WalletInteractionStateEvent> =
        flow {
            events(sessionId, afterRevision).forEach { event -> emit(event) }
            emitAll(liveEventBus.observeEvents(sessionId, afterRevision))
        }

    override suspend fun remove(sessionId: WalletInteractionSessionId) {
        sessions.remove(sessionId)
        eventHistory.remove(sessionId)
        tasks.remove(sessionId)
    }

    override suspend fun listTasks(walletUnitId: String, limit: Int): List<WalletInteractionTaskProjection> =
        tasks.values
            .filter { it.walletUnitId == walletUnitId }
            .sortedWith(compareByDescending<WalletInteractionTaskProjection> { it.updatedAtEpochSeconds }.thenBy { it.sessionId })
            .take(limit)

    override suspend fun listActivity(
        walletUnitId: String,
        afterSequence: Long?,
        limit: Int,
    ): List<WalletInteractionActivityProjection> =
        activityHistory.values
            .asSequence()
            .filter { it.walletUnitId == walletUnitId && (afterSequence == null || it.sequence > afterSequence) }
            .sortedBy { it.sequence }
            .take(limit)
            .toList()

    private fun WalletInteractionState.toEvent(): WalletInteractionStateEvent =
        WalletInteractionStateEvent(sessionId = sessionId, revision = revision, state = this)
}
