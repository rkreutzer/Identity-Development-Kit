/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.impl

import com.sphereon.data.store.kv.KotlinxSerializationJsonKvCodec
import com.sphereon.data.store.kv.KvNamespace
import com.sphereon.data.store.kv.KvStore
import com.sphereon.data.store.kv.KvStoreListing
import com.sphereon.data.store.kv.KvStoreVersioning
import com.sphereon.data.store.kv.KvVersionAppendResult
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionStateEvent
import com.sphereon.wallet.interaction.WalletInteractionActivityProjection
import com.sphereon.wallet.interaction.WalletInteractionTaskProjection
import com.sphereon.wallet.interaction.taskProjection
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlin.time.Clock
import kotlin.time.Duration

/**
 * KV-backed interaction session store for backend and web-wallet runtimes.
 *
 * Persisted events contain the same UI-safe [WalletInteractionState] sent to clients.
 * Protocol secrets belong in [KvWalletInteractionPrivateSessionStore], not in these
 * replayable UI state events.
 */
class KvWalletInteractionSessionStore(
    private val kv: KvStore,
    private val ttl: Duration = Duration.INFINITE,
    private val liveEventBus: WalletInteractionLiveEventBus = ProcessLocalWalletInteractionLiveEventBus(),
    json: Json = walletInteractionStoreJson,
    private val clock: Clock = Clock.System,
) : WalletInteractionSessionStore {
    private val sessionNamespace =
        KvNamespace(
            name = SESSION_NAMESPACE,
            codec = KotlinxSerializationJsonKvCodec(json, WalletInteractionStoredSession.serializer()),
        )
    private val eventNamespace =
        KvNamespace(
            name = EVENT_NAMESPACE,
            codec = KotlinxSerializationJsonKvCodec(json, KvWalletInteractionEventHistory.serializer()),
        )
    private val activityNamespace =
        KvNamespace(
            name = ACTIVITY_NAMESPACE,
            codec = KotlinxSerializationJsonKvCodec(json, WalletInteractionActivityProjection.serializer()),
        )
    private val taskNamespace =
        KvNamespace(
            name = TASK_NAMESPACE,
            codec = KotlinxSerializationJsonKvCodec(json, WalletInteractionTaskProjection.serializer()),
        )
    private val activitySequenceNamespace =
        KvNamespace(
            name = ACTIVITY_SEQUENCE_NAMESPACE,
            codec = KotlinxSerializationJsonKvCodec(json, KvWalletInteractionActivitySequence.serializer()),
        )

    override suspend fun save(session: WalletInteractionStoredSession) {
        kv.put(sessionNamespace, session.sessionId.value, session, ttl).getOrThrow()

        val event = session.state.toEvent()
        val history = eventHistory(session.sessionId)
        if (history.events.lastOrNull()?.revision != event.revision || history.events.lastOrNull()?.state != event.state) {
            kv.put(eventNamespace, session.sessionId.value, history.copy(events = history.events + event), ttl).getOrThrow()
            liveEventBus.publish(event)
        }
        recordTask(session.state)
        if (session.state.terminal) {
            val existing = kv.get(activityNamespace, session.sessionId.value).getOrThrow()
            if (existing?.status != session.state.status) {
                val sequence = allocateActivitySequence(session.state.walletUnitId)
                kv.put(activityNamespace, session.sessionId.value, session.state.activityProjection(sequence), ttl).getOrThrow()
            }
        }
    }

    override suspend fun load(sessionId: WalletInteractionSessionId): WalletInteractionStoredSession? = kv.get(sessionNamespace, sessionId.value).getOrThrow()

    override suspend fun events(
        sessionId: WalletInteractionSessionId,
        afterRevision: Long?,
    ): List<WalletInteractionStateEvent> =
        eventHistory(sessionId)
            .events
            .filter { event -> afterRevision == null || event.revision > afterRevision }

    override fun observeEvents(
        sessionId: WalletInteractionSessionId,
        afterRevision: Long?,
    ): Flow<WalletInteractionStateEvent> =
        flow {
            coroutineScope {
                val bufferedLiveEvents = Channel<WalletInteractionStateEvent>(Channel.UNLIMITED)
                val liveCollector =
                    launch(start = CoroutineStart.UNDISPATCHED) {
                        try {
                            liveEventBus.observeEvents(sessionId, afterRevision).collect { event -> bufferedLiveEvents.send(event) }
                        } finally {
                            bufferedLiveEvents.close()
                        }
                    }
                val emittedIdentities = mutableSetOf<Pair<WalletInteractionSessionId, Long>>()
                try {
                    events(sessionId, afterRevision).forEach { event ->
                        if (emittedIdentities.add(event.identity())) emit(event)
                    }
                    for (event in bufferedLiveEvents) {
                        if (emittedIdentities.add(event.identity())) emit(event)
                    }
                } finally {
                    liveCollector.cancel()
                    bufferedLiveEvents.close()
                }
            }
        }

    override suspend fun remove(sessionId: WalletInteractionSessionId) {
        kv.delete(sessionNamespace, sessionId.value).getOrThrow()
        kv.delete(eventNamespace, sessionId.value).getOrThrow()
        kv.delete(taskNamespace, sessionId.value).getOrThrow()
    }

    override suspend fun listTasks(
        walletUnitId: String,
        limit: Int,
    ): List<WalletInteractionTaskProjection> {
        val listing = kv as? KvStoreListing ?: error("wallet_interaction_task_listing_unavailable")
        val tasks = mutableListOf<WalletInteractionTaskProjection>()
        for (key in listing.listKeys(taskNamespace).getOrThrow()) {
            kv.get(taskNamespace, key).getOrThrow()?.takeIf { it.walletUnitId == walletUnitId }?.let(tasks::add)
        }
        return tasks
            .sortedWith(compareByDescending<WalletInteractionTaskProjection> { it.updatedAtEpochSeconds }.thenBy { it.sessionId })
            .take(limit)
    }

    /**
     * Keeps the task index in step with the session: a non-terminal state is an open task, a
     * terminal one closes it. The index carries the times the state does not: when the task opened
     * and when it last changed.
     */
    private suspend fun recordTask(state: WalletInteractionState) {
        val now = clock.now().epochSeconds
        val existing = kv.get(taskNamespace, state.sessionId.value).getOrThrow()
        val task = state.taskProjection(openedAtEpochSeconds = existing?.openedAtEpochSeconds ?: now, nowEpochSeconds = now)
        when {
            task == null -> if (existing != null) kv.delete(taskNamespace, state.sessionId.value).getOrThrow()
            existing == null || existing.revision != task.revision || existing.status != task.status ->
                kv.put(taskNamespace, state.sessionId.value, task, ttl).getOrThrow()
        }
    }

    override suspend fun listActivity(
        walletUnitId: String,
        afterSequence: Long?,
        limit: Int,
    ): List<WalletInteractionActivityProjection> {
        val listing = kv as? KvStoreListing ?: error("wallet_interaction_activity_listing_unavailable")
        val entries = mutableListOf<WalletInteractionActivityProjection>()
        for (key in listing.listKeys(activityNamespace).getOrThrow()) {
            kv.get(activityNamespace, key).getOrThrow()?.let(entries::add)
        }
        return entries
            .asSequence()
            .filter { it.walletUnitId == walletUnitId && (afterSequence == null || it.sequence > afterSequence) }
            .sortedBy { it.sequence }
            .take(limit)
            .toList()
    }

    private suspend fun eventHistory(sessionId: WalletInteractionSessionId): KvWalletInteractionEventHistory = kv.get(eventNamespace, sessionId.value).getOrThrow() ?: KvWalletInteractionEventHistory()

    private suspend fun allocateActivitySequence(walletUnitId: String): Long {
        val versioning = kv as? KvStoreVersioning ?: error("wallet_interaction_activity_versioning_unavailable")
        repeat(MAX_ACTIVITY_SEQUENCE_ATTEMPTS) {
            val head = versioning.getHead(activitySequenceNamespace, walletUnitId).getOrThrow()
            val sequence = (head?.value?.lastSequence ?: 0L) + 1L
            when (
                versioning.append(
                    namespace = activitySequenceNamespace,
                    key = walletUnitId,
                    expectedPreviousVersionId = head?.versionId,
                    value = KvWalletInteractionActivitySequence(sequence),
                    ttl = Duration.INFINITE,
                ).getOrThrow()
            ) {
                is KvVersionAppendResult.Applied -> return sequence
                is KvVersionAppendResult.Conflict -> Unit
            }
        }
        error("wallet_interaction_activity_sequence_conflict")
    }

    private fun WalletInteractionState.toEvent(): WalletInteractionStateEvent =
        WalletInteractionStateEvent(
            sessionId = sessionId,
            revision = revision,
            state = this,
        )

    private fun WalletInteractionStateEvent.identity(): Pair<WalletInteractionSessionId, Long> = sessionId to revision

    private companion object {
        const val SESSION_NAMESPACE = "wallet-interaction-sessions"
        const val EVENT_NAMESPACE = "wallet-interaction-events"
        const val ACTIVITY_NAMESPACE = "wallet-interaction-activity"
        const val ACTIVITY_SEQUENCE_NAMESPACE = "wallet-interaction-activity-sequence"
        const val TASK_NAMESPACE = "wallet-interaction-tasks"
        const val MAX_ACTIVITY_SEQUENCE_ATTEMPTS = 32
    }
}

@Serializable
private data class KvWalletInteractionEventHistory(
    val events: List<WalletInteractionStateEvent> = emptyList(),
)

@Serializable
private data class KvWalletInteractionActivitySequence(
    val lastSequence: Long,
)

internal val walletInteractionStoreJson: Json =
    Json {
        ignoreUnknownKeys = true
        encodeDefaults = true
        explicitNulls = false
    }
