/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.impl

import com.sphereon.data.store.kv.InMemoryKvStoreConfig
import com.sphereon.data.store.kv.KvStore
import com.sphereon.data.store.kv.KvStoreScopeBinding
import com.sphereon.data.store.kv.memory.InMemoryKvBackingStorageImpl
import com.sphereon.data.store.kv.memory.InMemoryKvStoreFactoryImpl
import com.sphereon.wallet.interaction.WalletDeferredRetrievalSummary
import com.sphereon.wallet.interaction.WalletEntryPoint
import com.sphereon.wallet.interaction.WalletInteractionFlowKind
import com.sphereon.wallet.interaction.WalletInteractionInput
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.interaction.WalletInteractionTaskAction
import com.sphereon.wallet.interaction.WalletInteractionTaskKind
import com.sphereon.wallet.interaction.WalletInteractionTaskParty
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Instant

class KvWalletInteractionSessionStoreTaskTest {
    private val clock = SteppingClock(1_760_000_000)

    @Test
    fun openInteractionsAreTasksOfTheirWalletUnitOnly() =
        runTest {
            val store = KvWalletInteractionSessionStore(kv(), clock = clock)
            store.save(session("offer", "wallet-a", WalletInteractionStatus.CredentialOfferReview, WalletInteractionFlowKind.CredentialReceive))
            clock.advance(5)
            store.save(session("consent", "wallet-a", WalletInteractionStatus.DisclosureConsent, WalletInteractionFlowKind.CredentialPresent))
            store.save(session("other", "wallet-b", WalletInteractionStatus.CredentialOfferReview, WalletInteractionFlowKind.CredentialReceive))

            val tasks = store.listTasks("wallet-a")

            assertEquals(listOf("consent", "offer"), tasks.map { it.sessionId })
            assertEquals(WalletInteractionTaskKind.DisclosureReview, tasks[0].kind)
            assertEquals(WalletInteractionTaskKind.OfferReview, tasks[1].kind)
            assertEquals(WalletInteractionTaskParty.HOLDER, tasks[1].waitingOn)
            assertEquals(listOf(WalletInteractionTaskAction.CONTINUE, WalletInteractionTaskAction.CANCEL), tasks[1].actions)
        }

    @Test
    fun deferredIssuanceKeepsItsOpeningTimeAndOffersRetry() =
        runTest {
            val store = KvWalletInteractionSessionStore(kv(), clock = clock)
            store.save(session("deferred", "wallet-a", WalletInteractionStatus.CredentialOfferReview, WalletInteractionFlowKind.CredentialReceive))
            val openedAt = clock.now().epochSeconds
            clock.advance(60)
            store.save(
                session(
                    "deferred",
                    "wallet-a",
                    WalletInteractionStatus.DeferredRetrievalPending,
                    WalletInteractionFlowKind.CredentialReceive,
                    revision = 2,
                    deferred = WalletDeferredRetrievalSummary(intervalSeconds = 30, attempt = 1),
                ),
            )

            val task = store.listTasks("wallet-a").single()

            assertEquals(WalletInteractionTaskKind.DeferredIssuance, task.kind)
            assertEquals(WalletInteractionTaskParty.COUNTERPARTY, task.waitingOn)
            assertEquals(openedAt, task.openedAtEpochSeconds)
            assertEquals(openedAt + 60, task.updatedAtEpochSeconds)
            assertEquals(30, task.deferred?.intervalSeconds)
            assertTrue(WalletInteractionTaskAction.RETRY_DEFERRED_RETRIEVAL in task.actions)
        }

    @Test
    fun aTerminalStateClosesTheTask() =
        runTest {
            val store = KvWalletInteractionSessionStore(kv(), clock = clock)
            store.save(session("done", "wallet-a", WalletInteractionStatus.DisclosureConsent, WalletInteractionFlowKind.CredentialPresent))
            store.save(
                session("done", "wallet-a", WalletInteractionStatus.Completed, WalletInteractionFlowKind.CredentialPresent, revision = 2, terminal = true),
            )

            assertTrue(store.listTasks("wallet-a").isEmpty())
            assertEquals(listOf("done"), store.listActivity("wallet-a").map { it.sessionId })
        }

    @Test
    fun runningProtocolWorkIsNotOfferedToContinue() =
        runTest {
            val store = KvWalletInteractionSessionStore(kv(), clock = clock)
            store.save(session("sharing", "wallet-a", WalletInteractionStatus.Sharing, WalletInteractionFlowKind.CredentialPresent))

            val task = store.listTasks("wallet-a").single()

            assertEquals(WalletInteractionTaskKind.InProgress, task.kind)
            assertEquals(WalletInteractionTaskParty.WALLET, task.waitingOn)
            assertEquals(listOf(WalletInteractionTaskAction.CANCEL), task.actions)
        }

    private fun session(
        id: String,
        walletUnitId: String,
        status: WalletInteractionStatus,
        flowKind: WalletInteractionFlowKind,
        revision: Long = 1,
        terminal: Boolean = false,
        deferred: WalletDeferredRetrievalSummary? = null,
    ): WalletInteractionStoredSession {
        val sessionId = WalletInteractionSessionId(id)
        return WalletInteractionStoredSession(
            sessionId = sessionId,
            input = WalletInteractionInput(walletUnitId, WalletEntryPoint.rawQr("openid-credential-offer://?credential_offer=x")),
            adapterId = "oid4vci",
            state = WalletInteractionState(
                sessionId = sessionId,
                walletUnitId = walletUnitId,
                status = status,
                revision = revision,
                flowKind = flowKind,
                deferred = deferred,
                terminal = terminal,
            ),
        )
    }

    private fun kv(): KvStore =
        InMemoryKvStoreFactoryImpl(InMemoryKvBackingStorageImpl()).create(
            InMemoryKvStoreConfig(id = "wallet-interaction-task-test", scopeBinding = KvStoreScopeBinding.APP),
            execution = null,
        )

    private class SteppingClock(private var epochSeconds: Long) : Clock {
        override fun now(): Instant = Instant.fromEpochSeconds(epochSeconds)

        fun advance(seconds: Long) {
            epochSeconds += seconds
        }
    }
}
