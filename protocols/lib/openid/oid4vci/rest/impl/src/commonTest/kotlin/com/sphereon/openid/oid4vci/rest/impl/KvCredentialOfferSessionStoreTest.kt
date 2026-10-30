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
 */

package com.sphereon.openid.oid4vci.rest.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.ConfigService
import com.sphereon.core.api.context.ContextConfig
import com.sphereon.core.api.context.IdkScope
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.log.AbstractLogManager
import com.sphereon.core.api.log.AppLogManager
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.data.store.kv.InMemoryKvStoreConfig
import com.sphereon.data.store.kv.KvEntry
import com.sphereon.data.store.kv.KvEntryMetadata
import com.sphereon.data.store.kv.KvNamespace
import com.sphereon.data.store.kv.KvNamespaceId
import com.sphereon.data.store.kv.KvPutResult
import com.sphereon.data.store.kv.KvStore
import com.sphereon.data.store.kv.KvStoreConfig
import com.sphereon.data.store.kv.KvStoreConfigBase
import com.sphereon.data.store.kv.KvStoreScopeBinding
import com.sphereon.data.store.kv.KvStoreVersioning
import com.sphereon.data.store.kv.KvVersionAppendResult
import com.sphereon.data.store.kv.KvVersionedEntry
import com.sphereon.data.store.kv.impl.KvStoreManager
import com.sphereon.data.store.kv.impl.KvStoreService
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionContextManager
import com.sphereon.openid.oid4vci.rest.CredentialOfferSession
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStatus
import com.sphereon.openid.oid4vci.rest.CredentialOfferTemplate
import com.sphereon.openid.oid4vci.rest.OfferRequestClaim
import com.sphereon.openid.oid4vci.rest.OfferRequestOutcome
import com.sphereon.openid.oid4vci.rest.OfferRequestReservation
import com.sphereon.openid.oid4vci.rest.OfferRequestState
import com.sphereon.openid.oid4vci.rest.Oid4vciRestConfig
import com.sphereon.openid.oid4vci.rest.Oid4vciRestConfigProvider
import com.sphereon.openid.oid4vci.rest.Oid4vciRestErrorCodes
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

class KvCredentialOfferSessionStoreTest {
    private val instanceId = "issuer-instance-credential-offer-store"

    private fun createStore(
        declared: Boolean = true,
        backendId: String = SHARED_BACKEND,
        versioned: Boolean = true,
        acknowledgedProcessLocal: Boolean = false,
        scopeBinding: KvStoreScopeBinding = KvStoreScopeBinding.TENANT,
    ): StoreFixture {
        val kvStoreManager = StoreTestKvStoreManager(versioned)
        val kvStoreService = NoOpKvStoreService(declared, backendId, scopeBinding)
        val store =
            KvCredentialOfferSessionStore(
                kvStoreManager = kvStoreManager,
                kvStoreService = kvStoreService,
                execution = StoreTestSessionExecution(),
                appLogManager = StoreTestAppLogManager(),
                configProvider = StoreTestRestConfigProvider(acknowledgedProcessLocal),
            )
        return StoreFixture(store, kvStoreManager.kv, kvStoreService)
    }

    @Test
    fun getByOfferIdReturnsSessionAfterCreate() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            val session =
                CredentialOfferSession(
                    correlationId = "corr-abc",
                    instanceId = instanceId,
                    offerId = "offer-xyz",
                    issuanceSessionId = "issuance-session-offer-xyz",
                    status = CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED,
                    createdAt = now,
                    lastUpdatedAt = now,
                )

            val createResult = store.create(session)
            assertTrue(createResult.isOk, "create should succeed")

            val lookupResult = store.getByOfferId("offer-xyz")
            assertTrue(lookupResult.isOk, "getByOfferId should succeed")
            assertNotNull(lookupResult.value)
            assertEquals("corr-abc", lookupResult.value!!.correlationId)
            assertEquals(instanceId, lookupResult.value!!.instanceId)
            assertEquals("offer-xyz", lookupResult.value!!.offerId)
            assertEquals("issuance-session-offer-xyz", lookupResult.value!!.issuanceSessionId)
        }

    @Test
    fun getByOfferIdReturnsNullForNonexistentOfferId() =
        runTest {
            val store = createStore().store

            val lookupResult = store.getByOfferId("nonexistent-offer")
            assertTrue(lookupResult.isOk, "getByOfferId should succeed for missing id")
            assertNull(lookupResult.value, "value should be null for nonexistent offerId")
        }

    @Test
    fun offerTemplateRoundTripsIntact() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            val template =
                CredentialOfferTemplate(
                    issuerId = "https://issuer.example.com/oid4vci",
                    credentialConfigurationIds = listOf("TestCred", "OtherCred"),
                    preAuthorizedCodeGrant = true,
                    authorizationCodeGrant = false,
                    txCodeRequired = true,
                    preSeededAttributes = mapOf("given_name" to JsonPrimitive("Ada")),
                    offerTtlSeconds = 1200,
                    scheme = "haip://",
                )
            val session =
                CredentialOfferSession(
                    correlationId = "corr-tmpl",
                    instanceId = instanceId,
                    offerId = "offer-tmpl",
                    issuanceSessionId = "issuance-session-offer-template",
                    status = CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED,
                    createdAt = now,
                    lastUpdatedAt = now,
                    offerTemplate = template,
                )

            assertTrue(store.create(session).isOk, "create should succeed")

            val loaded = store.getByOfferId("offer-tmpl")
            assertTrue(loaded.isOk, "getByOfferId should succeed")
            assertNotNull(loaded.value)
            assertEquals(template, loaded.value!!.offerTemplate)
        }

    @Test
    fun nullOfferTemplateRoundTripsAsNull() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            val session =
                CredentialOfferSession(
                    correlationId = "corr-no-tmpl",
                    instanceId = instanceId,
                    offerId = "offer-no-tmpl",
                    issuanceSessionId = "issuance-session-no-template",
                    status = CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED,
                    createdAt = now,
                    lastUpdatedAt = now,
                )

            assertTrue(store.create(session).isOk, "create should succeed")

            val loaded = store.getByOfferId("offer-no-tmpl")
            assertTrue(loaded.isOk, "getByOfferId should succeed")
            assertNotNull(loaded.value)
            assertNull(loaded.value!!.offerTemplate, "absent template must round-trip as null")
        }

    @Test
    fun shouldKeepASessionForTheRetentionGraceAfterItsOfferExpires() =
        runTest {
            val fixture = createStore()
            val now = Clock.System.now().toEpochMilliseconds()

            assertTrue(fixture.store.create(session("corr-grace", "offer-grace", createdAt = now, expiresAt = now + 600_000)).isOk)

            assertEquals((600 + RETENTION_GRACE_SECONDS).seconds, fixture.kv.lastTtl("oid4vci.rest.sessions"), "the session outlives its offer by the retention grace")
            assertEquals((600 + RETENTION_GRACE_SECONDS).seconds, fixture.kv.lastTtl("oid4vci.rest.sessions.offer-id"))
        }

    @Test
    fun shouldClaimACorrelationIdOnceAndShowLaterCallersTheFirstClaim() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            val first = OfferRequestReservation("key-1", "digest-a", now, now + 600_000)
            val second = OfferRequestReservation("key-1", "digest-b", now + 1, now + 600_001)

            val firstClaim = store.claimRequest(first).value
            val secondClaim = store.claimRequest(second).value

            assertTrue(firstClaim.claimed)
            assertEquals(first, firstClaim.reservation)
            assertNotNull(firstClaim.version, "a claim names the version it was stored under")
            assertTrue(!secondClaim.claimed)
            assertEquals(first, secondClaim.reservation, "the later caller is shown the claim that holds the key")
            assertEquals(firstClaim.version, secondClaim.version)
            assertTrue(store.claimRequest(OfferRequestReservation("key-2", "digest-a", now, now + 600_000)).value.claimed)
        }

    @Test
    fun shouldKeepAClaimForTheRetentionGraceAfterItExpires() =
        runTest {
            val fixture = createStore()
            val now = Clock.System.now().toEpochMilliseconds()

            fixture.store.claimRequest(OfferRequestReservation("key-ttl", "digest-a", now, now + 600_000))

            val ttl = fixture.kv.lastTtl("oid4vci.rest.sessions.requests")
            assertNotNull(ttl)
            assertTrue(ttl >= (599 + RETENTION_GRACE_SECONDS).seconds && ttl <= (600 + RETENTION_GRACE_SECONDS).seconds, "the claim outlives its expiry by the retention grace: $ttl")
        }

    @Test
    fun shouldRefuseARequestClaimWhenTheStoreIsNotDeclared() =
        runTest {
            val store = createStore(declared = false).store
            val now = Clock.System.now().toEpochMilliseconds()

            val refused = store.claimRequest(OfferRequestReservation("key-undeclared", "digest-a", now, now + 600_000))

            assertTrue(refused.isErr, "a claim in a store no replica shares would not stop a second offer")
            assertEquals("KV_STORE_NOT_DECLARED", refused.error.code)
            assertTrue(store.create(session("corr-undeclared", "offer-undeclared")).isOk, "sessions still work on the default store")
        }

    @Test
    fun shouldRefuseARequestClaimOnAProcessLocalBackend() =
        runTest {
            val now = Clock.System.now().toEpochMilliseconds()
            for (backend in listOf("memory", "kottage")) {
                val store = createStore(backendId = backend).store

                val refused = store.claimRequest(OfferRequestReservation("key-local", "digest-a", now, now + 600_000))

                assertTrue(refused.isErr, "two replicas could each claim the key on the '$backend' backend")
                assertEquals("KV_STORE_NOT_SHARED", refused.error.code)
            }
        }

    @Test
    fun shouldAllowARequestClaimOnAProcessLocalBackendWhenOneProcessServesTheDeployment() =
        runTest {
            val store = createStore(backendId = "memory", acknowledgedProcessLocal = true).store
            val now = Clock.System.now().toEpochMilliseconds()

            assertTrue(store.claimRequest(OfferRequestReservation("key-local", "digest-a", now, now + 600_000)).value.claimed)
        }

    @Test
    fun shouldRefuseARequestClaimWhenTheDeclaredStoreCannotVersion() =
        runTest {
            val store = createStore(versioned = false).store
            val now = Clock.System.now().toEpochMilliseconds()

            val refused = store.claimRequest(OfferRequestReservation("key-plain", "digest-a", now, now + 600_000))

            assertEquals("KV_VERSIONING_REQUIRED", refused.error.code)
            assertTrue(store.create(session("corr-plain", "offer-plain")).isOk, "sessions do not need versioning")
        }

    @Test
    fun shouldRefuseARequestClaimWhenTheDeclaredStoreUsesAnotherScopeBinding() =
        runTest {
            val store = createStore(scopeBinding = KvStoreScopeBinding.APP).store
            val now = Clock.System.now().toEpochMilliseconds()

            val refused = store.claimRequest(OfferRequestReservation("key-scope", "digest-a", now, now + 600_000))

            assertEquals(KvCredentialOfferSessionStore.SESSION_STORE_ERROR, refused.error.code)
            assertTrue(refused.error.message.defaultMessage.contains("scopeBinding"), refused.error.message.defaultMessage)
        }

    @Test
    fun shouldReadADeclaredStoreConfigurationAgainAfterItCouldNotBeRead() =
        runTest {
            val fixture = createStore()
            fixture.service.failNextLookups = 1
            val now = Clock.System.now().toEpochMilliseconds()
            val reservation = OfferRequestReservation("key-lookup", "digest-a", now, now + 600_000)

            val failed = fixture.store.claimRequest(reservation)
            val retried = fixture.store.claimRequest(reservation)

            assertEquals(KvCredentialOfferSessionStore.SESSION_STORE_ERROR, failed.error.code)
            assertTrue(retried.value.claimed, "a configuration that could not be read is read again, not remembered as undeclared")
        }

    @Test
    fun shouldRefuseABlankCorrelationIdAndTakeAnyOtherLength() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()

            for (key in listOf("", " ")) {
                val refused = store.claimRequest(OfferRequestReservation(key, "digest-a", now, now + 600_000))

                assertEquals(IdkError.ILLEGAL_ARGUMENT_ERROR().code, refused.error.code, "key of length ${key.length}")
            }
            assertTrue(store.claimRequest(OfferRequestReservation("k".repeat(1000), "digest-a", now, now + 600_000)).value.claimed, "a correlation id takes no length bound")
        }

    @Test
    fun shouldFreeAReleasedCorrelationIdForTheNextCaller() =
        runTest {
            val fixture = createStore()
            val store = fixture.store
            val now = Clock.System.now().toEpochMilliseconds()
            val reservation = OfferRequestReservation("key-3", "digest-a", now, now + 600_000)
            val claim = store.claimRequest(reservation).value

            assertTrue(store.releaseRequest(claim).value)

            val corrected = reservation.copy(intentDigest = "digest-corrected")
            val next = store.claimRequest(corrected).value
            assertFalse(next.claimed, "a released key still shows its marker until somebody takes it over")
            assertEquals(OfferRequestState.RELEASED, next.reservation.state, "the marker says the key was given back")
            assertEquals(60.seconds, fixture.kv.lastTtl("oid4vci.rest.sessions.requests"), "the marker lingers only briefly")
            val taken = store.reclaimRequest(next, corrected).value
            assertTrue(taken.claimed)
            assertEquals(corrected, taken.reservation)
        }

    @Test
    fun shouldNotFreeAClaimSomebodyElseHoldsByNow() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            store.claimRequest(OfferRequestReservation("key-4", "digest-a", now - 700_000, now - 100_000))
            val stale = store.claimRequest(OfferRequestReservation("key-4", "digest-a", now, now + 600_000)).value
            val fresh = OfferRequestReservation("key-4", "digest-a", now, now + 600_000)
            assertTrue(store.reclaimRequest(stale, fresh).value.claimed)

            assertFalse(store.releaseRequest(stale).value, "the claim the caller read is gone, the key now belongs to the taker")

            val shown = store.claimRequest(fresh.copy(createdAt = now + 5)).value
            assertFalse(shown.claimed)
            assertEquals(fresh, shown.reservation, "the taker still holds the key")
        }

    @Test
    fun shouldLetExactlyOneOfSeveralCallersThatReadTheSameExpiredClaimTakeItOver() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            store.claimRequest(OfferRequestReservation("key-5", "digest-a", now - 700_000, now - 100_000))
            val observed = store.claimRequest(OfferRequestReservation("key-5", "digest-a", now, now + 600_000)).value
            assertFalse(observed.claimed)
            val gate = CompletableDeferred<Unit>()

            val contenders =
                (1..8).map { index ->
                    async {
                        gate.await()
                        store.reclaimRequest(observed, OfferRequestReservation("key-5", "digest-a", now + index, now + 600_000 + index)).value
                    }
                }
            gate.complete(Unit)
            val answers = contenders.awaitAll()

            assertEquals(1, answers.count { it.claimed }, "exactly one of the callers that read the same claim holds the key")
            val winner = answers.single { it.claimed }
            for (loser in answers.filter { !it.claimed }) {
                assertEquals(winner.reservation, loser.reservation, "a caller that lost is shown the claim that won")
            }
            assertEquals(winner.reservation, store.claimRequest(OfferRequestReservation("key-5", "digest-a", now, now + 600_000)).value.reservation, "the chain head is the winner's claim")
        }

    @Test
    fun shouldClaimAfreshWhenTheClaimTheCallerObservedHasLapsed() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            val lapsed = OfferRequestClaim(claimed = false, reservation = OfferRequestReservation("key-6", "digest-a", now - 700_000, now - 100_000), version = "gone")

            val claim = store.reclaimRequest(lapsed, OfferRequestReservation("key-6", "digest-a", now, now + 600_000)).value

            assertTrue(claim.claimed, "no claim is left on the key, so nobody holds it")
        }

    @Test
    fun shouldRetryAClaimWhoseConflictingHeadLapsedBeforeItWasRead() =
        runTest {
            val fixture = createStore()
            fixture.kv.lapseNextAppendConflicts = 1
            val now = Clock.System.now().toEpochMilliseconds()

            val claim = fixture.store.claimRequest(OfferRequestReservation("key-lapse", "digest-a", now, now + 600_000))

            assertTrue(claim.value.claimed, "a head that lapses between the conflict and the read is a race, not a corrupt state")
        }

    @Test
    fun shouldReportAContendedKeyWhenItsHeadKeepsLapsing() =
        runTest {
            val fixture = createStore()
            fixture.kv.lapseNextAppendConflicts = 10
            val now = Clock.System.now().toEpochMilliseconds()

            val claim = fixture.store.claimRequest(OfferRequestReservation("key-lapse", "digest-a", now, now + 600_000))

            assertEquals(Oid4vciRestErrorCodes.CORRELATION_ID_IN_DOUBT, claim.error.code)
            assertEquals(ErrorCategory.CONFLICT, claim.error.category)
        }

    @Test
    fun shouldRefuseToReclaimFromAClaimThatCarriesNoVersion() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            val unversioned = OfferRequestClaim(claimed = false, reservation = OfferRequestReservation("key-7", "digest-a", now, now + 600_000))

            assertTrue(store.reclaimRequest(unversioned, unversioned.reservation).isErr)
            assertFalse(store.releaseRequest(unversioned).value, "a claim without a version names nothing to free")
            assertTrue(store.completeRequest(unversioned, offerOutcome(now)).isErr)
        }

    @Test
    fun shouldRecordTheOfferOnTheClaimThatStillHoldsTheKey() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            val claim = store.claimRequest(OfferRequestReservation("key-9", "digest-a", now, now + 660_000)).value
            val outcome = offerOutcome(now)

            val completed = store.completeRequest(claim, outcome).value

            assertTrue(completed.claimed)
            assertEquals(OfferRequestState.COMPLETED, completed.reservation.state)
            assertEquals(outcome, completed.reservation.outcome)
            val shown = store.claimRequest(OfferRequestReservation("key-9", "digest-a", now, now + 660_000)).value
            assertFalse(shown.claimed)
            assertEquals(outcome, shown.reservation.outcome, "a later caller is shown the recorded offer")
        }

    @Test
    fun shouldNotRecordAnOfferOnAClaimThatWasTakenOver() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            val slow = store.claimRequest(OfferRequestReservation("key-10", "digest-a", now, now + 660_000)).value
            val taker = OfferRequestReservation("key-10", "digest-a", now + 1, now + 660_001)
            assertTrue(store.reclaimRequest(slow, taker).value.claimed)

            val lost = store.completeRequest(slow, offerOutcome(now)).value

            assertFalse(lost.claimed, "the attempt whose claim was taken over must not hand out its offer")
            assertEquals(taker, lost.reservation, "it is shown the claim that took the key")
        }

    @Test
    fun shouldWithdrawTheCorrelationIdWhenItsSessionIsDeleted() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            val reservation = OfferRequestReservation("key-8", "digest-a", now, now + 600_000)
            val claim = store.claimRequest(reservation).value
            store.completeRequest(claim, offerOutcome(now))
            assertTrue(store.create(session("key-8", "offer-8")).isOk)

            assertTrue(store.delete("key-8").isOk)

            val shown = store.claimRequest(reservation).value
            assertFalse(shown.claimed)
            assertEquals(OfferRequestState.WITHDRAWN, shown.reservation.state, "deleting an offer withdraws its intent, the key creates no other offer")
            assertNull(shown.reservation.outcome)
        }

    @Test
    fun shouldNotClaimAKeyWhenDeletingASessionThatHadNoCorrelationId() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            assertTrue(store.create(session("plain-corr", "offer-plain-corr")).isOk)

            assertTrue(store.delete("plain-corr").isOk)

            assertTrue(store.claimRequest(OfferRequestReservation("plain-corr", "digest-a", now, now + 600_000)).value.claimed, "a plain session leaves no claim behind")
        }

    @Test
    fun getByOfferIdReturnsNullAfterDelete() =
        runTest {
            val store = createStore().store
            val now = Clock.System.now().toEpochMilliseconds()
            val session =
                CredentialOfferSession(
                    correlationId = "corr-del",
                    instanceId = instanceId,
                    offerId = "offer-del",
                    issuanceSessionId = "issuance-session-delete-offer",
                    status = CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED,
                    createdAt = now,
                    lastUpdatedAt = now,
                )

            store.create(session)
            store.delete("corr-del")

            val lookupResult = store.getByOfferId("offer-del")
            assertTrue(lookupResult.isOk, "getByOfferId should succeed after delete")
            assertNull(lookupResult.value, "value should be null after delete")
        }

    private fun offerOutcome(now: Long) =
        OfferRequestOutcome(
            offerUri = "openid-credential-offer://?credential_offer_uri=https://issuer.example/o",
            issuanceSessionId = "issuance-session-outcome",
            instanceId = instanceId,
            offerExpiresAt = now + 600_000,
        )

    private companion object {
        const val RETENTION_GRACE_SECONDS: Long = 3_600
    }
}

private const val SHARED_BACKEND = "shared-test"

private fun session(
    correlationId: String,
    offerId: String,
    createdAt: Long = Clock.System.now().toEpochMilliseconds(),
    expiresAt: Long? = null,
): CredentialOfferSession =
    CredentialOfferSession(
        correlationId = correlationId,
        instanceId = "issuer-instance-credential-offer-store",
        offerId = offerId,
        issuanceSessionId = "issuance-session-$offerId",
        status = CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED,
        createdAt = createdAt,
        lastUpdatedAt = createdAt,
        expiresAt = expiresAt,
    )

// ---------------------------------------------------------------------------
// Minimal test support types
// ---------------------------------------------------------------------------

private class StoreFixture(
    val store: KvCredentialOfferSessionStore,
    val kv: StoreTestKvStore,
    val service: NoOpKvStoreService,
)

private class StoreTestKvStore : KvStore, KvStoreVersioning {
    override val config: KvStoreConfigBase =
        InMemoryKvStoreConfig(id = "test-sessions", scopeBinding = KvStoreScopeBinding.APP)

    private data class Stored(
        val bytes: ByteArray,
        val createdAt: Long,
        val expiresAt: Long
    )

    private val entries = mutableMapOf<String, Stored>()
    private val chains = mutableMapOf<String, Pair<String, Stored>>()
    private val ttls = mutableMapOf<String, Duration>()

    // Holds the head check and the write together like an atomic backend does, and suspends inside it, so concurrent
    // appends really queue up on the lock instead of running one after another by accident.
    private val appendLock = Mutex()

    /** Version ids must never repeat, because a repeated id would make a stale append look current. */
    private var versionSequence = 0

    /** How many fresh claims are answered with a conflict whose head has lapsed by the time it is read. */
    var lapseNextAppendConflicts: Int = 0

    /** The ttl of the last write to [namespaceName], by put or append. */
    fun lastTtl(namespaceName: String): Duration? = ttls[namespaceName]

    override suspend fun <V : Any> getHead(namespace: KvNamespace<V>, key: String): IdkResult<KvVersionedEntry<V>?, IdkError> {
        val head = chains[compositeKey(namespace, key)] ?: return Ok(null)
        val now = Clock.System.now().toEpochMilliseconds()
        if (head.second.expiresAt <= now) {
            chains.remove(compositeKey(namespace, key))
            return Ok(null)
        }
        return Ok(KvVersionedEntry(head.first, null, namespace.codec.decode(head.second.bytes), KvEntryMetadata(createdAtEpochMillis = head.second.createdAt, expiresAtEpochMillis = head.second.expiresAt)))
    }

    override suspend fun <V : Any> getVersion(namespace: KvNamespace<V>, key: String, versionId: String): IdkResult<KvVersionedEntry<V>?, IdkError> =
        getHead(namespace, key).map { head -> head?.takeIf { it.versionId == versionId } }

    override suspend fun <V : Any> append(
        namespace: KvNamespace<V>,
        key: String,
        expectedPreviousVersionId: String?,
        value: V,
        ttl: Duration,
    ): IdkResult<KvVersionAppendResult<V>, IdkError> =
        appendLock.withLock {
            yield()
            if (expectedPreviousVersionId == null && lapseNextAppendConflicts > 0) {
                lapseNextAppendConflicts--
                return@withLock Ok(KvVersionAppendResult.Conflict(null))
            }
            val head = getHead(namespace, key).getOrElse { return@withLock Err(it) }
            if (head?.versionId != expectedPreviousVersionId) return@withLock Ok(KvVersionAppendResult.Conflict(head))
            val now = Clock.System.now().toEpochMilliseconds()
            val expiresAt = if (ttl.isInfinite()) Long.MAX_VALUE else now + ttl.inWholeMilliseconds
            val versionId = "v${++versionSequence}"
            chains[compositeKey(namespace, key)] = versionId to Stored(namespace.codec.encode(value), now, expiresAt)
            ttls[namespace.name] = ttl
            Ok(KvVersionAppendResult.Applied(KvVersionedEntry(versionId, expectedPreviousVersionId, value, KvEntryMetadata(createdAtEpochMillis = now, expiresAtEpochMillis = expiresAt))))
        }

    override suspend fun deleteVersioned(namespace: KvNamespaceId, key: String): IdkResult<Boolean, IdkError> =
        Ok(chains.remove(compositeKey(namespace, key)) != null)

    private fun compositeKey(
        namespace: KvNamespaceId,
        key: String,
    ) = "${namespace.name}:$key"

    override suspend fun <V : Any> put(
        namespace: KvNamespace<V>,
        key: String,
        value: V,
        ttl: Duration,
    ): IdkResult<KvPutResult, IdkError> {
        val now = Clock.System.now().toEpochMilliseconds()
        val expiresAt = if (ttl.isInfinite()) Long.MAX_VALUE else now + ttl.inWholeMilliseconds
        entries[compositeKey(namespace, key)] = Stored(bytes = namespace.codec.encode(value), createdAt = now, expiresAt = expiresAt)
        ttls[namespace.name] = ttl
        return Ok(KvPutResult(metadata = KvEntryMetadata(createdAtEpochMillis = now, expiresAtEpochMillis = expiresAt)))
    }

    override suspend fun <V : Any> get(
        namespace: KvNamespace<V>,
        key: String,
    ): IdkResult<V?, IdkError> = getEntry(namespace, key).map { it?.value }

    override suspend fun <V : Any> getEntry(
        namespace: KvNamespace<V>,
        key: String,
    ): IdkResult<KvEntry<V>?, IdkError> {
        val now = Clock.System.now().toEpochMilliseconds()
        val stored = entries[compositeKey(namespace, key)] ?: return Ok(null)
        if (stored.expiresAt <= now) {
            entries.remove(compositeKey(namespace, key))
            return Ok(null)
        }
        val value = namespace.codec.decode(stored.bytes)
        return Ok(KvEntry(value = value, metadata = KvEntryMetadata(createdAtEpochMillis = stored.createdAt, expiresAtEpochMillis = stored.expiresAt)))
    }

    override suspend fun delete(
        namespace: KvNamespaceId,
        key: String,
    ): IdkResult<Boolean, IdkError> = Ok(entries.remove(compositeKey(namespace, key)) != null)

    override suspend fun exists(
        namespace: KvNamespaceId,
        key: String,
    ): IdkResult<Boolean, IdkError> {
        val now = Clock.System.now().toEpochMilliseconds()
        val stored = entries[compositeKey(namespace, key)] ?: return Ok(false)
        if (stored.expiresAt <= now) {
            entries.remove(compositeKey(namespace, key))
            return Ok(false)
        }
        return Ok(true)
    }

    override suspend fun touch(
        namespace: KvNamespaceId,
        key: String,
        ttl: Duration,
    ): IdkResult<Boolean, IdkError> {
        val now = Clock.System.now().toEpochMilliseconds()
        val stored = entries[compositeKey(namespace, key)] ?: return Ok(false)
        if (stored.expiresAt <= now) {
            entries.remove(compositeKey(namespace, key))
            return Ok(false)
        }
        val newExpiresAt = if (ttl.isInfinite()) Long.MAX_VALUE else now + ttl.inWholeMilliseconds
        entries[compositeKey(namespace, key)] = stored.copy(expiresAt = newExpiresAt)
        return Ok(true)
    }

    override suspend fun cleanupExpired(namespace: KvNamespaceId?): IdkResult<Int, IdkError> {
        val now = Clock.System.now().toEpochMilliseconds()
        val keysToRemove =
            entries
                .filter { (k, stored) ->
                    (namespace == null || k.startsWith("${namespace.name}:")) && stored.expiresAt <= now
                }.keys
                .toList()
        keysToRemove.forEach { entries.remove(it) }
        return Ok(keysToRemove.size)
    }
}

/** A store that offers no versioning, like a backend that cannot append atomically. */
private class PlainKvStore(
    private val inner: KvStore,
) : KvStore by inner

private class StoreTestKvStoreManager(
    versioned: Boolean = true,
) : KvStoreManager {
    val kv = StoreTestKvStore()
    private val store: KvStore = if (versioned) kv else PlainKvStore(kv)

    override fun createFromKvStoreConfig(config: KvStoreConfigBase): KvStore = store

    override fun createFromKvStoreConfig(
        config: KvStoreConfigBase,
        execution: SessionExecution?,
    ): KvStore = store

    override fun createFromProperties(
        configService: ConfigService,
        execution: SessionExecution?,
    ): Set<KvStore> = setOf(store)
}

private class NoOpKvStoreService(
    private val declared: Boolean = true,
    private val backendId: String = SHARED_BACKEND,
    private val scopeBinding: KvStoreScopeBinding = KvStoreScopeBinding.TENANT,
) : KvStoreService {
    /** How many of the next lookups fail with something other than "not declared". */
    var failNextLookups: Int = 0

    override fun getStoreIds(): Array<String> = if (declared) arrayOf(KvCredentialOfferSessionStore.STORE_ID) else emptyArray()

    override fun getStoreConfig(storeId: String): KvStoreConfigBase {
        if (failNextLookups > 0) {
            failNextLookups--
            throw IllegalArgumentException("Failed to bind KV store config for '$storeId' under prefix 'kv.stores': a property is malformed")
        }
        // The real binder reports an id nobody declared with this message.
        return if (declared && storeId == KvCredentialOfferSessionStore.STORE_ID) {
            KvStoreConfig(id = storeId, scopeBinding = scopeBinding, backendId = backendId)
        } else {
            throw IllegalArgumentException("KV store config not found for store ID: $storeId")
        }
    }

    override fun getStore(storeId: String): KvStore = throw UnsupportedOperationException("no store in test")
}

private class StoreTestRestConfigProvider(
    private val allowProcessLocalRequestStore: Boolean,
) : Oid4vciRestConfigProvider {
    override fun getConfig(): Oid4vciRestConfig = Oid4vciRestConfig(allowProcessLocalRequestStore = allowProcessLocalRequestStore)
}

private class StoreTestSessionExecution : SessionExecution {
    override val sessionContextManager: SessionContextManager
        get() = throw UnsupportedOperationException("not used in store tests")
    override val sessionContext: SessionContext
        get() = throw UnsupportedOperationException("not used in store tests")
    override val log: SessionLogService
        get() = throw UnsupportedOperationException("not used in store tests")
    override val conf: ContextConfig
        get() = throw UnsupportedOperationException("not used in store tests")
}

private class StoreTestAppLogManager :
    AbstractLogManager(scope = IdkScope.APP, loggers = emptySet()),
    AppLogManager
