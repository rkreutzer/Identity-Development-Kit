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

package com.sphereon.openid.oid4vci.rest.impl.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.core.api.error.IdkError
import com.sphereon.openid.oid4vc.common.DisplayProperties
import com.sphereon.openid.oid4vc.common.QrCodeOptions
import com.sphereon.openid.oid4vc.common.QrCodeService
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialOffer
import com.sphereon.openid.oid4vci.issuer.command.CreateCredentialOfferArgs
import com.sphereon.openid.oid4vci.issuer.command.CreateCredentialOfferCommand
import com.sphereon.openid.oid4vci.issuer.command.CreatedCredentialOffer
import com.sphereon.openid.oid4vci.issuer.command.markNothingWritten
import com.sphereon.openid.oid4vci.issuer.authorization.*
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerSpecProfile
import com.sphereon.openid.oid4vci.issuer.impl.authorization.Oid4vciAuthorizationServerSelector
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider
import com.sphereon.openid.oid4vci.issuer.config.MutableOid4vciIssuerInstanceIdProvider
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferInput
import com.sphereon.openid.oid4vci.rest.CredentialOfferSession
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStore
import com.sphereon.openid.oid4vci.rest.IssuanceCallbackConfig
import com.sphereon.openid.oid4vci.rest.OfferRequestClaim
import com.sphereon.openid.oid4vci.rest.OfferRequestOutcome
import com.sphereon.openid.oid4vci.rest.OfferRequestReservation
import com.sphereon.openid.oid4vci.rest.OfferRequestState
import com.sphereon.openid.oid4vci.rest.Oid4vciRestConfig
import com.sphereon.openid.oid4vci.rest.Oid4vciRestConfigProvider
import com.sphereon.openid.oid4vci.rest.Oid4vciRestErrorCodes
import com.sphereon.openid.oid4vci.rest.validation.CreateCredentialOfferLimits
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * Wiring test for [CreateCredentialOfferServiceCommandImpl.doExecute] that exercises the *real*
 * command with its collaborators faked, rather than a hand-typed output model. Its purpose is to
 * catch a `sessionId = correlationId` copy-paste bug at the output-construction line: the fake
 * [CreateCredentialOfferCommand] returns a protocol session id that is deliberately distinct from
 * the caller-supplied correlation id, so the two would only match if the wiring collapsed them.
 */
class CreateCredentialOfferServiceCommandImplTest {
    private val issuerInstanceId = "00000000-0000-4000-8000-000000000001"
    private val otherInstanceId = "00000000-0000-4000-8000-000000000009"
    private val protocolSessionId = "protocol-session-distinct-from-correlation"
    private val callerCorrelationId = "caller-supplied-correlation-id"

    @Test
    fun executeReturnsCreatedSessionsProtocolSessionIdDistinctFromCorrelationId() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId, qrCodeService = NoOpQrCodeService())

            val result =
                fixture.command.execute(
                    CreateCredentialOfferInput(
                        credentialConfigurationIds = listOf("PID"),
                        correlationId = callerCorrelationId,
                        templateId = "issuance-template-id",
                    ),
                )

            assertTrue(result.isOk, "execute should succeed but was: $result")
            val output = result.value

            assertEquals(
                protocolSessionId,
                output.sessionId,
                "output.sessionId must be the created session's protocol session id",
            )
            assertEquals(callerCorrelationId, output.correlationId)
            assertNotEquals(
                output.correlationId,
                output.sessionId,
                "sessionId must not collapse onto correlationId",
            )

            assertEquals(1, fixture.store.created.size)
            assertEquals(issuerInstanceId, fixture.policyProvider.lastIssuerInstanceId)
            assertEquals(issuerInstanceId, fixture.createCommand.lastArgs?.instanceId)
            assertEquals(issuerInstanceId, fixture.store.created.first().instanceId)
            assertEquals(protocolSessionId, fixture.store.created.first().issuanceSessionId)
            assertEquals(1, fixture.eventService.emitted.size, "the real doExecute path should emit exactly one session-created event")
            val eventPayload = fixture.eventService.emitted.single().payload
            assertEquals("issuance-template-id", eventPayload["templateId"]?.jsonPrimitive?.content)
            assertEquals(
                "issuance-template-id",
                eventPayload["creationSnapshot"]?.jsonObject?.get("templateId")?.jsonPrimitive?.content,
            )
        }

    @Test
    fun executeRejectsMissingIssuerUuidSelectorBeforeCreatingOffer() =
        runTest {
            val fixture = commandFixture(instanceId = null)

            val result = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID")))

            assertTrue(result.isErr)
            assertEquals(null, fixture.createCommand.lastArgs)
        }

    @Test
    fun executeRejectsNonUuidIssuerSelectorBeforeCreatingOffer() =
        runTest {
            val fixture = commandFixture(instanceId = "default")

            val result = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID")))

            assertTrue(result.isErr)
            assertEquals(null, fixture.createCommand.lastArgs)
        }

    @Test
    fun shouldBindTheIssuerInstanceTheCallerNamesOnlyForTheCall() =
        runTest {
            val fixture = commandFixture(instanceId = null)

            val result = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), issuerInstanceId = issuerInstanceId))

            assertTrue(result.isOk, "execute should succeed but was: $result")
            assertEquals(issuerInstanceId, fixture.createCommand.lastArgs?.instanceId)
            assertNull(fixture.instanceIdProvider.currentInstanceId(), "the holder is session wide, so a binding that outlives the call would answer for the next one")
        }

    @Test
    fun shouldNotLeaveTheIssuerInstanceBoundWhenTheCallFails() =
        runTest {
            val fixture = commandFixture(instanceId = null, createResult = Err(IdkError.INVALID_STATE(message = "refused")))

            val result = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), issuerInstanceId = issuerInstanceId))

            assertTrue(result.isErr)
            assertNull(fixture.instanceIdProvider.currentInstanceId())
        }

    @Test
    fun shouldKeepTheIssuerInstanceTheRouteBound() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)

            fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), issuerInstanceId = issuerInstanceId))

            assertEquals(issuerInstanceId, fixture.instanceIdProvider.currentInstanceId(), "an instance the route bound is not the command's to clear")
        }

    @Test
    fun shouldRejectAnIssuerInstanceThatDiffersFromTheBoundOneBeforeCreatingOffer() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)

            val result = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), issuerInstanceId = otherInstanceId))

            assertTrue(result.isErr)
            assertEquals(null, fixture.createCommand.lastArgs)
        }

    @Test
    fun shouldRejectANonUuidIssuerInstanceTheCallerNamesBeforeCreatingOffer() =
        runTest {
            val fixture = commandFixture(instanceId = null)

            val result = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), issuerInstanceId = "default"))

            assertTrue(result.isErr)
            assertEquals(null, fixture.createCommand.lastArgs)
        }

    @Test
    fun shouldAnswerNotFoundWhenThePolicyProviderDoesNotKnowTheIssuerInstance() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId, policyProvider = ActiveAuthorizationPolicyProvider(unknownInstance = true))

            val result = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID")))

            assertEquals(IdkError.NOT_FOUND_ERROR().code, result.error.code, "an instance of another tenant is answered like one that does not exist")
            assertEquals(0, fixture.createCommand.calls)
        }

    @Test
    fun shouldReleaseTheKeyOfARequestWhoseIssuerInstanceIsNotAvailable() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId, policyProvider = ActiveAuthorizationPolicyProvider(unknownInstance = true))

            val result = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-prep"))

            assertEquals(IdkError.NOT_FOUND_ERROR().code, result.error.code)
            assertEquals(listOf("key-prep"), fixture.store.released, "nothing was written before the policy was resolved, so the key is free again")
            assertEquals(OfferRequestState.RELEASED, fixture.store.claims.getValue("key-prep").reservation.state)
        }

    @Test
    fun shouldCreateOneOfferAndReturnItOnAnIdenticalRepeat() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-1", state = "first")

            val first = fixture.command.execute(request).value
            val repeat = fixture.command.execute(request.copy(state = "second")).value

            assertEquals(1, fixture.createCommand.calls, "the repeat must not reach the issuer")
            assertEquals(1, fixture.store.created.size)
            assertEquals(1, fixture.eventService.emitted.size, "the offer is announced once, by the attempt that created it")
            assertEquals("key-1", first.correlationId)
            assertEquals(first.offerUri, repeat.offerUri)
            assertEquals(first.sessionId, repeat.sessionId)
            assertEquals(first.statusUri, repeat.statusUri)
            assertEquals(fixture.store.created.single().offerId, "offer-selector-test")
            assertEquals(null, repeat.txCode, "a transaction code is shown once and never stored")
            val recorded = fixture.store.claims.getValue("key-1").reservation
            assertEquals(OfferRequestState.COMPLETED, recorded.state)
            assertEquals(first.offerUri, recorded.outcome?.offerUri)
        }

    @Test
    fun shouldRenderTheQrCodeOfARepeatFromItsOwnOptions() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-qr")

            val first = fixture.command.execute(request).value
            val repeat = fixture.command.execute(request.copy(qrCodeOptions = QrCodeOptions())).value

            assertNull(first.qrUri, "the first attempt asked for no QR code")
            assertEquals("qr:${first.offerUri}", repeat.qrUri, "a repeat renders the stored offer for the QR options it sends")
        }

    @Test
    fun shouldRefuseADifferentRequestUnderTheSameKeyAsAConflict() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-2"))

            val other = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("Other"), correlationId = "key-2"))

            assertEquals(Oid4vciRestErrorCodes.CORRELATION_ID_CONFLICT, other.error.code)
            assertEquals(ErrorCategory.CONFLICT, other.error.category, "a key conflict is a client conflict, not a server fault")
            assertEquals(1, fixture.createCommand.calls)
        }

    @Test
    fun shouldRefuseTheSameRequestForAnotherIssuerInstanceUnderTheSameKey() =
        runTest {
            val first = commandFixture(instanceId = issuerInstanceId)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-instance")
            first.command.execute(request)
            val second = commandFixture(instanceId = otherInstanceId, store = first.store)

            val other = second.command.execute(request)

            assertEquals(Oid4vciRestErrorCodes.CORRELATION_ID_CONFLICT, other.error.code, "the offer of one issuer instance is no answer for another")
            assertEquals(0, second.createCommand.calls)
        }

    @Test
    fun shouldRefuseTheSameRequestWithAnotherCallbackUnderTheSameKey() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-callback", callback = IssuanceCallbackConfig(url = "https://a.example/hook"))
            fixture.command.execute(request)

            val other = fixture.command.execute(request.copy(callback = IssuanceCallbackConfig(url = "https://b.example/hook")))

            assertEquals(Oid4vciRestErrorCodes.CORRELATION_ID_CONFLICT, other.error.code, "a repeat that names another callback is not a retry that may keep the first one")
            assertEquals(1, fixture.createCommand.calls)
        }

    @Test
    fun shouldAnswerARepeatWhoseOfferExpiredWithTheExpiredCodeNotAStaleOffer() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-expired")
            val now = Clock.System.now().toEpochMilliseconds()
            fixture.store.seedClaim(completedReservation("key-expired", request.intentDigest(issuerInstanceId), now - 700_000, now - 100_000))

            val repeat = fixture.command.execute(request)

            assertEquals(Oid4vciRestErrorCodes.CORRELATION_ID_EXPIRED, repeat.error.code, "a dead offer URI must not be handed out as a success")
            assertEquals(ErrorCategory.CONFLICT, repeat.error.category)
            assertEquals(0, fixture.createCommand.calls, "the key creates no other offer")
        }

    @Test
    fun shouldAnswerARepeatWhoseOfferWasDeletedWithTheWithdrawnCode() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-withdrawn")
            val now = Clock.System.now().toEpochMilliseconds()
            fixture.store.seedClaim(OfferRequestReservation("key-withdrawn", request.intentDigest(issuerInstanceId), now, now + 600_000, OfferRequestState.WITHDRAWN))

            val repeat = fixture.command.execute(request)

            assertEquals(Oid4vciRestErrorCodes.CORRELATION_ID_WITHDRAWN, repeat.error.code)
            assertEquals(ErrorCategory.CONFLICT, repeat.error.category)
            assertEquals(0, fixture.createCommand.calls)
        }

    @Test
    fun shouldRefuseACompletedClaimThatRecordsNoOffer() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-no-outcome")
            val now = Clock.System.now().toEpochMilliseconds()
            fixture.store.seedClaim(OfferRequestReservation("key-no-outcome", request.intentDigest(issuerInstanceId), now, now + 600_000, OfferRequestState.COMPLETED))

            val repeat = fixture.command.execute(request)

            assertEquals(IdkError.INVALID_STATE().code, repeat.error.code)
            assertEquals(0, fixture.createCommand.calls)
        }

    @Test
    fun shouldReportARepeatWhoseEarlierAttemptRecordedNothingAsInDoubtUntilTheOfferExpires() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-3")
            val now = Clock.System.now().toEpochMilliseconds()
            fixture.store.seedClaim(OfferRequestReservation("key-3", request.intentDigest(issuerInstanceId), now, now + 600_000))

            val repeat = fixture.command.execute(request)

            assertEquals(Oid4vciRestErrorCodes.CORRELATION_ID_IN_DOUBT, repeat.error.code)
            assertEquals(ErrorCategory.CONFLICT, repeat.error.category)
            assertEquals(0, fixture.createCommand.calls, "an offer that may exist must not be created again")
        }

    @Test
    fun shouldTakeOverTheClaimOfAnUnknownAttemptWhoseOfferHasExpired() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-4")
            val now = Clock.System.now().toEpochMilliseconds()
            fixture.store.seedClaim(OfferRequestReservation("key-4", request.intentDigest(issuerInstanceId), now - 700_000, now - 100_000))

            val created = fixture.command.execute(request).value

            assertEquals(1, fixture.createCommand.calls)
            assertEquals("key-4", created.correlationId)
            assertEquals(1, fixture.store.reclaimed, "the expired claim is taken over, not deleted and claimed again")
            assertTrue(fixture.store.released.isEmpty())
        }

    @Test
    fun shouldTellTheLoserOfATakeoverThatTheOutcomeIsInDoubt() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-5")
            val now = Clock.System.now().toEpochMilliseconds()
            fixture.store.seedClaim(OfferRequestReservation("key-5", request.intentDigest(issuerInstanceId), now - 700_000, now - 100_000))
            fixture.store.loseNextReclaimTo = OfferRequestReservation("key-5", request.intentDigest(issuerInstanceId), now, now + 600_000)

            val lost = fixture.command.execute(request)

            assertEquals(Oid4vciRestErrorCodes.CORRELATION_ID_IN_DOUBT, lost.error.code)
            assertEquals(0, fixture.createCommand.calls, "only the caller that won the takeover may create the offer")
        }

    @Test
    fun shouldCreateTheOfferOfAReleasedKeyWhateverTheNextRequestAsks() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val now = Clock.System.now().toEpochMilliseconds()
            fixture.store.seedClaim(OfferRequestReservation("key-free", "digest-of-the-attempt-that-gave-it-back", now, now + 600_000, OfferRequestState.RELEASED))

            val created = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("Corrected"), correlationId = "key-free"))

            assertTrue(created.isOk, "a key that was given back is free for a corrected request: $created")
            assertEquals(1, fixture.store.reclaimed)
            assertEquals(1, fixture.createCommand.calls)
        }

    @Test
    fun shouldNotAnnounceOrHandOutAnOfferWhoseClaimWasTakenOverWhileItWasCreated() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-slow")
            val now = Clock.System.now().toEpochMilliseconds()
            fixture.store.loseNextCompleteTo = OfferRequestReservation("key-slow", request.intentDigest(issuerInstanceId), now + 1, now + 600_001)

            val lost = fixture.command.execute(request)

            assertEquals(Oid4vciRestErrorCodes.CORRELATION_ID_IN_DOUBT, lost.error.code)
            assertTrue(fixture.store.created.isEmpty(), "the attempt that lost its claim must not store a session")
            assertTrue(fixture.eventService.emitted.isEmpty(), "and must not announce an offer")
        }

    @Test
    fun shouldAnswerTheErrorWhenTheOfferCannotBeRecordedOnItsClaim() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            fixture.store.failComplete = true

            val failed = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-record"))

            assertTrue(failed.isErr)
            assertTrue(fixture.store.created.isEmpty())
            assertEquals(OfferRequestState.ACTIVE, fixture.store.claims.getValue("key-record").reservation.state, "the claim stays, so a repeat is in doubt until the offer expires")
        }

    @Test
    fun shouldReleaseTheKeyOfARefusalThatMarksNothingWritten() =
        runTest {
            val refusal = Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "refused").markNothingWritten())
            val fixture = commandFixture(instanceId = issuerInstanceId, createResult = refusal)

            val refused = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-6"))

            assertTrue(refused.isErr)
            assertEquals(listOf("key-6"), fixture.store.released)
            assertEquals(OfferRequestState.RELEASED, fixture.store.claims.getValue("key-6").reservation.state)
        }

    @Test
    fun shouldKeepTheKeyOfARefusalWithTheSameCodeThatDoesNotMarkNothingWritten() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId, createResult = Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "refused after a write")))

            val refused = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-code"))

            assertEquals(IdkError.ILLEGAL_ARGUMENT_ERROR().code, refused.error.code)
            assertTrue(fixture.store.released.isEmpty(), "the generic codes also follow a write, so only the marker frees the key")
            assertEquals(OfferRequestState.ACTIVE, fixture.store.claims.getValue("key-code").reservation.state)
        }

    @Test
    fun shouldKeepTheClaimWhenTheIssuerFailsWithAStoreError() =
        runTest {
            val storeError = Err(IdkError.fromString(code = "OID4VCI_SESSION_STORE_ERROR", message = "store down"))
            val fixture = commandFixture(instanceId = issuerInstanceId, createResult = storeError)

            val failed = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-7"))

            assertEquals("OID4VCI_SESSION_STORE_ERROR", failed.error.code)
            assertTrue(fixture.store.released.isEmpty(), "an offer may exist after a store error, so the id stays claimed")
            assertEquals(setOf("key-7"), fixture.store.claims.keys)
        }

    @Test
    fun shouldKeepTheClaimWhenTheIssuerThrows() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId, createFailure = IllegalStateException("connection reset"))

            val failed = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-throw"))

            assertEquals(IdkError.UNKNOWN_ERROR().code, failed.error.code)
            assertTrue(fixture.store.released.isEmpty(), "an exception does not say whether the issuer wrote anything")
        }

    @Test
    fun shouldAnswerTheRefusalAndMarkItWhenReleasingTheClaimFails() =
        runTest {
            val refusal = Err(IdkError.INVALID_STATE(message = "refused").markNothingWritten())
            val fixture = commandFixture(instanceId = issuerInstanceId, createResult = refusal)
            fixture.store.failRelease = true

            val refused = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-8"))

            assertEquals(IdkError.INVALID_STATE().code, refused.error.code, "the caller is told why the offer was refused, not why the release failed")
            assertEquals(true, refused.error.meta[STILL_CLAIMED_META], "and that the id stays claimed")
            assertEquals(listOf("key-8"), fixture.store.released)
        }

    @Test
    fun shouldMarkTheRefusalWhenAnotherAttemptHoldsTheKeyByNow() =
        runTest {
            val refusal = Err(IdkError.INVALID_STATE(message = "refused").markNothingWritten())
            val fixture = commandFixture(instanceId = issuerInstanceId, createResult = refusal)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-taken")
            val now = Clock.System.now().toEpochMilliseconds()
            fixture.store.takeOverBeforeRelease = OfferRequestReservation("key-taken", request.intentDigest(issuerInstanceId), now, now + 600_000)

            val refused = fixture.command.execute(request)

            assertEquals(IdkError.INVALID_STATE().code, refused.error.code)
            assertEquals(true, refused.error.meta[STILL_CLAIMED_META])
        }

    @Test
    fun shouldRefuseACorrelationIdWhenTheStoreCannotClaimAtomically() =
        runTest {
            val unsupported = commandFixture(instanceId = issuerInstanceId, supportsClaims = false)

            val refused = unsupported.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-9"))

            assertTrue(refused.isErr)
            assertEquals(0, unsupported.createCommand.calls)
        }

    @Test
    fun shouldAcceptAnyCorrelationIdAsTheIdempotencyKey() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)

            for (id in listOf("order-2026.10_19~a:b", "has/slash", "has space", "has?query", "k".repeat(1000))) {
                val created = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = id))

                assertTrue(created.isOk, "a correlation id is a released field and takes no new bound, so '$id' must be accepted: $created")
                assertEquals(id, created.value.correlationId)
            }
        }

    @Test
    fun shouldRefuseAnOfferLifetimeOutsideTheLimits() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)

            for (ttl in listOf(0L, -1L, CreateCredentialOfferLimits.TTL_SECONDS_MAX + 1)) {
                val refused = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), ttlSeconds = ttl))

                assertTrue(refused.isErr, "ttl_seconds $ttl must be refused")
                assertEquals(ErrorCategory.VALIDATION, refused.error.category)
            }
            assertEquals(0, fixture.createCommand.calls)
            for (ttl in listOf(1L, CreateCredentialOfferLimits.TTL_SECONDS_MAX)) {
                assertTrue(fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), ttlSeconds = ttl)).isOk, "ttl_seconds $ttl is allowed")
            }
        }

    @Test
    fun shouldCreateAnOfferOnEveryCallWithoutACorrelationId() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"))

            fixture.command.execute(request)
            fixture.command.execute(request)

            assertEquals(2, fixture.createCommand.calls, "without a correlation id nothing is claimed and nothing is replayed")
            assertTrue(fixture.store.claims.isEmpty())
        }

    @Test
    fun shouldRefuseACorrelationIdThatNamesTheSessionOfAnOfferCreatedWithoutIt() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId)
            val now = Clock.System.now().toEpochMilliseconds()
            fixture.store.created += session("existing-correlation", issuerInstanceId, now)

            val refused = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "existing-correlation"))

            assertEquals(Oid4vciRestErrorCodes.CORRELATION_ID_CONFLICT, refused.error.code)
            assertEquals(ErrorCategory.CONFLICT, refused.error.category)
            assertEquals(0, fixture.createCommand.calls, "the store would overwrite the session of the other offer")
            assertEquals(listOf("existing-correlation"), fixture.store.released, "the claim describes no offer, so it is given back")
        }

    @Test
    fun shouldCreateTheOfferWhenTheSessionCreatedEventCannotBeEmitted() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId, eventService = RecordingSessionEventService(failure = IllegalStateException("event hub down")))

            val created = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-11"))

            assertTrue(created.isOk, "an offer that exists must be answered even when the observational event is lost: $created")
            assertEquals(1, fixture.store.created.size)
        }

    @Test
    fun shouldReturnAnErrorWhenTheRequestedQrCodeCannotBeRendered() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId, qrCodeService = FailingQrCodeService())

            val created = fixture.command.execute(CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), qrCodeOptions = QrCodeOptions()))

            assertTrue(created.isErr, "a QR code that was asked for and cannot be drawn must not be dropped silently: $created")
        }

    @Test
    fun shouldReturnAnErrorWhenTheQrCodeOfAReplayedOfferCannotBeRendered() =
        runTest {
            val fixture = commandFixture(instanceId = issuerInstanceId, qrCodeService = FailingQrCodeService())
            val input = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), correlationId = "key-qr")
            assertTrue(fixture.command.execute(input).isOk)

            val repeat = fixture.command.execute(input.copy(qrCodeOptions = QrCodeOptions()))

            assertTrue(repeat.isErr, "a repeat that asks for a QR code that cannot be drawn must fail too: $repeat")
        }

    @Test
    fun shouldGiveTheSameIntentTheSameDigestWhateverTheMemberOrder() {
        val ascending = CreateCredentialOfferInput(
            credentialConfigurationIds = listOf("PID"),
            credentialSubjectData = linkedMapOf("a" to JsonPrimitive("1"), "b" to JsonPrimitive("2")),
        )
        val descending = ascending.copy(credentialSubjectData = linkedMapOf("b" to JsonPrimitive("2"), "a" to JsonPrimitive("1")))
        val other = ascending.copy(credentialSubjectData = linkedMapOf("a" to JsonPrimitive("1"), "b" to JsonPrimitive("3")))

        assertEquals(ascending.intentDigest(issuerInstanceId), descending.intentDigest(issuerInstanceId))
        assertNotEquals(ascending.intentDigest(issuerInstanceId), other.intentDigest(issuerInstanceId))
        assertEquals(
            ascending.intentDigest(issuerInstanceId),
            ascending.copy(correlationId = "k", state = "s", qrCodeOptions = QrCodeOptions()).intentDigest(issuerInstanceId),
            "the identity of the request, the caller's own state and how the offer is rendered are not part of its intent",
        )
    }

    @Test
    fun shouldTellRequestsApartThatDifferInTheirInstanceCallbackOrTemplate() {
        val request = CreateCredentialOfferInput(credentialConfigurationIds = listOf("PID"), callback = IssuanceCallbackConfig(url = "https://a.example/hook"))

        val digest = request.intentDigest(issuerInstanceId)

        assertNotEquals(digest, request.intentDigest(otherInstanceId))
        assertNotEquals(digest, request.copy(callback = IssuanceCallbackConfig(url = "https://b.example/hook")).intentDigest(issuerInstanceId))
        assertNotEquals(digest, request.copy(templateId = "template-a").intentDigest(issuerInstanceId))
        assertEquals(digest, request.copy(issuerInstanceId = issuerInstanceId).intentDigest(issuerInstanceId), "the instance the request names is replaced by the one it is bound to")
    }

    private fun commandFixture(
        instanceId: String?,
        createResult: IdkResult<CreatedCredentialOffer, IdkError>? = null,
        createFailure: Exception? = null,
        supportsClaims: Boolean = true,
        eventService: RecordingSessionEventService = RecordingSessionEventService(),
        policyProvider: ActiveAuthorizationPolicyProvider = ActiveAuthorizationPolicyProvider(),
        qrCodeService: QrCodeService = EchoingQrCodeService(),
        store: RecordingCredentialOfferSessionStore = RecordingCredentialOfferSessionStore(supportsClaims),
    ): OfferCommandFixture {
        val createdOffer =
            CreatedCredentialOffer(
                instanceId = issuerInstanceId,
                offerId = "offer-selector-test",
                sessionId = protocolSessionId,
                offer =
                    CredentialOffer(
                        credentialIssuer = "https://issuer.example.com/oid4vci",
                        credentialConfigurationIds = listOf("PID"),
                    ),
                offerUri = "openid-credential-offer://?credential_offer_uri=https://issuer.example.com/offer",
            )
        val createCommand = FakeCreateCredentialOfferCommand(createResult ?: Ok(createdOffer), createFailure)
        val instanceIdProvider = FixedOid4vciIssuerInstanceIdProvider(instanceId)
        return OfferCommandFixture(
            store = store,
            command =
                CreateCredentialOfferServiceCommandImpl(
                    sessionExecution = TestSessionExecution(),
                    createCredentialOfferCommand = createCommand,
                    credentialOfferSessionStore = store,
                    qrCodeService = qrCodeService,
                    configProvider = FixedOid4vciRestConfigProvider(),
                    issuerConfigProvider = FixedOid4vciIssuerConfigProvider(),
                    instanceIdProvider = instanceIdProvider,
                    sessionEventService = eventService,
                    authorizationPolicyProvider = policyProvider,
                    authorizationServerSelector = Oid4vciAuthorizationServerSelector(),
                ),
            createCommand = createCommand,
            instanceIdProvider = instanceIdProvider,
            eventService = eventService,
            policyProvider = policyProvider,
        )
    }

    private fun completedReservation(
        key: String,
        digest: String,
        createdAt: Long,
        offerExpiresAt: Long,
    ) = OfferRequestReservation(
        key = key,
        intentDigest = digest,
        createdAt = createdAt,
        expiresAt = offerExpiresAt + 60_000,
        state = OfferRequestState.COMPLETED,
        outcome = OfferRequestOutcome("openid-credential-offer://?credential_offer_uri=https://issuer.example.com/old", protocolSessionId, issuerInstanceId, offerExpiresAt),
    )

    private fun session(
        correlationId: String,
        instanceId: String,
        now: Long,
    ) = CredentialOfferSession(
        correlationId = correlationId,
        instanceId = instanceId,
        offerId = "offer-$correlationId",
        issuanceSessionId = protocolSessionId,
        status = com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED,
        createdAt = now,
        lastUpdatedAt = now,
    )

    private companion object {
        const val STILL_CLAIMED_META: String = "oid4vci.correlation_id.still_claimed"
    }
}

private class OfferCommandFixture(
    val store: RecordingCredentialOfferSessionStore,
    val command: CreateCredentialOfferServiceCommandImpl,
    val createCommand: FakeCreateCredentialOfferCommand,
    val instanceIdProvider: FixedOid4vciIssuerInstanceIdProvider,
    val eventService: RecordingSessionEventService,
    val policyProvider: ActiveAuthorizationPolicyProvider,
)

@OptIn(kotlin.uuid.ExperimentalUuidApi::class)
private class ActiveAuthorizationPolicyProvider(
    private val unknownInstance: Boolean = false,
) : Oid4vciIssuerAuthorizationPolicyProvider {
    private val issuerId = kotlin.uuid.Uuid.parse("00000000-0000-4000-8000-000000000001")
    private val serverId = kotlin.uuid.Uuid.parse("00000000-0000-4000-8000-000000000002")
    var lastIssuerInstanceId: String? = null

    override suspend fun resolve(tenantId: String, issuerInstanceId: String): Oid4vciIssuerAuthorizationPolicy {
        lastIssuerInstanceId = issuerInstanceId
        // The platform's policy provider refuses an instance that is not in the tenant with an IllegalStateException.
        check(!unknownInstance) { "Issuer instance '$issuerInstanceId' is not in tenant '$tenantId'" }
        return Oid4vciIssuerAuthorizationPolicy(
            tenantId = tenantId,
            issuerId = issuerId,
            issuerCapabilityId = issuerId,
            authorizationServers = listOf(
                Oid4vciBoundAuthorizationServer(
                    id = serverId,
                    tenantId = tenantId,
                    issuerIdentifier = "https://as.example.com",
                    enabled = true,
                    default = true,
                    lifecycle = Oid4vciAuthorizationServerLifecycle.ACTIVE,
                    deployment = Oid4vciAuthorizationServerDeployment.HOSTED,
                    credentialIssuancePurpose = true,
                    allowedGrants = setOf(Oid4vciAuthorizationGrant.AUTHORIZATION_CODE, Oid4vciAuthorizationGrant.PRE_AUTHORIZED_CODE),
                    authorizationEndpoint = "https://as.example.com/authorize",
                    tokenEndpoint = "https://as.example.com/token",
                    discoveryCurrent = true,
                    bindingRevision = 0,
                ),
            ),
            profile = Oid4vciIssuerSpecProfile.OID4VCI_1_0_FINAL,
            profileRevision = 0,
        )
    }
}

/** Fake [CreateCredentialOfferCommand] that returns a canned [CreatedCredentialOffer], or throws [failure]. */
private class FakeCreateCredentialOfferCommand(
    private val result: IdkResult<CreatedCredentialOffer, IdkError>,
    private val failure: Exception? = null,
) : CreateCredentialOfferCommand {
    var lastArgs: CreateCredentialOfferArgs? = null
    var calls: Int = 0
    override val isEnabled: Boolean = true
    override val inputTypeToken: TypeToken<CreateCredentialOfferArgs> = typeToken()
    override val outputTypeToken: TypeToken<CreatedCredentialOffer> = typeToken()

    override suspend fun execute(args: CreateCredentialOfferArgs): IdkResult<CreatedCredentialOffer, IdkError> {
        lastArgs = args
        calls++
        failure?.let { throw it }
        return result
    }
}

/**
 * Records every session passed to [create] for post-execute inspection, and keeps request claims the way a store with an
 * atomic versioned backend does: a claim carries the version it was stored under, and a takeover, a completion or a
 * release only succeeds against the version the caller read. A released key leaves its marker behind, like the real one.
 */
private class RecordingCredentialOfferSessionStore(private val supportsClaims: Boolean = true) : CredentialOfferSessionStore {
    val created = mutableListOf<CredentialOfferSession>()
    val claims = mutableMapOf<String, OfferRequestClaim>()
    val released = mutableListOf<String>()
    var reclaimed = 0
    var failRelease = false
    var failComplete = false

    /** When set, the next takeover is lost to this reservation, as if another caller read the same claim first. */
    var loseNextReclaimTo: OfferRequestReservation? = null

    /** When set, the next completion finds the key already taken over by this reservation. */
    var loseNextCompleteTo: OfferRequestReservation? = null

    /** When set, the next release finds the key already taken over by this reservation. */
    var takeOverBeforeRelease: OfferRequestReservation? = null
    private var versions = 0

    fun seedClaim(reservation: OfferRequestReservation) {
        claims[reservation.key] = OfferRequestClaim(claimed = true, reservation = reservation, version = "v${++versions}")
    }

    override suspend fun claimRequest(reservation: OfferRequestReservation): IdkResult<OfferRequestClaim, IdkError> {
        if (!supportsClaims) return super.claimRequest(reservation)
        val held = claims[reservation.key]
        if (held != null) return Ok(held.copy(claimed = false))
        val claim = OfferRequestClaim(claimed = true, reservation = reservation, version = "v${++versions}")
        claims[reservation.key] = claim
        return Ok(claim)
    }

    override suspend fun reclaimRequest(observed: OfferRequestClaim, replacement: OfferRequestReservation): IdkResult<OfferRequestClaim, IdkError> {
        if (!supportsClaims) return super.reclaimRequest(observed, replacement)
        loseNextReclaimTo?.let { winner ->
            loseNextReclaimTo = null
            seedClaim(winner)
        }
        val held = claims.getValue(replacement.key)
        if (held.version != observed.version) return Ok(held.copy(claimed = false))
        reclaimed++
        val claim = OfferRequestClaim(claimed = true, reservation = replacement, version = "v${++versions}")
        claims[replacement.key] = claim
        return Ok(claim)
    }

    override suspend fun completeRequest(claim: OfferRequestClaim, outcome: OfferRequestOutcome): IdkResult<OfferRequestClaim, IdkError> {
        if (!supportsClaims) return super.completeRequest(claim, outcome)
        if (failComplete) return Err(IdkError.UNKNOWN_ERROR(message = "the claim store is down"))
        loseNextCompleteTo?.let { winner ->
            loseNextCompleteTo = null
            seedClaim(winner)
        }
        val key = claim.reservation.key
        val held = claims.getValue(key)
        if (held.version != claim.version) return Ok(held.copy(claimed = false))
        val completed = OfferRequestClaim(claimed = true, reservation = claim.reservation.copy(state = OfferRequestState.COMPLETED, outcome = outcome), version = "v${++versions}")
        claims[key] = completed
        return Ok(completed)
    }

    override suspend fun releaseRequest(claim: OfferRequestClaim): IdkResult<Boolean, IdkError> {
        released += claim.reservation.key
        if (failRelease) return Err(IdkError.UNKNOWN_ERROR(message = "the claim store is down"))
        takeOverBeforeRelease?.let { winner ->
            takeOverBeforeRelease = null
            seedClaim(winner)
        }
        val key = claim.reservation.key
        val held = claims[key]
        if (held?.version != claim.version) return Ok(false)
        claims[key] = OfferRequestClaim(claimed = false, reservation = claim.reservation.copy(state = OfferRequestState.RELEASED), version = "v${++versions}")
        return Ok(true)
    }

    override suspend fun create(session: CredentialOfferSession): IdkResult<CredentialOfferSession, IdkError> {
        created += session
        return Ok(session)
    }

    override suspend fun get(correlationId: String): IdkResult<CredentialOfferSession?, IdkError> = Ok(created.firstOrNull { it.correlationId == correlationId })

    override suspend fun getByOfferId(offerId: String): IdkResult<CredentialOfferSession?, IdkError> = Ok(created.firstOrNull { it.offerId == offerId })

    override suspend fun update(session: CredentialOfferSession): IdkResult<CredentialOfferSession, IdkError> = Ok(session)

    override suspend fun delete(correlationId: String): IdkResult<Boolean, IdkError> = Ok(true)
}

/** Renders a QR code as the content it was asked for, so a test can tell which offer a QR code stands for. */
private class EchoingQrCodeService : QrCodeService {
    override fun generateDataUri(
        content: String,
        options: QrCodeOptions,
    ): String = "qr:$content"
}

private class FailingQrCodeService : QrCodeService {
    override fun generateDataUri(
        content: String,
        options: QrCodeOptions,
    ): String = throw IllegalStateException("no renderer")
}

private class NoOpQrCodeService : QrCodeService {
    override fun generateDataUri(
        content: String,
        options: QrCodeOptions,
    ): String = "data:image/png;base64,test"
}

private class FixedOid4vciRestConfigProvider(
    private val config: Oid4vciRestConfig = Oid4vciRestConfig(externalBaseUrl = "https://issuer.example.com"),
) : Oid4vciRestConfigProvider {
    override fun getConfig(): Oid4vciRestConfig = config
}

private class FixedOid4vciIssuerConfigProvider(
    override val issuerIdentifier: String = "https://issuer.example.com/oid4vci",
) : Oid4vciIssuerConfigProvider {
    override val credentialConfigurations: Map<String, CredentialConfigurationSupported> = emptyMap()
    override val authorizationServers: List<String>? = null
    override val display: List<DisplayProperties>? = null
}

private class FixedOid4vciIssuerInstanceIdProvider(
    private var instanceId: String? = "00000000-0000-4000-8000-000000000001",
) : MutableOid4vciIssuerInstanceIdProvider {
    override fun currentInstanceId(): String? = instanceId

    override fun setCurrentInstanceId(instanceId: String) {
        this.instanceId = instanceId
    }

    override fun clearCurrentInstanceId() {
        instanceId = null
    }
}
