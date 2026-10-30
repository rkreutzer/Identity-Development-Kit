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
import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.core.api.error.IdkError
import com.sphereon.openid.oid4vci.issuer.store.CredentialIssuanceSessionStore
import com.sphereon.openid.oid4vci.issuer.store.IssuanceSession
import com.sphereon.openid.oid4vci.issuer.store.IssuanceSessionStatus
import com.sphereon.openid.oid4vci.rest.CredentialOfferSession
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStatus
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStore
import com.sphereon.openid.oid4vci.rest.GetCredentialOfferStatusInput
import com.sphereon.openid.oid4vci.rest.Oid4vciRestErrorCodes
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class GetCredentialOfferStatusServiceCommandImplTest {
    private val instanceId = "00000000-0000-4000-8000-000000000001"
    private val protocolSessionId = "protocol-session-1"
    private val correlationId = "correlation-1"

    private fun storedSession(status: CredentialOfferSessionStatus = CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED) =
        CredentialOfferSession(
            correlationId = correlationId,
            instanceId = instanceId,
            offerId = "offer-1",
            issuanceSessionId = protocolSessionId,
            status = status,
            createdAt = 1_000,
            lastUpdatedAt = 1_000,
        )

    private fun protocolSession(status: IssuanceSessionStatus) =
        IssuanceSession(
            sessionId = protocolSessionId,
            instanceId = instanceId,
            issuerId = "https://issuer.example.com/oid4vci",
            credentialConfigurationIds = listOf("PID"),
            status = status,
            createdAt = 1_000,
            expiresAt = 2_000,
        )

    private fun command(
        offers: StatusTestOfferStore,
        protocol: StatusTestIssuanceStore,
    ) = GetCredentialOfferStatusServiceCommandImpl(
        execution = TestSessionExecution(),
        credentialOfferSessionStore = offers,
        issuanceSessionStore = protocol,
        sessionEventService = RecordingSessionEventService(),
    )

    @Test
    fun shouldReportTheStatusOfTheProtocolSessionAndRefreshTheStoredOne() =
        runTest {
            val offers = StatusTestOfferStore(storedSession())
            val protocol = StatusTestIssuanceStore(Ok(protocolSession(IssuanceSessionStatus.OFFER_RECEIVED)))

            val answer = command(offers, protocol).execute(GetCredentialOfferStatusInput(correlationId))

            assertTrue(answer.isOk, "the status should be answered but was: $answer")
            assertEquals(CredentialOfferSessionStatus.CREDENTIAL_OFFER_RETRIEVED, answer.value.status)
            assertEquals(CredentialOfferSessionStatus.CREDENTIAL_OFFER_RETRIEVED, offers.updated.single().status)
        }

    @Test
    fun shouldNotAnswerWithTheStoredStatusWhenTheProtocolSessionCannotBeRead() =
        runTest {
            val offers = StatusTestOfferStore(storedSession(CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED))
            val unreadable = IdkError.fromString(code = "OID4VCI_SESSION_STORE_ERROR", message = "store down")
            val protocol = StatusTestIssuanceStore(Err(unreadable))

            val answer = command(offers, protocol).execute(GetCredentialOfferStatusInput(correlationId))

            assertTrue(answer.isErr, "a stale stored status would be reported as if it were current")
            assertEquals("OID4VCI_SESSION_STORE_ERROR", answer.error.code)
            assertTrue(offers.updated.isEmpty())
        }

    @Test
    fun shouldReportAMissingProtocolSessionAsAnUnknownOutcomeInsteadOfAsTheStoredStatus() =
        runTest {
            for (stored in listOf(CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED, CredentialOfferSessionStatus.CREDENTIAL_OFFER_RETRIEVED, CredentialOfferSessionStatus.TOKEN_REQUESTED)) {
                val offers = StatusTestOfferStore(storedSession(stored))
                val protocol = StatusTestIssuanceStore(Ok(null))

                val answer = command(offers, protocol).execute(GetCredentialOfferStatusInput(correlationId))

                assertTrue(answer.isErr, "a protocol session that is gone proves nothing about a $stored offer")
                assertEquals(Oid4vciRestErrorCodes.OFFER_OUTCOME_UNKNOWN, answer.error.code, "it is not the answer for a correlation id that never existed")
                assertEquals(ErrorCategory.CONFLICT, answer.error.category)
                assertTrue(offers.updated.isEmpty())
            }
        }

    @Test
    fun shouldAnswerTheTerminalStatusAnEarlierReadStoredAfterTheProtocolSessionExpired() =
        runTest {
            for (terminal in listOf(CredentialOfferSessionStatus.CREDENTIAL_ISSUED, CredentialOfferSessionStatus.ERROR)) {
                val offers = StatusTestOfferStore(storedSession(terminal))
                val protocol = StatusTestIssuanceStore(Ok(null))

                val answer = command(offers, protocol).execute(GetCredentialOfferStatusInput(correlationId))

                assertTrue(answer.isOk, "a poll after the protocol session expired still learns how the offer ended: $answer")
                assertEquals(terminal, answer.value.status)
                assertTrue(offers.updated.isEmpty(), "nothing moved, so nothing is refreshed")
            }
        }

    @Test
    fun shouldReportNotFoundWhenNoSessionIsStoredForTheCorrelationId() =
        runTest {
            val offers = StatusTestOfferStore(null)
            val protocol = StatusTestIssuanceStore(Ok(protocolSession(IssuanceSessionStatus.OFFER_CREATED)))

            val answer = command(offers, protocol).execute(GetCredentialOfferStatusInput(correlationId))

            assertEquals(IdkError.NOT_FOUND_ERROR().code, answer.error.code)
        }

    @Test
    fun shouldAnswerASessionOfAnotherInstanceAsNotFoundAndASessionOfTheRequestedInstanceNormally() =
        runTest {
            val offers = StatusTestOfferStore(storedSession())
            val protocol = StatusTestIssuanceStore(Ok(protocolSession(IssuanceSessionStatus.OFFER_CREATED)))

            val otherInstance = command(offers, protocol).execute(GetCredentialOfferStatusInput(correlationId, instanceId = "00000000-0000-4000-8000-000000000002"))
            val sameInstance = command(offers, protocol).execute(GetCredentialOfferStatusInput(correlationId, instanceId = instanceId))

            assertTrue(otherInstance.isErr)
            assertEquals(IdkError.NOT_FOUND_ERROR().code, otherInstance.error.code)
            assertTrue(sameInstance.isOk, "the instance the session belongs to is answered: $sameInstance")
        }

    @Test
    fun shouldAnswerWhenTheStoredStatusCannotBeRefreshed() =
        runTest {
            val offers = StatusTestOfferStore(storedSession(), failUpdate = true)
            val protocol = StatusTestIssuanceStore(Ok(protocolSession(IssuanceSessionStatus.CREDENTIAL_ISSUED)))

            val answer = command(offers, protocol).execute(GetCredentialOfferStatusInput(correlationId))

            assertTrue(answer.isOk, "the refresh is best effort: $answer")
            assertEquals(CredentialOfferSessionStatus.CREDENTIAL_ISSUED, answer.value.status)
            assertEquals(1, offers.updated.size, "the refresh was attempted")
        }
}

private class StatusTestOfferStore(
    private val stored: CredentialOfferSession?,
    private val failUpdate: Boolean = false,
) : CredentialOfferSessionStore {
    val updated = mutableListOf<CredentialOfferSession>()

    override suspend fun create(session: CredentialOfferSession): IdkResult<CredentialOfferSession, IdkError> = Ok(session)

    override suspend fun get(correlationId: String): IdkResult<CredentialOfferSession?, IdkError> = Ok(stored?.takeIf { it.correlationId == correlationId })

    override suspend fun getByOfferId(offerId: String): IdkResult<CredentialOfferSession?, IdkError> = Ok(stored?.takeIf { it.offerId == offerId })

    override suspend fun update(session: CredentialOfferSession): IdkResult<CredentialOfferSession, IdkError> {
        updated += session
        return if (failUpdate) Err(IdkError.UNKNOWN_ERROR(message = "the session store is down")) else Ok(session)
    }

    override suspend fun delete(correlationId: String): IdkResult<Boolean, IdkError> = Ok(true)
}

private class StatusTestIssuanceStore(
    private val answer: IdkResult<IssuanceSession?, IdkError>,
) : CredentialIssuanceSessionStore {
    override suspend fun create(session: IssuanceSession): IdkResult<IssuanceSession, IdkError> = Ok(session)

    override suspend fun get(sessionId: String): IdkResult<IssuanceSession?, IdkError> = answer

    override suspend fun getByIssuerState(state: String): IdkResult<IssuanceSession?, IdkError> = Ok(null)

    override suspend fun findByCredentialConfigurationId(configId: String): IdkResult<IssuanceSession?, IdkError> = Ok(null)

    override suspend fun update(session: IssuanceSession): IdkResult<IssuanceSession, IdkError> = Ok(session)
}
