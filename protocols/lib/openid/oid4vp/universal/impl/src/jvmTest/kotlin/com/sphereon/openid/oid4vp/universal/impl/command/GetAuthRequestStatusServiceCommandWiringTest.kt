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

package com.sphereon.openid.oid4vp.universal.impl.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.events.SessionEventService
import com.sphereon.di.context.PrincipalType
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.common.store.StoreMetadata
import com.sphereon.openid.oid4vp.common.store.StoredEntry
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.universal.GetAuthRequestStatusInput
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.universal.universalOid4vpResponseJson
import com.sphereon.openid.oid4vp.universal.impl.createJvmUniversalOid4vpTestAppGraph
import com.sphereon.openid.oid4vp.universal.VerifiedDataMode
import com.sphereon.openid.oid4vp.universal.VerifiedDataOpts
import com.sphereon.openid.oid4vp.verifier.MatchedCredential
import com.sphereon.openid.oid4vp.verifier.impl.AuthorizationSessionStatusResponseMapperImpl
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionCallbackConfig
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejection
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejectionReason
import com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse
import com.sphereon.openid.oid4vp.verifier.ValidationResult
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionCreateArgs
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionError
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.openid.oid4vp.verifier.store.AuthorizationSessionStore
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

private const val REJECTED_CORRELATION_ID = "status-command-wiring-rejected"

/**
 * Guards the production wiring, not the helper.
 *
 * The mapper's own tests call it directly, so they stay green even if
 * [GetAuthRequestStatusServiceCommandImpl.doExecute] stops using the mapper's output for the
 * response. That is exactly the regression this task exists to prevent: a
 * refactor drops one named argument and the rejection silently disappears from the API again.
 *
 * This test therefore drives the command through its real public entry point, [
 * com.sphereon.core.api.service.ServiceCommand.execute], against a store holding a rejected
 * session, using the real session graph for execution context and events. Deleting the
 * mapper call from `doExecute` makes it fail.
 */
class GetAuthRequestStatusServiceCommandWiringTest {
    @Test
    fun executingTheStatusCommandReturnsTheStoredRejection() =
        runTest {
            val rejection =
                CredentialValidationRejection(
                    credentialQueryId = "identity_credential",
                    reason = CredentialValidationRejectionReason.REVOKED,
                    checkedAtEpochMillis = 1_764_000_000_000L,
                    statusValue = 1,
                )
            val command = statusCommandOver(rejectedSession(rejection))

            val output =
                command
                    .execute(GetAuthRequestStatusInput(correlationId = REJECTED_CORRELATION_ID))
                    .getOrElse { failure -> error("status command failed: $failure") }

            assertEquals(
                listOf(rejection),
                output.validation?.rejections,
                "doExecute must pass the stored rejection into the response, not merely be able to compute it",
            )
            assertEquals(false, output.validation?.valid)
            assertNull(output.verifiedData, "A rejected session has no verified data to report")

            val rejectionOnTheWire =
                universalOid4vpResponseJson
                    .parseToJsonElement(
                        universalOid4vpResponseJson.encodeToString(
                            GetAuthorizationRequestStatusOutput.serializer(),
                            output,
                        ),
                    ).jsonObject
                    .getValue("validation")
                    .jsonObject
                    .getValue("rejections")
                    .jsonArray
                    .single()
                    .jsonObject

            assertEquals("identity_credential", rejectionOnTheWire.getValue("credential_query_id").jsonPrimitive.content)
            assertEquals("revoked", rejectionOnTheWire.getValue("reason").jsonPrimitive.content)
            assertEquals("1", rejectionOnTheWire.getValue("status_value").jsonPrimitive.content)
        }

    @Test
    fun executingTheStatusCommandOnAVerifiedSessionReportsAnEmptyRejectionList() =
        runTest {
            val command = statusCommandOver(verifiedSession())

            val output =
                command
                    .execute(GetAuthRequestStatusInput(correlationId = REJECTED_CORRELATION_ID))
                    .getOrElse { failure -> error("status command failed: $failure") }

            assertEquals(true, output.validation?.valid)
            assertEquals(emptyList(), output.validation?.rejections)
        }

    @Test
    fun shouldOfferBothVerifiedDataRepresentationsWhateverModesTheCallbackSelects() =
        runTest {
            val selections =
                listOf(
                    null,
                    VerifiedDataOpts(),
                    VerifiedDataOpts(listOf(VerifiedDataMode.CREDENTIAL_CLAIMS_DESERIALIZED)),
                    VerifiedDataOpts(listOf(VerifiedDataMode.VP_TOKEN)),
                )
            for (selection in selections) {
                val session =
                    verifiedSession().copy(
                        parsedResponse =
                            ParsedAuthorizationResponse(
                                vpToken = com.sphereon.openid.oid4vp.common.vpTokenOf("identity_credential", "presentation"),
                                rawVpToken = "{\"identity_credential\":[\"presentation\"]}",
                                state = REJECTED_CORRELATION_ID,
                            ),
                        validationResult =
                            ValidationResult(
                                valid = true,
                                matchedCredentials =
                                    listOf(
                                        MatchedCredential(
                                            credentialQueryId = "identity_credential",
                                            credentialFormat = com.sphereon.openid.oid4vc.common.CredentialFormat.SD_JWT_VC,
                                            presentation = "presentation",
                                            disclosedClaims = mapOf("given_name" to "Ada"),
                                        ),
                                    ),
                            ),
                        callback = AuthorizationSessionCallbackConfig(url = "https://receiver.example.com/cb", verifiedData = selection),
                    )

                val output =
                    statusCommandOver(session)
                        .execute(GetAuthRequestStatusInput(correlationId = REJECTED_CORRELATION_ID))
                        .getOrElse { failure -> error("status command failed: $failure") }

                assertEquals(true, output.verifiedData?.credentialClaims != null, "claims for $selection")
                assertEquals(true, output.verifiedData?.authorizationResponse != null, "authorization response for $selection")
            }
        }

    private fun kotlinx.coroutines.test.TestScope.statusCommandOver(
        session: AuthorizationSession,
    ): GetAuthRequestStatusServiceCommandImpl {
        val app = createJvmUniversalOid4vpTestAppGraph(this)
        val sessionGraph =
            app.userContextManager
                .getAnonymous()
                .sessionContextManager
                .createOrGetFromId(session.sessionId, principalType = PrincipalType.USER)
                .graph
        return GetAuthRequestStatusServiceCommandImpl(
            execution = (sessionGraph as SessionExecution.Graph).sessionExecution,
            authorizationSessionStore = SingleSessionAuthorizationSessionStore(session),
            sessionEventService = (sessionGraph as SessionEventService.Graph).sessionEventService,
            statusResponseMapper = AuthorizationSessionStatusResponseMapperImpl(),
        )
    }

    private fun rejectedSession(rejection: CredentialValidationRejection): AuthorizationSession =
        baseSession().copy(
            sessionId = "status-command-wiring-rejected-session",
            status = AuthorizationSessionStatus.ERROR,
            validationResult =
                ValidationResult(
                    valid = false,
                    errors = listOf("Credential status asserts revocation"),
                    rejections = listOf(rejection),
                ),
        )

    private fun verifiedSession(): AuthorizationSession =
        baseSession().copy(
            sessionId = "status-command-wiring-verified-session",
            status = AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED,
            validationResult = ValidationResult(valid = true),
        )

    private fun baseSession(): AuthorizationSession =
        AuthorizationSession(
            instanceId = "verifier-instance-status-command-wiring",
            sessionId = "status-command-wiring-session",
            correlationId = REJECTED_CORRELATION_ID,
            dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "identity_credential",
                                format = "dc+sd-jwt",
                                meta = sdJwtVcMeta("urn:test:identity"),
                            ),
                        ),
                ),
            authorizationRequest =
                AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/response",
                    state = REJECTED_CORRELATION_ID,
                ),
            status = AuthorizationSessionStatus.ERROR,
            createdAt = 1_000L,
            updatedAt = 2_000L,
            expiresAt = 43_000L,
        )
}

/**
 * Holds exactly one session and refuses every mutation. The status command only reads, so anything
 * beyond [getByCorrelationId] being exercised would mean the command has grown a side effect that
 * this test should be told about.
 */
private class SingleSessionAuthorizationSessionStore(
    private val session: AuthorizationSession,
) : AuthorizationSessionStore {
    private fun readOnly(operation: String): IdkError =
        IdkError.INVALID_STATE(message = "The status command must not call $operation")

    override suspend fun createSession(
        correlationId: String?,
        args: AuthorizationSessionCreateArgs,
        ttlSeconds: Long,
    ): IdkResult<AuthorizationSession, IdkError> = Err(readOnly("createSession"))

    override suspend fun getByCorrelationId(correlationId: String): IdkResult<AuthorizationSession?, IdkError> =
        Ok(session.takeIf { candidate -> candidate.correlationId == correlationId })

    override suspend fun updateStatus(
        correlationId: String,
        status: AuthorizationSessionStatus,
        error: AuthorizationSessionError?,
    ): IdkResult<AuthorizationSession, IdkError> = Err(readOnly("updateStatus"))

    override suspend fun storeResponse(
        correlationId: String,
        parsedResponse: ParsedAuthorizationResponse,
    ): IdkResult<AuthorizationSession, IdkError> = Err(readOnly("storeResponse"))

    override suspend fun storeValidationResult(
        correlationId: String,
        validationResult: ValidationResult,
    ): IdkResult<AuthorizationSession, IdkError> = Err(readOnly("storeValidationResult"))

    override suspend fun getForRequestUri(
        correlationId: String,
        markRetrieved: Boolean,
    ): IdkResult<AuthorizationSession?, IdkError> = Err(readOnly("getForRequestUri"))

    override suspend fun put(
        key: String,
        value: AuthorizationSession,
        ttlSeconds: Long,
    ): IdkResult<StoreMetadata, IdkError> = Err(readOnly("put"))

    override suspend fun get(key: String): IdkResult<AuthorizationSession?, IdkError> =
        Ok(session.takeIf { candidate -> candidate.correlationId == key })

    override suspend fun getEntry(key: String): IdkResult<StoredEntry<AuthorizationSession>?, IdkError> =
        Err(readOnly("getEntry"))

    override suspend fun delete(key: String): IdkResult<Boolean, IdkError> = Err(readOnly("delete"))

    override suspend fun exists(key: String): IdkResult<Boolean, IdkError> = Ok(session.correlationId == key)

    override suspend fun touch(
        key: String,
        ttlSeconds: Long,
    ): IdkResult<Boolean, IdkError> = Err(readOnly("touch"))

    override suspend fun cleanupExpired(): IdkResult<Int, IdkError> = Err(readOnly("cleanupExpired"))
}
