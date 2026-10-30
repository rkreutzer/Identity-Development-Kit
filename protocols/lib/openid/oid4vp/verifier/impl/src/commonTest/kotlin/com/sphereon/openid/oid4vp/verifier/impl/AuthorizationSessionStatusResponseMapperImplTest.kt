package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vp.common.vpTokenOf
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.universal.VerifiedDataMode
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejection
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejectionReason
import com.sphereon.openid.oid4vp.verifier.MatchedCredential
import com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse
import com.sphereon.openid.oid4vp.verifier.ValidationResult
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionError
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AuthorizationSessionStatusResponseMapperImplTest {
    private val mapper = AuthorizationSessionStatusResponseMapperImpl()

    @Test
    fun shouldMapEveryStatusFieldOfTheSession() {
        val session = verifiedSession().copy(verifierId = "verifier-a", templateId = "template-a", templateRevision = "rev-1")

        val output = mapper.build(session, emptyList())

        assertEquals(session.correlationId, output.correlationId)
        assertEquals(session.queryId, output.queryId)
        assertEquals(session.status, output.status)
        assertEquals(session.updatedAt, output.lastUpdated)
        assertEquals(session.sessionId, output.sessionId)
        assertEquals("verifier-a", output.verifierId)
        assertEquals(session.createdAt, output.createdAt)
        assertEquals(session.expiresAt, output.expiresAt)
        assertEquals(session.instanceId, output.verificationBinding?.instanceId)
        assertEquals("template-a", output.verificationBinding?.templateId)
        assertEquals("rev-1", output.verificationBinding?.templateRevision)
        assertEquals(true, output.validation?.valid)
    }

    @Test
    fun shouldMapTheStructuredErrorOfAnErroredSession() {
        val session =
            verifiedSession().copy(
                status = AuthorizationSessionStatus.ERROR,
                error = AuthorizationSessionError(code = "invalid_request", message = "bad response"),
            )

        val output = mapper.build(session, VerifiedDataMode.entries.toList())

        assertEquals("invalid_request", output.error?.code)
        assertEquals("bad response", output.error?.message)
        assertNull(output.verifiedData)
    }

    @Test
    fun shouldSelectExactlyTheRepresentationsEachModeSubsetAsksFor() {
        val session = verifiedSession()
        for (subset in subsets(VerifiedDataMode.entries)) {
            val data = mapper.build(session, subset).verifiedData

            if (subset.isEmpty()) {
                assertNull(data, "no modes must carry no verified data")
                continue
            }
            val wantsClaims = VerifiedDataMode.CREDENTIAL_CLAIMS_DESERIALIZED in subset
            val wantsResponse = VerifiedDataMode.AUTHORIZATION_RESPONSE in subset || VerifiedDataMode.VP_TOKEN in subset
            assertNotNull(data, "$subset")
            assertEquals(wantsClaims, data.credentialClaims != null, "credential_claims for $subset")
            assertEquals(wantsResponse, data.authorizationResponse != null, "authorization_response for $subset")
        }
    }

    @Test
    fun shouldTreatDuplicateAndReorderedModesAsTheirSet() {
        val session = verifiedSession()
        val ordered = mapper.build(session, listOf(VerifiedDataMode.VP_TOKEN, VerifiedDataMode.CREDENTIAL_CLAIMS_DESERIALIZED))
        val shuffled =
            mapper.build(
                session,
                listOf(
                    VerifiedDataMode.CREDENTIAL_CLAIMS_DESERIALIZED,
                    VerifiedDataMode.VP_TOKEN,
                    VerifiedDataMode.VP_TOKEN,
                    VerifiedDataMode.AUTHORIZATION_RESPONSE,
                ),
            )

        assertEquals(ordered.verifiedData, shuffled.verifiedData)
    }

    @Test
    fun shouldNotSelectVerifiedDataForAStatusOtherThanVerifiedEvenWithAValidResult() {
        for (status in AuthorizationSessionStatus.entries - AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED) {
            val output = mapper.build(verifiedSession().copy(status = status), VerifiedDataMode.entries.toList())

            assertNull(output.verifiedData, "$status must not carry verified data")
        }
    }

    @Test
    fun shouldNotSelectVerifiedDataWithoutAValidValidationResult() {
        assertNull(mapper.build(verifiedSession().copy(validationResult = null), VerifiedDataMode.entries.toList()).verifiedData)
        assertNull(mapper.build(verifiedSession().copy(validationResult = ValidationResult(valid = false)), VerifiedDataMode.entries.toList()).verifiedData)
    }

    @Test
    fun shouldSummarizeAValidationThatRejectedACredentialWithoutVerifiedData() {
        val rejection =
            CredentialValidationRejection(
                credentialQueryId = "identity_credential",
                reason = CredentialValidationRejectionReason.REVOKED,
                checkedAtEpochMillis = 7L,
            )
        val session =
            verifiedSession().copy(
                status = AuthorizationSessionStatus.ERROR,
                validationResult = ValidationResult(valid = false, rejections = listOf(rejection)),
            )

        val output = mapper.build(session, VerifiedDataMode.entries.toList())

        assertEquals(listOf(rejection), output.validation?.rejections)
        assertEquals(false, output.validation?.valid)
        assertNull(output.verifiedData)
    }

    @Test
    fun shouldReportNoValidationSummaryBeforeAnyValidationRan() {
        val output = mapper.build(verifiedSession().copy(status = AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED, validationResult = null), emptyList())

        assertNull(output.validation)
    }

    @Test
    fun shouldBuildTheAuthorizationResponseFromTheParsedResponse() {
        val data = assertNotNull(mapper.build(verifiedSession(), listOf(VerifiedDataMode.AUTHORIZATION_RESPONSE)).verifiedData)

        val response = assertNotNull(data.authorizationResponse)
        assertTrue(response.containsKey("vp_token"))
        assertEquals("state-1", response.getValue("state").toString().trim('"'))
    }

    @Test
    fun shouldCarryNoVerifiedDataWhenTheSelectedRepresentationHasNothingToCarry() {
        val withoutResponse = verifiedSession().copy(parsedResponse = null)

        assertNull(mapper.build(withoutResponse, listOf(VerifiedDataMode.AUTHORIZATION_RESPONSE)).verifiedData)
        assertNull(mapper.build(withoutResponse, listOf(VerifiedDataMode.VP_TOKEN)).verifiedData)
        assertNotNull(mapper.build(withoutResponse, listOf(VerifiedDataMode.CREDENTIAL_CLAIMS_DESERIALIZED)).verifiedData?.credentialClaims)
    }

    private fun <T> subsets(items: List<T>): List<List<T>> =
        (0 until (1 shl items.size)).map { mask -> items.filterIndexed { index, _ -> mask and (1 shl index) != 0 } }

    private fun verifiedSession(): AuthorizationSession =
        AuthorizationSession(
            instanceId = "mapper-instance",
            sessionId = "mapper-session",
            correlationId = "mapper-correlation",
            queryId = "mapper-query",
            dcqlQuery = DcqlQuery(
                credentials = listOf(DcqlCredentialQuery(id = "identity_credential", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
            ),
            authorizationRequest = AuthorizationRequest(
                clientId = "https://verifier.example.com",
                redirectUri = "https://verifier.example.com/response",
                state = "mapper-correlation",
            ),
            status = AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED,
            parsedResponse = ParsedAuthorizationResponse(
                vpToken = vpTokenOf("identity_credential", "presentation"),
                rawVpToken = "{\"identity_credential\":[\"presentation\"]}",
                state = "state-1",
            ),
            validationResult = ValidationResult(
                valid = true,
                matchedCredentials = listOf(
                    MatchedCredential(
                        credentialQueryId = "identity_credential",
                        credentialFormat = CredentialFormat.SD_JWT_VC,
                        presentation = "presentation",
                        disclosedClaims = mapOf("given_name" to "Ada"),
                    ),
                ),
            ),
            createdAt = 1_000L,
            updatedAt = 2_000L,
            expiresAt = 43_000L,
        )
}
