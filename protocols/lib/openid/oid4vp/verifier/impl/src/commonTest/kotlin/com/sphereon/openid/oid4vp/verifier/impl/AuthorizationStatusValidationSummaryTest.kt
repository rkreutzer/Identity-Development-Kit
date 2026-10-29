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

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.universal.AuthorizationValidationSummary
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.universal.VerifiedDataMode
import com.sphereon.openid.oid4vp.universal.universalOid4vpResponseJson
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejection
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejectionReason
import com.sphereon.openid.oid4vp.verifier.ValidationResult
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The verifier's typed credential-status rejection is worthless to a relying party unless it
 * survives the wire. [com.sphereon.openid.oid4vp.verifier.ValidationResult] is deliberately not
 * `@Serializable`, so nothing before this test proved that a rejection can leave the process at
 * all: these assertions serialize the real
 * [GetAuthorizationRequestStatusOutput] and read the rejection back out of JSON, rather than
 * inspecting a Kotlin object that never crossed a codec.
 */
class AuthorizationStatusValidationSummaryTest {
    /** The configuration the REST endpoint and the callback dispatcher write this response with, referenced rather than copied. */
    private val productionJson = universalOid4vpResponseJson

    private val mapper = AuthorizationSessionStatusResponseMapperImpl()

    @Test
    fun rejectedSessionExposesTheRejectionByCorrelationId() {
        val rejection =
            CredentialValidationRejection(
                credentialQueryId = "identity_credential",
                reason = CredentialValidationRejectionReason.STATUS_NOT_ACCEPTED,
                checkedAtEpochMillis = 1_764_000_000_000L,
                statusValue = 3,
            )
        val session =
            session(
                correlationId = "rejected-correlation",
                status = AuthorizationSessionStatus.ERROR,
                validationResult =
                    ValidationResult(
                        valid = false,
                        errors = listOf("Credential status is not accepted"),
                        rejections = listOf(rejection),
                    ),
            )

        val summary = authorizationValidationSummaryOf(session)
        assertEquals(AuthorizationValidationSummary(valid = false, rejections = listOf(rejection)), summary)

        val encoded =
            productionJson.encodeToString(
                GetAuthorizationRequestStatusOutput.serializer(),
                mapper.build(session, VerifiedDataMode.entries.toList()),
            )
        val outputJson = productionJson.parseToJsonElement(encoded).jsonObject

        assertEquals("rejected-correlation", outputJson.getValue("correlation_id").jsonPrimitive.content)
        assertEquals(
            JsonNull,
            outputJson.getValue("verified_data"),
            "A rejected session carries no verified data. The production encoder leaves explicitNulls at " +
                "its default, so the key is present and explicitly null - it is never a populated object.",
        )

        val validationJson = outputJson.getValue("validation").jsonObject
        assertEquals(false, validationJson.getValue("valid").jsonPrimitive.content.toBoolean())
        val rejectionsJson = validationJson.getValue("rejections")
        assertEquals(true, rejectionsJson is JsonArray)
        val rejectionJson = rejectionsJson.jsonArray.single().jsonObject
        assertEquals(
            setOf("credential_query_id", "reason", "checked_at_epoch_millis", "status_value"),
            rejectionJson.keys,
        )
        assertEquals("identity_credential", rejectionJson.getValue("credential_query_id").jsonPrimitive.content)
        assertEquals("status_not_accepted", rejectionJson.getValue("reason").jsonPrimitive.content)
        assertEquals("1764000000000", rejectionJson.getValue("checked_at_epoch_millis").jsonPrimitive.content)
        assertEquals("3", rejectionJson.getValue("status_value").jsonPrimitive.content)

        val decoded =
            productionJson.decodeFromString(GetAuthorizationRequestStatusOutput.serializer(), encoded)
        assertEquals(listOf(rejection), decoded.validation?.rejections)
        assertEquals(false, decoded.validation?.valid)
    }

    @Test
    fun everyRejectionReasonSurvivesTheWire() {
        val rejections =
            CredentialValidationRejectionReason.entries.map { reason ->
                CredentialValidationRejection(
                    credentialQueryId = "identity_credential",
                    reason = reason,
                    checkedAtEpochMillis = 42L,
                )
            }
        val session =
            session(
                correlationId = "all-reasons",
                status = AuthorizationSessionStatus.ERROR,
                validationResult = ValidationResult(valid = false, rejections = rejections),
            )

        val encoded =
            productionJson.encodeToString(
                GetAuthorizationRequestStatusOutput.serializer(),
                mapper.build(session, VerifiedDataMode.entries.toList()),
            )
        val reasonsOnTheWire =
            productionJson
                .parseToJsonElement(encoded)
                .jsonObject
                .getValue("validation")
                .jsonObject
                .getValue("rejections")
                .jsonArray
                .map { entry -> entry.jsonObject.getValue("reason").jsonPrimitive.content }

        assertEquals(
            listOf("revoked", "suspended", "status_not_accepted", "status_unresolvable", "status_required_but_absent"),
            reasonsOnTheWire,
        )
        assertEquals(
            rejections,
            productionJson
                .decodeFromString(GetAuthorizationRequestStatusOutput.serializer(), encoded)
                .validation
                ?.rejections,
        )
    }

    @Test
    fun validSessionExposesAnEmptyRejectionList() {
        val session =
            session(
                correlationId = "verified-correlation",
                status = AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED,
                validationResult = ValidationResult(valid = true),
            )

        val summary = authorizationValidationSummaryOf(session)
        assertEquals(AuthorizationValidationSummary(valid = true), summary)
        assertEquals(emptyList(), summary?.rejections)

        val encoded =
            productionJson.encodeToString(
                GetAuthorizationRequestStatusOutput.serializer(),
                mapper.build(session, VerifiedDataMode.entries.toList()),
            )
        val validationJson =
            productionJson.parseToJsonElement(encoded).jsonObject.getValue("validation").jsonObject
        assertEquals(true, validationJson.getValue("valid").jsonPrimitive.content.toBoolean())
        assertEquals(emptyList(), validationJson.getValue("rejections").jsonArray.toList())
    }

    @Test
    fun sessionWithoutAValidationRunCarriesNoSummary() {
        val session =
            session(
                correlationId = "pending-correlation",
                status = AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED,
                validationResult = null,
            )

        assertNull(authorizationValidationSummaryOf(session))

        val encoded =
            productionJson.encodeToString(
                GetAuthorizationRequestStatusOutput.serializer(),
                mapper.build(session, VerifiedDataMode.entries.toList()),
            )
        assertFalse(
            productionJson.parseToJsonElement(encoded).jsonObject.containsKey("validation"),
            "A session that never ran a validation must not advertise one",
        )
    }

    private fun session(
        correlationId: String,
        status: AuthorizationSessionStatus,
        validationResult: ValidationResult?,
    ): AuthorizationSession =
        AuthorizationSession(
            instanceId = "verifier-instance-universal-status-test",
            sessionId = "session-$correlationId",
            correlationId = correlationId,
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
                    state = correlationId,
                ),
            status = status,
            validationResult = validationResult,
            createdAt = 1_000L,
            updatedAt = 2_000L,
            expiresAt = 43_000L,
        )
}
