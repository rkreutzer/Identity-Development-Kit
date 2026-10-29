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
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialSetQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vp.universal.VerifiedClaimsValue
import com.sphereon.openid.oid4vp.universal.VerifiedDataMode
import com.sphereon.openid.oid4vp.verifier.CredentialIssuerRef
import com.sphereon.openid.oid4vp.verifier.CredentialTrustValidation
import com.sphereon.openid.oid4vp.verifier.CredentialTrustValidationMode
import com.sphereon.openid.oid4vp.verifier.MatchedCredential
import com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse
import com.sphereon.openid.oid4vp.verifier.ValidationResult
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

private val allModes = VerifiedDataMode.entries.toList()

class VerifiedDataBuilderTest {
    @Test
    fun verifiedClaimsRetainDisclosedArraysNestedObjectsAndScalarTypes() {
        val values = claimsFor(matched(CredentialFormat.SD_JWT_VC, "urn:test:achievement").copy(
            disclosedClaims = mapOf(
                "outcomes" to listOf("personal-care", "mobility"),
                "assessment" to mapOf("level" to 2, "supervised" to true, "notes" to null),
                "structured" to Json.parseToJsonElement("""{"items":[1,false,null]}"""),
            ),
        ))
        assertEquals(Json.parseToJsonElement("""["personal-care","mobility"]"""), values.claims?.get("outcomes"))
        assertEquals(Json.parseToJsonElement("""{"level":2,"supervised":true,"notes":null}"""), values.claims?.get("assessment"))
        assertEquals(Json.parseToJsonElement("""{"items":[1,false,null]}"""), values.claims?.get("structured"))
    }

    @Test
    fun `build verified data reconstructs authorization response and credential set refs`() {
        val session =
            AuthorizationSession(
                instanceId = "verifier-instance-verified-data-builder",
                sessionId = "session-1",
                correlationId = "corr-1",
                queryId = "kw1c-enrollment",
                dcqlQuery =
                    DcqlQuery(
                        credentials =
                            listOf(
                                DcqlCredentialQuery(id = "passport", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:passport")),
                            ),
                        credential_sets =
                            listOf(
                                DcqlCredentialSetQuery(
                                    required = true,
                                    options =
                                        listOf(
                                            listOf("passport"),
                                        ),
                                ),
                            ),
                    ),
                authorizationRequest =
                    AuthorizationRequest(
                        clientId = "https://verifier.example.com",
                        redirectUri = "https://verifier.example.com/callback",
                        state = "state-123",
                    ),
                status = AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED,
                parsedResponse =
                    ParsedAuthorizationResponse(
                        vpToken =
                            com.sphereon.openid.oid4vp.common.vpTokenOf(
                                "passport",
                                "eyJhbGciOiJFUzI1NiJ9.payload.signature",
                            ),
                        state = "state-123",
                        rawVpToken = """{"passport":["eyJhbGciOiJFUzI1NiJ9.payload.signature"]}""",
                    ),
                validationResult =
                    ValidationResult(
                        valid = true,
                        matchedCredentials =
                            listOf(
                                MatchedCredential(
                                    credentialQueryId = "passport",
                                    credentialFormat = CredentialFormat.SD_JWT_VC,
                                    presentation = "eyJhbGciOiJFUzI1NiJ9.payload.signature",
                                    issuer =
                                        CredentialIssuerRef(
                                            issuer = "https://issuer.example.com",
                                            method = "openid_federation",
                                            oidfedEntityId = "https://issuer.example.com",
                                        ),
                                    trust =
                                        CredentialTrustValidation(
                                            enabled = true,
                                            trusted = true,
                                            mode = CredentialTrustValidationMode.DEFAULT_ENFORCE,
                                            method = "openid_federation",
                                            trustDomainIds = listOf("domain-1"),
                                            matchedTrustDomainId = "domain-1",
                                            matchedAnchorId = "anchor-1",
                                            status = "TRUSTED",
                                        ),
                                    disclosedClaims =
                                        mapOf(
                                            "given_name" to "Ada",
                                            "family_name" to "Lovelace",
                                        ),
                                ),
                            ),
                    ),
                createdAt = 1L,
                updatedAt = 2L,
                expiresAt = 3L,
            )

        val verifiedData = buildVerifiedData(session, allModes)
        assertNotNull(verifiedData)

        val authorizationResponse = verifiedData.authorizationResponse
        assertNotNull(authorizationResponse)
        assertEquals("state-123", authorizationResponse["state"]?.toString()?.trim('"'))
        assertNotNull(authorizationResponse["vp_token"])

        assertEquals(null, authorizationResponse["dcql_response"])
        // A valid historical result does not fabricate the newly required provenance.
        assertEquals(null, verifiedData.credentialClaims?.single()?.verificationEvidence)
        val evidence = com.sphereon.openid.oid4vp.verifier.VerifiedCredentialEvidence(
            presentationSha256 = "server-digest",
            verifiedAtEpochMillis = 2L,
            trust = CredentialTrustValidation(enabled = true, trusted = false,
                mode = CredentialTrustValidationMode.AUDIT, details = "private-diagnostic",
                diagnostics = listOf("private-address")),
            status = com.sphereon.openid.oid4vp.verifier.VerifiedCredentialStatus(
                com.sphereon.openid.oid4vp.verifier.VerifiedCredentialStatusOutcome.SKIPPED,
                required = false, rejectOnUnresolvable = true),
        )
        val original = session.validationResult!!.matchedCredentials.single()
        val withEvidence = session.copy(validationResult = ValidationResult(true, listOf(original.copy(
            verificationEvidence = evidence,
            disclosedClaims = mapOf("verificationEvidence" to "forged", "verifiedAtEpochMillis" to 999L),
        ))))
        val exposed = assertNotNull(buildVerifiedData(withEvidence, allModes)?.credentialClaims?.single()?.verificationEvidence)
        assertEquals("server-digest", exposed.presentationSha256)
        assertEquals(2L, exposed.verifiedAtEpochMillis)
        assertEquals(CredentialTrustValidationMode.AUDIT, exposed.trust?.mode)
        assertEquals(false, exposed.trust?.trusted)
        assertEquals(null, exposed.trust?.details)
        assertEquals(emptyList(), exposed.trust?.diagnostics)

        // Universal OID4VP VerifiedClaimsValue.type is the digital credential type (a vct or json-ld
        // type); the format is only the fallback for a credential whose type is unknown.
        assertEquals("urn:example:passport", buildVerifiedData(session.copy(validationResult = ValidationResult(true, listOf(
            original.copy(credentialType = "urn:example:passport"),
        ))), allModes)?.credentialClaims?.single()?.type)
        assertEquals(CredentialFormat.SD_JWT_VC.value, verifiedData.credentialClaims?.single()?.type)
        assertEquals(CredentialFormat.SD_JWT_VC, verifiedData.credentialClaims?.single()?.format)
    }

    @Test
    fun shouldCarryTheCredentialTypeAndTheDetectedFormatIndependently() {
        val vct = "eu.we-build:authorisedsignatories:1"
        val typed = claimsFor(matched(CredentialFormat.SD_JWT_VC, credentialType = vct))
        assertEquals(vct, typed.type)
        assertEquals(CredentialFormat.SD_JWT_VC, typed.format)

        val mdoc = claimsFor(matched(CredentialFormat.MSO_MDOC, credentialType = "org.iso.18013.5.1.mDL"))
        assertEquals("org.iso.18013.5.1.mDL", mdoc.type)
        assertEquals(CredentialFormat.MSO_MDOC, mdoc.format)

        // A type that spells another format does not change the detected format.
        val lookalike = claimsFor(matched(CredentialFormat.SD_JWT_VC, credentialType = CredentialFormat.MSO_MDOC.value))
        assertEquals(CredentialFormat.MSO_MDOC.value, lookalike.type)
        assertEquals(CredentialFormat.SD_JWT_VC, lookalike.format)

        // An untyped credential keeps the existing type fallback, and the format stays explicit.
        val untyped = claimsFor(matched(CredentialFormat.JWT_VC_JSON, credentialType = null))
        assertEquals(CredentialFormat.JWT_VC_JSON.value, untyped.type)
        assertEquals(CredentialFormat.JWT_VC_JSON, untyped.format)
    }

    @Test
    fun shouldKeepTheRealTypeAndUseTheExplicitFormatWhenConvertingToAVerifiedCredential() {
        val vct = "eu.we-build:authorisedsignatories:1"
        val converted = VerifiedClaimsValue(id = "q", type = vct, format = CredentialFormat.SD_JWT_VC).toVerifiedCredential()
        assertEquals(vct, converted.type)
        assertEquals("dc+sd-jwt", converted.format)

        val lookalike = VerifiedClaimsValue(id = "q", type = "mso_mdoc", format = CredentialFormat.SD_JWT_VC).toVerifiedCredential()
        assertEquals("mso_mdoc", lookalike.type)
        assertEquals("dc+sd-jwt", lookalike.format)

        // Without a detected format the conversion reports it unavailable and never infers it from the type.
        val unavailable = VerifiedClaimsValue(id = "q", type = "dc+sd-jwt").toVerifiedCredential()
        assertEquals("dc+sd-jwt", unavailable.type)
        assertEquals("", unavailable.format)
    }

    @Test
    fun shouldSerializeTheFormatWithItsCanonicalValueAndRejectUnknownValues() {
        val json = Json
        val encoded = json.encodeToJsonElement(
            VerifiedClaimsValue.serializer(),
            VerifiedClaimsValue(id = "q", type = "urn:example:vct", format = CredentialFormat.SD_JWT_VC),
        ).jsonObject
        assertEquals("urn:example:vct", encoded.getValue("type").jsonPrimitive.content)
        assertEquals("dc+sd-jwt", encoded.getValue("format").jsonPrimitive.content)

        val decoded = json.decodeFromString(
            VerifiedClaimsValue.serializer(),
            """{"id":"q","type":"urn:example:vct","format":"mso_mdoc"}""",
        )
        assertEquals(CredentialFormat.MSO_MDOC, decoded.format)

        assertNull(json.decodeFromString(VerifiedClaimsValue.serializer(), """{"id":"q","type":"urn:example:vct"}""").format)
        assertNull(json.decodeFromString(VerifiedClaimsValue.serializer(), """{"id":"q","type":"urn:example:vct","format":null}""").format)
        assertFailsWith<SerializationException> {
            json.decodeFromString(VerifiedClaimsValue.serializer(), """{"id":"q","type":"urn:example:vct","format":"not-a-format"}""")
        }
    }

    @Test
    fun shouldSerializeClaimsAtTheirJsonTypesWithoutTurningStructureIntoText() {
        val address = Json.parseToJsonElement("""{"street":"Main","geo":[1,2.5],"unit":null}""")
        val typed = claimsFor(
            matched(CredentialFormat.SD_JWT_VC, credentialType = null).copy(
                disclosedClaims = linkedMapOf(
                    "phone" to "0612345678",
                    "flag_text" to "true",
                    "nan_text" to "NaN",
                    "age" to 30L,
                    "score" to 1.5,
                    "active" to true,
                    "none" to null,
                    "address" to address,
                    "tags" to Json.parseToJsonElement("""["a","b"]"""),
                    "sub" to "protected-and-dropped",
                ),
            ),
        )

        val encoded = Json.encodeToJsonElement(VerifiedClaimsValue.serializer(), typed).jsonObject.getValue("claims")

        assertEquals(
            Json.parseToJsonElement(
                """{"phone":"0612345678","flag_text":"true","nan_text":"NaN","age":30,"score":1.5,"active":true,"none":null,"address":{"street":"Main","geo":[1,2.5],"unit":null},"tags":["a","b"]}""",
            ),
            encoded,
        )
        assertEquals(true, typed.claims?.getValue("phone")?.jsonPrimitive?.isString)
        assertEquals(false, typed.claims?.getValue("age")?.jsonPrimitive?.isString)
    }

    @Test
    fun shouldReportEachMatchedCredentialOfOneQueryAsItsOwnEntry() {
        val session = sessionWith(
            matched(CredentialFormat.JWT_VC_JSON, credentialType = "Diploma").copy(disclosedClaims = mapOf("name" to "one")),
            matched(CredentialFormat.LDP_VC, credentialType = "Passport").copy(disclosedClaims = mapOf("name" to "two")),
        )

        val entries = assertNotNull(buildVerifiedData(session, allModes)).credentialClaims!!

        assertEquals(listOf("Diploma", "Passport"), entries.map { it.type })
        assertEquals(listOf(CredentialFormat.JWT_VC_JSON, CredentialFormat.LDP_VC), entries.map { it.format })
        assertEquals(listOf("one", "two"), entries.map { it.claims?.getValue("name")?.jsonPrimitive?.content })
    }

    @Test
    fun shouldRefuseAClaimValueThatCannotBeRepresentedAsJson() {
        assertFailsWith<IllegalArgumentException> {
            claimsFor(matched(CredentialFormat.SD_JWT_VC, credentialType = null).copy(disclosedClaims = mapOf("opaque" to Any())))
        }
    }

    private fun matched(format: CredentialFormat, credentialType: String?) =
        MatchedCredential(
            credentialQueryId = "passport",
            credentialFormat = format,
            presentation = "eyJhbGciOiJFUzI1NiJ9.payload.signature",
            credentialType = credentialType,
            disclosedClaims = mapOf("given_name" to "Ada"),
        )

    // The requested query always asks for dc+sd-jwt, so a matched format that differs proves the output does not echo the request.
    private fun claimsFor(matched: MatchedCredential): VerifiedClaimsValue =
        assertNotNull(buildVerifiedData(sessionWith(matched), allModes)).credentialClaims!!.single()

    private fun sessionWith(vararg matched: MatchedCredential) =
        AuthorizationSession(
            instanceId = "verifier-instance-verified-data-builder",
            sessionId = "session-format",
            correlationId = "corr-format",
            queryId = "format-query",
            dcqlQuery = DcqlQuery(credentials = listOf(DcqlCredentialQuery(id = "passport", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:passport")))),
            authorizationRequest = AuthorizationRequest(clientId = "https://verifier.example.com", redirectUri = "https://verifier.example.com/callback"),
            status = AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED,
            validationResult = ValidationResult(valid = true, matchedCredentials = matched.toList()),
            createdAt = 1L,
            updatedAt = 2L,
            expiresAt = 3L,
        )
}
