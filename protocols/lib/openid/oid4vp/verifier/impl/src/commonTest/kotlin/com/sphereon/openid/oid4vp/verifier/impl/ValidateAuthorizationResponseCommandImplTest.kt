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

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.encodeToBase64
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.dataintegrity.model.ProofPurpose
import com.sphereon.crypto.dataintegrity.resolution.TrustedVerificationMethod
import com.sphereon.crypto.dataintegrity.resolution.VerificationMethodResolutionPolicy
import com.sphereon.crypto.jose.jws.JwsJsonGeneralWithIdentifiers
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.crypto.resolution.IdentifierOptsOrResult
import com.sphereon.crypto.resolution.extern.ExternalIdentifierDidOpts
import com.sphereon.crypto.resolution.extern.ExternalIdentifierX5cOpts
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vp.common.VpToken
import com.sphereon.openid.oid4vp.common.vpTokenOf
import com.sphereon.openid.oid4vp.common.ClientMetadata
import com.sphereon.openid.oid4vp.common.VpFormatInfo
import com.sphereon.openid.oid4vc.common.PresentationFormat
import com.sphereon.openid.oid4vp.dcql.DcqlClaimQuery
import com.sphereon.openid.oid4vp.dcql.ClaimsPathPointer
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialSetQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.mdocMeta
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.verifier.CredentialTrustValidation
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejectionReason
import com.sphereon.openid.oid4vp.verifier.CredentialIssuerRef
import com.sphereon.openid.oid4vp.verifier.CredentialTrustValidationMode
import com.sphereon.openid.oid4vp.verifier.HolderBindingResult
import com.sphereon.openid.oid4vp.verifier.Oid4vpCredentialTrustValidationArgs
import com.sphereon.openid.oid4vp.verifier.Oid4vpCredentialTrustValidator
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerificationArgs
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerificationResult
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerifier
import com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse
import com.sphereon.openid.oid4vp.verifier.ValidateAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.verifier.VerifyHolderBindingArgs
import com.sphereon.openid.oid4vp.verifier.VerifyHolderBindingCommand
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import com.sphereon.openid.oid4vp.verifier.CredentialTypeMatcher
import com.sphereon.openid.oid4vp.verifier.impl.testutil.CountingTypeMetadataCommand
import com.sphereon.openid.oid4vp.verifier.impl.testutil.Oid4vpVerifierTestContext
import com.sphereon.openid.oid4vp.verifier.impl.testutil.testCredentialTypeMatcher
import com.sphereon.sdjwt.vc.SdJwtVcTypeMetadata
import com.sphereon.sdjwt.vc.StaticTypeMetadataResolver
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.openid.oid4vp.verifier.store.AuthorizationSessionStore
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * Unit tests for ValidateAuthorizationResponseCommandImpl
 */
private const val FEDERATION_DID = "did:web:summa.fed.example"
private const val FEDERATION_KID = "did:web:summa.fed.example#issuer-assertion-summa"
private const val FEDERATION_ENTITY = "https://summa.fed.example/oid4vci/summa"

class ValidateAuthorizationResponseCommandImplTest {
    private val testContext = Oid4vpVerifierTestContext("validate-auth-response-test", this)

    @Test
    fun sdJwtExtractionRetainsNestedClaimStructureAndStringTypes() {
        val header = """{"alg":"ES256","typ":"dc+sd-jwt"}"""
        val payload = """{"iss":"https://issuer.example","vct":"urn:test:achievement","outcomes":{"personal_care":true},"items":[1,false,null],"reference":"001","text":"true"}"""
        val compact = "${header.encodeToByteArray().encodeToBase64Url()}.${payload.encodeToByteArray().encodeToBase64Url()}.signature~"
        val claims = createTestCommand().extractClaimProjections(compact, CredentialFormat.SD_JWT_VC).value.single().claims
        assertEquals(buildJsonObject { put("personal_care", JsonPrimitive(true)) }, claims["outcomes"])
        assertEquals(JsonArray(listOf(JsonPrimitive(1), JsonPrimitive(false), kotlinx.serialization.json.JsonNull)), claims["items"])
        assertEquals(JsonPrimitive("001"), claims["reference"])
        assertEquals(JsonPrimitive("true"), claims["text"])
    }

    @Test
    fun `test validate response with matching SD-JWT credential`() =
        runTest {
            // Given: DCQL query requesting SD-JWT credential
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "identity_credential",
                                format = "dc+sd-jwt",
                                meta = sdJwtVcMeta("urn:test:identity"),
                                claims =
                                    listOf(
                                        DcqlClaimQuery(path = ClaimsPathPointer(listOf(JsonPrimitive("first_name")))),
                                        DcqlClaimQuery(path = ClaimsPathPointer(listOf(JsonPrimitive("last_name")))),
                                    ),
                            ),
                        ),
                )

            // And: Parsed response with SD-JWT in DCQL format
            val sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoidXJuOnRlc3Q6aWRlbnRpdHkiLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSJ9.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.e30.sig"
            val parsedResponse =
                ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("identity_credential", sdJwt),
                    state = "state123",
                    rawVpToken = """{"identity_credential":["$sdJwt"]}""",
                )

            val originalRequest =
                AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = "state123",
                )

            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse = parsedResponse,
                    originalRequest = originalRequest,
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce123",
                )

            // When: Validating the response
            val result = validateWithPersistedSession(args, instanceId = "verifier-instance-sd-jwt-validation")

            // Then: Should validate successfully
            assertIs<Ok<*>>(result)
            val validation = result.value

            assertTrue(validation.valid)
            assertEquals(1, validation.matchedCredentials.size)
            assertEquals("identity_credential", validation.matchedCredentials[0].credentialQueryId)
            assertEquals("dc+sd-jwt", validation.matchedCredentials[0].credentialFormat.value)
            assertTrue(validation.errors.isEmpty())
        }

    @Test
    fun `credential trust validation receives stored dcql query id separately from credential query id`() =
        runTest {
            val trustValidator = CapturingTrustValidator()
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "identity_credential", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
                )
            val sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoidXJuOnRlc3Q6aWRlbnRpdHkiLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSJ9.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.e30.sig"
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("identity_credential", sdJwt),
                            state = "state123",
                            rawVpToken = """{"identity_credential":["$sdJwt"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = "state123",
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce123",
                    verifierId = "verifier-party-uuid",
                    dcqlQueryId = "employee-vp",
                )
            val result =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-trust-validation",
                    credentialTrustValidators = setOf(trustValidator),
                )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid)
            val validationArgs = assertNotNull(trustValidator.lastArgs)
            assertEquals("verifier-instance-trust-validation", validationArgs.verifierId)
            assertEquals("employee-vp", validationArgs.dcqlQueryId)
            assertEquals("identity_credential", validationArgs.credentialQueryId)
        }

    @Test
    fun `https issuer without federation material is presented to trust validation as an issuer uri`() =
        runTest {
            val issuer = validatedSdJwtIssuer(
                header = """{"alg":"ES256","kid":"key-1"}""",
                instanceId = "verifier-instance-issuer-uri",
            )

            assertEquals("https://issuer.example", issuer.issuer)
            assertEquals("issuer_uri", issuer.method)
            assertNull(issuer.oidfedEntityId)
        }

    @Test
    fun `https issuer with a federation trust chain header is presented as a federation entity`() =
        runTest {
            val issuer = validatedSdJwtIssuer(
                header = """{"alg":"ES256","trust_chain":["ZW50aXR5LXN0YXRlbWVudA"]}""",
                instanceId = "verifier-instance-federation-entity",
            )

            assertEquals("openid_federation", issuer.method)
            assertEquals("https://issuer.example", issuer.oidfedEntityId)
        }

    @Test
    fun `did issuer keeps did evidence and never becomes a federation entity`() =
        runTest {
            val issuer = validatedSdJwtIssuer(
                header = """{"alg":"ES256","kid":"did:web:issuer.example#key-1","trust_chain":["ZW50aXR5LXN0YXRlbWVudA"]}""",
                instanceId = "verifier-instance-did-issuer",
                iss = "did:web:issuer.example",
            )

            assertEquals("did", issuer.method)
            assertEquals("did:web:issuer.example", issuer.did)
            assertNull(issuer.oidfedEntityId)
        }

    private suspend fun validatedSdJwtIssuer(
        header: String,
        instanceId: String,
        iss: String = "https://issuer.example",
    ): CredentialIssuerRef {
        val trustValidator = CapturingTrustValidator()
        val issuerJwt =
            "${header.encodeToByteArray().encodeToBase64Url()}." +
                "${"""{"iss":"$iss","vct":"urn:test:identity"}""".encodeToByteArray().encodeToBase64Url()}.signature"
        val sdJwt = "$issuerJwt~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.e30.sig"
        val args =
            ValidateAuthorizationResponseArgs(
                parsedResponse =
                    ParsedAuthorizationResponse(
                        vpToken = vpTokenOf("identity_credential", sdJwt),
                        state = "state123",
                        rawVpToken = """{"identity_credential":["$sdJwt"]}""",
                    ),
                originalRequest =
                    AuthorizationRequest(
                        clientId = "https://verifier.example.com",
                        redirectUri = "https://verifier.example.com/callback",
                        state = "state123",
                    ),
                dcqlQuery =
                    DcqlQuery(
                        credentials = listOf(DcqlCredentialQuery(id = "identity_credential", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
                    ),
                expectedNonce = "nonce123",
            )
        val result = validateWithPersistedSession(args, instanceId = instanceId, credentialTrustValidators = setOf(trustValidator))
        assertIs<Ok<*>>(result)
        return assertNotNull(trustValidator.lastArgs?.issuer)
    }

    @Test
    fun `credential trust validation receives explicit templateId from args`() =
        runTest {
            val trustValidator = CapturingTrustValidator()
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "identity_credential", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
                )
            val sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoidXJuOnRlc3Q6aWRlbnRpdHkiLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSJ9.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.e30.sig"
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("identity_credential", sdJwt),
                            state = "state-template-explicit",
                            rawVpToken = """{"identity_credential":["$sdJwt"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = "state-template-explicit",
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce123",
                    templateId = "template-a",
                )
            val result =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-template-explicit",
                    credentialTrustValidators = setOf(trustValidator),
                )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid)
            val validationArgs = assertNotNull(trustValidator.lastArgs)
            assertEquals("template-a", validationArgs.templateId)
        }

    @Test
    fun `credential trust validation falls back to the session templateId when args omit one`() =
        runTest {
            val trustValidator = CapturingTrustValidator()
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "identity_credential", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
                )
            val sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoidXJuOnRlc3Q6aWRlbnRpdHkiLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSJ9.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.e30.sig"
            // args.templateId is deliberately left null — the wallet direct_post response never
            // carries a templateId. Only the session (persisted at request-creation time from the
            // template) knows it.
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("identity_credential", sdJwt),
                            state = "state-template-fallback",
                            rawVpToken = """{"identity_credential":["$sdJwt"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = "state-template-fallback",
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce123",
                )
            val result =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-template-fallback",
                    credentialTrustValidators = setOf(trustValidator),
                    sessionTemplateId = "template-from-session",
                )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid)
            val validationArgs = assertNotNull(trustValidator.lastArgs)
            assertEquals("template-from-session", validationArgs.templateId)
        }

    @Test
    fun `credential trust validation leaves templateId null when neither args nor session carry one`() =
        runTest {
            val trustValidator = CapturingTrustValidator()
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "identity_credential", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
                )
            val sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoidXJuOnRlc3Q6aWRlbnRpdHkiLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSJ9.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.e30.sig"
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("identity_credential", sdJwt),
                            state = "state-template-none",
                            rawVpToken = """{"identity_credential":["$sdJwt"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = "state-template-none",
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce123",
                )
            val result =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-template-none",
                    credentialTrustValidators = setOf(trustValidator),
                )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid)
            val validationArgs = assertNotNull(trustValidator.lastArgs)
            assertEquals(null, validationArgs.templateId)
        }

    @Test
    fun `test revoked credential is rejected by default status policy`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "identity_credential", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
                )
            val sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoidXJuOnRlc3Q6aWRlbnRpdHkiLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSJ9.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.e30.sig"
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("identity_credential", sdJwt),
                            state = "state123",
                            rawVpToken = """{"identity_credential":["$sdJwt"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = "state123",
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce123",
                )

            // A revoked status with no per-query policy uses the strict default → reject + discard.
            val result =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-revoked-status-validation",
                    credentialStatusVerifiers = setOf(FixedStatusVerifier(value = 1)),
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            // Short, user-facing message naming the credential + state; the misleading "not found" for a
            // submitted-but-discarded credential is suppressed, and the technical status-list URI/index
            // never leaks into the returned error (it goes to logs + an event instead).
            assertTrue(result.value.errors.any { it == "identity_credential is revoked" })
            assertTrue(result.value.errors.none { it.contains("not found") })
            assertTrue(result.value.errors.none { it.contains("status list") || it.contains("https://") })

            // An active status passes the same default policy.
            val activeResult =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-active-status-validation",
                    credentialStatusVerifiers = setOf(FixedStatusVerifier(value = 0)),
                )
            assertIs<Ok<*>>(activeResult)
            assertTrue(activeResult.value.valid)
            assertEquals(1, activeResult.value.matchedCredentials.size)
        }

    @Test
    fun `test validate response with matching mDoc credential`() =
        runTest {
            // Given: DCQL query requesting mDoc credential
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "mdl_credential",
                                format = "mso_mdoc",
                                meta = mdocMeta("org.iso.18013.5.1.mDL"),
                            ),
                        ),
                )

            // And: Parsed response with mDoc (base64 CBOR - not containing dots or tildes)
            val mdocPresentation = unsignedMdocPresentation(mdlFixtureDocument())
            val parsedResponse =
                ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("mdl_credential", mdocPresentation),
                    state = "state456",
                    rawVpToken = """{"mdl_credential":["$mdocPresentation"]}""",
                )

            val originalRequest =
                AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = "state456",
                )

            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse = parsedResponse,
                    originalRequest = originalRequest,
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce456",
                )

            // When: Validating the response
            val result = validateWithPersistedSession(args, instanceId = "verifier-instance-mdoc-validation")

            // Then: Should validate successfully
            assertIs<Ok<*>>(result)
            val validation = result.value

            assertTrue(validation.valid)
            assertEquals(1, validation.matchedCredentials.size)
            assertEquals("mdl_credential", validation.matchedCredentials[0].credentialQueryId)
            assertEquals("mso_mdoc", validation.matchedCredentials[0].credentialFormat.value)
        }

    @Test
    fun `mDoc validation uses persisted document type when caller query tries to override it`() =
        runTest {
            val persistedDocumentType = "org.iso.18013.5.1.mDL"
            val queryId = "mdl_credential"
            val persistedDcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = queryId,
                                format = "mso_mdoc",
                                meta = mdocMeta(persistedDocumentType),
                            ),
                        ),
                )
            val presentation = unsignedMdocPresentation(mdlFixtureDocument())

            listOf("org.iso.18013.5.1.caller-override", persistedDocumentType).forEachIndexed { index, callerDocumentType ->
                val state = "persisted-mdoc-type-$index"
                val callerDcqlQuery =
                    DcqlQuery(
                        credentials =
                            listOf(
                                DcqlCredentialQuery(
                                    id = queryId,
                                    format = "mso_mdoc",
                                    meta = mdocMeta(callerDocumentType),
                                ),
                            ),
                    )
                val args =
                    ValidateAuthorizationResponseArgs(
                        parsedResponse =
                            ParsedAuthorizationResponse(
                                vpToken = vpTokenOf(queryId, presentation),
                                state = state,
                                rawVpToken = """{"$queryId":["$presentation"]}""",
                            ),
                        originalRequest =
                            AuthorizationRequest(
                                clientId = "https://verifier.example.com",
                                redirectUri = "https://verifier.example.com/callback",
                                state = state,
                            ),
                        dcqlQuery = callerDcqlQuery,
                        expectedNonce = "nonce-$index",
                    )

                val result =
                    validateWithPersistedSession(
                        args = args,
                        instanceId = "verifier-instance-$state",
                        persistedDcqlQuery = persistedDcqlQuery,
                        verifyHolderBindingCommand = ExpectedMdocDocumentTypeHolderBindingCommand(persistedDocumentType),
                    )

                assertIs<Ok<*>>(result)
                assertTrue(
                    result.value.valid,
                    "Persisted document type must remain authoritative for caller type '$callerDocumentType': ${result.value.errors}",
                )
                assertEquals(1, result.value.matchedCredentials.size)
            }
        }

    @Test
    fun `test validate response with state mismatch`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "test", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential"))),
                )

            val sdjwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoidXJuOnRlc3Q6Y3JlZGVudGlhbCIsImZpcnN0X25hbWUiOiJKb2huIiwibGFzdF9uYW1lIjoiRG9lIn0.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.e30.sig"
            val parsedResponse =
                ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("test", sdjwt),
                    state = "wrong_state",
                    rawVpToken = """{"test":["$sdjwt"]}""",
                )

            val originalRequest =
                AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = "expected_state",
                )

            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse = parsedResponse,
                    originalRequest = originalRequest,
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce123",
                )

            val result = validateWithPersistedSession(args, instanceId = "verifier-instance-state-mismatch-validation")

            assertIs<Ok<*>>(result)
            val validation = result.value

            assertFalse(validation.valid)
            assertTrue(validation.errors.any { it.contains("State mismatch") })
        }

    @Test
    fun `test validate response with multiple credentials`() =
        runTest {
            // Given: DCQL query requesting multiple credentials
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(id = "identity_cred", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity")),
                            DcqlCredentialQuery(id = "mdl_cred", format = "mso_mdoc", meta = mdocMeta("org.iso.18013.5.1.mDL")),
                        ),
                )

            // And: Response with multiple presentations (DCQL format)
            val sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoidXJuOnRlc3Q6aWRlbnRpdHkiLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSJ9.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.e30.sig"
            val mdoc = unsignedMdocPresentation(mdlFixtureDocument())
            val parsedResponse =
                ParsedAuthorizationResponse(
                    vpToken =
                        VpToken.fromStrings(
                            mapOf(
                                "identity_cred" to listOf(sdJwt),
                                "mdl_cred" to listOf(mdoc),
                            ),
                        ),
                    state = "state789",
                    rawVpToken = """{"identity_cred":["$sdJwt"],"mdl_cred":["$mdoc"]}""",
                )

            val originalRequest =
                AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = "state789",
                )

            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse = parsedResponse,
                    originalRequest = originalRequest,
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce789",
                )

            val result = validateWithPersistedSession(args, instanceId = "verifier-instance-multiple-credential-validation")

            assertIs<Ok<*>>(result)
            val validation = result.value

            assertTrue(validation.valid)
            assertEquals(2, validation.matchedCredentials.size)
        }

    @Test
    fun `test validate response with credential_sets OR logic`() =
        runTest {
            // Given: DCQL query with credential_sets (OR logic)
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(id = "eu_pid", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:eu-pid")),
                            DcqlCredentialQuery(id = "mdl", format = "mso_mdoc", meta = mdocMeta("org.iso.18013.5.1.mDL")),
                        ),
                    credential_sets =
                        listOf(
                            DcqlCredentialSetQuery(
                                required = true,
                                options =
                                    listOf(
                                        listOf("eu_pid"),
                                        listOf("mdl"),
                                    ),
                            ),
                        ),
                )

            // And: Response with only one option satisfied (mdl)
            val mdoc = unsignedMdocPresentation(mdlFixtureDocument())
            val parsedResponse =
                ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("mdl", mdoc),
                    state = "state_or",
                    rawVpToken = """{"mdl":["$mdoc"]}""",
                )

            val originalRequest =
                AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = "state_or",
                )

            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse = parsedResponse,
                    originalRequest = originalRequest,
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce_or",
                )

            val result = validateWithPersistedSession(args, instanceId = "verifier-instance-credential-set-validation")

            assertIs<Ok<*>>(result)
            val validation = result.value

            // Should be valid because one option is satisfied
            assertTrue(validation.valid)
            assertEquals(1, validation.matchedCredentials.size)
            assertEquals("mdl", validation.matchedCredentials[0].credentialQueryId)
        }

    @Test
    fun `test validate response with missing required credential`() =
        runTest {
            // Given: DCQL query requiring specific credential
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(id = "required_cred", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:required")),
                        ),
                )

            // And: Response with mismatched format (no SD-JWT, just regular JWT)
            val jwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoidXJuOnRlc3Q6cmVxdWlyZWQifQ.signature"
            val parsedResponse =
                ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("required_cred", jwt),
                    state = "state_missing",
                    rawVpToken = """{"required_cred":["$jwt"]}""",
                )

            val originalRequest =
                AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = "state_missing",
                )

            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse = parsedResponse,
                    originalRequest = originalRequest,
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce_missing",
                )

            val result = validateWithPersistedSession(args, instanceId = "verifier-instance-missing-credential-validation")

            assertIs<Ok<*>>(result)
            val validation = result.value

            // Should fail because the response format doesn't match the required format
            assertFalse(validation.valid)
            assertTrue(validation.errors.any { it.contains("required_cred") || it.contains("not found") })
        }

    @Test
    fun `test rejects response without session correlation state`() =
        runTest {
            // Given: Original request without state
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "test", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential"))),
                )

            val sdjwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoidXJuOnRlc3Q6Y3JlZGVudGlhbCIsImZpcnN0X25hbWUiOiJKb2huIiwibGFzdF9uYW1lIjoiRG9lIn0.sig~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.e30.sig"
            val parsedResponse =
                ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("test", sdjwt),
                    state = null,
                    rawVpToken = """{"test":["$sdjwt"]}""",
                )

            val originalRequest =
                AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = null, // No state in original request
                )

            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse = parsedResponse,
                    originalRequest = originalRequest,
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce_no_state",
                )

            val result = createTestCommand().validateAuthorizationResponse(args)

            assertIs<Err<*>>(result)
            assertTrue(result.error.message.defaultMessage.contains("session correlation state"))
        }

    @Test
    fun testValidateResponseRejectsVcLdJsonJwtPresentationContainingVocab() =
        runTest {
            // VCDM 2.0 JWT body whose @context contains an embedded @vocab. The
            // validator catches this without any remote resolution: @vocab in any
            // embedded context object is forbidden by UNTP 0.7.0 VCP. The JWT is
            // unsigned for test purposes; AlwaysValidHolderBindingCommand stands
            // in for cryptographic verification.
            val jwt =
                unsignedVcLdJwt(
                    atVocab = "https://example.com/poison/",
                    primaryType = "DigitalProductPassport",
                )

            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "dpp",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                                require_cryptographic_holder_binding = false,
                            ),
                        ),
                )
            val parsedResponse =
                ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("dpp", jwt),
                    state = "state123",
                    rawVpToken = """{"dpp":["$jwt"]}""",
                )
            val originalRequest =
                AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = "state123",
                )
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse = parsedResponse,
                    originalRequest = originalRequest,
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce123",
                )

            val result =
                validateWithPersistedSession(
                    args,
                    instanceId = "verifier-instance-jsonld-vocab-validation",
                    verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
                )
            assertIs<Ok<*>>(result)
            val validation = result.value

            assertFalse(validation.valid, "presentation with @vocab must fail validation")
            assertTrue(
                validation.errors.any { it.contains("@vocab") },
                "expected explicit @vocab rejection in errors: ${validation.errors}",
            )
        }

    @Test
    fun `test validate response accepts non-vc_ld_json_jwt presentation unchanged`() =
        runTest {
            // SD-JWT presentation: the new VCDM 2.0 validator path must skip it
            // entirely (referencesVcdm2Context returns false because there is no
            // @context at the JWT body root) and the SD-JWT path goes through as
            // before. This is the regression-guard for the older 8 tests.
            val sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoidXJuOnRlc3Q6aWRlbnRpdHkiLCJmaXJzdF9uYW1lIjoiSm9obiIsImxhc3RfbmFtZSI6IkRvZSJ9.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.e30.sig"
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(id = "id", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity")),
                        ),
                )
            val parsedResponse =
                ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("id", sdJwt),
                    state = "s",
                    rawVpToken = """{"id":["$sdJwt"]}""",
                )
            val originalRequest =
                AuthorizationRequest(
                    clientId = "https://v.example.com",
                    redirectUri = "https://v.example.com/cb",
                    state = "s",
                )
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse = parsedResponse,
                    originalRequest = originalRequest,
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "n",
                )
            val result = validateWithPersistedSession(args, instanceId = "verifier-instance-non-jsonld-validation")
            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid)
            assertEquals(1, result.value.matchedCredentials.size)
        }

    @Test
    fun `VCDM 2 JOSE credential requires a bound VP when holder binding is required`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                            ),
                        ),
                )
            val presentation = validUnsignedVcLdJwt()
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("credential", presentation),
                            state = "v2-credential-state",
                            rawVpToken = """{"credential":["$presentation"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = "v2-credential-state",
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce-is-not-a-vp-claim",
                )
            val holderBinding = RecordingHolderBindingCommand()

            val result =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-v2-credential-routing",
                    verifyHolderBindingCommand = holderBinding,
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(0, holderBinding.calls)
            assertTrue(result.value.matchedCredentials.isEmpty())
            assertTrue(result.value.errors.any { it.contains("bound Verifiable Presentation") })
        }

    @Test
    fun `VCDM 2 JOSE bare credential with binding disabled rejects an invalid issuer JWS`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                                require_cryptographic_holder_binding = false,
                            ),
                        ),
                )
            val presentation = validUnsignedVcLdJwt()
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("credential", presentation),
                            state = "v2-credential-state-no-binding",
                            rawVpToken = """{"credential":["$presentation"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = "v2-credential-state-no-binding",
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce-is-not-a-vp-claim",
                )

            val result =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-v2-credential-no-binding",
                    verifyJwsCommand = FixedVerifyJwsCommand(valid = false),
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.matchedCredentials.isEmpty())
            assertTrue(result.value.errors.any { it.contains("signature", ignoreCase = true) || it.contains("issuer", ignoreCase = true) })
        }

    @Test
    fun `VCDM 2 JOSE issuer-authenticated bare credential is accepted when holder binding is disabled`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                                require_cryptographic_holder_binding = false,
                            ),
                        ),
                )
            val presentation = validUnsignedVcLdJwt()
            val state = "v2-credential-authenticated-state"
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("credential", presentation),
                            state = state,
                            rawVpToken = """{"credential":["$presentation"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = state,
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce-is-not-a-vp-claim",
                )

            val result = validateWithPersistedSession(
                args,
                instanceId = "verifier-instance-v2-authenticated",
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "issuer-authenticated bare VCDM 2.0 VC should match: ${result.value.errors}")
            assertEquals(1, result.value.matchedCredentials.size)
            val matched = result.value.matchedCredentials.single()
            val provenance = kotlin.test.assertNotNull(matched.verificationEvidence)
            assertEquals(
                com.sphereon.crypto.core.generic.hash(matched.presentation.encodeToByteArray(), com.sphereon.crypto.core.generic.DigestAlg.SHA256).encodeToBase64Url(),
                provenance.presentationSha256,
            )
            assertEquals(com.sphereon.openid.oid4vp.verifier.VerifiedCredentialStatusOutcome.SKIPPED, provenance.status.evaluation)
            assertTrue(provenance.verifiedAtEpochMillis > 0)
            val temporal = kotlin.test.assertNotNull(provenance.temporalFacts)
            assertEquals(kotlin.time.Instant.parse("2026-01-01T00:00:00Z").toEpochMilliseconds(), temporal.notBeforeEpochMillis)
            kotlin.test.assertNull(temporal.expiresAtEpochMillis)
        }

    @Test
    fun `VCDM non-DID issuer cannot resolve crypto key from holder-purpose source`() =
        runTest {
            val issuer = "https://issuer.example"
            val presentation = validUnsignedVcLdJwt(
                headerJson = """{"alg":"ES256","typ":"vc+jwt","cty":"vc","kid":"issuer-key"}""",
                issuer = issuer,
            )
            val dcqlQuery = DcqlQuery(
                credentials = listOf(
                    DcqlCredentialQuery(
                        id = "credential",
                        format = "jwt_vc_json-ld",
                        meta = JsonObject(emptyMap()),
                        require_cryptographic_holder_binding = false,
                    ),
                ),
            )
            val state = "vcdm-non-did-holder-purpose-key"
            val verifier = FixedVerifyJwsCommand(valid = true)
            val result = validateWithPersistedSession(
                ValidateAuthorizationResponseArgs(
                    parsedResponse = ParsedAuthorizationResponse(
                        vpToken = vpTokenOf("credential", presentation),
                        state = state,
                        rawVpToken = """{"credential":["$presentation"]}""",
                    ),
                    originalRequest = AuthorizationRequest(
                        clientId = "https://verifier.example.com",
                        redirectUri = "https://verifier.example.com/callback",
                        state = state,
                    ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce-is-not-a-vp-claim",
                    trustedAuthentications = listOf(
                        TrustedAuthenticationResolution(
                            controller = issuer,
                            trustedJwks = testTrustedJwks(),
                            purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.HOLDER,
                        ),
                    ),
                ),
                instanceId = "verifier-instance-non-did-holder-purpose",
                verifyJwsCommand = verifier,
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid, "holder-purpose material must not authenticate a non-DID credential issuer")
            assertEquals(0, verifier.calls, "issuer verification must fail before invoking crypto without issuer-purpose material")
        }

    @Test
    fun `VCDM 2 JOSE credential accepts an omitted recommended typ header`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                                require_cryptographic_holder_binding = false,
                            ),
                        ),
                )
            val presentation = validUnsignedVcLdJwt(
                headerJson = """{"alg":"ES256","kid":"did:example:issuer#key-1"}""",
            )
            val state = "v2-credential-optional-typ-state"
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("credential", presentation),
                            state = state,
                            rawVpToken = """{"credential":["$presentation"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = state,
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce-is-not-a-vp-claim",
                )

            val result = validateWithPersistedSession(
                args,
                instanceId = "verifier-instance-v2-optional-typ",
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "VCDM 2.0 typ is recommended rather than required: ${result.value.errors}")
            assertEquals(1, result.value.matchedCredentials.size)
        }

    @Test
    fun `DIIP VCDM credential under a DID is verified with the vc_issuer keys of its OpenID Federation entity`() =
        runTest {
            val verifier = FixedVerifyJwsCommand(valid = true)
            val trust = CapturingTrustValidator()
            val federationKeys = federationEntityJwks()
            val result = validateFederatedVcdm(
                state = "diip-vcdm-federation-admitted",
                trustedAuthentications = listOf(federationEntitySource(FEDERATION_ENTITY, federationKeys)),
                verifier = verifier,
                trust = trust,
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "the admitted vc_issuer keys must verify the credential: ${result.value.errors}")
            assertEquals(1, verifier.calls)
            assertEquals(federationKeys, verifier.trustedJwks.single(), "only the federation entity's vc_issuer keys may verify")
            assertEquals(null, verifier.identifiers.single(), "no DID document or header key is consulted")
            val issuer = kotlin.test.assertNotNull(trust.lastArgs?.issuer)
            assertEquals(FEDERATION_DID, issuer.issuer, "the credential keeps its DID as issuer")
            assertEquals(FEDERATION_ENTITY, issuer.oidfedEntityId, "the admitted controller is the federation entity")
            assertEquals("openid_federation", issuer.method)
        }

    @Test
    fun `DIIP VCDM credential naming a federation entity the verifier does not admit stays on the DID path`() =
        runTest {
            listOf(
                emptyList(),
                // Material for another entity, or issuer material for the entity itself, never verifies it.
                listOf(federationEntitySource("https://other.fed.example/issuer", federationEntityJwks())),
                listOf(
                    TrustedAuthenticationResolution(
                        FEDERATION_ENTITY,
                        trustedJwks = federationEntityJwks(),
                        purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                    ),
                ),
            ).forEachIndexed { index, authentications ->
                val verifier = FixedVerifyJwsCommand(valid = true)
                val result = validateFederatedVcdm(
                    state = "diip-vcdm-federation-refused-$index",
                    trustedAuthentications = authentications,
                    verifier = verifier,
                )

                assertIs<Ok<*>>(result)
                assertTrue(verifier.trustedJwks.none { it == federationEntityJwks() }, "case $index: the entity's vc_issuer keys must not be used")
                assertTrue(result.value.errors.none { it.contains("federation entity") }, "case $index: ${result.value.errors}")
            }
        }

    @Test
    fun `DIIP VCDM credential whose DID the verifier admits directly keeps the DID admission`() =
        runTest {
            val verifier = FixedVerifyJwsCommand(valid = true)
            val trust = CapturingTrustValidator()
            val result = validateFederatedVcdm(
                state = "diip-vcdm-did-anchor",
                trustedAuthentications = listOf(
                    TrustedAuthenticationResolution(
                        FEDERATION_DID,
                        identifier = ExternalIdentifierDidOpts(FEDERATION_DID),
                        purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                    ),
                    federationEntitySource(FEDERATION_ENTITY, federationEntityJwks()),
                ),
                verifier = verifier,
                trust = trust,
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, result.value.errors.joinToString())
            assertEquals(null, verifier.trustedJwks.single())
            assertEquals(FEDERATION_KID, (verifier.identifiers.single() as ExternalIdentifierDidOpts).identifier)
            assertEquals("did", trust.lastArgs?.issuer?.method)
            assertEquals(null, trust.lastArgs?.issuer?.oidfedEntityId)
        }

    private suspend fun validateFederatedVcdm(
        state: String,
        trustedAuthentications: List<TrustedAuthenticationResolution>,
        verifier: FixedVerifyJwsCommand,
        trust: Oid4vpCredentialTrustValidator? = null,
    ): IdkResult<com.sphereon.openid.oid4vp.verifier.ValidationResult, IdkError> {
        val presentation = federatedVcdm11VcJwt()
        return validateWithPersistedSession(
            ValidateAuthorizationResponseArgs(
                parsedResponse = ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("credential", presentation),
                    state = state,
                    rawVpToken = """{"credential":["$presentation"]}""",
                ),
                originalRequest = AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = state,
                ),
                dcqlQuery = DcqlQuery(
                    credentials = listOf(
                        DcqlCredentialQuery(
                            id = "credential",
                            format = "jwt_vc_json",
                            meta = vcdm11CredentialMeta(),
                            require_cryptographic_holder_binding = false,
                        ),
                    ),
                ),
                expectedNonce = "nonce-is-not-a-vp-claim",
                trustedAuthentications = trustedAuthentications,
            ),
            instanceId = "verifier-instance-$state",
            credentialTrustValidators = listOfNotNull(trust).toSet(),
            verifyJwsCommand = verifier,
        )
    }

    /** A VCDM 1.1 credential issued under did:web that names its Issuer's federation entity (DIIP v5, Appendix B). */
    private fun federatedVcdm11VcJwt(): String {
        val payload =
            """
            {
                "iss": "$FEDERATION_DID",
                "sub": "did:example:subject",
                "nbf": 1700000000,
                "vc": {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiableCredential"],
                    "issuanceDate": "2023-11-14T22:13:20Z",
                    "termsOfUse": [{"type": "OpenIDFederation", "policyId": "$FEDERATION_ENTITY"}],
                    "credentialSubject": {"id": "did:example:subject", "name": "Alice"}
                }
            }
            """.trimIndent()
        val header = """{"alg":"ES256","typ":"JWT","kid":"$FEDERATION_KID"}"""
        return "${header.encodeToByteArray().encodeToBase64Url()}.${payload.encodeToByteArray().encodeToBase64Url()}.fakesig"
    }

    private fun federationEntitySource(entity: String, jwks: JsonObject) =
        TrustedAuthenticationResolution(
            controller = entity,
            trustedJwks = jwks,
            purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
            controllerClaim = com.sphereon.openid.oid4vp.verifier.CredentialIssuerControllerClaim.FEDERATION_ENTITY,
        )

    private fun federationEntityJwks(): JsonObject =
        buildJsonObject {
            putJsonArray("keys") {
                add(
                    buildJsonObject {
                        put("kty", "EC")
                        put("crv", "P-256")
                        put("x", "WbbFpp0eS8_rJlvpuX_qEyU1J2PNmXYnqPCBJTqqiBA")
                        put("y", "F8kbfVPRQc5M9kJA1fy3c_0Q6vCqHy1X7CZQC6XQy9I")
                        put("kid", FEDERATION_KID)
                    },
                )
            }
        }

    @Test
    fun `VCDM 1 point 1 issuer-authenticated bare credential is accepted when holder binding is disabled`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "jwt_vc_json",
                                meta = vcdm11CredentialMeta(),
                                require_cryptographic_holder_binding = false,
                            ),
                        ),
                )
            val presentation = validVcdm11VcJwt()
            val state = "v1-credential-authenticated-state"
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("credential", presentation),
                            state = state,
                            rawVpToken = """{"credential":["$presentation"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = state,
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce-is-not-a-vp-claim",
                )

            val result = validateWithPersistedSession(
                args,
                instanceId = "verifier-instance-v1-authenticated",
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "issuer-authenticated bare VCDM 1.1 VC should match: ${result.value.errors}")
            assertEquals(1, result.value.matchedCredentials.size)
        }

    @Test
    fun `VCDM JOSE verification keeps credential id and credential subject id mappings independent`() =
        runTest {
            suspend fun rejectionErrors(
                presentation: String,
                format: String,
                metadata: JsonObject,
                state: String,
            ): String {
                val args =
                    ValidateAuthorizationResponseArgs(
                        parsedResponse =
                            ParsedAuthorizationResponse(
                                vpToken = vpTokenOf("credential", presentation),
                                state = state,
                                rawVpToken = """{"credential":["$presentation"]}""",
                            ),
                        originalRequest =
                            AuthorizationRequest(
                                clientId = "https://verifier.example.com",
                                redirectUri = "https://verifier.example.com/callback",
                                state = state,
                            ),
                        dcqlQuery =
                            DcqlQuery(
                                credentials =
                                    listOf(
                                        DcqlCredentialQuery(
                                            id = "credential",
                                            format = format,
                                            meta = metadata,
                                            require_cryptographic_holder_binding = false,
                                        ),
                                    ),
                            ),
                        expectedNonce = "nonce-is-not-a-vp-claim",
                    )
                val result =
                    validateWithPersistedSession(
                        args,
                        instanceId = "verifier-instance-$state",
                        verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
                    )
                assertIs<Ok<*>>(result)
                assertFalse(result.value.valid, "identity-mapping mismatch must invalidate $state")
                assertTrue(result.value.matchedCredentials.isEmpty())
                return result.value.errors.joinToString(" ")
            }

            val v11CredentialIdMismatch =
                rejectionErrors(
                    presentation =
                        validVcdm11VcJwt(
                            credentialId = "urn:uuid:v11-credential",
                            jwtId = "urn:uuid:not-the-v11-credential",
                        ),
                    format = "jwt_vc_json",
                    metadata = vcdm11CredentialMeta(),
                    state = "v11-jti-id-mismatch",
                )
            assertTrue(
                v11CredentialIdMismatch.contains("jti", ignoreCase = true),
                "expected an explicit jti/id mapping failure, got: $v11CredentialIdMismatch",
            )
            assertTrue(
                v11CredentialIdMismatch.contains("'id'", ignoreCase = true),
                "expected an explicit jti/id mapping failure, got: $v11CredentialIdMismatch",
            )

            val v11SubjectIdMismatch =
                rejectionErrors(
                    presentation = validVcdm11VcJwt(jwtSubjectId = "did:example:not-the-credential-subject"),
                    format = "jwt_vc_json",
                    metadata = vcdm11CredentialMeta(),
                    state = "v11-sub-subject-id-mismatch",
                )
            assertTrue(v11SubjectIdMismatch.contains("sub", ignoreCase = true), v11SubjectIdMismatch)
            assertTrue(v11SubjectIdMismatch.contains("credentialSubject.id", ignoreCase = true), v11SubjectIdMismatch)

            val v20CredentialIdMismatch =
                rejectionErrors(
                    presentation =
                        validUnsignedVcLdJwt(
                            credentialId = "urn:uuid:v20-credential",
                            jwtId = "urn:uuid:not-the-v20-credential",
                        ),
                    format = "jwt_vc_json-ld",
                    metadata = JsonObject(emptyMap()),
                    state = "v20-jti-id-mismatch",
                )
            assertTrue(v20CredentialIdMismatch.contains("jti", ignoreCase = true), v20CredentialIdMismatch)
            assertTrue(v20CredentialIdMismatch.contains("'id'", ignoreCase = true), v20CredentialIdMismatch)

            val v20SubjectIdMismatch =
                rejectionErrors(
                    presentation = validUnsignedVcLdJwt(jwtSubjectId = "did:example:not-the-credential-subject"),
                    format = "jwt_vc_json-ld",
                    metadata = JsonObject(emptyMap()),
                    state = "v20-sub-subject-id-mismatch",
                )
            assertTrue(v20SubjectIdMismatch.contains("sub", ignoreCase = true), v20SubjectIdMismatch)
            assertTrue(v20SubjectIdMismatch.contains("credentialSubject.id", ignoreCase = true), v20SubjectIdMismatch)
        }

    @Test
    fun `VCDM 2 JOSE credential with expired validUntil is rejected before status evaluation`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                                require_cryptographic_holder_binding = false,
                            ),
                        ),
                )
            val presentation =
                validUnsignedVcLdJwt(
                    validFrom = "2019-01-01T00:00:00Z",
                    validUntil = "2020-01-01T00:00:00Z",
                )
            val state = "v2-credential-expired-state"
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("credential", presentation),
                            state = state,
                            rawVpToken = """{"credential":["$presentation"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = state,
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce-is-not-a-vp-claim",
                )

            val result =
                validateWithPersistedSession(
                    args,
                    instanceId = "verifier-instance-v2-expired",
                    verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.matchedCredentials.isEmpty())
            assertTrue(
                result.value.errors.any { it.contains("expired", ignoreCase = true) || it.contains("validUntil") },
                result.value.errors.toString(),
            )
        }

    @Test
    fun `JOSE credential temporal policy rejects future and expired VCDM and JWT claims`() =
        runTest {
            suspend fun validateCredential(
                presentation: String,
                format: String,
                metadata: JsonObject,
                state: String,
            ): String {
                val args =
                    ValidateAuthorizationResponseArgs(
                        parsedResponse =
                            ParsedAuthorizationResponse(
                                vpToken = vpTokenOf("credential", presentation),
                                state = state,
                                rawVpToken = """{"credential":["$presentation"]}""",
                            ),
                        originalRequest =
                            AuthorizationRequest(
                                clientId = "https://verifier.example.com",
                                redirectUri = "https://verifier.example.com/callback",
                                state = state,
                            ),
                        dcqlQuery =
                            DcqlQuery(
                                credentials =
                                    listOf(
                                        DcqlCredentialQuery(
                                            id = "credential",
                                            format = format,
                                            meta = metadata,
                                            require_cryptographic_holder_binding = false,
                                        ),
                                    ),
                            ),
                        expectedNonce = "nonce-is-not-a-vp-claim",
                    )
                val result =
                    validateWithPersistedSession(
                        args,
                        instanceId = "verifier-instance-$state",
                        verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
                    )
                assertIs<Ok<*>>(result)
                assertFalse(
                    result.value.valid,
                    "temporal defect must invalidate the credential for $state: ${result.value.errors}",
                )
                return result.value.errors.joinToString(" ")
            }

            val futureVcdm2 =
                validateCredential(
                    presentation = validUnsignedVcLdJwt(validFrom = "2099-01-01T00:00:00Z"),
                    format = "jwt_vc_json-ld",
                    metadata = JsonObject(emptyMap()),
                    state = "temporal-v2-valid-from-future",
                )
            assertTrue(futureVcdm2.contains("not yet valid", ignoreCase = true))
            assertTrue(futureVcdm2.contains("validFrom", ignoreCase = true))

            val futureVcdm11 =
                validateCredential(
                    presentation = validVcdm11VcJwt(issuanceDate = "2099-01-01T00:00:00Z", notBefore = 4070908800),
                    format = "jwt_vc_json",
                    metadata = vcdm11CredentialMeta(),
                    state = "temporal-v11-issuance-date-future",
                )
            assertTrue(futureVcdm11.contains("not yet valid", ignoreCase = true))
            assertTrue(futureVcdm11.contains("issuanceDate", ignoreCase = true))

            val expiredVcdm11 =
                validateCredential(
                    presentation =
                        validVcdm11VcJwt(
                            issuanceDate = "2019-01-01T00:00:00Z",
                            expirationDate = "2020-01-01T00:00:00Z",
                            notBefore = 1546300800,
                            expiresAt = 1577836800,
                        ),
                    format = "jwt_vc_json",
                    metadata = vcdm11CredentialMeta(),
                    state = "temporal-v11-expiration-date-past",
                )
            assertTrue(expiredVcdm11.contains("expired", ignoreCase = true))
            assertTrue(expiredVcdm11.contains("expirationDate", ignoreCase = true))

            val futureIat =
                validateCredential(
                    presentation = validUnsignedVcLdJwt(jwtTimeClaims = "\"iat\":4102444800,"),
                    format = "jwt_vc_json-ld",
                    metadata = JsonObject(emptyMap()),
                    state = "temporal-v2-iat-future",
                )
            assertTrue(futureIat.contains("iat", ignoreCase = true))
            assertTrue(futureIat.contains("not yet valid", ignoreCase = true))

            val futureNbf =
                validateCredential(
                    presentation = validUnsignedVcLdJwt(jwtTimeClaims = "\"nbf\":4102444800,"),
                    format = "jwt_vc_json-ld",
                    metadata = JsonObject(emptyMap()),
                    state = "temporal-v2-nbf-future",
                )
            assertTrue(futureNbf.contains("nbf", ignoreCase = true))
            assertTrue(futureNbf.contains("not yet valid", ignoreCase = true))

            val expiredExp =
                validateCredential(
                    presentation = validUnsignedVcLdJwt(jwtTimeClaims = "\"exp\":1700000000,"),
                    format = "jwt_vc_json-ld",
                    metadata = JsonObject(emptyMap()),
                    state = "temporal-v2-exp-past",
                )
            assertTrue(expiredExp.contains("exp", ignoreCase = true))
            assertTrue(expiredExp.contains("expired", ignoreCase = true))
        }

    @Test
    fun `VCDM JOSE credential rejects an embedded attacker JWK before verification`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                                require_cryptographic_holder_binding = false,
                            ),
                        ),
                )
            val presentation =
                validUnsignedVcLdJwt(
                    headerJson = """{"alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"attacker","y":"attacker"}}""",
                )
            val state = "v2-credential-embedded-jwk-state"
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("credential", presentation),
                            state = state,
                            rawVpToken = """{"credential":["$presentation"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = state,
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "unused-bare-vc-nonce",
                )
            val verifier = FixedVerifyJwsCommand(valid = true)

            val result =
                validateWithPersistedSession(
                    args,
                    instanceId = "verifier-instance-v2-embedded-jwk",
                    verifyJwsCommand = verifier,
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(0, verifier.calls)
            assertTrue(result.value.errors.any { it.contains("embedded", ignoreCase = true) })
        }

    @Test
    fun `VCDM JOSE credential does not admit x5c through a configured JWKS source`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                                require_cryptographic_holder_binding = false,
                            ),
                        ),
                )
            val issuer = "https://issuer.example"
            val presentation =
                validUnsignedVcLdJwt(
                    headerJson = """{"alg":"ES256","kid":"issuer-key","x5c":["ZmFrZQ"]}""",
                    issuer = issuer,
                )
            val state = "v2-credential-x5c-with-jwks-state"
            val verifier = FixedVerifyJwsCommand(valid = true)

            val result =
                validateWithPersistedSession(
                    args =
                        ValidateAuthorizationResponseArgs(
                            parsedResponse =
                                ParsedAuthorizationResponse(
                                    vpToken = vpTokenOf("credential", presentation),
                                    state = state,
                                    rawVpToken = """{"credential":["$presentation"]}""",
                                ),
                            originalRequest =
                                AuthorizationRequest(
                                    clientId = "https://verifier.example.com",
                                    redirectUri = "https://verifier.example.com/callback",
                                    state = state,
                                ),
                            dcqlQuery = dcqlQuery,
                            expectedNonce = "unused-bare-vc-nonce",
                            trustedAuthentications =
                                listOf(
                                    TrustedAuthenticationResolution(
                                        controller = issuer,
                                        trustedJwks = testTrustedJwks(),
                                        purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                                    ),
                                ),
                        ),
                    instanceId = "verifier-instance-v2-x5c-with-jwks",
                    verifyJwsCommand = verifier,
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(0, verifier.calls)
            assertTrue(result.value.errors.any { it.contains("X.509", ignoreCase = true) })
        }

    // VC-JOSE-COSE section 4.2: the issuer kid is the absolute URL of the verification method that
    // signed. An admitted bare-DID issuer source must verify with that exact method, never with the
    // DID document's default key (a document can list e.g. a request-object key first).
    private suspend fun validateDidIssuerCredential(state: String, kid: String) =
        FixedVerifyJwsCommand(valid = true).let { verifier ->
            val presentation = validUnsignedVcLdJwt(headerJson = """{"alg":"ES256","kid":"$kid"}""")
            verifier to validateWithPersistedSession(
                args = ValidateAuthorizationResponseArgs(
                    parsedResponse = ParsedAuthorizationResponse(
                        vpToken = vpTokenOf("credential", presentation),
                        state = state,
                        rawVpToken = """{"credential":["$presentation"]}""",
                    ),
                    originalRequest = AuthorizationRequest(
                        clientId = "https://verifier.example.com",
                        redirectUri = "https://verifier.example.com/callback",
                        state = state,
                    ),
                    dcqlQuery = DcqlQuery(
                        credentials = listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                                require_cryptographic_holder_binding = false,
                            ),
                        ),
                    ),
                    expectedNonce = "unused-bare-vc-nonce",
                    trustedAuthentications = listOf(
                        TrustedAuthenticationResolution(
                            controller = "did:example:issuer",
                            identifier = ExternalIdentifierDidOpts("did:example:issuer"),
                            purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                        ),
                    ),
                ),
                instanceId = "verifier-instance-$state",
                verifyJwsCommand = verifier,
            )
        }

    @Test
    fun `an admitted issuer DID verifies the credential with the exact verification method named by kid`() =
        runTest {
            listOf("did:example:issuer#key-1", "did:example:issuer#assertion-2").forEach { kid ->
                val (verifier, result) = validateDidIssuerCredential("did-issuer-kid-${kid.substringAfter('#')}", kid)

                assertIs<Ok<*>>(result)
                assertTrue(result.value.valid, "kid=$kid: ${result.value.errors}")
                assertEquals(listOf<IdentifierOptsOrResult?>(ExternalIdentifierDidOpts(kid)), verifier.identifiers)
            }
        }

    @Test
    fun `an issuer kid outside the admitted issuer DID is refused before any signature verification`() =
        runTest {
            val (verifier, result) = validateDidIssuerCredential("did-issuer-foreign-kid", "did:example:other#key-1")

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(0, verifier.calls)
        }

    @Test
    fun `VCDM JOSE credential requires x5c to equal the configured X509 chain`() =
        runTest {
            val issuer = "https://issuer.example"
            val state = "v2-credential-x5c-chain-mismatch"
            val presentation =
                validUnsignedVcLdJwt(
                    headerJson = """{"alg":"ES256","x5c":["cHJlc2VudGVk"]}""",
                    issuer = issuer,
                )
            val query =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                                require_cryptographic_holder_binding = false,
                            ),
                        ),
                )
            val verifier = FixedVerifyJwsCommand(valid = true)
            val result =
                validateWithPersistedSession(
                    args =
                        ValidateAuthorizationResponseArgs(
                            parsedResponse =
                                ParsedAuthorizationResponse(
                                    vpToken = vpTokenOf("credential", presentation),
                                    state = state,
                                    rawVpToken = """{"credential":["$presentation"]}""",
                                ),
                            originalRequest =
                                AuthorizationRequest(
                                    clientId = "https://verifier.example.com",
                                    redirectUri = "https://verifier.example.com/callback",
                                    state = state,
                                ),
                            dcqlQuery = query,
                            expectedNonce = "unused-bare-vc-nonce",
                            trustedAuthentications =
                                listOf(
                                    TrustedAuthenticationResolution(
                                        controller = issuer,
                                        identifier = ExternalIdentifierX5cOpts(listOf("Y29uZmlndXJlZA")),
                                        purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                                    ),
                                ),
                        ),
                    instanceId = "verifier-instance-$state",
                    verifyJwsCommand = verifier,
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(0, verifier.calls)
            assertTrue(result.value.errors.any { it.contains("does not match", ignoreCase = true) })
        }

    @Test
    fun `VCDM JOSE credential rejects x5c combined with kid`() =
        runTest {
            val issuer = "https://issuer.example"
            val state = "v2-credential-x5c-with-kid"
            val presentation =
                validUnsignedVcLdJwt(
                    headerJson = """{"alg":"ES256","kid":"issuer-key","x5c":["cHJlc2VudGVk"]}""",
                    issuer = issuer,
                )
            val query =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                                require_cryptographic_holder_binding = false,
                            ),
                        ),
                )
            val verifier = FixedVerifyJwsCommand(valid = true)
            val result =
                validateWithPersistedSession(
                    args =
                        ValidateAuthorizationResponseArgs(
                            parsedResponse =
                                ParsedAuthorizationResponse(
                                    vpToken = vpTokenOf("credential", presentation),
                                    state = state,
                                    rawVpToken = """{"credential":["$presentation"]}""",
                                ),
                            originalRequest =
                                AuthorizationRequest(
                                    clientId = "https://verifier.example.com",
                                    redirectUri = "https://verifier.example.com/callback",
                                    state = state,
                                ),
                            dcqlQuery = query,
                            expectedNonce = "unused-bare-vc-nonce",
                            trustedAuthentications =
                                listOf(
                                    TrustedAuthenticationResolution(
                                        controller = issuer,
                                        identifier = ExternalIdentifierX5cOpts(listOf("cHJlc2VudGVk")),
                                        purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                                    ),
                                ),
                        ),
                    instanceId = "verifier-instance-$state",
                    verifyJwsCommand = verifier,
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(0, verifier.calls)
            assertTrue(result.value.errors.any { it.contains("cannot be combined", ignoreCase = true) })
        }

    @Test
    fun `VCDM JOSE credential rejects a DID kid for a different issuer`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "credential",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                                require_cryptographic_holder_binding = false,
                            ),
                        ),
                )
            val presentation =
                validUnsignedVcLdJwt(
                    headerJson = """{"alg":"ES256","kid":"did:example:attacker#key-1"}""",
                )
            val state = "v2-credential-wrong-kid-state"
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("credential", presentation),
                            state = state,
                            rawVpToken = """{"credential":["$presentation"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = state,
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "unused-bare-vc-nonce",
                )
            val verifier = FixedVerifyJwsCommand(valid = true)

            val result =
                validateWithPersistedSession(
                    args,
                    instanceId = "verifier-instance-v2-wrong-kid",
                    verifyJwsCommand = verifier,
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(0, verifier.calls)
            assertTrue(result.value.errors.any { it.contains("kid", ignoreCase = true) })
        }

    @Test
    fun `classified VCDM 2 JOSE presentation uses VP holder binding`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "presentation",
                                format = "jwt_vc_json-ld",
                                meta = JsonObject(emptyMap()),
                            ),
                        ),
                )
            val presentation = validUnsignedVcdm2VpJwt()
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("presentation", presentation),
                            state = "v2-presentation-state",
                            rawVpToken = """{"presentation":["$presentation"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = "v2-presentation-state",
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce-vp",
                    trustedAuthentications = listOf(
                        TrustedAuthenticationResolution(
                            controller = "https://holder.example",
                            trustedJwks = testTrustedJwks(),
                        ),
                    ),
                )
            val holderBinding = RecordingHolderBindingCommand()

            val result =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-v2-presentation-routing",
                    verifyHolderBindingCommand = holderBinding,
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(1, holderBinding.calls, "holder binding must run before child verification: ${result.value.errors}")
            assertEquals(PresentationFormat.JWT_VP_JSON, holderBinding.lastArgs?.presentationFormat)
            assertEquals("nonce-vp", holderBinding.lastArgs?.expectedNonce)
            assertEquals("https://verifier.example.com", holderBinding.lastArgs?.expectedAudience)
            assertEquals(1, holderBinding.lastArgs?.trustedAuthentications?.size)
            assertEquals("https://holder.example", holderBinding.lastArgs?.trustedAuthentications?.single()?.controller)
            assertTrue(result.value.matchedCredentials.isEmpty())
            assertTrue(result.value.errors.any { it.contains("recursive") || it.contains("child") || it.contains("verifiableCredential") })
        }

    @Test
    fun `VCDM 2 JOSE presentation rejects an algorithm outside persisted verifier metadata`() =
        runTest {
            val state = "v2-presentation-algorithm-mismatch"
            val holderBinding = RecordingHolderBindingCommand()
            val result =
                validateWithPersistedSession(
                    args = vcdm2PresentationArgs(
                        state = state,
                        presentation = validUnsignedVcdm2VpJwt(algorithm = "ES384"),
                    ),
                    instanceId = "verifier-instance-$state",
                    verifyHolderBindingCommand = holderBinding,
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(0, holderBinding.calls, "an unadvertised algorithm must be rejected before holder-binding crypto")
            assertTrue(result.value.errors.any { it.contains("persisted verifier allowlist", ignoreCase = true) })
        }

    @Test
    fun `jwt_vc_json accepts a VCDM one point one VP document and routes it to holder binding`() =
        runTest {
            val queryId = "v1-presentation"
            val state = "v1-presentation-state"
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = queryId,
                                format = "jwt_vc_json",
                                meta =
                                    JsonObject(
                                        mapOf(
                                            "type_values" to
                                                JsonArray(
                                                    listOf(
                                                        JsonArray(listOf(JsonPrimitive("https://www.w3.org/2018/credentials#VerifiableCredential"))),
                                                    ),
                                                ),
                                        ),
                                    ),
                            ),
                        ),
                )
            val presentation = validVcdm11VpJwtWithEmbeddedVc()
            val holderBinding = RecordingHolderBindingCommand()
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf(queryId, presentation),
                            state = state,
                            rawVpToken = """{"$queryId":["$presentation"]}""",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = state,
                        ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce-v1",
                )

            val result =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-$state",
                    verifyHolderBindingCommand = holderBinding,
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(1, holderBinding.calls)
            assertEquals(PresentationFormat.JWT_VP_JSON, holderBinding.lastArgs?.presentationFormat)
            assertTrue(result.value.matchedCredentials.isEmpty())
            assertTrue(result.value.errors.none { it.contains("does not match required format") })
            assertTrue(result.value.errors.any { it.contains("recursive") || it.contains("child") || it.contains("signature") })
        }

    @Test
    fun `VCDM 2 JOSE VP child representations never match in J1`() =
        runTest {
            val dcqlQuery = DcqlQuery(
                credentials = listOf(
                    DcqlCredentialQuery(
                        id = "presentation",
                        format = "jwt_vc_json-ld",
                        meta = JsonObject(emptyMap()),
                    ),
                ),
            )
            listOf<String?>(null, "null", "[]", "{}", VCDM2_ENVELOPED_VC_ENTRIES).forEach { children ->
                val presentation = validUnsignedVcdm2VpJwt(children)
                val state = "v2-presentation-child-${children ?: "absent"}"
                val args = ValidateAuthorizationResponseArgs(
                    parsedResponse = ParsedAuthorizationResponse(
                        vpToken = vpTokenOf("presentation", presentation),
                        state = state,
                        rawVpToken = """{"presentation":["$presentation"]}""",
                    ),
                    originalRequest = AuthorizationRequest(
                        clientId = "https://verifier.example.com",
                        redirectUri = "https://verifier.example.com/callback",
                        state = state,
                    ),
                    dcqlQuery = dcqlQuery,
                    expectedNonce = "nonce-vp",
                )
                val holderBinding = RecordingHolderBindingCommand()
                val result = validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-$state",
                    verifyHolderBindingCommand = holderBinding,
                )

                assertIs<Ok<*>>(result)
                assertFalse(result.value.valid, "children=$children must fail closed")
                assertTrue(result.value.matchedCredentials.isEmpty(), "children=$children must not match")
                assertEquals(1, holderBinding.calls, "outer VP binding must run before recursive boundary")
                assertTrue(result.value.errors.any { it.contains("recursive") || it.contains("no verifiableCredential") || it.contains("malformed") || it.contains("empty") })
            }
        }

    // OID4VP 1.0 (Cryptographic Holder Binding): the credential references the key whose control the
    // holder proves in the presentation. For a DID holder that is the credential's credentialSubject.id.
    private suspend fun validateDidHolderVp(
        state: String,
        children: String,
        holder: String = "did:example:alice",
        queryFormat: String = "jwt_vc_json-ld",
        requireHolderBinding: Boolean = true,
    ) = validateWithPersistedSession(
        args = vcdm2PresentationArgs(state, validUnsignedVcdm2VpJwt(children, holder = holder), queryFormat, requireHolderBinding),
        instanceId = "verifier-instance-$state",
        verifyHolderBindingCommand = RecordingHolderBindingCommand(),
        verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
        vcdmDataIntegrityVerifier = RecordingDataIntegrityVerifier(mutableListOf()),
    )

    @Test
    fun `DID holder VP is accepted when every child credential names the holder as subject`() =
        runTest {
            val children = "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, validVcdm2ChildCredential("alice"))},${dataIntegrityCredential("alice")}]"

            val result = validateDidHolderVp("did-holder-bound-children", children)

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "children bound to the DID holder must verify: ${result.value.errors}")
        }

    @Test
    fun `DID holder VP rejects an enveloped child credential issued to another subject`() =
        runTest {
            val children = "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, validVcdm2ChildCredential("bob"))}]"

            val result = validateDidHolderVp("did-holder-unbound-enveloped-child", children)

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.matchedCredentials.isEmpty())
            assertTrue(result.value.errors.any { it.contains("not bound to the presentation holder") }, "${result.value.errors}")
        }

    @Test
    fun `DID holder VP rejects a direct Data Integrity child issued to another subject even beside a bound child`() =
        runTest {
            val children = "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, validVcdm2ChildCredential("alice"))},${dataIntegrityCredential("bob")}]"

            val result = validateDidHolderVp("did-holder-one-unbound-di-child", children, queryFormat = "ldp_vc")

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.errors.any { it.contains("not bound to the presentation holder") }, "${result.value.errors}")
        }

    // VC-JOSE-COSE section 4.1.3: a VCDM 2.0 credential secured with JOSE may confirm the holder key
    // with cnf (RFC 7800), in the JWT claims or the protected header.
    @Test
    fun `VCDM 2 DID holder VP accepts a child confirmed by cnf kid and rejects one confirming another DID`() =
        runTest {
            listOf(false, true).forEach { inHeader ->
                val bound = validateDidHolderVp(
                    "did-holder-cnf-bound-$inHeader",
                    "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, vcdm2ChildCredentialConfirmedBy("did:example:alice#key-1", inHeader))}]",
                )
                assertIs<Ok<*>>(bound)
                assertTrue(bound.value.valid, "cnf.kid of the VP holder (header=$inHeader) must bind: ${bound.value.errors}")

                val unbound = validateDidHolderVp(
                    "did-holder-cnf-unbound-$inHeader",
                    "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, vcdm2ChildCredentialConfirmedBy("did:example:bob#key-1", inHeader))}]",
                )
                assertIs<Ok<*>>(unbound)
                assertFalse(unbound.value.valid)
                assertTrue(unbound.value.errors.any { it.contains("not bound to the presentation holder") }, "${unbound.value.errors}")
            }
        }

    @Test
    fun `VCDM 2 DID holder VP rejects a child with neither a subject id nor a confirmation`() =
        runTest {
            val result = validateDidHolderVp(
                "did-holder-no-subject-no-cnf",
                "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, vcdm2ChildCredentialConfirmedBy(null))}]",
            )
            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.errors.any { it.contains("not bound to the presentation holder") }, "${result.value.errors}")
        }

    @Test
    fun `subject binding is not required when the query disables cryptographic holder binding`() =
        runTest {
            val children = "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, validVcdm2ChildCredential("bob"))}]"

            val result = validateDidHolderVp("did-holder-binding-disabled", children, requireHolderBinding = false)

            assertIs<Ok<*>>(result)
            assertTrue(result.value.errors.none { it.contains("not bound to the presentation holder") }, "${result.value.errors}")
        }

    @Test
    fun `VCDM 1 point 1 DID holder VP binds its embedded credential through the JWT sub claim`() =
        runTest {
            fun args(state: String, presentation: String) =
                ValidateAuthorizationResponseArgs(
                    parsedResponse = ParsedAuthorizationResponse(
                        vpToken = vpTokenOf("presentation", presentation),
                        state = state,
                        rawVpToken = """{"presentation":["$presentation"]}""",
                    ),
                    originalRequest = AuthorizationRequest(
                        clientId = "https://verifier.example.com",
                        redirectUri = "https://verifier.example.com/callback",
                        state = state,
                    ),
                    dcqlQuery = DcqlQuery(
                        credentials = listOf(
                            DcqlCredentialQuery(id = "presentation", format = "jwt_vc_json", meta = vcdm11CredentialMeta()),
                        ),
                    ),
                    expectedNonce = "nonce-v1",
                )
            suspend fun validate(state: String, subjectId: String, confirmationKid: String? = null) = validateWithPersistedSession(
                args = args(state, validVcdm11VpJwtWithEmbeddedVc(validVcdm11VcJwt(subjectId = subjectId, confirmationKid = confirmationKid))),
                instanceId = "verifier-instance-$state",
                verifyHolderBindingCommand = RecordingHolderBindingCommand(),
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
            )

            val bound = validate("v11-did-holder-bound", subjectId = "holder")
            assertIs<Ok<*>>(bound)
            assertTrue(bound.value.valid, "a VCDM 1.1 credential issued to the VP holder must verify: ${bound.value.errors}")

            val unbound = validate("v11-did-holder-unbound", subjectId = "someone-else")
            assertIs<Ok<*>>(unbound)
            assertFalse(unbound.value.valid)
            assertTrue(unbound.value.errors.any { it.contains("not bound to the presentation holder") }, "${unbound.value.errors}")

            // VCDM 1.1 section 6.3.1 defines no cnf: a confirmation naming the holder does not bind it.
            val confirmedOnly = validate("v11-did-holder-cnf-only", subjectId = "someone-else", confirmationKid = "did:example:holder#key-1")
            assertIs<Ok<*>>(confirmedOnly)
            assertFalse(confirmedOnly.value.valid)
            assertTrue(confirmedOnly.value.errors.any { it.contains("not bound to the presentation holder") }, "${confirmedOnly.value.errors}")
        }

    // The VP envelope carries no credential claims: the match reports the verified child credential's
    // most specific type (Universal OID4VP "json-ld type") and its subject claims without the subject id.
    @Test
    fun `a DID holder VP match reports its child credential type and subject claims`() =
        runTest {
            val children = "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, validVcdm2ChildCredential("alice"))}]"

            val result = validateDidHolderVp("did-holder-match-type-and-claims", children)

            assertIs<Ok<*>>(result)
            val match = result.value.matchedCredentials.single()
            assertEquals("ExampleCredential", match.credentialType)
            assertEquals("alice", match.disclosedClaims["name"])
            assertFalse(match.disclosedClaims.containsKey("id"), "the subject id is a binding artefact, not a claim")
        }

    @Test
    fun `a VCDM 1 point 1 VP match reports its embedded credential type and subject claims`() =
        runTest {
            val state = "v11-match-type-and-claims"
            val presentation = validVcdm11VpJwtWithEmbeddedVc(validVcdm11VcJwt(subjectId = "holder", credentialType = "UniversityDegreeCredential"))
            val result = validateWithPersistedSession(
                args = ValidateAuthorizationResponseArgs(
                    parsedResponse = ParsedAuthorizationResponse(
                        vpToken = vpTokenOf("presentation", presentation),
                        state = state,
                        rawVpToken = """{"presentation":["$presentation"]}""",
                    ),
                    originalRequest = AuthorizationRequest(
                        clientId = "https://verifier.example.com",
                        redirectUri = "https://verifier.example.com/callback",
                        state = state,
                    ),
                    dcqlQuery = DcqlQuery(
                        credentials = listOf(DcqlCredentialQuery(id = "presentation", format = "jwt_vc_json", meta = vcdm11CredentialMeta())),
                    ),
                    expectedNonce = "nonce-v1",
                ),
                instanceId = "verifier-instance-$state",
                verifyHolderBindingCommand = RecordingHolderBindingCommand(),
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "${result.value.errors}")
            val match = result.value.matchedCredentials.single()
            assertEquals("UniversityDegreeCredential", match.credentialType)
            assertEquals("Alice", match.disclosedClaims["name"])
            assertFalse(match.disclosedClaims.containsKey("id"))
        }

    @Test
    fun `VCDM 2 J4 verifies every enveloped VC child`() =
        runTest {
            val first = validVcdm2ChildCredential("one")
            val second = validVcdm2ChildCredential("two")
            val children = "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, first, extensionContext = "https://example.com/credential-extension")},${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, second)}]"
            val presentation = validUnsignedVcdm2VpJwt(children)
            val state = "v2-j4-multiple-vc"
            val args = vcdm2PresentationArgs(state, presentation)
            val holderBinding = RecordingHolderBindingCommand()

            val result = validateWithPersistedSession(
                args = args,
                instanceId = "verifier-instance-$state",
                verifyHolderBindingCommand = holderBinding,
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "all VCDM 2 child credentials should verify: ${result.value.errors}")
            assertEquals(1, holderBinding.calls, "only the outer VP needs the outer holder binding")
            assertEquals(listOf("one", "two"), result.value.matchedCredentials.map { it.disclosedClaims["name"] })
        }

    @Test
    fun `VCDM 2 VP DCQL format matches the actual mixed child credential formats`() =
        runTest {
            // The VP version does not determine the child credential format. This VP is a
            // VCDM 2.0 JWT presentation containing one VCDM 2.0 JOSE-enveloped VC and one direct
            // Data Integrity VC. A query for ldp_vc must match because that format is actually
            // present in the second child, even though the outer VP is JWT-secured.
            val currentChild = validVcdm2ChildCredential("current-child")
            val directDataIntegrityChild = dataIntegrityCredential("direct-di-child")
            val children =
                "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, currentChild)},$directDataIntegrityChild]"
            val state = "v2-j4-mixed-child-formats"
            val dataIntegrityVerifier = RecordingDataIntegrityVerifier(mutableListOf())

            val result =
                validateWithPersistedSession(
                    args = vcdm2PresentationArgs(state, validUnsignedVcdm2VpJwt(children), "ldp_vc"),
                    instanceId = "verifier-instance-$state",
                    verifyHolderBindingCommand = RecordingHolderBindingCommand(),
                    verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
                    vcdmDataIntegrityVerifier = dataIntegrityVerifier,
                )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "actual child format should satisfy DCQL: ${result.value.errors}")
            val matches = result.value.matchedCredentials
            assertEquals(listOf<Any?>("current-child", "direct-di-child"), matches.map { it.disclosedClaims["name"] })
            assertEquals(CredentialFormat.LDP_VC, matches.last().credentialFormat)
            assertTrue(matches.all { it.presentationFormat == PresentationFormat.JWT_VP_JSON })
            assertEquals(1, dataIntegrityVerifier.calls.size)
        }

    @Test
    fun `VCDM 2 JOSE presentation dispatches a direct Data Integrity credential child`() =
        runTest {
            val child = dataIntegrityCredential("mixed-jose-di")
            val presentation = validUnsignedVcdm2VpJwt("[$child]")
            val state = "v2-j4-direct-di-child"
            val dataIntegrityVerifier = RecordingDataIntegrityVerifier(mutableListOf())

            val result = validateWithPersistedSession(
                args = vcdm2PresentationArgs(state, presentation, "ldp_vc"),
                instanceId = "verifier-instance-$state",
                verifyHolderBindingCommand = RecordingHolderBindingCommand(),
                vcdmDataIntegrityVerifier = dataIntegrityVerifier,
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "mixed JOSE/DI presentation should verify: ${result.value.errors}")
            assertEquals(1, dataIntegrityVerifier.calls.size)
            assertEquals(ProofPurpose.ASSERTION_METHOD, dataIntegrityVerifier.calls.single().expectedProofPurpose)
        }

    @Test
    fun `VCDM 1_1 J4 verifies every compact VC child`() =
        runTest {
            // Both children are issued to the VP holder (VCDM 1.1 holder binding is sub = credentialSubject.id).
            val first = validVcdm11VcJwt(subjectId = "holder", credentialId = "urn:example:first")
            val second = validVcdm11VcJwt(subjectId = "holder", credentialId = "urn:example:second")
            val presentation = validVcdm11VpJwtWithEmbeddedVc(first, second)
            val state = "v1-j4-multiple-vc"
            val queryId = "presentation"
            val args = ValidateAuthorizationResponseArgs(
                parsedResponse = ParsedAuthorizationResponse(
                    vpToken = vpTokenOf(queryId, presentation),
                    state = state,
                    rawVpToken = """{"$queryId":["$presentation"]}""",
                ),
                originalRequest = AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = state,
                ),
                dcqlQuery = DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(queryId, "jwt_vc_json", vcdm11CredentialMeta())),
                ),
                expectedNonce = "nonce-v1",
            )
            val verifier = FixedVerifyJwsCommand(valid = true)
            val result = validateWithPersistedSession(
                args = args,
                instanceId = "verifier-instance-$state",
                verifyJwsCommand = verifier,
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "all VCDM 1.1 child credentials should verify: ${result.value.errors}")
            assertEquals(2, verifier.calls, "both VCDM 1.1 child signatures must be independently checked")
            assertEquals(2, result.value.matchedCredentials.size, "each child credential is its own entry")
        }

    @Test
    fun `VCDM 1_1 JWT VP verifies a secured JSON Data Integrity VC child`() =
        runTest {
            val child = buildJsonObject {
                putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/2018/credentials/v1")) }
                putJsonArray("type") { add(JsonPrimitive("VerifiableCredential")) }
                put("issuer", "did:example:issuer")
                put("issuanceDate", "2026-08-25T12:00:00Z")
                putJsonObject("credentialSubject") { put("id", "did:example:holder") }
                putJsonObject("proof") {
                    put("type", "DataIntegrityProof")
                    put("cryptosuite", "eddsa-jcs-2022")
                    put("proofPurpose", "assertionMethod")
                    put("verificationMethod", "did:example:issuer#key")
                    put("proofValue", "zproof")
                }
            }
            val state = "v1-j4-json-child"
            val presentation = validVcdm11VpJwtWithEmbeddedJsonVc(child)
            val dataIntegrityVerifier = RecordingDataIntegrityVerifier(mutableListOf())
            val args = ValidateAuthorizationResponseArgs(
                parsedResponse = ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("presentation", presentation),
                    state = state,
                    rawVpToken = "{\"presentation\":[\"$presentation\"]}",
                ),
                originalRequest = AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = state,
                ),
                dcqlQuery = DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery("presentation", "ldp_vc", vcdm11CredentialMeta())),
                ),
                expectedNonce = "nonce-v1",
            )

            val result = validateWithPersistedSession(
                args = args,
                instanceId = "verifier-instance-$state",
                verifyHolderBindingCommand = RecordingHolderBindingCommand(),
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
                vcdmDataIntegrityVerifier = dataIntegrityVerifier,
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "VCDM 1.1 JSON child should verify: ${result.value.errors}")
            assertEquals(CredentialFormat.LDP_VC, result.value.matchedCredentials.single().credentialFormat)
            assertEquals(PresentationFormat.JWT_VP_JSON, result.value.matchedCredentials.single().presentationFormat)
            assertEquals(1, dataIntegrityVerifier.calls.size)
            assertEquals(ProofPurpose.ASSERTION_METHOD, dataIntegrityVerifier.calls.single().expectedProofPurpose)
        }

    @Test
    fun `VCDM 1_1 JWT VP rejects a cryptographically accepted profile-invalid JSON child`() =
        runTest {
            val invalidChild = buildJsonObject {
                putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/2018/credentials/v1")) }
                putJsonArray("type") { add(JsonPrimitive("VerifiableCredential")) }
                put("issuer", "did:example:issuer")
                put("issuanceDate", "2026-08-25T12:00:00Z")
                putJsonObject("proof") {
                    put("type", "DataIntegrityProof")
                    put("cryptosuite", "eddsa-jcs-2022")
                    put("proofPurpose", "assertionMethod")
                    put("verificationMethod", "did:example:issuer#key")
                    put("proofValue", "zproof")
                }
            }
            val state = "v1-j4-invalid-json-child"
            val dataIntegrityVerifier = RecordingDataIntegrityVerifier(mutableListOf())
            val presentation = validVcdm11VpJwtWithEmbeddedJsonVc(invalidChild)
            val result = validateWithPersistedSession(
                args = ValidateAuthorizationResponseArgs(
                    parsedResponse = ParsedAuthorizationResponse(
                        vpToken = vpTokenOf("presentation", presentation),
                        state = state,
                        rawVpToken = "{\"presentation\":[\"$presentation\"]}",
                    ),
                    originalRequest = AuthorizationRequest(
                        clientId = "https://verifier.example.com",
                        redirectUri = "https://verifier.example.com/callback",
                        state = state,
                    ),
                    dcqlQuery = DcqlQuery(
                        credentials = listOf(DcqlCredentialQuery("presentation", "ldp_vc", vcdm11CredentialMeta())),
                    ),
                    expectedNonce = "nonce-v1",
                ),
                instanceId = "verifier-instance-$state",
                verifyHolderBindingCommand = RecordingHolderBindingCommand(),
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
                vcdmDataIntegrityVerifier = dataIntegrityVerifier,
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.errors.any { it.contains("profile", ignoreCase = true) })
            assertEquals(1, dataIntegrityVerifier.calls.size)
        }

    @Test
    fun `VCDM 2 JWT VP rejects a cryptographically accepted profile-invalid direct JSON child`() =
        runTest {
            val invalidChild = buildJsonObject {
                putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/ns/credentials/v2")) }
                putJsonArray("type") { add(JsonPrimitive("VerifiableCredential")) }
                put("issuer", "https://issuer.example/invalid")
                putJsonObject("proof") {
                    put("type", "DataIntegrityProof")
                    put("cryptosuite", "eddsa-jcs-2022")
                    put("proofPurpose", "assertionMethod")
                    put("verificationMethod", "did:example:issuer#key")
                    put("proofValue", "zproof")
                }
            }
            val state = "v2-j4-invalid-json-child"
            val dataIntegrityVerifier = RecordingDataIntegrityVerifier(mutableListOf())
            val result = validateWithPersistedSession(
                args = vcdm2PresentationArgs(state, validUnsignedVcdm2VpJwt("[$invalidChild]"), "ldp_vc"),
                instanceId = "verifier-instance-$state",
                verifyHolderBindingCommand = RecordingHolderBindingCommand(),
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
                vcdmDataIntegrityVerifier = dataIntegrityVerifier,
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.errors.any { it.contains("profile", ignoreCase = true) })
            assertEquals(1, dataIntegrityVerifier.calls.size)
        }

    @Test
    fun `VCDM 2 J4 rejects a tampered second child after checking the first`() =
        runTest {
            val first = validVcdm2ChildCredential("first")
            val second = validVcdm2ChildCredential("second")
            val presentation = validUnsignedVcdm2VpJwt(
                "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, first)},${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, second)}]",
            )
            val state = "v2-j4-tampered-second"
            val verifier = FixedVerifyJwsCommand(valid = true, rejectOnCall = 2)
            val result = validateWithPersistedSession(
                args = vcdm2PresentationArgs(state, presentation),
                instanceId = "verifier-instance-$state",
                verifyJwsCommand = verifier,
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(2, verifier.calls, "both child signatures must be independently checked")
            assertTrue(result.value.errors.any { it.contains("signature", true) })
            assertTrue(result.value.matchedCredentials.isEmpty(), "a bad later child must not leave the earlier child accepted")
        }

    @Test
    fun `VCDM compact credential does not invoke issuer trust before cryptographic verification`() =
        runTest {
            val state = "vcdm-crypto-before-trust"
            val events = mutableListOf<String>()
            val presentation = validUnsignedVcLdJwt()
            val args = ValidateAuthorizationResponseArgs(
                parsedResponse = ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("credential", presentation),
                    state = state,
                    rawVpToken = """{"credential":["$presentation"]}""",
                ),
                originalRequest = AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = state,
                ),
                dcqlQuery = DcqlQuery(
                    credentials = listOf(
                        DcqlCredentialQuery(
                            id = "credential",
                            format = "jwt_vc_json-ld",
                            meta = JsonObject(emptyMap()),
                            require_cryptographic_holder_binding = false,
                        ),
                    ),
                ),
                expectedNonce = "unused-bare-vc-nonce",
            )
            val trust = OrderedTrustValidator(events, trusted = true)
            val result = validateWithPersistedSession(
                args = args,
                instanceId = "verifier-instance-$state",
                credentialTrustValidators = setOf(trust),
                verifyJwsCommand = OrderedVerifyJwsCommand(events, valid = false),
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(0, trust.calls)
            assertEquals(listOf("crypto"), events)
        }

    @Test
    fun `VCDM VP rejects an untrusted second child after verifying every child`() =
        runTest {
            val first = validVcdm2ChildCredential("first")
            val second = validVcdm2ChildCredential("second")
            val state = "vcdm-untrusted-second-child"
            val events = mutableListOf<String>()
            val trust = OrderedTrustValidator(events, trusted = false, trustedCalls = setOf(1))
            val result = validateWithPersistedSession(
                args = vcdm2PresentationArgs(
                    state,
                    validUnsignedVcdm2VpJwt(
                        "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, first)},${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, second)}]",
                    ),
                ),
                instanceId = "verifier-instance-$state",
                credentialTrustValidators = setOf(trust),
                verifyJwsCommand = OrderedVerifyJwsCommand(events, valid = true),
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(2, trust.calls)
            assertEquals(listOf("crypto", "trust", "crypto", "trust"), events)
            assertTrue(result.value.errors.any { it.contains("trust", ignoreCase = true) })
            assertTrue(result.value.matchedCredentials.isEmpty())
        }

    @Test
    fun `VCDM VP rejects a revoked second child after verifying every child`() =
        runTest {
            val first = validVcdm2ChildCredential("first")
            val second = validVcdm2ChildCredential("second")
            val state = "vcdm-revoked-second-child"
            val events = mutableListOf<String>()
            val result = validateWithPersistedSession(
                args = vcdm2PresentationArgs(
                    state,
                    validUnsignedVcdm2VpJwt(
                        "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, first)},${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, second)}]",
                    ),
                ),
                instanceId = "verifier-instance-$state",
                credentialStatusVerifiers = setOf(SecondChildRevokedStatusVerifier(events)),
                verifyJwsCommand = OrderedVerifyJwsCommand(events, valid = true),
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(listOf("crypto", "status", "crypto", "status"), events)
            assertTrue(result.value.errors.any { it.contains("status", ignoreCase = true) })
            assertTrue(result.value.matchedCredentials.isEmpty())
            // A credential nested in the submitted VP reaches the typed rejection channel too, under
            // the parent DCQL query identity - the child has no query id of its own.
            val nestedRejection = result.value.rejections.single()
            assertEquals("presentation", nestedRejection.credentialQueryId)
            assertEquals(CredentialValidationRejectionReason.REVOKED, nestedRejection.reason)
            assertEquals(1, nestedRejection.statusValue)
        }

    @Test
    fun `ldp VP verifies every nested VC before invoking trust callbacks`() =
        runTest {
            val state = "ldp-vp-nested-children"
            val events = mutableListOf<String>()
            val first = dataIntegrityCredential("first", subjectId = "did:example:holder")
            val second = dataIntegrityCredential("second", subjectId = "did:example:holder")
            val verificationMethodResolutionPolicy = VerificationMethodResolutionPolicy.of(
                listOf(
                    TrustedVerificationMethod(
                        reference = "did:example:holder#key",
                        identifierOpts = ExternalIdentifierDidOpts("did:example:holder"),
                        controller = "did:example:holder",
                        authorizedProofPurposes = setOf(ProofPurpose.AUTHENTICATION),
                    ),
                    TrustedVerificationMethod(
                        reference = "did:example:issuer#key",
                        identifierOpts = ExternalIdentifierDidOpts("did:example:issuer"),
                        controller = "did:example:issuer",
                        authorizedProofPurposes = setOf(ProofPurpose.ASSERTION_METHOD),
                    ),
                ),
            )
            val vp = buildJsonObject {
                putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/ns/credentials/v2")) }
                putJsonArray("type") { add(JsonPrimitive("VerifiablePresentation")) }
                put("holder", "did:example:holder")
                putJsonArray("verifiableCredential") { add(first); add(second) }
                putJsonObject("proof") { put("type", "DataIntegrityProof"); put("cryptosuite", "eddsa-jcs-2022"); put("proofPurpose", "authentication"); put("verificationMethod", "did:example:holder#key"); put("proofValue", "zproof"); put("created", "2026-08-25T12:00:00Z") }
            }
            val args = ValidateAuthorizationResponseArgs(
                parsedResponse = ParsedAuthorizationResponse(
                    vpToken = VpToken(mapOf("presentation" to listOf(vp))),
                    state = state,
                    rawVpToken = "{}",
                ),
                originalRequest = AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = state,
                ),
                dcqlQuery = DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery("presentation", "ldp_vc", vcdm11CredentialMeta())),
                ),
                expectedNonce = "nonce-vp",
                verificationMethodResolutionPolicy = verificationMethodResolutionPolicy,
            )
            val dataIntegrityVerifier = RecordingDataIntegrityVerifier(events)
            val result = validateWithPersistedSession(
                args = args,
                instanceId = "verifier-instance-$state",
                credentialTrustValidators = setOf(OrderedTrustValidator(events, trusted = true)),
                verifyHolderBindingCommand = AlwaysValidHolderBindingCommand,
                vcdmDataIntegrityVerifier = dataIntegrityVerifier,
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "nested ldp credentials should verify: ${result.value.errors}")
            assertEquals(listOf("crypto", "crypto", "trust", "crypto", "trust"), events)
            val matches = result.value.matchedCredentials
            assertEquals(listOf<Any?>("first", "second"), matches.map { it.disclosedClaims["name"] })
            assertEquals(listOf("https://issuer.example/first", "https://issuer.example/second"), matches.map { it.issuer?.issuer })
            assertTrue(matches.all { it.presentationFormat == PresentationFormat.LDP_VP && it.credentialFormat == CredentialFormat.LDP_VC })
            val outerProof = dataIntegrityVerifier.calls.first()
            assertEquals(ProofPurpose.AUTHENTICATION, outerProof.expectedProofPurpose)
            assertEquals("did:example:holder", outerProof.expectedController)
            assertEquals("https://verifier.example.com", outerProof.expectedDomain)
            assertEquals("nonce-vp", outerProof.expectedChallenge)
            assertTrue(outerProof.requireDomainAndChallenge)
            assertEquals(3, dataIntegrityVerifier.calls.size)
            dataIntegrityVerifier.calls.forEach { call ->
                assertSame(verificationMethodResolutionPolicy, call.verificationMethodResolutionPolicy)
            }
        }

    @Test
    fun `holderless VCDM 2 ldp VP accepts multiple authenticated proof controllers`() =
        runTest {
            val state = "ldp-vp-holderless-controller"
            val holder = "did:example:holder"
            val events = mutableListOf<String>()
            val vp = holderlessDataIntegrityPresentation(
                dataIntegrityCredential("holderless"),
                proofVerificationMethods = listOf("$holder#key", "did:example:other#key"),
            )
            val verifier = RecordingDataIntegrityVerifier(
                events,
                authenticatedControllers = setOf(holder, "did:example:other"),
            )
            val args = ValidateAuthorizationResponseArgs(
                parsedResponse = ParsedAuthorizationResponse(
                    vpToken = VpToken(mapOf("presentation" to listOf(vp))),
                    state = state,
                    rawVpToken = "{}",
                ),
                originalRequest = AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = state,
                ),
                dcqlQuery = DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery("presentation", "ldp_vc", vcdm11CredentialMeta())),
                ),
                expectedNonce = "nonce-vp",
            )

            val result = validateWithPersistedSession(
                args = args,
                instanceId = "verifier-instance-$state",
                vcdmDataIntegrityVerifier = verifier,
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "holderless VCDM 2 VP should use the authenticated controller: ${result.value.errors}")
            assertEquals(null, verifier.calls.first().expectedController)
        }

    @Test
    fun `holderless VCDM 2 ldp VP is rejected when Data Integrity verification exposes no controller`() =
        runTest {
            val state = "ldp-vp-holderless-no-controller"
            val events = mutableListOf<String>()
            val vp = holderlessDataIntegrityPresentation(dataIntegrityCredential("holderless-no-controller"))
            val verifier = RecordingDataIntegrityVerifier(events)
            val args = ValidateAuthorizationResponseArgs(
                parsedResponse = ParsedAuthorizationResponse(
                    vpToken = VpToken(mapOf("presentation" to listOf(vp))),
                    state = state,
                    rawVpToken = "{}",
                ),
                originalRequest = AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = state,
                ),
                dcqlQuery = DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery("presentation", "ldp_vc", vcdm11CredentialMeta())),
                ),
                expectedNonce = "nonce-vp",
            )

            val result = validateWithPersistedSession(
                args = args,
                instanceId = "verifier-instance-$state",
                vcdmDataIntegrityVerifier = verifier,
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.errors.any { it.contains("authenticated controller", ignoreCase = true) })
        }

    @Test
    fun `ldp VP dispatches an enveloped JWT credential to JOSE verification`() =
        runTest {
            val state = "ldp-vp-enveloped-jwt-child"
            val childJwt = validVcdm2ChildCredential("enveloped", subjectId = "did:example:holder")
            val envelope =
                buildJsonObject {
                    put("@context", "https://www.w3.org/ns/credentials/v2")
                    put("type", VCDM2_ENVELOPED_VC_TYPE)
                    put("id", "data:application/vc+jwt,$childJwt")
                }
            val vp =
                buildJsonObject {
                    putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/ns/credentials/v2")) }
                    putJsonArray("type") { add(JsonPrimitive("VerifiablePresentation")) }
                    put("holder", "did:example:holder")
                    putJsonArray("verifiableCredential") { add(envelope) }
                    putJsonObject("proof") {
                        put("type", "DataIntegrityProof")
                        put("cryptosuite", "eddsa-jcs-2022")
                        put("proofPurpose", "authentication")
                        put("verificationMethod", "did:example:holder#key")
                        put("proofValue", "zproof")
                    }
                }
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = VpToken(mapOf("presentation" to listOf(vp))),
                            state = state,
                            rawVpToken = "{}",
                        ),
                    originalRequest =
                        AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = state,
                        ),
                    dcqlQuery =
                        DcqlQuery(
                            credentials =
                                listOf(
                                    DcqlCredentialQuery(
                                        id = "presentation",
                                        format = "ldp_vc",
                                        meta = vcdm11CredentialMeta(),
                                    ),
                                ),
                        ),
                    expectedNonce = "nonce-vp",
                )
            val dataIntegrityVerifier = RecordingDataIntegrityVerifier(mutableListOf())
            val joseVerifier = FixedVerifyJwsCommand(valid = true)

            val result =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-$state",
                    verifyJwsCommand = joseVerifier,
                    vcdmDataIntegrityVerifier = dataIntegrityVerifier,
                )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "mixed DI/JOSE presentation should verify: ${result.value.errors}")
            assertEquals(1, dataIntegrityVerifier.calls.size, "only the outer DI VP uses the DI verifier")
            assertEquals(1, joseVerifier.calls, "the enveloped credential must use JOSE verification")
        }

    @Test
    fun `ldp_vc bare credential uses assertion proof semantics when holder binding is not requested`() =
        runTest {
            val state = "ldp-vc-bare-credential"
            val events = mutableListOf<String>()
            val credential = dataIntegrityCredential("bare")
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse = ParsedAuthorizationResponse(
                        vpToken = VpToken(mapOf("credential" to listOf(credential))),
                        state = state,
                        rawVpToken = "{}",
                    ),
                    originalRequest = AuthorizationRequest(
                        clientId = "https://verifier.example.com",
                        redirectUri = "https://verifier.example.com/callback",
                        state = state,
                    ),
                    dcqlQuery =
                        DcqlQuery(
                            credentials =
                                listOf(
                                    DcqlCredentialQuery(
                                        id = "credential",
                                        format = "ldp_vc",
                                        meta = vcdm11CredentialMeta(),
                                        require_cryptographic_holder_binding = false,
                                    ),
                                ),
                        ),
                    expectedNonce = "nonce-not-used-for-bare-vc",
                )
            val dataIntegrityVerifier = RecordingDataIntegrityVerifier(events)

            val result =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-instance-$state",
                    vcdmDataIntegrityVerifier = dataIntegrityVerifier,
                )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "bare ldp_vc should verify without holder binding: ${result.value.errors}")
            val proof = dataIntegrityVerifier.calls.single()
            assertEquals(ProofPurpose.ASSERTION_METHOD, proof.expectedProofPurpose)
            assertEquals(null, proof.expectedDomain)
            assertEquals(null, proof.expectedChallenge)
            assertFalse(proof.requireDomainAndChallenge)
        }

    @Test
    fun `VCDM 2 J4 verifies nested enveloped VP with its own binding`() =
        runTest {
            val child = validVcdm2ChildCredential("nested")
            val nestedVp = validUnsignedVcdm2VpJwt("[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, child)}]")
            val outer = validUnsignedVcdm2VpJwt("[${vcdm2Envelope(VCDM2_ENVELOPED_VP_TYPE, nestedVp)}]")
            val state = "v2-j4-nested-vp"
            val holderBinding = RecordingHolderBindingCommand()

            val result = validateWithPersistedSession(
                args = vcdm2PresentationArgs(state, outer),
                instanceId = "verifier-instance-$state",
                verifyHolderBindingCommand = holderBinding,
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "nested VCDM 2 VP should verify: ${result.value.errors}")
            assertEquals(2, holderBinding.calls, "nested VP must have an independent holder binding")
        }

    @Test
    fun `VCDM 2 J4 rejects a nested VP with the wrong nonce`() =
        runTest {
            val child = validVcdm2ChildCredential("wrong-nonce")
            val nestedVp = validUnsignedVcdm2VpJwt(
                "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, child)}]",
                nonce = "different-nonce",
            )
            val outer = validUnsignedVcdm2VpJwt("[${vcdm2Envelope(VCDM2_ENVELOPED_VP_TYPE, nestedVp)}]")
            val state = "v2-j4-wrong-nonce"
            val holderBinding = NonceAwareHolderBindingCommand()
            val result = validateWithPersistedSession(
                args = vcdm2PresentationArgs(state, outer),
                instanceId = "verifier-instance-$state",
                verifyHolderBindingCommand = holderBinding,
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals(2, holderBinding.calls)
            assertTrue(result.value.errors.any { it.contains("nonce", true) || it.contains("binding", true) })
        }

    @Test
    fun `VCDM 2 J4 enforces nested presentation depth`() =
        runTest {
            val child = validVcdm2ChildCredential("depth")
            var nested = validUnsignedVcdm2VpJwt("[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, child)}]")
            repeat(5) {
                nested = validUnsignedVcdm2VpJwt("[${vcdm2Envelope(VCDM2_ENVELOPED_VP_TYPE, nested)}]")
            }
            val state = "v2-j4-depth"
            val result = validateWithPersistedSession(
                args = vcdm2PresentationArgs(state, nested),
                instanceId = "verifier-instance-$state",
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.errors.any { it.contains("depth", true) })
        }

    @Test
    fun `VCDM 2 J4 rejects raw JWT children and duplicate artifacts`() =
        runTest {
            val child = validVcdm2ChildCredential("duplicate")
            val raw = validUnsignedVcdm2VpJwt("[\"$child\"]")
            val duplicate = validUnsignedVcdm2VpJwt("[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, child)},${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, child)}]")

            listOf(raw to "raw JWT", duplicate to "duplicate").forEach { (presentation, label) ->
                val state = "v2-j4-$label"
                val result = validateWithPersistedSession(
                    args = vcdm2PresentationArgs(state, presentation),
                    instanceId = "verifier-instance-$state",
                    verifyHolderBindingCommand = AlwaysValidHolderBindingCommand,
                    verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
                )
                assertIs<Ok<*>>(result)
                assertFalse(result.value.valid, "$label child must fail closed")
                val expectedDefect = if (label == "raw JWT") "EnvelopedVerifiableCredential" else "duplicate"
                assertTrue(
                    result.value.errors.any { it.contains(expectedDefect, true) },
                    "$label rejection must identify the recursive artifact defect: ${result.value.errors}",
                )
            }
        }

    @Test
    fun `holder binding uses persisted authorization request inputs`() =
        runTest {
            val presentation = validUnsignedVcdm2VpJwt()
            val state = "persisted-binding-state"
            val args = ValidateAuthorizationResponseArgs(
                parsedResponse = ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("presentation", presentation),
                    state = state,
                    rawVpToken = """{"presentation":["$presentation"]}""",
                ),
                originalRequest = AuthorizationRequest(
                    clientId = "https://caller.example.com",
                    redirectUri = "https://caller.example.com/callback",
                    state = state,
                ),
                dcqlQuery = DcqlQuery(
                    credentials = listOf(
                        DcqlCredentialQuery("presentation", "jwt_vc_json-ld", JsonObject(emptyMap())),
                    ),
                ),
                expectedNonce = "caller-supplied-nonce",
            )
            val persistedRequest = AuthorizationRequest(
                clientId = "https://persisted.example.com",
                redirectUri = "https://persisted.example.com/callback",
                state = state,
                nonce = "persisted-nonce",
            )
            val holderBinding = RecordingHolderBindingCommand()

            val result = validateWithPersistedSession(
                args = args,
                instanceId = "verifier-instance-$state",
                verifyHolderBindingCommand = holderBinding,
                persistedAuthorizationRequest = persistedRequest,
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertEquals("persisted-nonce", holderBinding.lastArgs?.expectedNonce)
            assertEquals("https://persisted.example.com", holderBinding.lastArgs?.expectedAudience)
            assertTrue(result.value.errors.any { it.contains("nonce") && it.contains("persisted") })
            assertTrue(result.value.errors.any { it.contains("client_id") && it.contains("persisted") })
        }

    /**
     * Build an unsigned JWT-shaped string with a VCDM 2.0 + JSON-LD body whose
     * @context contains the supplied @vocab keyword. Suitable for testing the
     * validator path; AlwaysValidHolderBindingCommand stubs out the signature
     * check.
     */
    private fun unsignedVcLdJwt(
        atVocab: String,
        primaryType: String
    ): String {
        val payload =
            """
            {
                "@context": [
                  "https://www.w3.org/ns/credentials/v2",
                  {"@vocab": "$atVocab"}
                ],
                "type": ["VerifiableCredential", "$primaryType"],
                "issuer": "did:example:issuer",
                "iss": "did:example:issuer",
                "validFrom": "2026-01-01T00:00:00Z",
                "credentialSubject": {"id": "did:example:holder", "name": "Alice"}
            }
            """.trimIndent()
        val header = """{"alg":"ES256","typ":"vc+jwt","cty":"vc","kid":"did:example:issuer#key-1"}"""
        return "${header.encodeToByteArray().encodeToBase64Url()}.${payload.encodeToByteArray().encodeToBase64Url()}.fakesig"
    }

    private fun validUnsignedVcLdJwt(
        validFrom: String = "2026-01-01T00:00:00Z",
        validUntil: String? = null,
        jwtTimeClaims: String = "",
        headerJson: String = """{"alg":"ES256","typ":"vc+jwt","kid":"did:example:issuer#key-1"}""",
        issuer: String = "did:example:issuer",
        credentialId: String? = null,
        jwtId: String? = credentialId,
        jwtSubjectId: String? = null,
    ): String {
        val validUntilClaim = validUntil?.let { "\"validUntil\": \"$it\", " } ?: ""
        val jwtTimeClaimsLine = jwtTimeClaims.takeIf { it.isNotBlank() } ?: ""
        val credentialIdClaim = credentialId?.let { "\"id\": \"$it\", " } ?: ""
        val jwtIdClaim = jwtId?.let { "\"jti\": \"$it\", " } ?: ""
        val jwtSubjectClaim = jwtSubjectId?.let { "\"sub\": \"$it\", " } ?: ""
        val payload =
            """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "ExampleCredential"],
                $credentialIdClaim
                "issuer": "$issuer",
                "iss": "$issuer",
                $jwtIdClaim
                $jwtSubjectClaim
                $jwtTimeClaimsLine
                "validFrom": "$validFrom",
                $validUntilClaim
                "credentialSubject": {"id": "did:example:holder", "name": "Alice"}
            }
            """.trimIndent()
        return "${headerJson.encodeToByteArray().encodeToBase64Url()}.${payload.encodeToByteArray().encodeToBase64Url()}.fakesig"
    }

    private fun validVcdm2ChildCredential(label: String, subjectId: String = "did:example:$label"): String {
        val payload =
            """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "ExampleCredential"],
                "issuer": "did:example:issuer",
                "iss": "did:example:issuer",
                "validFrom": "2026-01-01T00:00:00Z",
                "credentialSubject": {"id": "$subjectId", "name": "$label"}
            }
            """.trimIndent()
        val header = """{"alg":"ES256","typ":"vc+jwt","kid":"did:example:issuer#key-1"}"""
        return "${header.encodeToByteArray().encodeToBase64Url()}.${payload.encodeToByteArray().encodeToBase64Url()}.fakesig"
    }

    /** A VCDM 2.0 JWT child without a subject id, optionally confirming a holder key via `cnf.kid`. */
    private fun vcdm2ChildCredentialConfirmedBy(confirmationKid: String?, inHeader: Boolean = false): String {
        val cnf = confirmationKid?.let { "\"cnf\":{\"kid\":\"$it\"}" }
        val claimCnf = if (cnf != null && !inHeader) ",$cnf" else ""
        val headerCnf = if (cnf != null && inHeader) ",$cnf" else ""
        val payload =
            """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiableCredential", "ExampleCredential"],
                "issuer": "did:example:issuer",
                "iss": "did:example:issuer",
                "validFrom": "2026-01-01T00:00:00Z",
                "credentialSubject": {"name": "confirmed"}$claimCnf
            }
            """.trimIndent()
        val header = """{"alg":"ES256","typ":"vc+jwt","kid":"did:example:issuer#key-1"$headerCnf}"""
        return "${header.encodeToByteArray().encodeToBase64Url()}.${payload.encodeToByteArray().encodeToBase64Url()}.fakesig"
    }

    private fun vcdm2Envelope(type: String, compact: String, extensionContext: String? = null): String {
        val mediaType = if (type == VCDM2_ENVELOPED_VC_TYPE) "vc" else "vp"
        val context = extensionContext?.let { "[\"https://www.w3.org/ns/credentials/v2\",\"$it\"]" }
            ?: "\"https://www.w3.org/ns/credentials/v2\""
        return """{"@context":$context,"type":"$type","id":"data:application/$mediaType+jwt,$compact"}"""
    }

    private fun vcdm2PresentationArgs(
        state: String,
        presentation: String,
        queryFormat: String = "jwt_vc_json-ld",
        requireHolderBinding: Boolean = true,
    ): ValidateAuthorizationResponseArgs =
        ValidateAuthorizationResponseArgs(
            parsedResponse = ParsedAuthorizationResponse(
                vpToken = vpTokenOf("presentation", presentation),
                state = state,
                rawVpToken = """{"presentation":["$presentation"]}""",
            ),
            originalRequest = AuthorizationRequest(
                clientId = "https://verifier.example.com",
                redirectUri = "https://verifier.example.com/callback",
                state = state,
            ),
            dcqlQuery = DcqlQuery(
                credentials = listOf(
                    DcqlCredentialQuery(
                        id = "presentation",
                        format = queryFormat,
                        meta = vcdm11CredentialMeta(),
                        require_cryptographic_holder_binding = requireHolderBinding,
                    ),
                ),
            ),
            expectedNonce = "nonce-vp",
        )

    private fun validUnsignedVcdm2VpJwt(
        verifiableCredential: String? = VCDM2_ENVELOPED_VC_ENTRIES,
        nonce: String = "nonce-vp",
        algorithm: String = "ES256",
        holder: String = "https://holder.example",
    ): String {
        val childProperty = verifiableCredential?.let { "\"verifiableCredential\":$it," } ?: ""
        val payload =
            """
            {
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "type": ["VerifiablePresentation"],
                "holder": "$holder",
                "iss": "$holder",
                $childProperty
                "nonce": "$nonce",
                "aud": "https://verifier.example.com"
            }
            """.trimIndent()
        val header = """{"alg":"$algorithm","typ":"vp+jwt","cty":"vp"}"""
        return "${header.encodeToByteArray().encodeToBase64Url()}.${payload.encodeToByteArray().encodeToBase64Url()}.fakesig"
    }

    private fun validVcdm11VpJwtWithEmbeddedVc(vararg embeddedVcs: String): String {
        val embeddedCredentials = embeddedVcs.toList().ifEmpty { listOf(validVcdm11VcJwt()) }
        val embeddedVc = embeddedCredentials.joinToString(",") { "\"$it\"" }
        val payload =
            """
            {
                "iss": "did:example:holder",
                "vp": {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiablePresentation"],
                    "verifiableCredential": [$embeddedVc]
                },
                "nonce": "nonce-v1",
                "aud": "https://verifier.example.com"
            }
            """.trimIndent()
        val header = """{"alg":"ES256","typ":"JWT"}"""
        return "${header.encodeToByteArray().encodeToBase64Url()}.${payload.encodeToByteArray().encodeToBase64Url()}.fakesig"
    }

    private fun validVcdm11VpJwtWithEmbeddedJsonVc(vararg embeddedVcs: JsonObject): String {
        val embeddedCredentials = embeddedVcs.toList().ifEmpty { listOf(dataIntegrityCredential("v1-default")) }
        val embeddedVc = embeddedCredentials.joinToString(",") { it.toString() }
        val payload =
            """
            {
                "iss": "did:example:holder",
                "vp": {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": ["VerifiablePresentation"],
                    "verifiableCredential": [$embeddedVc]
                },
                "nonce": "nonce-v1",
                "aud": "https://verifier.example.com"
            }
            """.trimIndent()
        val header = """{"alg":"ES256","typ":"JWT"}"""
        return "${header.encodeToByteArray().encodeToBase64Url()}.${payload.encodeToByteArray().encodeToBase64Url()}.fakesig"
    }

    private fun validVcdm11VcJwt(
        subjectId: String = "subject",
        issuanceDate: String = "2023-11-14T22:13:20Z",
        expirationDate: String? = null,
        notBefore: Long = 1700000000,
        expiresAt: Long? = null,
        credentialId: String? = null,
        jwtId: String? = credentialId,
        jwtSubjectId: String = "did:example:$subjectId",
        confirmationKid: String? = null,
        credentialType: String? = null,
    ): String {
        val typeEntries = listOfNotNull("VerifiableCredential", credentialType).joinToString(",") { "\"$it\"" }
        val confirmationClaim = confirmationKid?.let { "\"cnf\": {\"kid\": \"$it\"}," } ?: ""
        val expirationClaim = expirationDate?.let { "\"expirationDate\":\"$it\"," } ?: ""
        val expiresAtClaim = expiresAt?.let { "\"exp\":$it," } ?: ""
        val credentialIdClaim = credentialId?.let { "\"id\": \"$it\", " } ?: ""
        val jwtIdClaim = jwtId?.let { "\"jti\": \"$it\", " } ?: ""
        val payload =
            """
            {
                "iss": "did:example:issuer",
                "sub": "$jwtSubjectId",
                $confirmationClaim
                "nbf": $notBefore,
                $jwtIdClaim
                $expiresAtClaim
                "vc": {
                    "@context": ["https://www.w3.org/2018/credentials/v1"],
                    "type": [$typeEntries],
                    $credentialIdClaim
                    "issuanceDate": "$issuanceDate",
                    $expirationClaim
                    "credentialSubject": {"id": "did:example:$subjectId", "name": "Alice"}
                }
            }
            """.trimIndent()
        val header = """{"alg":"ES256","typ":"JWT","kid":"did:example:issuer#key-1"}"""
        return "${header.encodeToByteArray().encodeToBase64Url()}.${payload.encodeToByteArray().encodeToBase64Url()}.fakesig"
    }

    private fun testTrustedJwks(): JsonObject =
        buildJsonObject {
            putJsonArray("keys") {
                add(
                    buildJsonObject {
                        put("kty", "EC")
                        put("crv", "P-256")
                        put("x", "WbbFpp0eS8_rJlvpuX_qEyU1J2PNmXYnqPCBJTqqiBA")
                        put("y", "F8kbfVPRQc5M9kJA1fy3c_0Q6vCqHy1X7CZQC6XQy9I")
                        put("kid", "holder-key")
                    },
                )
            }
        }

    private fun dataIntegrityCredential(name: String, subjectId: String = "did:example:$name"): JsonObject = buildJsonObject {
        putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/ns/credentials/v2")) }
        putJsonArray("type") { add(JsonPrimitive("VerifiableCredential")) }
        put("issuer", "https://issuer.example/$name")
        putJsonObject("credentialSubject") { put("id", subjectId); put("name", name) }
        putJsonObject("proof") { put("type", "DataIntegrityProof"); put("cryptosuite", "eddsa-jcs-2022"); put("proofPurpose", "assertionMethod"); put("verificationMethod", "did:example:issuer#key"); put("proofValue", "zproof"); put("created", "2026-08-25T12:00:00Z") }
    }

    private fun holderlessDataIntegrityPresentation(
        child: JsonObject,
        proofVerificationMethods: List<String> = listOf("did:example:holder#key"),
    ): JsonObject = buildJsonObject {
        putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/ns/credentials/v2")) }
        putJsonArray("type") { add(JsonPrimitive("VerifiablePresentation")) }
        putJsonArray("verifiableCredential") { add(child) }
        if (proofVerificationMethods.size == 1) {
            put("proof", authenticationProof(proofVerificationMethods.single()))
        } else {
            putJsonArray("proof") {
                proofVerificationMethods.forEach { add(authenticationProof(it)) }
            }
        }
    }

    private fun authenticationProof(verificationMethod: String): JsonObject = buildJsonObject {
            put("type", "DataIntegrityProof")
            put("cryptosuite", "eddsa-jcs-2022")
            put("proofPurpose", "authentication")
            put("verificationMethod", verificationMethod)
            put("proofValue", "zproof")
            put("domain", "https://verifier.example.com")
            put("challenge", "nonce-vp")
    }

    private fun vcdm11CredentialMeta(): JsonObject =
        buildJsonObject {
            putJsonArray("type_values") {
                add(JsonArray(listOf(JsonPrimitive("https://www.w3.org/2018/credentials#VerifiableCredential"))))
            }
        }

    private val identityPayload =
        """{"iss":"https://issuer.example","vct":"urn:test:identity","first_name":"John","last_name":"Doe","nationality":"NL"}"""

    private fun sdJwtPresentation(payload: String = identityPayload): String =
        "${"""{"alg":"ES256"}""".encodeToByteArray().encodeToBase64Url()}.${payload.encodeToByteArray().encodeToBase64Url()}.signature" +
            "~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.e30.sig"

    private fun stringPath(vararg components: String) = ClaimsPathPointer(components.map { JsonPrimitive(it) })

    private fun identityQuery(
        claims: List<DcqlClaimQuery>? = null,
        claimSets: List<List<String>>? = null,
        multiple: Boolean = false,
    ) = DcqlCredentialQuery(
        id = "identity_credential",
        format = "dc+sd-jwt",
        meta = sdJwtVcMeta("urn:test:identity"),
        claims = claims,
        claim_sets = claimSets,
        multiple = multiple,
    )

    private suspend fun validateIdentity(state: String, presentations: List<String>, query: DcqlCredentialQuery) =
        validateWithPersistedSession(
            args = ValidateAuthorizationResponseArgs(
                parsedResponse = ParsedAuthorizationResponse(
                    vpToken = VpToken.fromStrings(mapOf("identity_credential" to presentations)),
                    state = state,
                    rawVpToken = "{}",
                ),
                originalRequest = AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = state,
                ),
                dcqlQuery = DcqlQuery(credentials = listOf(query)),
                expectedNonce = "nonce-$state",
            ),
            instanceId = "verifier-instance-$state",
        )

    @Test
    fun shouldRejectTwoPresentationsForAQueryThatDoesNotAllowMultiple() =
        runTest {
            val result = validateIdentity("cardinality-single", listOf(sdJwtPresentation(), sdJwtPresentation()), identityQuery())

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.errors.any { it.contains("allows one presentation") }, "${result.value.errors}")
        }

    @Test
    fun shouldReportEveryPresentationWhenTheQueryAllowsMultiple() =
        runTest {
            val result = validateIdentity("cardinality-multiple", listOf(sdJwtPresentation(), sdJwtPresentation()), identityQuery(multiple = true))

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "${result.value.errors}")
            assertEquals(2, result.value.matchedCredentials.size)
        }

    // An empty presentation list never reaches validation: the vp_token model refuses it, so a required
    // query cannot be bypassed by answering it with an empty array.
    @Test
    fun shouldNotLetAnEmptyPresentationArrayThroughTheVpTokenModel() {
        kotlin.test.assertFailsWith<IllegalArgumentException> { VpToken(mapOf("identity_credential" to emptyList())) }
    }

    @Test
    fun shouldAcceptACredentialThatHasEveryRequestedClaim() =
        runTest {
            val query = identityQuery(listOf(DcqlClaimQuery(stringPath("first_name")), DcqlClaimQuery(stringPath("last_name"))))

            val result = validateIdentity("claims-complete", listOf(sdJwtPresentation()), query)

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "${result.value.errors}")
        }

    @Test
    fun shouldRejectACredentialThatLacksARequestedClaim() =
        runTest {
            val query = identityQuery(listOf(DcqlClaimQuery(stringPath("first_name")), DcqlClaimQuery(stringPath("date_of_birth"))))

            val result = validateIdentity("claims-missing", listOf(sdJwtPresentation()), query)

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.errors.any { it.contains("requested claims") }, "${result.value.errors}")
            assertTrue(result.value.matchedCredentials.isEmpty())
        }

    @Test
    fun shouldRejectACredentialWhoseRequestedClaimIsOutsideTheAllowedValues() =
        runTest {
            val query = identityQuery(listOf(DcqlClaimQuery(stringPath("nationality"), values = listOf(JsonPrimitive("DE"), JsonPrimitive("BE")))))

            val result = validateIdentity("claims-value", listOf(sdJwtPresentation()), query)

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.errors.any { it.contains("requested claims") }, "${result.value.errors}")
        }

    @Test
    fun shouldAcceptTheSecondClaimSetWhenTheFirstFailsOnAValueOutsideTheAllowedValues() =
        runTest {
            val query =
                identityQuery(
                    claims = listOf(
                        DcqlClaimQuery(stringPath("nationality"), id = "nationality", values = listOf(JsonPrimitive("DE"))),
                        DcqlClaimQuery(stringPath("first_name"), id = "first"),
                        DcqlClaimQuery(stringPath("last_name"), id = "last"),
                    ),
                    claimSets = listOf(listOf("nationality", "first"), listOf("first", "last")),
                )

            val result = validateIdentity("claims-second-set", listOf(sdJwtPresentation()), query)

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "${result.value.errors}")
        }

    @Test
    fun shouldRejectTheWholeResponseWhenOneOfSeveralCredentialsFallsShort() =
        runTest {
            val german = sdJwtPresentation(identityPayload.replace("\"NL\"", "\"DE\""))
            val query = identityQuery(listOf(DcqlClaimQuery(stringPath("nationality"), values = listOf(JsonPrimitive("NL")))), multiple = true)

            val result = validateIdentity("claims-mixed-siblings", listOf(sdJwtPresentation(), german), query)

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.errors.any { it.contains("at index 1") && it.contains("requested claims") }, "${result.value.errors}")
        }

    @Test
    fun shouldRejectAW3cPresentationWhenOneChildLacksTheRequestedClaimValue() =
        runTest {
            val presentation = validUnsignedVcdm2VpJwt(
                "[${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, validVcdm2ChildCredential("one"))},${vcdm2Envelope(VCDM2_ENVELOPED_VC_TYPE, validVcdm2ChildCredential("two"))}]",
            )
            fun argsFor(values: List<JsonPrimitive>?, state: String) =
                vcdm2PresentationArgs(state, presentation).let { base ->
                    base.copy(
                        dcqlQuery = DcqlQuery(
                            credentials = listOf(
                                base.dcqlQuery.credentials.single().copy(
                                    claims = listOf(DcqlClaimQuery(stringPath("credentialSubject", "name"), values = values)),
                                ),
                            ),
                        ),
                    )
                }

            val allPresent = validateWithPersistedSession(argsFor(null, "w3c-claims-present"), "verifier-instance-w3c-claims-present", verifyJwsCommand = FixedVerifyJwsCommand(valid = true))
            val oneWrong = validateWithPersistedSession(argsFor(listOf(JsonPrimitive("one")), "w3c-claims-wrong"), "verifier-instance-w3c-claims-wrong", verifyJwsCommand = FixedVerifyJwsCommand(valid = true))

            assertIs<Ok<*>>(allPresent)
            assertTrue(allPresent.value.valid, "${allPresent.value.errors}")
            assertIs<Ok<*>>(oneWrong)
            assertFalse(oneWrong.value.valid)
            assertTrue(oneWrong.value.errors.any { it.contains("requested claims") }, "${oneWrong.value.errors}")
        }

    @Test
    fun shouldRejectAnMdocDocumentThatLacksARequestedElement() =
        runTest {
            val presentation = unsignedMdocPresentation(mdlFixtureDocument(FixtureElement("given_name", "Jane")))
            suspend fun result(element: String, state: String) =
                validateWithPersistedSession(
                    args = ValidateAuthorizationResponseArgs(
                        parsedResponse = ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("mdl_credential", presentation),
                            state = state,
                            rawVpToken = "{}",
                        ),
                        originalRequest = AuthorizationRequest(
                            clientId = "https://verifier.example.com",
                            redirectUri = "https://verifier.example.com/callback",
                            state = state,
                        ),
                        dcqlQuery = DcqlQuery(
                            credentials = listOf(
                                DcqlCredentialQuery(
                                    id = "mdl_credential",
                                    format = "mso_mdoc",
                                    meta = mdocMeta("org.iso.18013.5.1.mDL"),
                                    claims = listOf(DcqlClaimQuery(stringPath("org.iso.18013.5.1", element))),
                                ),
                            ),
                        ),
                        expectedNonce = "nonce-$state",
                    ),
                    instanceId = "verifier-instance-$state",
                )

            val present = result("given_name", "mdoc-claim-present")
            val absent = result("family_name", "mdoc-claim-absent")

            assertIs<Ok<*>>(present)
            assertTrue(present.value.valid, "${present.value.errors}")
            assertIs<Ok<*>>(absent)
            assertFalse(absent.value.valid)
            assertTrue(absent.value.errors.any { it.contains("requested claims") }, "${absent.value.errors}")
        }

    private fun mdlFixtureDocument(vararg elements: FixtureElement, nameSpace: String = "org.iso.18013.5.1") =
        FixtureDocument(
            docType = "org.iso.18013.5.1.mDL",
            nameSpaces = mapOf(nameSpace to elements.toList().ifEmpty { listOf(FixtureElement("given_name", "Jane")) }),
        )

    private suspend fun validateMdocPresentation(state: String, presentation: String) =
        validateWithPersistedSession(
            args = ValidateAuthorizationResponseArgs(
                parsedResponse = ParsedAuthorizationResponse(
                    vpToken = vpTokenOf("mdl_credential", presentation),
                    state = state,
                    rawVpToken = """{"mdl_credential":["$presentation"]}""",
                ),
                originalRequest = AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = state,
                ),
                dcqlQuery = DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "mdl_credential", format = "mso_mdoc", meta = mdocMeta("org.iso.18013.5.1.mDL"))),
                ),
                expectedNonce = "nonce-mdoc",
            ),
            instanceId = "verifier-instance-$state",
        )

    @Test
    fun shouldKeepMdocDocumentsApartWhenTheyShareNamespaceAndElementNames() =
        runTest {
            val presentation =
                unsignedMdocPresentation(
                    mdlFixtureDocument(FixtureElement("given_name", "Jane")),
                    mdlFixtureDocument(FixtureElement("given_name", "Janet")),
                )

            val result = validateMdocPresentation("mdoc-two-documents", presentation)

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "${result.value.errors}")
            val matches = result.value.matchedCredentials
            assertEquals(listOf<Any?>("Jane", "Janet"), matches.map { it.disclosedClaims["org.iso.18013.5.1.given_name"] })
            assertEquals(listOf("org.iso.18013.5.1.mDL", "org.iso.18013.5.1.mDL"), matches.map { it.credentialType })
            assertTrue(matches.all { it.disclosedClaims.keys == setOf("org.iso.18013.5.1.given_name") })
        }

    @Test
    fun shouldReportMdocValuesAtTheirJsonTypes() =
        runTest {
            val presentation =
                unsignedMdocPresentation(
                    mdlFixtureDocument(
                        FixtureElement("portrait", byteArrayOf(0xfb.toByte(), 0xff.toByte())),
                        FixtureElement("document_number", "0612345678"),
                        FixtureElement("age_over_18", true),
                        FixtureElement("height", 180L),
                        FixtureElement("address", mapOf("street" to "Main", "numbers" to listOf(1L, 2L))),
                    ),
                )

            val result = validateMdocPresentation("mdoc-typed-values", presentation)

            assertIs<Ok<*>>(result)
            assertTrue(result.value.valid, "${result.value.errors}")
            val claims = result.value.matchedCredentials.single().disclosedClaims
            assertEquals("-_8", claims["org.iso.18013.5.1.portrait"])
            assertEquals("0612345678", claims["org.iso.18013.5.1.document_number"])
            assertEquals(true, claims["org.iso.18013.5.1.age_over_18"])
            assertEquals(180L, claims["org.iso.18013.5.1.height"])
            assertEquals(
                kotlinx.serialization.json.Json.parseToJsonElement("""{"street":"Main","numbers":[1,2]}"""),
                claims["org.iso.18013.5.1.address"],
            )
        }

    @Test
    fun shouldRejectAResponseWhenAnMdocPresentationCannotBeRead() =
        runTest {
            val unreadable = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBleBhvcmcuaXNvLjE4MDEzLjUuMS5tRExqaXNzdWVyU2lnbmVk"

            val result = validateMdocPresentation("mdoc-unreadable", unreadable)

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
            assertTrue(result.value.errors.any { it.contains("could not be read") }, "${result.value.errors}")
            assertTrue(result.value.matchedCredentials.isEmpty())
        }

    private companion object {
        const val VCDM2_ENVELOPED_VC_TYPE = "EnvelopedVerifiableCredential"
        const val VCDM2_ENVELOPED_VP_TYPE = "EnvelopedVerifiablePresentation"
        const val VCDM2_ENVELOPED_VC_ENTRIES = "[{\"id\":\"data:application/vc+jwt,eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6MX0.sig-one\"},{\"id\":\"data:application/vc+jwt,eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6Mn0.sig-two\"}]"
        const val VCDM2_VC_JWT = "eyJhbGciOiJub25lIn0.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiXSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCJdLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpleGFtcGxlOmhvbGRlciJ9fQ.fakesig"
    }

    private fun sdJwtOfType(
        vct: String,
        integrity: String? = null,
    ): String {
        val claims =
            buildJsonObject {
                put("iss", "https://issuer.example")
                put("vct", vct)
                integrity?.let { put("vct#integrity", it) }
            }
        val keyBinding =
            buildJsonObject {
                put("nonce", "nonce123")
                put("aud", "https://verifier.example.com")
                put("iat", 1_700_000_000)
            }
        return "eyJhbGciOiJFUzI1NiJ9.${claims.toString().encodeToByteArray().encodeToBase64Url()}.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~" +
            "eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.${keyBinding.toString().encodeToByteArray().encodeToBase64Url()}.sig"
    }

    private suspend fun validateSdJwtTypes(
        accepted: String,
        credentials: List<String>,
        instance: String,
        matcher: CredentialTypeMatcher = testCredentialTypeMatcher(),
    ): com.sphereon.openid.oid4vp.verifier.ValidationResult {
        val state = "state-$instance"
        val args =
            ValidateAuthorizationResponseArgs(
                parsedResponse =
                    ParsedAuthorizationResponse(
                        vpToken = vpTokenOf(*credentials.map { "typed" to it }.toTypedArray()),
                        state = state,
                        rawVpToken = "{}",
                    ),
                originalRequest = AuthorizationRequest(clientId = "https://verifier.example.com", redirectUri = "https://verifier.example.com/callback", state = state),
                dcqlQuery = DcqlQuery(credentials = listOf(DcqlCredentialQuery(id = "typed", format = "dc+sd-jwt", meta = sdJwtVcMeta(accepted), multiple = true))),
                expectedNonce = "nonce123",
            )
        val result = validateWithPersistedSession(args, instanceId = "verifier-$instance", credentialTypeMatcher = matcher)
        assertIs<Ok<*>>(result)
        return result.value
    }

    @Test
    fun shouldAcceptExactVctWithoutResolvingMetadata() =
        runTest {
            val metadata = CountingTypeMetadataCommand()

            val validation = validateSdJwtTypes("urn:test:pid", listOf(sdJwtOfType("urn:test:pid")), "exact", testCredentialTypeMatcher(metadata))

            assertTrue(validation.valid, validation.errors.toString())
            assertTrue(metadata.resolvedVcts.isEmpty())
        }

    @Test
    fun shouldRefuseAVctThatIsNotListedAndInheritsFromNothingListed() =
        runTest {
            val metadata =
                CountingTypeMetadataCommand(StaticTypeMetadataResolver(mapOf("urn:test:other" to SdJwtVcTypeMetadata(vct = "urn:test:other"))))

            val validation = validateSdJwtTypes("urn:test:pid", listOf(sdJwtOfType("urn:test:other")), "unlisted", testCredentialTypeMatcher(metadata))

            assertFalse(validation.valid)
            assertTrue(validation.matchedCredentials.isEmpty())
        }

    @Test
    fun shouldAcceptATypeThatExtendsAListedTypeThroughAParent() =
        runTest {
            val metadata =
                CountingTypeMetadataCommand(
                    StaticTypeMetadataResolver(
                        mapOf(
                            "urn:test:leaf" to SdJwtVcTypeMetadata(vct = "urn:test:leaf", extends = "urn:test:middle"),
                            "urn:test:middle" to SdJwtVcTypeMetadata(vct = "urn:test:middle", extends = "urn:test:pid"),
                            "urn:test:pid" to SdJwtVcTypeMetadata(vct = "urn:test:pid"),
                        ),
                    ),
                )

            val validation = validateSdJwtTypes("urn:test:pid", listOf(sdJwtOfType("urn:test:leaf")), "inherits", testCredentialTypeMatcher(metadata))

            assertTrue(validation.valid, validation.errors.toString())
            assertEquals(listOf("urn:test:leaf", "urn:test:middle", "urn:test:pid"), metadata.resolvedVcts)
        }

    @Test
    fun shouldRefuseWhenTheExtendsChainClosesALoop() =
        runTest {
            val metadata =
                CountingTypeMetadataCommand(
                    StaticTypeMetadataResolver(
                        mapOf(
                            "urn:test:leaf" to SdJwtVcTypeMetadata(vct = "urn:test:leaf", extends = "urn:test:middle"),
                            "urn:test:middle" to SdJwtVcTypeMetadata(vct = "urn:test:middle", extends = "urn:test:leaf"),
                        ),
                    ),
                )

            assertFalse(validateSdJwtTypes("urn:test:pid", listOf(sdJwtOfType("urn:test:leaf")), "loop", testCredentialTypeMatcher(metadata)).valid)
        }

    @Test
    fun shouldRefuseWhenTheMetadataNamesAnotherVct() =
        runTest {
            val metadata =
                CountingTypeMetadataCommand(
                    StaticTypeMetadataResolver(mapOf("urn:test:leaf" to SdJwtVcTypeMetadata(vct = "urn:test:pid", extends = "urn:test:pid"))),
                )

            assertFalse(validateSdJwtTypes("urn:test:pid", listOf(sdJwtOfType("urn:test:leaf")), "identity", testCredentialTypeMatcher(metadata)).valid)
        }

    @Test
    fun shouldRefuseWhenTheTypeMetadataFailsItsIntegrityCheck() =
        runTest {
            val document = """{"vct":"urn:test:leaf","extends":"urn:test:pid"}""".encodeToByteArray()
            val metadata =
                CountingTypeMetadataCommand(
                    StaticTypeMetadataResolver(
                        mapOf(
                            "urn:test:leaf" to SdJwtVcTypeMetadata(vct = "urn:test:leaf", extends = "urn:test:pid"),
                            "urn:test:pid" to SdJwtVcTypeMetadata(vct = "urn:test:pid"),
                        ),
                        mapOf("urn:test:leaf" to document),
                    ),
                )
            val wrongPin = "sha256-" + com.sphereon.crypto.core.generic.hash("tampered".encodeToByteArray()).encodeToBase64()

            val validation = validateSdJwtTypes("urn:test:pid", listOf(sdJwtOfType("urn:test:leaf", wrongPin)), "integrity", testCredentialTypeMatcher(metadata))

            assertFalse(validation.valid)
        }

    @Test
    fun shouldAcceptWhenTheTypeMetadataMatchesItsIntegrityPin() =
        runTest {
            val document = """{"vct":"urn:test:leaf","extends":"urn:test:pid"}""".encodeToByteArray()
            val metadata =
                CountingTypeMetadataCommand(
                    StaticTypeMetadataResolver(
                        mapOf(
                            "urn:test:leaf" to SdJwtVcTypeMetadata(vct = "urn:test:leaf", extends = "urn:test:pid"),
                            "urn:test:pid" to SdJwtVcTypeMetadata(vct = "urn:test:pid"),
                        ),
                        mapOf("urn:test:leaf" to document),
                    ),
                )
            val pin = "sha256-" + com.sphereon.crypto.core.generic.hash(document).encodeToBase64()

            val validation = validateSdJwtTypes("urn:test:pid", listOf(sdJwtOfType("urn:test:leaf", pin)), "pinned", testCredentialTypeMatcher(metadata))

            assertTrue(validation.valid, validation.errors.toString())
        }

    @Test
    fun shouldRefuseWhenTheTypeMetadataCannotBeFetched() =
        runTest {
            assertFalse(validateSdJwtTypes("urn:test:pid", listOf(sdJwtOfType("urn:test:leaf")), "unavailable").valid)
        }

    @Test
    fun shouldInvalidateTheResponseWhenOneOfTwoPresentationsIsOfAnotherType() =
        runTest {
            val metadata =
                CountingTypeMetadataCommand(StaticTypeMetadataResolver(mapOf("urn:test:other" to SdJwtVcTypeMetadata(vct = "urn:test:other"))))

            val validation =
                validateSdJwtTypes(
                    "urn:test:pid",
                    listOf(sdJwtOfType("urn:test:pid"), sdJwtOfType("urn:test:other")),
                    "second-wrong",
                    testCredentialTypeMatcher(metadata),
                )

            assertFalse(validation.valid)
        }

    @Test
    fun shouldAcceptTwoPresentationsThatAreBothOfTheRequestedType() =
        runTest {
            val validation = validateSdJwtTypes("urn:test:pid", listOf(sdJwtOfType("urn:test:pid"), sdJwtOfType("urn:test:pid")), "both-right")

            assertTrue(validation.valid, validation.errors.toString())
            assertEquals(2, validation.matchedCredentials.size)
        }

    private suspend fun validateVcdm11Types(
        children: List<String>,
        alternatives: List<List<String>>,
        instance: String,
        matcher: CredentialTypeMatcher = testCredentialTypeMatcher(),
    ): com.sphereon.openid.oid4vp.verifier.ValidationResult {
        val presentation = validVcdm11VpJwtWithEmbeddedVc(*children.toTypedArray())
        val state = "state-$instance"
        val meta =
            buildJsonObject {
                putJsonArray("type_values") { alternatives.forEach { add(JsonArray(it.map(::JsonPrimitive))) } }
            }
        val args =
            ValidateAuthorizationResponseArgs(
                parsedResponse =
                    ParsedAuthorizationResponse(
                        vpToken = vpTokenOf("presentation", presentation),
                        state = state,
                        rawVpToken = """{"presentation":["$presentation"]}""",
                    ),
                originalRequest = AuthorizationRequest(clientId = "https://verifier.example.com", redirectUri = "https://verifier.example.com/callback", state = state),
                dcqlQuery = DcqlQuery(credentials = listOf(DcqlCredentialQuery("presentation", "jwt_vc_json", meta))),
                expectedNonce = "nonce-v1",
            )
        val result =
            validateWithPersistedSession(
                args = args,
                instanceId = "verifier-$instance",
                verifyHolderBindingCommand = RecordingHolderBindingCommand(),
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
                credentialTypeMatcher = matcher,
            )
        assertIs<Ok<*>>(result)
        return result.value
    }

    private val verifiableCredentialIri = "https://www.w3.org/2018/credentials#VerifiableCredential"

    @Test
    fun shouldAcceptAPresentationWhoseCredentialsAllMatchTheirQueryType() =
        runTest {
            val children = listOf(
                validVcdm11VcJwt(subjectId = "holder", credentialId = "urn:example:first", credentialType = "IdentityCredential"),
                validVcdm11VcJwt(subjectId = "holder", credentialId = "urn:example:second", credentialType = "IdentityCredential"),
            )

            val validation = validateVcdm11Types(children, listOf(listOf(verifiableCredentialIri, "IdentityCredential")), "w3c-all-match")

            assertTrue(validation.valid, validation.errors.toString())
        }

    @Test
    fun shouldRefuseACredentialOfAnotherType() =
        runTest {
            val children = listOf(validVcdm11VcJwt(subjectId = "holder", credentialType = "OtherCredential"))

            val validation = validateVcdm11Types(children, listOf(listOf(verifiableCredentialIri, "IdentityCredential")), "w3c-wrong-type")

            assertFalse(validation.valid)
        }

    @Test
    fun shouldRefuseThePresentationWhenOnlyTheSecondCredentialHasTheWrongType() =
        runTest {
            val children = listOf(
                validVcdm11VcJwt(subjectId = "holder", credentialId = "urn:example:first", credentialType = "IdentityCredential"),
                validVcdm11VcJwt(subjectId = "holder", credentialId = "urn:example:second"),
            )

            val validation = validateVcdm11Types(children, listOf(listOf("IdentityCredential")), "w3c-second-wrong")

            assertFalse(validation.valid)
        }

    @Test
    fun shouldNotLetTwoCredentialsJointlySatisfyOneAlternative() =
        runTest {
            val children = listOf(
                validVcdm11VcJwt(subjectId = "holder", credentialId = "urn:example:first", credentialType = "TypeA"),
                validVcdm11VcJwt(subjectId = "holder", credentialId = "urn:example:second", credentialType = "TypeB"),
            )

            val validation = validateVcdm11Types(children, listOf(listOf("TypeA", "TypeB")), "w3c-joint")

            assertFalse(validation.valid)
        }

    @Test
    fun shouldAcceptEachCredentialAgainstItsOwnAlternative() =
        runTest {
            val children = listOf(
                validVcdm11VcJwt(subjectId = "holder", credentialId = "urn:example:first", credentialType = "TypeA"),
                validVcdm11VcJwt(subjectId = "holder", credentialId = "urn:example:second", credentialType = "TypeB"),
            )

            val validation = validateVcdm11Types(children, listOf(listOf("TypeA"), listOf("TypeB")), "w3c-own-alternative")

            assertTrue(validation.valid, validation.errors.toString())
        }

    @Test
    fun shouldRefuseTheDefinedShortNameOfAnExpandedType() =
        runTest {
            val children = listOf(validVcdm11VcJwt(subjectId = "holder"))

            val validation = validateVcdm11Types(children, listOf(listOf("VerifiableCredential")), "w3c-short-name")

            assertFalse(validation.valid)
        }

    @Test
    fun shouldRefuseACredentialWhoseContextCannotBeLoaded() =
        runTest {
            val unreachable =
                com.sphereon.jsonld.loader.LinkedDataDocumentLoader { iri ->
                    Err(com.sphereon.jsonld.JsonLdError.LoadingDocumentFailed(iri, "context server is down"))
                }
            val children = listOf(validVcdm11VcJwt(subjectId = "holder", credentialType = "IdentityCredential"))

            val validation =
                validateVcdm11Types(
                    children,
                    listOf(listOf("VerifiableCredential", "IdentityCredential")),
                    "w3c-context-unavailable",
                    testCredentialTypeMatcher(documentLoader = unreachable),
                )

            assertFalse(validation.valid)
        }

    private suspend fun validateBareVcdm11Credential(
        credential: String,
        alternatives: List<List<String>>,
        instance: String,
    ): com.sphereon.openid.oid4vp.verifier.ValidationResult {
        val state = "state-$instance"
        val meta =
            buildJsonObject {
                putJsonArray("type_values") { alternatives.forEach { add(JsonArray(it.map(::JsonPrimitive))) } }
            }
        val args =
            ValidateAuthorizationResponseArgs(
                parsedResponse =
                    ParsedAuthorizationResponse(
                        vpToken = vpTokenOf("credential", credential),
                        state = state,
                        rawVpToken = """{"credential":["$credential"]}""",
                    ),
                originalRequest = AuthorizationRequest(clientId = "https://verifier.example.com", redirectUri = "https://verifier.example.com/callback", state = state),
                dcqlQuery =
                    DcqlQuery(
                        credentials = listOf(DcqlCredentialQuery("credential", "jwt_vc_json", meta, require_cryptographic_holder_binding = false)),
                    ),
                expectedNonce = "nonce-is-not-a-vp-claim",
            )
        val result =
            validateWithPersistedSession(args, instanceId = "verifier-$instance", verifyJwsCommand = FixedVerifyJwsCommand(valid = true))
        assertIs<Ok<*>>(result)
        return result.value
    }

    @Test
    fun shouldAcceptABareCredentialOfTheRequestedType() =
        runTest {
            val validation =
                validateBareVcdm11Credential(
                    validVcdm11VcJwt(credentialType = "IdentityCredential"),
                    listOf(listOf(verifiableCredentialIri, "IdentityCredential")),
                    "bare-right",
                )

            assertTrue(validation.valid, validation.errors.toString())
        }

    @Test
    fun shouldRefuseABareCredentialOfAnotherType() =
        runTest {
            val validation =
                validateBareVcdm11Credential(
                    validVcdm11VcJwt(credentialType = "OtherCredential"),
                    listOf(listOf(verifiableCredentialIri, "IdentityCredential")),
                    "bare-wrong",
                )

            assertFalse(validation.valid)
            assertTrue(validation.matchedCredentials.isEmpty())
        }

    @Test
    fun shouldRefuseASecuredJsonChildOfAnotherType() =
        runTest {
            val child =
                buildJsonObject {
                    putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/2018/credentials/v1")) }
                    putJsonArray("type") {
                        add(JsonPrimitive("VerifiableCredential"))
                        add(JsonPrimitive("OtherCredential"))
                    }
                    put("issuer", "did:example:issuer")
                    put("issuanceDate", "2026-08-25T12:00:00Z")
                    putJsonObject("credentialSubject") { put("id", "did:example:holder") }
                    putJsonObject("proof") {
                        put("type", "DataIntegrityProof")
                        put("cryptosuite", "eddsa-jcs-2022")
                        put("proofPurpose", "assertionMethod")
                        put("verificationMethod", "did:example:issuer#key")
                        put("proofValue", "zproof")
                    }
                }
            val state = "state-di-child-wrong-type"
            val presentation = validVcdm11VpJwtWithEmbeddedJsonVc(child)
            val args =
                ValidateAuthorizationResponseArgs(
                    parsedResponse =
                        ParsedAuthorizationResponse(
                            vpToken = vpTokenOf("presentation", presentation),
                            state = state,
                            rawVpToken = "{\"presentation\":[\"$presentation\"]}",
                        ),
                    originalRequest = AuthorizationRequest(clientId = "https://verifier.example.com", redirectUri = "https://verifier.example.com/callback", state = state),
                    dcqlQuery =
                        DcqlQuery(
                            credentials =
                                listOf(
                                    DcqlCredentialQuery(
                                        "presentation",
                                        "ldp_vc",
                                        buildJsonObject {
                                            putJsonArray("type_values") { add(JsonArray(listOf(JsonPrimitive(verifiableCredentialIri), JsonPrimitive("IdentityCredential")))) }
                                        },
                                    ),
                                ),
                        ),
                    expectedNonce = "nonce-v1",
                )

            val result =
                validateWithPersistedSession(
                    args = args,
                    instanceId = "verifier-$state",
                    verifyHolderBindingCommand = RecordingHolderBindingCommand(),
                    verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
                    vcdmDataIntegrityVerifier = RecordingDataIntegrityVerifier(mutableListOf()),
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.valid)
        }

    private fun securedJsonChild(
        id: String,
        vararg extraTypes: String,
    ): JsonObject =
        buildJsonObject {
            putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/2018/credentials/v1")) }
            putJsonArray("type") {
                add(JsonPrimitive("VerifiableCredential"))
                extraTypes.forEach { add(JsonPrimitive(it)) }
            }
            put("id", id)
            put("issuer", "did:example:issuer")
            put("issuanceDate", "2026-08-25T12:00:00Z")
            putJsonObject("credentialSubject") { put("id", "did:example:holder") }
            putJsonObject("proof") {
                put("type", "DataIntegrityProof")
                put("cryptosuite", "eddsa-jcs-2022")
                put("proofPurpose", "assertionMethod")
                put("verificationMethod", "did:example:issuer#key")
                put("proofValue", "zproof")
            }
        }

    private suspend fun validateSecuredJsonChildren(
        children: List<JsonObject>,
        instance: String,
        matcher: CredentialTypeMatcher = testCredentialTypeMatcher(),
    ): com.sphereon.openid.oid4vp.verifier.ValidationResult {
        val state = "state-$instance"
        val presentation = validVcdm11VpJwtWithEmbeddedJsonVc(*children.toTypedArray())
        val args =
            ValidateAuthorizationResponseArgs(
                parsedResponse =
                    ParsedAuthorizationResponse(
                        vpToken = vpTokenOf("presentation", presentation),
                        state = state,
                        rawVpToken = "{\"presentation\":[\"$presentation\"]}",
                    ),
                originalRequest = AuthorizationRequest(clientId = "https://verifier.example.com", redirectUri = "https://verifier.example.com/callback", state = state),
                dcqlQuery =
                    DcqlQuery(
                        credentials =
                            listOf(
                                DcqlCredentialQuery(
                                    "presentation",
                                    "ldp_vc",
                                    buildJsonObject {
                                        putJsonArray("type_values") { add(JsonArray(listOf(JsonPrimitive(verifiableCredentialIri), JsonPrimitive("IdentityCredential")))) }
                                    },
                                ),
                            ),
                    ),
                expectedNonce = "nonce-v1",
            )
        val result =
            validateWithPersistedSession(
                args = args,
                instanceId = "verifier-$instance",
                verifyHolderBindingCommand = RecordingHolderBindingCommand(),
                verifyJwsCommand = FixedVerifyJwsCommand(valid = true),
                vcdmDataIntegrityVerifier = RecordingDataIntegrityVerifier(mutableListOf()),
                credentialTypeMatcher = matcher,
            )
        assertIs<Ok<*>>(result)
        return result.value
    }

    @Test
    fun shouldAcceptSecuredJsonChildrenThatAllMatch() =
        runTest {
            val validation =
                validateSecuredJsonChildren(
                    listOf(securedJsonChild("urn:example:one", "IdentityCredential"), securedJsonChild("urn:example:two", "IdentityCredential")),
                    "di-all-match",
                )

            assertTrue(validation.valid, validation.errors.toString())
        }

    @Test
    fun shouldRefuseSecuredJsonChildrenWhenOnlyTheSecondHasTheWrongType() =
        runTest {
            val validation =
                validateSecuredJsonChildren(
                    listOf(securedJsonChild("urn:example:one", "IdentityCredential"), securedJsonChild("urn:example:two", "OtherCredential")),
                    "di-second-wrong",
                )

            assertFalse(validation.valid)
        }

    @Test
    fun shouldRefuseSecuredJsonChildrenWhoseContextCannotBeLoaded() =
        runTest {
            val unreachable =
                com.sphereon.jsonld.loader.LinkedDataDocumentLoader { iri ->
                    Err(com.sphereon.jsonld.JsonLdError.LoadingDocumentFailed(iri, "context server is down"))
                }

            val validation =
                validateSecuredJsonChildren(
                    listOf(securedJsonChild("urn:example:one", "IdentityCredential")),
                    "di-context-unavailable",
                    testCredentialTypeMatcher(documentLoader = unreachable),
                )

            assertFalse(validation.valid)
        }

    private suspend fun validateBareLdpCredential(
        types: List<String>,
        instance: String,
        matcher: CredentialTypeMatcher = testCredentialTypeMatcher(),
    ): com.sphereon.openid.oid4vp.verifier.ValidationResult {
        val state = "state-$instance"
        val args =
            ValidateAuthorizationResponseArgs(
                parsedResponse =
                    ParsedAuthorizationResponse(
                        vpToken = VpToken(mapOf("credential" to listOf(dataIntegrityCredential("bare")))),
                        state = state,
                        rawVpToken = "{}",
                    ),
                originalRequest = AuthorizationRequest(clientId = "https://verifier.example.com", redirectUri = "https://verifier.example.com/callback", state = state),
                dcqlQuery =
                    DcqlQuery(
                        credentials =
                            listOf(
                                DcqlCredentialQuery(
                                    id = "credential",
                                    format = "ldp_vc",
                                    meta = buildJsonObject { putJsonArray("type_values") { add(JsonArray(types.map(::JsonPrimitive))) } },
                                    require_cryptographic_holder_binding = false,
                                ),
                            ),
                    ),
                expectedNonce = "nonce-not-used-for-bare-vc",
            )
        val result =
            validateWithPersistedSession(
                args = args,
                instanceId = "verifier-$instance",
                vcdmDataIntegrityVerifier = RecordingDataIntegrityVerifier(mutableListOf()),
                credentialTypeMatcher = matcher,
            )
        assertIs<Ok<*>>(result)
        return result.value
    }

    @Test
    fun shouldAcceptABareLdpCredentialOfTheRequestedType() =
        runTest {
            assertTrue(validateBareLdpCredential(listOf(verifiableCredentialIri), "ldp-bare-right").valid)
        }

    @Test
    fun shouldRefuseABareLdpCredentialOfAnotherType() =
        runTest {
            assertFalse(validateBareLdpCredential(listOf(verifiableCredentialIri, "IdentityCredential"), "ldp-bare-wrong").valid)
        }

    @Test
    fun shouldRefuseABareLdpCredentialWhoseContextCannotBeLoaded() =
        runTest {
            val unreachable =
                com.sphereon.jsonld.loader.LinkedDataDocumentLoader { iri ->
                    Err(com.sphereon.jsonld.JsonLdError.LoadingDocumentFailed(iri, "context server is down"))
                }

            val validation =
                validateBareLdpCredential(listOf(verifiableCredentialIri), "ldp-bare-context", testCredentialTypeMatcher(documentLoader = unreachable))

            assertFalse(validation.valid)
        }

    private val issuerDependentIdentityIri = "IdentityCredential"

    private fun v2TypedChild(
        name: String,
        vararg extraTypes: String,
    ): JsonObject =
        JsonObject(
            dataIntegrityCredential(name) +
                ("type" to buildJsonArray { (listOf("VerifiableCredential") + extraTypes).forEach { add(JsonPrimitive(it)) } }),
        )

    private fun v2Presentation(vararg children: JsonObject): JsonObject =
        buildJsonObject {
            putJsonArray("@context") { add(JsonPrimitive("https://www.w3.org/ns/credentials/v2")) }
            putJsonArray("type") { add(JsonPrimitive("VerifiablePresentation")) }
            putJsonArray("verifiableCredential") { children.forEach { add(it) } }
            put("proof", authenticationProof("did:example:holder#key"))
        }

    private suspend fun validateDataIntegrityPresentation(
        presentation: JsonObject,
        instance: String,
        matcher: CredentialTypeMatcher = testCredentialTypeMatcher(),
    ): com.sphereon.openid.oid4vp.verifier.ValidationResult {
        val state = "state-$instance"
        val args =
            ValidateAuthorizationResponseArgs(
                parsedResponse =
                    ParsedAuthorizationResponse(
                        vpToken = VpToken(mapOf("presentation" to listOf(presentation))),
                        state = state,
                        rawVpToken = "{}",
                    ),
                originalRequest = AuthorizationRequest(clientId = "https://verifier.example.com", redirectUri = "https://verifier.example.com/callback", state = state),
                dcqlQuery =
                    DcqlQuery(
                        credentials =
                            listOf(
                                DcqlCredentialQuery(
                                    id = "presentation",
                                    format = "ldp_vc",
                                    meta =
                                        buildJsonObject {
                                            putJsonArray("type_values") {
                                                add(JsonArray(listOf(JsonPrimitive(verifiableCredentialIri), JsonPrimitive(issuerDependentIdentityIri))))
                                            }
                                        },
                                    require_cryptographic_holder_binding = false,
                                ),
                            ),
                    ),
                expectedNonce = "nonce-vp",
            )
        val result =
            validateWithPersistedSession(
                args = args,
                instanceId = "verifier-$instance",
                vcdmDataIntegrityVerifier = RecordingDataIntegrityVerifier(mutableListOf(), authenticatedControllers = setOf("did:example:holder")),
                credentialTypeMatcher = matcher,
            )
        assertIs<Ok<*>>(result)
        return result.value
    }

    @Test
    fun shouldAcceptADataIntegrityPresentationWhoseChildrenAllMatch() =
        runTest {
            val presentation = v2Presentation(v2TypedChild("one", "IdentityCredential"), v2TypedChild("two", "IdentityCredential"))

            val validation = validateDataIntegrityPresentation(presentation, "dip-all-match")

            assertTrue(validation.valid, validation.errors.toString())
        }

    @Test
    fun shouldRefuseADataIntegrityPresentationWhenOnlyTheSecondChildHasTheWrongType() =
        runTest {
            val presentation = v2Presentation(v2TypedChild("one", "IdentityCredential"), v2TypedChild("two", "OtherCredential"))

            assertFalse(validateDataIntegrityPresentation(presentation, "dip-second-wrong").valid)
        }

    @Test
    fun shouldRefuseADataIntegrityPresentationWhoseContextCannotBeLoaded() =
        runTest {
            val unreachable =
                com.sphereon.jsonld.loader.LinkedDataDocumentLoader { iri ->
                    Err(com.sphereon.jsonld.JsonLdError.LoadingDocumentFailed(iri, "context server is down"))
                }

            val validation =
                validateDataIntegrityPresentation(
                    v2Presentation(v2TypedChild("one", "IdentityCredential")),
                    "dip-context",
                    testCredentialTypeMatcher(documentLoader = unreachable),
                )

            assertFalse(validation.valid)
        }

    @Test
    fun shouldAcceptANestedPresentationWhoseChildrenAllMatch() =
        runTest {
            val inner = v2Presentation(v2TypedChild("one", "IdentityCredential"), v2TypedChild("two", "IdentityCredential"))

            val validation = validateDataIntegrityPresentation(v2Presentation(inner), "dip-nested-right")

            assertTrue(validation.valid, validation.errors.toString())
        }

    @Test
    fun shouldRefuseANestedPresentationWhenOnlyTheSecondChildHasTheWrongType() =
        runTest {
            val inner = v2Presentation(v2TypedChild("one", "IdentityCredential"), v2TypedChild("two", "OtherCredential"))

            assertFalse(validateDataIntegrityPresentation(v2Presentation(inner), "dip-nested-wrong").valid)
        }

    @Test
    fun shouldRefuseANestedPresentationWhoseContextCannotBeLoaded() =
        runTest {
            val unreachable =
                com.sphereon.jsonld.loader.LinkedDataDocumentLoader { iri ->
                    Err(com.sphereon.jsonld.JsonLdError.LoadingDocumentFailed(iri, "context server is down"))
                }
            val inner = v2Presentation(v2TypedChild("one", "IdentityCredential"))

            val validation = validateDataIntegrityPresentation(v2Presentation(inner), "dip-nested-context", testCredentialTypeMatcher(documentLoader = unreachable))

            assertFalse(validation.valid)
        }

    private fun createTestCommand(
        credentialStatusVerifiers: Set<com.sphereon.statuslist.spi.CredentialStatusVerifier> = emptySet(),
        credentialTrustValidators: Set<Oid4vpCredentialTrustValidator> = emptySet(),
        authorizationSessionStore: AuthorizationSessionStore = TestAuthorizationSessionStore(),
        verifyHolderBindingCommand: VerifyHolderBindingCommand = AlwaysValidHolderBindingCommand,
        verifyJwsCommand: VerifyJwsCommand = FixedVerifyJwsCommand(valid = false),
        vcdmDataIntegrityVerifier: VcdmDataIntegrityVerifier = RejectingVcdmDataIntegrityVerifier,
        credentialTypeMatcher: CredentialTypeMatcher = testCredentialTypeMatcher(),
    ): ValidateAuthorizationResponseCommandImpl {
        // Validators wired through the built-in W3C/UNTP @context bundle so
        // VCDM 2.0 references resolve from the JAR (no network). For
        // non-VCDM-2.0 presentations the validator path is skipped entirely
        // (referencesVcdm2Context returns false).
        val builtInLoader =
            com.sphereon.jsonld.loader.BuiltInContextLinkedDataDocumentLoader(
                com.sphereon.jsonld.loader
                    .DefaultBuiltInContextRegistry(),
            )
        return ValidateAuthorizationResponseCommandImpl(
            execution = testContext.execution,
            authorizationSessionStore = authorizationSessionStore,
            verifyHolderBindingCommand = verifyHolderBindingCommand,
            verifyJwsCommand = verifyJwsCommand,
            jsonLdContextValidator =
                com.sphereon.jsonld.command
                    .JsonLdContextValidator(builtInLoader),
            jsonLdSchemaValidator =
                com.sphereon.jsonld.command.JsonLdSchemaValidator(
                    com.sphereon.jsonld.command
                        .MapBackedJsonLdSchemaRegistry(emptyMap()),
                ),
             deviceResponseCborCodec =
                 com.sphereon.mdoc.data.device
                         .DeviceResponseCborCodecImpl(),
             mobileSecurityObjectCborCodec =
                 com.sphereon.mdoc.data.mso
                         .MobileSecurityObjectCborCodecImpl(),
             cborParser = com.sphereon.cbor.CborParserImpl(),
             vcdmDataIntegrityVerifier = vcdmDataIntegrityVerifier,
            credentialStatusVerifiers = credentialStatusVerifiers,
            credentialTrustValidators = credentialTrustValidators,
            businessAuthorizations = emptySet(),
            credentialTypeMatcher = credentialTypeMatcher,
        )
    }

    private suspend fun validateWithPersistedSession(
        args: ValidateAuthorizationResponseArgs,
        instanceId: String,
        credentialStatusVerifiers: Set<com.sphereon.statuslist.spi.CredentialStatusVerifier> = emptySet(),
        credentialTrustValidators: Set<Oid4vpCredentialTrustValidator> = emptySet(),
        verifyHolderBindingCommand: VerifyHolderBindingCommand = AlwaysValidHolderBindingCommand,
        verifyJwsCommand: VerifyJwsCommand = FixedVerifyJwsCommand(valid = false),
        vcdmDataIntegrityVerifier: VcdmDataIntegrityVerifier = RejectingVcdmDataIntegrityVerifier,
        // Defaults to mirroring args.templateId (as verifierId/dcqlQueryId already do below) so
        // existing callers are unaffected; tests exercising the session-fallback path pass a
        // value here while leaving args.templateId null.
        sessionTemplateId: String? = args.templateId,
        persistedAuthorizationRequest: AuthorizationRequest = args.originalRequest,
        persistedDcqlQuery: DcqlQuery = args.dcqlQuery,
        credentialTypeMatcher: CredentialTypeMatcher = testCredentialTypeMatcher(),
    ): IdkResult<com.sphereon.openid.oid4vp.verifier.ValidationResult, IdkError> {
        val correlationState = requireNotNull(args.originalRequest.state) { "Test authorization request must have correlation state" }
        val authorizationSessionStore = TestAuthorizationSessionStore()
        val now = Clock.System.now().toEpochMilliseconds()
        val persistedRequestWithJwtVpAlgorithms =
            if ("client_metadata" in persistedAuthorizationRequest.additionalParameters) {
                persistedAuthorizationRequest
            } else {
                persistedAuthorizationRequest.copy(
                    additionalParameters =
                        persistedAuthorizationRequest.additionalParameters +
                            ("client_metadata" to
                                kotlinx.serialization.json.Json.encodeToJsonElement(
                                    ClientMetadata.serializer(),
                                    ClientMetadata(
                                        vpFormatsSupported =
                                            mapOf(
                                                "jwt_vc_json" to VpFormatInfo(algValuesSupported = listOf("ES256")),
                                                "jwt_vc_json-ld" to VpFormatInfo(algValuesSupported = listOf("ES256")),
                                                "ldp_vc" to VpFormatInfo(algValuesSupported = listOf("ES256")),
                                            ),
                                    ),
                                )),
                )
            }
        val session =
            AuthorizationSession(
                instanceId = instanceId,
                sessionId = "validation-session-$correlationState",
                correlationId = correlationState,
                dcqlQuery = persistedDcqlQuery,
                dcqlQueryId = args.dcqlQueryId,
                verifierId = args.verifierId,
                templateId = sessionTemplateId,
                authorizationRequest = persistedRequestWithJwtVpAlgorithms,
                status = AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_RECEIVED,
                parsedResponse = args.parsedResponse,
                createdAt = now,
                updatedAt = now,
                expiresAt = now + 600_000,
            )

        assertIs<Ok<*>>(authorizationSessionStore.put(correlationState, session, ttlSeconds = 600))
        val persistedSession = authorizationSessionStore.get(correlationState)
        assertIs<Ok<*>>(persistedSession)
        assertEquals(instanceId, persistedSession.value?.instanceId)

        return createTestCommand(
            credentialStatusVerifiers = credentialStatusVerifiers,
            credentialTrustValidators = credentialTrustValidators,
            authorizationSessionStore = authorizationSessionStore,
            verifyHolderBindingCommand = verifyHolderBindingCommand,
            verifyJwsCommand = verifyJwsCommand,
            vcdmDataIntegrityVerifier = vcdmDataIntegrityVerifier,
            credentialTypeMatcher = credentialTypeMatcher,
        ).validateAuthorizationResponse(args)
    }
}

private class OrderedTrustValidator(
    private val events: MutableList<String>,
    private val trusted: Boolean,
    private val trustedCalls: Set<Int> = emptySet(),
) : Oid4vpCredentialTrustValidator {
    var calls: Int = 0
        private set

    override suspend fun validate(args: Oid4vpCredentialTrustValidationArgs): IdkResult<CredentialTrustValidation, IdkError> {
        calls++
        events += "trust"
        return Ok(
            CredentialTrustValidation(
                enabled = true,
                trusted = if (trustedCalls.isEmpty()) trusted else calls in trustedCalls,
                mode = CredentialTrustValidationMode.DEFAULT_ENFORCE,
            ),
        )
    }
}

private class OrderedVerifyJwsCommand(
    private val events: MutableList<String>,
    private val valid: Boolean,
) : VerifyJwsCommand {
    override val commandId: String = VerifyJwsCommand.COMMAND_ID
    override val inputTypeToken: TypeToken<VerifyJwsArgs> = typeToken<VerifyJwsArgs>()
    override val outputTypeToken: TypeToken<JwsValidationResult> = typeToken<JwsValidationResult>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is VerifyJwsArgs

    override suspend fun execute(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> {
        events += "crypto"
        return Ok(
            JwsValidationResult(
                jws = JwsJsonGeneralWithIdentifiers(payload = "", signatures = emptyList()),
                isValid = valid,
                errorMessages = if (valid) emptyList() else listOf("invalid issuer signature"),
                parsedPayload = JsonObject(emptyMap()),
                trustEstablished = true,
                cryptoVerified = valid,
            ),
        )
    }
}

private class SecondChildRevokedStatusVerifier(
    private val events: MutableList<String>,
) : com.sphereon.statuslist.spi.CredentialStatusVerifier {
    override val mechanism: String = "test"

    override fun references(credentialClaims: JsonObject): List<com.sphereon.statuslist.CredentialStatusReference> {
        val subject = credentialClaims["credentialSubject"] as? JsonObject
        val name = (subject?.get("name") as? JsonPrimitive)?.content
        return listOf(com.sphereon.statuslist.CredentialStatusReference(mechanism = mechanism, uri = "https://issuer.example.com/sl", index = if (name == "second") 1 else 0))
    }

    override suspend fun resolve(reference: com.sphereon.statuslist.CredentialStatusReference): IdkResult<com.sphereon.statuslist.ResolvedStatus, IdkError> {
        events += "status"
        val value = reference.index
        return Ok(com.sphereon.statuslist.ResolvedStatus(value = value, valid = value == 0, statusListUri = reference.uri))
    }
}

private object RejectingVcdmDataIntegrityVerifier : VcdmDataIntegrityVerifier {
    override suspend fun verify(args: VcdmDataIntegrityVerificationArgs): IdkResult<VcdmDataIntegrityVerificationResult, IdkError> =
        Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Data Integrity test stub was not configured"))
}

private class RecordingDataIntegrityVerifier(
    private val events: MutableList<String>,
    private val authenticatedControllers: Set<String> = emptySet(),
) : VcdmDataIntegrityVerifier {
    val calls = mutableListOf<VcdmDataIntegrityVerificationArgs>()

    override suspend fun verify(args: VcdmDataIntegrityVerificationArgs): IdkResult<VcdmDataIntegrityVerificationResult, IdkError> {
        calls += args
        events += "crypto"
        return Ok(
            VcdmDataIntegrityVerificationResult(
                JsonObject(args.document - "proof"),
                proofCount = 1,
                authenticatedControllers = authenticatedControllers,
            ),
        )
    }
}

private class CapturingTrustValidator : Oid4vpCredentialTrustValidator {
    var lastArgs: Oid4vpCredentialTrustValidationArgs? = null
        private set

    override suspend fun validate(args: Oid4vpCredentialTrustValidationArgs): IdkResult<CredentialTrustValidation, IdkError> {
        lastArgs = args
        return Ok(
            CredentialTrustValidation(
                enabled = false,
                mode = CredentialTrustValidationMode.DISABLED,
                details = "captured",
            ),
        )
    }
}

/**
 * Test verifier that always reports one status reference and resolves it to a fixed [value],
 * independent of the credential claims — lets the integration tests drive the verifier's status
 * decision without hand-crafting a parseable signed status-list token.
 */
private class FixedStatusVerifier(
    private val value: Int,
) : com.sphereon.statuslist.spi.CredentialStatusVerifier {
    override val mechanism: String = "test"

    override fun references(credentialClaims: kotlinx.serialization.json.JsonObject) =
        listOf(com.sphereon.statuslist.CredentialStatusReference(mechanism = "test", uri = "https://issuer.example.com/sl", index = 0))

    override suspend fun resolve(reference: com.sphereon.statuslist.CredentialStatusReference) =
        Ok(com.sphereon.statuslist.ResolvedStatus(value = value, valid = value == 0, statusListUri = reference.uri))
}

/**
 * Test stub that always returns a verified holder binding. The unit tests in this file
 * exercise the validation/matching pipeline with synthesized vp_token strings; cryptographic
 * holder-binding checks are covered by [VerifyHolderBindingCommandImplTest].
 */
private object AlwaysValidHolderBindingCommand : VerifyHolderBindingCommand {
    override val commandId: String = VerifyHolderBindingCommand.COMMAND_ID
    override val inputTypeToken: TypeToken<VerifyHolderBindingArgs> = typeToken<VerifyHolderBindingArgs>()
    override val outputTypeToken: TypeToken<HolderBindingResult> = typeToken<HolderBindingResult>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is VerifyHolderBindingArgs

    override suspend fun execute(args: VerifyHolderBindingArgs): IdkResult<HolderBindingResult, IdkError> =
        Ok(
            HolderBindingResult(
                verified = true,
                bindingMethod = "stub",
                signatureValid = true,
                nonceValid = true,
                audienceValid = true,
            ),
        )
}

private class ExpectedMdocDocumentTypeHolderBindingCommand(
    private val expectedDocumentType: String,
) : VerifyHolderBindingCommand {
    override val commandId: String = VerifyHolderBindingCommand.COMMAND_ID
    override val inputTypeToken: TypeToken<VerifyHolderBindingArgs> = typeToken<VerifyHolderBindingArgs>()
    override val outputTypeToken: TypeToken<HolderBindingResult> = typeToken<HolderBindingResult>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is VerifyHolderBindingArgs

    override suspend fun execute(args: VerifyHolderBindingArgs): IdkResult<HolderBindingResult, IdkError> {
        val matchesPersistedType = args.expectedMdocDocumentType == expectedDocumentType
        return Ok(
            HolderBindingResult(
                verified = matchesPersistedType,
                bindingMethod = "test-persisted-mdoc-document-type",
                signatureValid = matchesPersistedType,
                nonceValid = matchesPersistedType,
                audienceValid = matchesPersistedType,
                errors = if (matchesPersistedType) emptyList() else listOf("document type was not sourced from the persisted session"),
            ),
        )
    }
}

private class RecordingHolderBindingCommand : VerifyHolderBindingCommand {
    var calls: Int = 0
        private set
    var lastArgs: VerifyHolderBindingArgs? = null
        private set

    override val commandId: String = VerifyHolderBindingCommand.COMMAND_ID
    override val inputTypeToken: TypeToken<VerifyHolderBindingArgs> = typeToken<VerifyHolderBindingArgs>()
    override val outputTypeToken: TypeToken<HolderBindingResult> = typeToken<HolderBindingResult>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is VerifyHolderBindingArgs

    override suspend fun execute(args: VerifyHolderBindingArgs): IdkResult<HolderBindingResult, IdkError> {
        calls++
        lastArgs = args
        return AlwaysValidHolderBindingCommand.execute(args)
    }
}

private class FixedVerifyJwsCommand(
    private val valid: Boolean,
    private val rejectOnCall: Int? = null,
) : VerifyJwsCommand {
    var calls: Int = 0
        private set
    val identifiers = mutableListOf<IdentifierOptsOrResult?>()
    val trustedJwks = mutableListOf<JsonObject?>()

    override val commandId: String = VerifyJwsCommand.COMMAND_ID
    override val inputTypeToken: TypeToken<VerifyJwsArgs> = typeToken<VerifyJwsArgs>()
    override val outputTypeToken: TypeToken<JwsValidationResult> = typeToken<JwsValidationResult>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is VerifyJwsArgs

    override suspend fun execute(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> {
        calls++
        identifiers += args.identifier
        trustedJwks += args.trustedJwks
        if (args.jws == null) return Err(IdkError.fromString("JWS is required"))
        val resultValid = valid && calls != rejectOnCall
        return Ok(
            JwsValidationResult(
                jws =
                    JwsJsonGeneralWithIdentifiers(
                        payload = "",
                        signatures = emptyList(),
                    ),
                isValid = resultValid,
                errorMessages = if (resultValid) emptyList() else listOf("invalid issuer signature"),
                parsedPayload = JsonObject(emptyMap()),
                trustEstablished = true,
                cryptoVerified = resultValid,
            ),
        )
    }
}

private class NonceAwareHolderBindingCommand : VerifyHolderBindingCommand {
    var calls: Int = 0
        private set

    override val commandId: String = VerifyHolderBindingCommand.COMMAND_ID
    override val inputTypeToken: TypeToken<VerifyHolderBindingArgs> = typeToken<VerifyHolderBindingArgs>()
    override val outputTypeToken: TypeToken<HolderBindingResult> = typeToken<HolderBindingResult>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is VerifyHolderBindingArgs

    override suspend fun execute(args: VerifyHolderBindingArgs): IdkResult<HolderBindingResult, IdkError> {
        calls++
        val verified = calls == 1
        return Ok(
            HolderBindingResult(
                verified = verified,
                bindingMethod = "test",
                signatureValid = verified,
                nonceValid = verified,
                audienceValid = verified,
            ),
        )
    }
}
