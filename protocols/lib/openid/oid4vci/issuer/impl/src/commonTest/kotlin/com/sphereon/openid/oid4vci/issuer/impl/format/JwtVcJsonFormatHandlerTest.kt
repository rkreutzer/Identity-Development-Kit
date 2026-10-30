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

package com.sphereon.openid.oid4vci.issuer.impl.format

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.jose.jws.JwsJsonFlattened
import com.sphereon.crypto.jose.jws.JwsJsonGeneral
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.crypto.jose.jws.JwtCompactResult
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.PreparedJwsObject
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialDefinition
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.long
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JwtVcJsonFormatHandlerTest {
    // These tests exercise SigningKeyMode.None (the default on IssuanceContext), so the KMS and
    // key-id resolver are never invoked — a mock + a no-op stub satisfy the constructor.
    private object StubIssuerKeyIdResolver : com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver {
        override suspend fun resolveDidVerificationMethodId(
            keyAlias: String,
            didMethod: String,
        ): IdkResult<String, IdkError> = error("StubIssuerKeyIdResolver should not be invoked under SigningKeyMode.None")

        override suspend fun resolvePublicJwk(keyAlias: String,): IdkResult<kotlinx.serialization.json.JsonObject, IdkError> =
            error("StubIssuerKeyIdResolver should not be invoked under SigningKeyMode.None")
    }

    private class RecordingIssuerKeyIdResolver : IssuerKeyIdResolver {
        var resolvedIssuerIdentifier: String? = null
        var validatedVerificationMethodId: String? = null

        override suspend fun resolveDidVerificationMethodId(
            keyAlias: String,
            didMethod: String,
        ): IdkResult<String, IdkError> = error("Hosted DID issuance must use the issuer-aware resolver overload")

        override suspend fun resolveDidVerificationMethodId(
            keyAlias: String,
            didMethod: String,
            issuerIdentifier: String,
        ): IdkResult<String, IdkError> {
            resolvedIssuerIdentifier = issuerIdentifier
            return Ok("did:web:issuer.example.com#$keyAlias")
        }

        override suspend fun resolvePublicJwk(keyAlias: String): IdkResult<JsonObject, IdkError> =
            error("resolvePublicJwk is not used by this test")

        override suspend fun validateDidVerificationMethodId(
            keyAlias: String,
            verificationMethodId: String,
        ): IdkResult<String, IdkError> {
            validatedVerificationMethodId = verificationMethodId
            return Ok(verificationMethodId)
        }
    }

    private val handler =
        JwtVcJsonFormatHandler(
            signatureService = (FakeJwtService()).asSignatureServiceFixture(),
            kms = TestKmsMock(),
            issuerKeyIdResolver = StubIssuerKeyIdResolver,
        )

    private fun makeConfig(
        format: String,
        types: List<String>? = listOf("VerifiableCredential", "ExampleCredential"),
    ) = CredentialConfigurationSupported(
        format = format,
        credentialDefinition = types?.let { CredentialDefinition(type = it) },
    )

    private fun makeRequest(format: String? = null) = CredentialRequest(format = format)

    private fun makeContext(
        config: CredentialConfigurationSupported,
        attributes: Map<String, kotlinx.serialization.json.JsonElement> = mapOf("name" to JsonPrimitive("Holder")),
    ) = IssuanceContext(
        subject = "did:example:holder123",
        clientId = "client-1",
        issuerIdentifier = "https://issuer.example.com",
        credentialConfigurationId = "jwt-vc-config-1",
        credentialConfiguration = config,
        holderBindingKey = null,
        attributes = attributes,
        signingKeyAlias = "issuer-signing-jwt-vc",
    )

    @Test
    fun canHandleReturnsTrueForJwtVcJsonFormat() =
        runTest {
            val config = makeConfig("jwt_vc_json")
            val request = makeRequest()
            assertTrue(handler.canHandle(request, config))
        }

    @Test
    fun canHandleReturnsFalseForSdJwtVcFormat() =
        runTest {
            val config = makeConfig("dc+sd-jwt")
            val request = makeRequest()
            assertFalse(handler.canHandle(request, config))
        }

    @Test
    fun canHandleReturnsFalseForMsoMdocFormat() =
        runTest {
            val config = makeConfig("mso_mdoc")
            val request = makeRequest()
            assertFalse(handler.canHandle(request, config))
        }

    @Test
    fun issueCredentialProducesJwtWithCorrectFormat() =
        runTest {
            val config = makeConfig("jwt_vc_json", listOf("VerifiableCredential", "UniversityDegreeCredential"))
            val context =
                makeContext(
                    config = config,
                    attributes =
                        mapOf(
                            "degree" to JsonPrimitive("Bachelor of Science"),
                            "university" to JsonPrimitive("Example University"),
                        ),
                )
            val request = makeRequest("jwt_vc_json")

            val result = handler.issueCredential(request, context)

            assertTrue(result.isOk)
            val envelope = result.getOrThrow()
            assertEquals("jwt_vc_json", envelope.format)

            // The credential should be a JWT compact string (3 dot-separated parts)
            val jwtString = (envelope.credential as JsonPrimitive).content
            val parts = jwtString.split(".")
            assertEquals(3, parts.size, "JWT compact serialization should have 3 parts")
        }

    @Test
    fun issueCredentialRefusesACredentialWithoutASpecificType() =
        runTest {
            val request = makeRequest("jwt_vc_json")
            for (types in listOf(null, listOf("VerifiableCredential"))) {
                val context =
                    makeContext(
                        config = makeConfig("jwt_vc_json", types),
                        attributes = mapOf("name" to JsonPrimitive("Alice")),
                    )

                val result = handler.issueCredential(request, context)

                assertTrue(result.isErr, "types $types must be refused")
                assertEquals("invalid_vcdm_credential", result.error.code)
            }
        }

    @Test
    fun issuedTypesAlwaysLeadWithVerifiableCredential() =
        runTest {
            val context =
                makeContext(
                    config = makeConfig("jwt_vc_json", listOf("EmployeeBadgeCredential", "VerifiableCredential", "EmployeeBadgeCredential")),
                    attributes = mapOf("name" to JsonPrimitive("Alice")),
                )

            val types = vcdmCredentialTypes(context.credentialConfiguration.credentialDefinition?.type).value

            assertEquals(listOf("VerifiableCredential", "EmployeeBadgeCredential"), types)
        }

    @Test
    fun vcdm11JwtVcJsonKeepsVcWrapperRegisteredClaimMappingsAndV11ProtectedType() =
        runTest {
            val jwtService = RecordingJwtService()
            val vcdm11Handler =
                JwtVcJsonFormatHandler(
                    signatureService = (jwtService).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                )

            val result = vcdm11Handler.issueCredential(makeRequest("jwt_vc_json"), makeContext(makeConfig("jwt_vc_json")))

            assertTrue(result.isOk)
            val payload = assertNotNull(jwtService.lastArgs?.payload as? JsonObject)
            val vc = assertNotNull(payload["vc"]?.jsonObject)
            assertNotNull(vc["issuanceDate"])
            assertNull(vc["validFrom"])
            assertEquals(
                60L,
                payload["nbf"]!!.jsonPrimitive.content.toLong() - payload["iat"]!!.jsonPrimitive.content.toLong(),
            )
            assertEquals(
                vc["credentialSubject"]?.jsonObject?.get("id")?.jsonPrimitive?.content,
                payload["sub"]?.jsonPrimitive?.content,
            )
            val protectedHeader = jwtService.lastArgs?.opts?.protectedHeader
            assertEquals("JWT", protectedHeader?.get("typ")?.jsonPrimitive?.content)
            assertNull(protectedHeader?.get("cty"))
        }

    @Test
    fun vcdm11FederationEntityIssuerAddsOpenIdFederationTermsOfUseInsideVc() =
        runTest {
            val jwtService = RecordingJwtService()
            val vcdm11Handler =
                JwtVcJsonFormatHandler(
                    signatureService = (jwtService).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                )

            val result =
                vcdm11Handler.issueCredential(
                    makeRequest("jwt_vc_json"),
                    makeContext(makeConfig("jwt_vc_json")).copy(federationEntityIdentifier = "https://issuer.example.com"),
                )

            assertTrue(result.isOk, "issuance must succeed: ${if (result.isErr) result.error else ""}")
            val payload = assertNotNull(jwtService.lastArgs?.payload as? JsonObject)
            val vc = assertNotNull(payload["vc"]?.jsonObject)
            assertEquals(
                buildJsonObject {
                    put("type", "OpenIDFederation")
                    put("policyId", "https://issuer.example.com")
                },
                vc["termsOfUse"],
            )
            assertNull(payload["termsOfUse"], "termsOfUse is a VC property, not a JWT claim")
            assertEquals("https://issuer.example.com", payload["iss"]?.jsonPrimitive?.content)
        }

    @Test
    fun vcdm11IssueKeepsFutureDataValiditySeparateFromSigningIat() =
        runTest {
            val jwtService = RecordingJwtService()
            val vcdm11Handler =
                JwtVcJsonFormatHandler(
                    signatureService = (jwtService).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                )
            val futureValidFrom = Instant.parse("2099-01-01T00:00:00Z")
            val futureValidUntil = Instant.parse("2100-01-01T00:00:00Z")
            val context =
                makeContext(makeConfig("jwt_vc_json")).copy(
                    validFrom = futureValidFrom,
                    validUntil = futureValidUntil,
                )

            val result = vcdm11Handler.issueCredential(makeRequest("jwt_vc_json"), context)

            assertTrue(result.isOk)
            val payload = assertNotNull(jwtService.lastArgs?.payload as? JsonObject)
            val vc = assertNotNull(payload["vc"]?.jsonObject)
            assertEquals(futureValidFrom.toString(), vc["issuanceDate"]?.jsonPrimitive?.content)
            assertEquals(futureValidFrom.epochSeconds, payload["nbf"]?.jsonPrimitive?.long)
            assertTrue(payload["iat"]!!.jsonPrimitive.long < futureValidFrom.epochSeconds)
            assertEquals(futureValidUntil.toString(), vc["expirationDate"]?.jsonPrimitive?.content)
            assertEquals(futureValidUntil.epochSeconds, payload["exp"]?.jsonPrimitive?.long)
        }

    @Test
    fun vcdm11JwtVcJsonPreservesApplicablePropertiesWithoutV2DateTranslation() =
        runTest {
            val jwtService = RecordingJwtService()
            val vcdm11Handler =
                JwtVcJsonFormatHandler(
                    signatureService = (jwtService).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                )
            val context =
                makeContext(makeConfig("jwt_vc_json")).copy(
                    vcdmProperties = buildJsonObject {
                        put("credentialSchema", buildJsonObject {
                            put("id", "https://issuer.example/schema")
                            put("type", "JsonSchema")
                        })
                        put("termsOfUse", buildJsonObject {
                            put("type", "IssuerPolicy")
                        })
                        put("https://issuer.example/ext", JsonPrimitive("preserved"))
                    },
                )

            val result = vcdm11Handler.issueCredential(makeRequest("jwt_vc_json"), context)

            assertTrue(result.isOk)
            val vc = assertNotNull((jwtService.lastArgs?.payload as JsonObject)["vc"]?.jsonObject)
            assertNotNull(vc["credentialSchema"])
            assertNotNull(vc["termsOfUse"])
            assertEquals("preserved", vc["https://issuer.example/ext"]?.jsonPrimitive?.content)
            assertNull(vc["validFrom"])
            assertNull(vc["validUntil"])
        }

    @Test
    fun didSigningUsesTheExactSelectedAssertionMethod() =
        runTest {
            val resolver = RecordingIssuerKeyIdResolver()
            val jwtService = RecordingJwtService()
            val didWebHandler =
                JwtVcJsonFormatHandler(
                    signatureService = (jwtService).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = resolver,
                )
            val context =
                makeContext(makeConfig("jwt_vc_json")).copy(
                    issuerIdentifier = "https://issuer.example.com/oid4vci",
                    signingKeyMode = SigningKeyMode.Did("web"),
                    signingVerificationMethodId = "did:web:issuer.example.com#issuer-assertion",
                )

            val result = didWebHandler.issueCredential(makeRequest("jwt_vc_json"), context)

            assertTrue(result.isOk)
            assertEquals("did:web:issuer.example.com#issuer-assertion", resolver.validatedVerificationMethodId)
            assertEquals(
                "did:web:issuer.example.com#issuer-assertion",
                jwtService.lastArgs?.opts?.protectedHeader?.get("kid")?.jsonPrimitive?.content,
            )
            assertEquals("JWT", jwtService.lastArgs?.opts?.protectedHeader?.get("typ")?.jsonPrimitive?.content)
            // OID4VCI 1.0 §14.4: a DID-signed credential names its DID, not the Credential Issuer URL.
            val payload = assertNotNull(jwtService.lastArgs?.payload as? JsonObject)
            assertEquals("did:web:issuer.example.com", payload["iss"]?.jsonPrimitive?.content)
            assertEquals("did:web:issuer.example.com", payload["vc"]?.jsonObject?.get("issuer")?.jsonPrimitive?.content)
        }

    @Test
    fun permitsAnonymousCredentialSubjectObject() =
        runTest {
            val jwtService = RecordingJwtService()
            val handler = JwtVcJsonFormatHandler((jwtService).asSignatureServiceFixture(), TestKmsMock(), StubIssuerKeyIdResolver)
            val result = handler.issueCredential(
                makeRequest("jwt_vc_json"),
                makeContext(makeConfig("jwt_vc_json"), attributes = mapOf("name" to JsonPrimitive("Holder"))),
            )

            assertTrue(result.isOk)
            val payload = assertNotNull(jwtService.lastArgs?.payload as? JsonObject)
            assertNull(payload["sub"])
            assertFalse(payload["vc"]!!.jsonObject["credentialSubject"]!!.jsonObject.containsKey("id"))
        }

    @Test
    fun emitsSubOnlyFromTheSingleCredentialSubjectId() =
        runTest {
            val jwtService = RecordingJwtService()
            val result = JwtVcJsonFormatHandler((jwtService).asSignatureServiceFixture(), TestKmsMock(), StubIssuerKeyIdResolver)
                .issueCredential(
                    makeRequest("jwt_vc_json"),
                    makeContext(makeConfig("jwt_vc_json"), attributes = emptyMap()).copy(
                        credentialSubjects = listOf(
                            buildJsonObject {
                                put("id", "https://example.com/subjects/one")
                                put("name", "Holder")
                            },
                        ),
                    ),
                )
            assertTrue(result.isOk)
            val payload = assertNotNull(jwtService.lastArgs?.payload as? JsonObject)
            assertEquals("https://example.com/subjects/one", payload["sub"]?.jsonPrimitive?.content)
            assertEquals(
                "https://example.com/subjects/one",
                payload["vc"]!!.jsonObject["credentialSubject"]!!.jsonObject["id"]?.jsonPrimitive?.content,
            )
        }

    @Test
    fun rejectsMultipleCredentialSubjectsBecauseV11JwtCannotEncodeThem() =
        runTest {
            val jwtService = RecordingJwtService()
            val result = JwtVcJsonFormatHandler((jwtService).asSignatureServiceFixture(), TestKmsMock(), StubIssuerKeyIdResolver)
                .issueCredential(
                    makeRequest("jwt_vc_json"),
                    makeContext(makeConfig("jwt_vc_json"), attributes = emptyMap()).copy(
                        credentialSubjects = listOf(
                            buildJsonObject { put("name", "One") },
                            buildJsonObject { put("name", "Two") },
                        ),
                    ),
                )
            assertTrue(result.isErr)
            assertTrue(result.error.message.defaultMessage.contains("exactly one credentialSubject"))
            assertNull(jwtService.lastArgs)
        }

    @Test
    fun keepsCredentialIdAndSubjectIdIndependentAndMapsOnlySubjectIdToV11Sub() =
        runTest {
            val jwtService = RecordingJwtService()
            val subjectId = "https://example.com/subjects/v11"
            val handler =
                JwtVcJsonFormatHandler(
                    signatureService = (jwtService).asSignatureServiceFixture(),
                    kms = TestKmsMock(),
                    issuerKeyIdResolver = StubIssuerKeyIdResolver,
                )
            val result =
                handler.issueCredential(
                    makeRequest("jwt_vc_json"),
                    makeContext(makeConfig("jwt_vc_json"), attributes = emptyMap()).copy(
                        subject = "urn:proof-holder:v11",
                        credentialId = "https://example.com/credentials/v11",
                        credentialSubjects = listOf(
                            buildJsonObject {
                                put("id", subjectId)
                                put("name", "V11 subject")
                            },
                        ),
                    ),
                )

            assertTrue(result.isOk)
            val payload = assertNotNull(jwtService.lastArgs?.payload as? JsonObject)
            val vc = assertNotNull(payload["vc"]?.jsonObject)
            val credentialId = assertNotNull(vc["id"]?.jsonPrimitive?.content)
            assertEquals(credentialId, payload["jti"]?.jsonPrimitive?.content)
            assertNotEquals(subjectId, credentialId)
            assertEquals(subjectId, vc["credentialSubject"]!!.jsonObject["id"]?.jsonPrimitive?.content)
            assertEquals(subjectId, payload["sub"]?.jsonPrimitive?.content)
            assertNotEquals(payload["iss"]?.jsonPrimitive?.content, subjectId)
            assertNotEquals(payload["iss"]?.jsonPrimitive?.content, "urn:proof-holder:v11")
        }

    // Cryptographic Holder Binding for VCDM 1.1 JWTs: `sub` = credentialSubject.id is the only
    // binding (VCDM 1.1 section 6.3.1 defines no cnf); OID4VCI Appendix A.1.1 binds jwt_vc_json to DIDs.
    private suspend fun issueWithProof(
        holderKeyId: String?,
        credentialSubject: JsonObject = buildJsonObject { put("name", "Holder") },
    ): Pair<IdkResult<*, IdkError>, RecordingJwtService> {
        val jwtService = RecordingJwtService()
        val result = JwtVcJsonFormatHandler((jwtService).asSignatureServiceFixture(), TestKmsMock(), StubIssuerKeyIdResolver)
            .issueCredential(
                makeRequest("jwt_vc_json"),
                makeContext(makeConfig("jwt_vc_json"), attributes = emptyMap()).copy(
                    holderKeyId = holderKeyId,
                    holderBindingKey = buildJsonObject {
                put("kty", "EC")
                put("crv", "P-256")
                put("x", "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
                put("y", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
            },
                    credentialSubjects = listOf(credentialSubject),
                ),
            )
        return result to jwtService
    }

    @Test
    fun didProofBindsTheHolderDidAsSubjectAndEmitsNoCnf() =
        runTest {
            val (result, jwtService) = issueWithProof("did:example:alice#key-1")

            assertTrue(result.isOk, "a DID-bound proof must issue")
            val payload = assertNotNull(jwtService.lastArgs?.payload as? JsonObject)
            assertEquals("did:example:alice", payload["sub"]?.jsonPrimitive?.content)
            assertEquals("did:example:alice", payload["vc"]!!.jsonObject["credentialSubject"]!!.jsonObject["id"]?.jsonPrimitive?.content)
            assertEquals("Holder", payload["vc"]!!.jsonObject["credentialSubject"]!!.jsonObject["name"]?.jsonPrimitive?.content)
            assertNull(payload["cnf"], "VCDM 1.1 JWTs define no cnf")
        }

    @Test
    fun didProofAcceptsASuppliedSubjectIdThatIsTheHolderDid() =
        runTest {
            val (result, jwtService) = issueWithProof(
                "did:example:alice#key-1",
                buildJsonObject { put("id", "did:example:alice"); put("name", "Holder") },
            )

            assertTrue(result.isOk)
            assertEquals("did:example:alice", (jwtService.lastArgs?.payload as? JsonObject)?.get("sub")?.jsonPrimitive?.content)
        }

    @Test
    fun didProofRefusesASuppliedSubjectIdForAnotherSubject() =
        runTest {
            val (result, jwtService) = issueWithProof(
                "did:example:alice#key-1",
                buildJsonObject { put("id", "did:example:bob"); put("name", "Holder") },
            )

            assertTrue(result.isErr)
            assertEquals("invalid_vcdm_credential", result.error.code)
            assertNull(jwtService.lastArgs, "nothing may be signed for an unbindable subject")
        }

    @Test
    fun bareJwkProofIsRefusedBecauseVcdm11CannotBindIt() =
        runTest {
            val (result, jwtService) = issueWithProof(holderKeyId = null)

            assertTrue(result.isErr)
            assertEquals("invalid_proof", result.error.code)
            assertNull(jwtService.lastArgs)
        }

    @Test
    fun rejectsAmbiguousExplicitSubjectsAndAttributes() =
        runTest {
            val jwtService = RecordingJwtService()
            val result =
                JwtVcJsonFormatHandler((jwtService).asSignatureServiceFixture(), TestKmsMock(), StubIssuerKeyIdResolver).issueCredential(
                    makeRequest("jwt_vc_json"),
                    makeContext(makeConfig("jwt_vc_json"), attributes = mapOf("name" to JsonPrimitive("attribute"))).copy(
                        credentialSubjects = listOf(buildJsonObject { put("name", "explicit") }),
                    ),
                )
            assertTrue(result.isErr)
            assertTrue(result.error.message.defaultMessage.contains("cannot both be supplied"))
            assertNull(jwtService.lastArgs)
        }

    @Test
    fun rejectsNonUriCredentialId() =
        runTest {
            val jwtService = RecordingJwtService()
            val result =
                JwtVcJsonFormatHandler((jwtService).asSignatureServiceFixture(), TestKmsMock(), StubIssuerKeyIdResolver).issueCredential(
                    makeRequest("jwt_vc_json"),
                    makeContext(makeConfig("jwt_vc_json")).copy(credentialId = "not a URI"),
                )
            assertTrue(result.isErr)
            assertEquals("invalid_vcdm_identifier", result.error.code)
            assertNull(jwtService.lastArgs)
        }

    /**
     * Fake JwtService that produces deterministic JWT compact output for testing.
     */
    private open class FakeJwtService : JwtService {
        var lastArgs: CreateJwsArgs? = null

        override val commands: JwtService.Commands
            get() = throw UnsupportedOperationException("not used in tests")

        open override suspend fun createJwsCompact(args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError> {
            lastArgs = args
            // Produce a fake but structurally valid JWT (3 dot-separated parts)
            return Ok(JwtCompactResult(jwt = "eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6e319.fakesignature"))
        }

        override suspend fun prepareJws(args: CreateJwsJsonArgs): IdkResult<PreparedJwsObject, IdkError> = throw UnsupportedOperationException("not used in tests")

        override suspend fun createJwsJsonFlattened(args: CreateJwsJsonArgs): IdkResult<JwsJsonFlattened, IdkError> = throw UnsupportedOperationException("not used in tests")

        override suspend fun createJwsJsonGeneral(args: CreateJwsJsonArgs): IdkResult<JwsJsonGeneral, IdkError> = throw UnsupportedOperationException("not used in tests")

        override suspend fun verifyJws(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> = throw UnsupportedOperationException("not used in tests")

        override fun assembleJwsGeneral(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray,
        ) = throw UnsupportedOperationException("not used in tests")

        override fun assembleJwsFlattened(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray,
        ) = throw UnsupportedOperationException("not used in tests")

        override fun assembleJwsCompact(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray,
        ) = throw UnsupportedOperationException("not used in tests")
    }

    private class RecordingJwtService : FakeJwtService()

}
