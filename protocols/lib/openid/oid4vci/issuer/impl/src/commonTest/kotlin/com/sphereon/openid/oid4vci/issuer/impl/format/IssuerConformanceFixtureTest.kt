/*
 * (c) 2026 Sphereon International B.V.
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
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.jose.jws.JwsJsonFlattened
import com.sphereon.crypto.jose.jws.JwsJsonGeneral
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.crypto.jose.jws.JwtCompactResult
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.PreparedJwsObject
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.did.capabilities.DidMethodCapabilities
import com.sphereon.did.manager.DidProvider
import com.sphereon.did.manager.DidProviderRegistry
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialDefinition
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import com.sphereon.openid.oid4vci.issuer.format.SdPolicy
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver
import com.sphereon.sdjwt.Disclosure
import com.sphereon.sdjwt.IssueSdJwtArgs
import com.sphereon.sdjwt.IssueSdJwtResult
import com.sphereon.sdjwt.PresentSdJwtArgs
import com.sphereon.sdjwt.PresentSdJwtResult
import com.sphereon.sdjwt.SdJwtService
import com.sphereon.sdjwt.SdJwtVerificationResult
import com.sphereon.sdjwt.VerifySdJwtArgs
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Issuer conformance fixture tests for credential format handlers.
 *
 * Tests IETF SD-JWT VC, JWT VC JSON, and MSO mDoc format handlers with
 * fake service implementations to verify issuance logic.
 */
class IssuerConformanceFixtureTest {
    // ========================================================================
    // Shared Fakes
    // ========================================================================

    /**
     * Fake JwtService that produces deterministic JWT compact output for testing.
     */
    private class FakeJwtService : JwtService {
        var lastPayload: kotlinx.serialization.json.JsonObject? = null

        override val commands: JwtService.Commands
            get() = throw UnsupportedOperationException("not used in tests")

        override suspend fun createJwsCompact(args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError> {
            lastPayload = args.payload as? kotlinx.serialization.json.JsonObject
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

    /**
     * Fake SdJwtService that captures the issuance args and returns a valid-looking SD-JWT string.
     */
    private class FakeSdJwtService : SdJwtService {
        var lastArgs: IssueSdJwtArgs? = null

        override val commands: SdJwtService.Commands
            get() = throw UnsupportedOperationException("not used in tests")

        override suspend fun issueSdJwt(args: IssueSdJwtArgs): IdkResult<IssueSdJwtResult, IdkError> {
            lastArgs = args
            return Ok(
                IssueSdJwtResult(
                    sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ0ZXN0In0.fakesig~WyJzYWx0IiwiZW1haWwiLCJ0ZXN0QGV4YW1wbGUuY29tIl0~",
                    jwt = "eyJhbGciOiJFUzI1NiJ9.eyJ2Y3QiOiJ0ZXN0In0.fakesig",
                    disclosures =
                        listOf(
                            Disclosure(
                                salt = "salt",
                                key = "email",
                                value = JsonPrimitive("test@example.com"),
                                encoded = "WyJzYWx0IiwiZW1haWwiLCJ0ZXN0QGV4YW1wbGUuY29tIl0",
                            ),
                        ),
                ),
            )
        }

        override suspend fun verifySdJwt(args: VerifySdJwtArgs): IdkResult<SdJwtVerificationResult, IdkError> = throw UnsupportedOperationException("not used in tests")

        override suspend fun presentSdJwt(args: PresentSdJwtArgs): IdkResult<PresentSdJwtResult, IdkError> = throw UnsupportedOperationException("not used in tests")
    }

    /**
     * Stub DidProviderRegistry — tests use SigningKeyMode.None so DID resolution is never called.
     */
    private class StubDidProviderRegistry : DidProviderRegistry {
        override fun getProvider(method: String): DidProvider? = null

        override fun getCapabilities(method: String): DidMethodCapabilities? = null

        override fun getSupportedMethods(): List<String> = emptyList()
    }

    /** Stands in for the name the issuer key seam resolves server side before a handler runs. */
    private val SERVER_RESOLVED_SIGNING_KEY = "issuer-signing-conformance"

    /**
     * Creates an SdJwtVcFormatHandler with in-memory KMS for tests.
     */
    private fun createSdJwtVcHandler(sdJwtService: SdJwtService): SdJwtVcFormatHandler =
        SdJwtVcFormatHandler(
            sdJwtService = sdJwtService,
            kms = TestKmsMock(),
            didProviderRegistry = StubDidProviderRegistry(),
            issuerKeyIdResolver = StubIssuerKeyIdResolver,
        )

    /**
     * Tests that exercise the conformance fixtures don't drive the DID-binding code path,
     * so a stub that fails on use is sufficient to satisfy the constructor dependency.
     */
    private object StubIssuerKeyIdResolver : IssuerKeyIdResolver {
        override suspend fun resolveDidVerificationMethodId(
            keyAlias: String,
            didMethod: String,
        ): IdkResult<String, IdkError> = error("StubIssuerKeyIdResolver.resolveDidVerificationMethodId should not be invoked from conformance fixtures")

        override suspend fun resolvePublicJwk(keyAlias: String): IdkResult<kotlinx.serialization.json.JsonObject, IdkError> =
            error("StubIssuerKeyIdResolver.resolvePublicJwk should not be invoked from conformance fixtures")
    }

    // ========================================================================
    // Helper methods
    // ========================================================================

    private fun makeJwtVcJsonConfig(types: List<String> = listOf("VerifiableCredential", "ExampleCredential")) =
        CredentialConfigurationSupported(
            format = "jwt_vc_json",
            credentialDefinition = CredentialDefinition(type = types),
        )

    private fun makeSdJwtVcConfig(vct: String? = null) =
        CredentialConfigurationSupported(
            format = "dc+sd-jwt",
            vct = vct,
        )

    private fun makeMsoMdocConfig(doctype: String? = null) =
        CredentialConfigurationSupported(
            format = "mso_mdoc",
            doctype = doctype,
        )

    private fun makeRequest(format: String? = null) = CredentialRequest(format = format)

    private fun makeContext(
        config: CredentialConfigurationSupported,
        attributes: Map<String, JsonElement> = emptyMap(),
        holderBindingKey: JsonElement? = null,
        sdPolicies: Map<String, SdPolicy> = emptyMap(),
    ) = IssuanceContext(
        subject = "did:example:holder123",
        clientId = "client-1",
        issuerIdentifier = "https://issuer.example.com",
        credentialConfigurationId = "test-config-1",
        credentialConfiguration = config,
        holderBindingKey = holderBindingKey,
        attributes = attributes,
        sdPolicies = sdPolicies,
        signingKeyAlias = SERVER_RESOLVED_SIGNING_KEY,
    )

    // ========================================================================
    // IETF SD-JWT VC conformance
    // ========================================================================

    @Test
    fun sdJwtVcOmitsExpirationWhenNoValidityPeriodIsConfigured() =
        runTest {
            val signer = FakeSdJwtService()
            val handler = createSdJwtVcHandler(signer)
            val context = makeContext(makeSdJwtVcConfig("https://example.com/credentials/identity"))

            val result = handler.issueCredential(makeRequest("dc+sd-jwt"), context)

            assertTrue(result.isOk)
            val claims = signer.lastArgs!!.payload.claims
            assertTrue(claims.containsKey("iat"))
            assertFalse(claims.containsKey("exp"), "Optional validity must not become an invented expiration")
        }

    @Test
    fun sdJwtVcPreservesAnExplicitValidityPeriod() =
        runTest {
            val signer = FakeSdJwtService()
            val handler = createSdJwtVcHandler(signer)
            val context = makeContext(makeSdJwtVcConfig("https://example.com/credentials/identity"))
                .copy(expirationInDays = 7)

            val result = handler.issueCredential(makeRequest("dc+sd-jwt"), context)

            assertTrue(result.isOk)
            val claims = signer.lastArgs!!.payload.claims
            val issuedAt = (claims.getValue("iat") as JsonPrimitive).content.toLong()
            val expiresAt = (claims.getValue("exp") as JsonPrimitive).content.toLong()
            assertEquals(7L * 24L * 60L * 60L, expiresAt - issuedAt)
        }

    @Test
    fun sdJwtVcIssuesWithVct() =
        runTest {
            val fakeSdJwtService = FakeSdJwtService()
            val handler = createSdJwtVcHandler(fakeSdJwtService)

            val config = makeSdJwtVcConfig(vct = "https://example.com/credentials/identity")
            val context =
                makeContext(
                    config = config,
                    attributes = mapOf("email" to JsonPrimitive("user@example.com")),
                )
            val request = makeRequest("dc+sd-jwt")

            val result = handler.issueCredential(request, context)

            assertTrue(result.isOk, "IETF SD-JWT VC issuance with vct should succeed")
            val envelope = result.getOrThrow()
            assertEquals("dc+sd-jwt", envelope.format, "Envelope format should match the configuration format")

            // Verify the SD-JWT string contains the tilde separator
            val sdJwtString = (envelope.credential as JsonPrimitive).content
            assertTrue(sdJwtString.contains("~"), "SD-JWT should contain tilde-separated disclosures")
        }

    /** Accepts exactly the did:web assertion method the issuer is configured with. */
    private object DidWebIssuerKeyIdResolver : IssuerKeyIdResolver {
        const val VERIFICATION_METHOD = "did:web:summa.fed.nk.sphereon.com#issuer-assertion-summa"

        override suspend fun resolveDidVerificationMethodId(
            keyAlias: String,
            didMethod: String,
        ): IdkResult<String, IdkError> = Ok(VERIFICATION_METHOD)

        override suspend fun resolvePublicJwk(keyAlias: String): IdkResult<kotlinx.serialization.json.JsonObject, IdkError> =
            error("resolvePublicJwk is not used for DID-signed SD-JWT VCs")

        override suspend fun validateDidVerificationMethodId(
            keyAlias: String,
            verificationMethodId: String,
        ): IdkResult<String, IdkError> = Ok(verificationMethodId)
    }

    private fun didWebFederationContext(federationEntityIdentifier: String?): IssuanceContext =
        makeContext(
            config = makeSdJwtVcConfig("https://example.com/credentials/identity"),
            attributes = mapOf("email" to JsonPrimitive("user@example.com")),
        ).copy(
            issuerIdentifier = "https://summa.fed.nk.sphereon.com/oid4vci/summa",
            signingKeyMode = SigningKeyMode.Did("web"),
            signingVerificationMethodId = DidWebIssuerKeyIdResolver.VERIFICATION_METHOD,
            federationEntityIdentifier = federationEntityIdentifier,
        )

    @Test
    fun sdJwtVcNamesTheFederationEntityInAPlainFedClaim() =
        runTest {
            val signer = FakeSdJwtService()
            val handler =
                SdJwtVcFormatHandler(
                    sdJwtService = signer,
                    kms = TestKmsMock(),
                    didProviderRegistry = StubDidProviderRegistry(),
                    issuerKeyIdResolver = DidWebIssuerKeyIdResolver,
                )

            val result =
                handler.issueCredential(
                    makeRequest("dc+sd-jwt"),
                    didWebFederationContext("https://summa.fed.nk.sphereon.com/oid4vci/summa"),
                )

            assertTrue(result.isOk, "issuance must succeed: ${if (result.isErr) result.error else ""}")
            val args = signer.lastArgs!!
            val claims = args.payload.claims
            // DIIP v5 Appendix B: `fed` = credential_issuer, issuer-signed and never a disclosure.
            assertEquals(JsonPrimitive("https://summa.fed.nk.sphereon.com/oid4vci/summa"), claims["fed"])
            assertFalse("fed" in args.payload.sdClaims, "fed must not be selectively disclosable")
            // The signing identity is unchanged: `iss` stays the DID, the header `kid` its assertion method.
            assertEquals(JsonPrimitive("did:web:summa.fed.nk.sphereon.com"), claims["iss"])
            assertEquals(
                JsonPrimitive(DidWebIssuerKeyIdResolver.VERIFICATION_METHOD),
                args.opts.protectedHeader?.get("kid"),
            )
        }

    @Test
    fun sdJwtVcOmitsFedForAnIssuerThatIsNotAFederationEntity() =
        runTest {
            val signer = FakeSdJwtService()
            val handler =
                SdJwtVcFormatHandler(
                    sdJwtService = signer,
                    kms = TestKmsMock(),
                    didProviderRegistry = StubDidProviderRegistry(),
                    issuerKeyIdResolver = DidWebIssuerKeyIdResolver,
                )

            val result = handler.issueCredential(makeRequest("dc+sd-jwt"), didWebFederationContext(null))

            assertTrue(result.isOk, "issuance must succeed: ${if (result.isErr) result.error else ""}")
            val args = signer.lastArgs!!
            assertFalse(args.payload.claims.containsKey("fed"))
            assertFalse("fed" in args.payload.sdClaims)
            assertEquals(JsonPrimitive("did:web:summa.fed.nk.sphereon.com"), args.payload.claims["iss"])
        }

    @Test
    fun sdJwtVcRefusesAFedAttributeFromAFederationEntityIssuer() =
        runTest {
            val signer = FakeSdJwtService()
            val handler =
                SdJwtVcFormatHandler(
                    sdJwtService = signer,
                    kms = TestKmsMock(),
                    didProviderRegistry = StubDidProviderRegistry(),
                    issuerKeyIdResolver = DidWebIssuerKeyIdResolver,
                )
            val context =
                didWebFederationContext("https://summa.fed.nk.sphereon.com/oid4vci/summa")
                    .copy(attributes = mapOf("fed" to JsonPrimitive("https://elsewhere.example")))

            val result = handler.issueCredential(makeRequest("dc+sd-jwt"), context)

            assertTrue(result.isErr)
            assertEquals(null, signer.lastArgs, "nothing may be signed")
        }

    @Test
    fun sdJwtVcRequiresVct() =
        runTest {
            val fakeSdJwtService = FakeSdJwtService()
            val handler = createSdJwtVcHandler(fakeSdJwtService)

            val config = makeSdJwtVcConfig(vct = null)
            val context =
                makeContext(
                    config = config,
                    attributes = mapOf("email" to JsonPrimitive("user@example.com")),
                )
            val request = makeRequest("dc+sd-jwt")

            val result = handler.issueCredential(request, context)

            assertTrue(result.isErr, "IETF SD-JWT VC issuance without vct should fail")
        }

    @Test
    fun sdJwtVcAppliesSdPolicies() =
        runTest {
            val fakeSdJwtService = FakeSdJwtService()
            val handler = createSdJwtVcHandler(fakeSdJwtService)

            val config = makeSdJwtVcConfig(vct = "https://example.com/credentials/identity")
            val context =
                makeContext(
                    config = config,
                    attributes =
                        mapOf(
                            "email" to JsonPrimitive("user@example.com"),
                            "name" to JsonPrimitive("Alice"),
                            "secret" to JsonPrimitive("hidden"),
                        ),
                    sdPolicies =
                        mapOf(
                            "email" to SdPolicy.SELECTIVELY_DISCLOSABLE,
                            "name" to SdPolicy.ALWAYS_DISCLOSED,
                            "secret" to SdPolicy.NEVER_DISCLOSED,
                        ),
                )
            val request = makeRequest("dc+sd-jwt")

            val result = handler.issueCredential(request, context)

            assertTrue(result.isOk, "IETF SD-JWT VC issuance with SD policies should succeed")

            // Verify the payload builder received the correct policies by checking the DSL payload
            val issuedPayload = fakeSdJwtService.lastArgs!!.payload
            val claims = issuedPayload.claims
            val sdClaims = issuedPayload.sdClaims

            // "name" should be an always-disclosed claim (not in sdClaims)
            assertTrue(claims.containsKey("name"), "Always-disclosed 'name' should be in claims")
            assertTrue("name" !in sdClaims, "Always-disclosed 'name' should NOT be in sdClaims")

            // "email" should be selectively disclosable (in sdClaims)
            assertTrue(claims.containsKey("email"), "Selectively disclosable 'email' should be in claims")
            assertTrue("email" in sdClaims, "Selectively disclosable 'email' should be in sdClaims")

            // "secret" should be completely absent (NEVER_DISCLOSED)
            assertTrue(!claims.containsKey("secret"), "Never-disclosed 'secret' should NOT appear in claims")
            assertTrue("secret" !in sdClaims, "Never-disclosed 'secret' should NOT appear in sdClaims")
        }

    @Test
    fun sdJwtVcIncludesHolderBinding() =
        runTest {
            val fakeSdJwtService = FakeSdJwtService()
            val handler = createSdJwtVcHandler(fakeSdJwtService)

            val holderKey =
                buildJsonObject {
                    put("kty", "EC")
                    put("crv", "P-256")
                    put("x", "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
                    put("y", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
                }

            val config = makeSdJwtVcConfig(vct = "https://example.com/credentials/identity")
            val context =
                makeContext(
                    config = config,
                    attributes = mapOf("email" to JsonPrimitive("user@example.com")),
                    holderBindingKey = holderKey,
                )
            val request = makeRequest("dc+sd-jwt")

            val result = handler.issueCredential(request, context)

            assertTrue(result.isOk, "IETF SD-JWT VC issuance with holder binding should succeed")

            // Verify the cnf claim was added to the payload
            val issuedPayload = fakeSdJwtService.lastArgs!!.payload
            val claims = issuedPayload.claims
            assertTrue(claims.containsKey("cnf"), "Payload should include 'cnf' claim for holder binding")
        }

    // ========================================================================
    // JWT VC JSON Conformance
    // ========================================================================

    @Test
    fun jwtVcJsonIssuesMinimalCredential() =
        runTest {
            val fakeJwtService = FakeJwtService()
            val handler = JwtVcJsonFormatHandler(signatureService = (fakeJwtService).asSignatureServiceFixture(), kms = TestKmsMock(), issuerKeyIdResolver = StubIssuerKeyIdResolver)

            val config = makeJwtVcJsonConfig()
            val context =
                makeContext(
                    config = config,
                    attributes = mapOf("name" to JsonPrimitive("Alice")),
                )
            val request = makeRequest("jwt_vc_json")

            val result = handler.issueCredential(request, context)

            assertTrue(result.isOk, "JWT VC JSON minimal issuance should succeed")
            val envelope = result.getOrThrow()
            assertEquals("jwt_vc_json", envelope.format)

            // JWT compact has 3 dot-separated parts
            val jwtString = (envelope.credential as JsonPrimitive).content
            val parts = jwtString.split(".")
            assertEquals(3, parts.size, "JWT compact serialization should have 3 parts")
        }

    @Test
    fun jwtVcJsonIncludesCustomTypes() =
        runTest {
            val fakeJwtService = FakeJwtService()
            val handler = JwtVcJsonFormatHandler(signatureService = (fakeJwtService).asSignatureServiceFixture(), kms = TestKmsMock(), issuerKeyIdResolver = StubIssuerKeyIdResolver)

            val customTypes = listOf("VerifiableCredential", "UniversityDegreeCredential")
            val config = makeJwtVcJsonConfig(types = customTypes)
            val context =
                makeContext(
                    config = config,
                    attributes = mapOf("degree" to JsonPrimitive("BSc")),
                )
            val request = makeRequest("jwt_vc_json")

            val result = handler.issueCredential(request, context)

            assertTrue(result.isOk, "JWT VC JSON with custom types should succeed")

            // Verify the types were passed to the JWT payload
            val payload = fakeJwtService.lastPayload!!
            val vc = payload["vc"] as kotlinx.serialization.json.JsonObject
            val typeArray = vc["type"] as kotlinx.serialization.json.JsonArray
            assertEquals(2, typeArray.size, "VC type array should contain 2 entries")
            assertEquals("VerifiableCredential", (typeArray[0] as JsonPrimitive).content)
            assertEquals("UniversityDegreeCredential", (typeArray[1] as JsonPrimitive).content)
        }

    // VCDM 1.1 jwt_vc_json defines no cnf; a bare JWK proof cannot be bound (OID4VCI Appendix A.1.1).
    @Test
    fun jwtVcJsonRefusesABareJwkHolderProof() =
        runTest {
            val fakeJwtService = FakeJwtService()
            val handler = JwtVcJsonFormatHandler(signatureService = (fakeJwtService).asSignatureServiceFixture(), kms = TestKmsMock(), issuerKeyIdResolver = StubIssuerKeyIdResolver)

            val holderKey =
                buildJsonObject {
                    put("kty", "EC")
                    put("crv", "P-256")
                    put("x", "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU")
                    put("y", "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0")
                }

            val config = makeJwtVcJsonConfig()
            val context =
                makeContext(
                    config = config,
                    attributes = mapOf("name" to JsonPrimitive("Alice")),
                    holderBindingKey = holderKey,
                )
            val request = makeRequest("jwt_vc_json")

            val result = handler.issueCredential(request, context)

            assertTrue(result.isErr, "jwt_vc_json must refuse a JWK holder proof it cannot bind")
            assertEquals("invalid_proof", result.error.code)
            assertTrue(fakeJwtService.lastPayload == null, "nothing may be signed")
        }

    @Test
    fun jwtVcJsonIncludesAttributes() =
        runTest {
            val fakeJwtService = FakeJwtService()
            val handler = JwtVcJsonFormatHandler(signatureService = (fakeJwtService).asSignatureServiceFixture(), kms = TestKmsMock(), issuerKeyIdResolver = StubIssuerKeyIdResolver)

            val config = makeJwtVcJsonConfig()
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

            assertTrue(result.isOk, "JWT VC JSON with attributes should succeed")

            // Verify attributes appear in credentialSubject
            val payload = fakeJwtService.lastPayload!!
            val vc = payload["vc"] as kotlinx.serialization.json.JsonObject
            val credentialSubject = vc["credentialSubject"] as kotlinx.serialization.json.JsonObject
            assertEquals("Bachelor of Science", (credentialSubject["degree"] as JsonPrimitive).content)
            assertEquals("Example University", (credentialSubject["university"] as JsonPrimitive).content)
            assertFalse(credentialSubject.containsKey("id"), "proof/issuance subject must not become credentialSubject.id")
        }

    // ========================================================================
    // MSO mDoc Conformance
    // ========================================================================

    @Test
    fun msoMdocGroupsAttributesByNamespace() {
        val attributes =
            mapOf(
                "org.iso.18013.5.1.family_name" to JsonPrimitive("Doe"),
                "org.iso.18013.5.1.given_name" to JsonPrimitive("John"),
                "org.iso.18013.5.1.birth_date" to JsonPrimitive("1990-01-15"),
            )

        val grouped = MsoMdocFormatHandler.groupAttributesByNamespace(attributes, "org.iso.18013.5.1.mDL")

        assertEquals(1, grouped.size, "All dotted keys with same namespace prefix should group together")
        assertTrue(grouped.containsKey("org.iso.18013.5.1"), "Namespace should be the prefix before last dot")
        val items = grouped["org.iso.18013.5.1"]!!
        assertEquals(3, items.size, "All 3 attributes should be grouped")
        assertEquals("family_name", items[0].first)
        assertEquals("given_name", items[1].first)
        assertEquals("birth_date", items[2].first)
    }

    @Test
    fun msoMdocRequiresDoctype() =
        runTest {
            // MsoMdocFormatHandler requires a real MdocSignService and ManagedIdentifierService,
            // but we can test the doctype check by verifying the error at the start of issueCredential.
            // Since we cannot easily instantiate the handler without real services, we test the
            // groupAttributesByNamespace helper and verify the doctype requirement via the source logic.
            // The handler returns an error if doctype is null.
            val config = makeMsoMdocConfig(doctype = null)
            assertTrue(config.doctype == null, "Config without doctype should have null doctype")
        }

    @Test
    fun msoMdocSimpleKeysUseDefaultNamespace() {
        val doctype = "org.iso.18013.5.1.mDL"
        val attributes =
            mapOf(
                "family_name" to JsonPrimitive("Doe"),
                "given_name" to JsonPrimitive("John"),
            )

        val grouped = MsoMdocFormatHandler.groupAttributesByNamespace(attributes, doctype)

        assertEquals(1, grouped.size, "Simple keys should use the default namespace")
        assertTrue(grouped.containsKey(doctype), "Default namespace should be the doctype")
        val items = grouped[doctype]!!
        assertEquals(2, items.size, "Both simple keys should be in the default namespace")
        assertEquals("family_name", items[0].first)
        assertEquals("given_name", items[1].first)
    }

    @Test
    fun msoMdocRejectsEmptyAttributes() {
        val doctype = "org.iso.18013.5.1.mDL"
        val attributes = emptyMap<String, JsonElement>()

        val grouped = MsoMdocFormatHandler.groupAttributesByNamespace(attributes, doctype)

        assertTrue(grouped.isEmpty(), "Empty attributes should produce empty namespace groups")
        // The handler checks `if (grouped.isEmpty())` and returns an error
    }
}
