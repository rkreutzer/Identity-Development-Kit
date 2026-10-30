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
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.compat.DateTimeUtils
import com.sphereon.core.compat.LocalDateTimeKMP
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.cbor.CborUInt
import com.sphereon.crypto.core.cose.CoseKey
import com.sphereon.crypto.core.cose.CoseKeyType
import com.sphereon.crypto.core.cose.CoseSign1
import com.sphereon.crypto.core.generic.VerifyResults
import com.sphereon.crypto.core.generic.VerifyResultsType
import com.sphereon.crypto.core.generic.VerifySignatureResult
import com.sphereon.crypto.core.generic.VerifySignatureResultType
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.crypto.jose.jws.JwsUtils
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.crypto.resolution.extern.ExternalIdentifierX5cOpts
import com.sphereon.mdoc.data.DeviceAuthValidation
import com.sphereon.mdoc.data.MdocVerification
import com.sphereon.mdoc.data.MdocValidations
import com.sphereon.mdoc.data.MdocVerificationTypes
import com.sphereon.mdoc.data.device.DeviceResponse
import com.sphereon.mdoc.data.device.DeviceResponseCborCodec
import com.sphereon.mdoc.data.device.Document
import com.sphereon.mdoc.data.device.DocType
import com.sphereon.mdoc.data.device.DocumentResponseEncryptionProvider
import com.sphereon.mdoc.data.device.EncryptedDocuments
import com.sphereon.mdoc.data.device.EncryptedDocumentsPlaintext
import com.sphereon.mdoc.data.device.EncryptionParameters
import com.sphereon.mdoc.data.device.ZkDocument
import com.sphereon.mdoc.data.device.ZkDocumentData
import com.sphereon.mdoc.data.device.ZkProofProvider
import com.sphereon.mdoc.data.device.ZkRequest
import com.sphereon.mdoc.data.device.ZkSystemSpec
import com.sphereon.mdoc.data.mso.MobileSecurityObject
import com.sphereon.mdoc.DecodedMdoc
import com.sphereon.mdoc.transfer.reader.SessionTranscript
import com.sphereon.mdoc.transfer.reader.OID4VPDCAPIHandover
import com.sphereon.openid.oid4vp.verifier.VerifyHolderBindingArgs
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vc.common.PresentationFormat
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import com.sphereon.openid.oid4vp.verifier.impl.testutil.Oid4vpVerifierTestContext
import com.sphereon.sdjwt.SdJwtCodec
import com.sphereon.sdjwt.SdJwtVerificationResult
import com.sphereon.sdjwt.VerifySdJwtArgs
import com.sphereon.sdjwt.command.VerifySdJwtCommand
import com.sphereon.crypto.resolution.extern.ExternalIdentifierDidOpts
import com.sphereon.did.capabilities.DidMethodCapabilities
import com.sphereon.did.models.DidDocument
import com.sphereon.did.models.VerificationMethod
import com.sphereon.did.models.VerificationMethodOrReference
import com.sphereon.did.resolver.DidDereferenceOptions
import com.sphereon.did.resolver.DidDereferenceResult
import com.sphereon.did.resolver.DidResolutionMetadata
import com.sphereon.did.resolver.DidResolutionOptions
import com.sphereon.did.resolver.DidResolutionResult
import com.sphereon.did.resolver.DidResolver
import com.sphereon.did.resolver.DidResolverRegistry
import dev.zacsweers.metro.Provider
import kotlinx.coroutines.test.runTest
import kotlin.time.Clock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Unit tests for VerifyHolderBindingCommandImpl
 *
 * These tests verify the holder binding verification logic using mock dependencies.
 * For full integration tests with real crypto verification, see the integration test suite.
 */
class VerifyHolderBindingCommandImplTest {
    private val testContext = Oid4vpVerifierTestContext("verify-holder-binding-test", this)

    private val command = createTestCommand(verificationShouldSucceed = true)
    private val failingCommand = createTestCommand(verificationShouldSucceed = false)

    private companion object {
        const val MDL_DOC_TYPE = "org.iso.18013.5.1.mDL"
        const val WRONG_DOC_TYPE = "org.iso.18013.5.1.wrong"
        const val ISSUER_DID = "did:example:issuer"
        const val FEDERATION_DID = "did:example:summa"
        const val FEDERATION_KID = "did:example:summa#issuer-assertion-summa"
        const val FEDERATION_ENTITY = "https://summa.fed.example/oid4vci/summa"
    }

    @Test
    fun `mdoc holder binding excludes certificate trust but retains crypto and content checks`() {
        assertFalse(MdocVerification.CERTIFICATE_CHAIN in OID4VP_MDOC_HOLDER_BINDING_VALIDATIONS)
        assertEquals(
            setOf(
                MdocVerification.ISSUER_AUTH_SIGNATURE,
                MdocVerification.DIGEST_VALUES,
                MdocVerification.DOC_TYPE,
                MdocVerification.VALIDITY,
            ),
            OID4VP_MDOC_HOLDER_BINDING_VALIDATIONS,
        )
    }

    // ============================================================================
    // SD-JWT (KB-JWT) Tests
    // Note: These tests use mock dependencies. The mock SD-JWT command returns
    // an error, which causes the command to return verified=false with error details.
    // Full integration tests with real SD-JWT verification are in the integration test suite.
    // ============================================================================

    @Test
    fun `test SD-JWT holder binding returns correct binding method`() =
        runTest {
            // Given: SD-JWT with KB-JWT (issuer~disclosure1~disclosure2~kb-jwt)
            val sdJwt = "eyJhbGciOiJFUzI1NiJ9.payload.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~WyJkZWY0NTYiLCJsYXN0X25hbWUiLCJEb2UiXQ~eyJhbGciOiJFUzI1NiJ9.kb.signature"

            val args =
                VerifyHolderBindingArgs(
                    presentation = sdJwt,
                    credentialFormat = CredentialFormat.SD_JWT_VC,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                )

            // When: Verifying holder binding
            val result = command.execute(args)

            // Then: Should return result with kb-jwt binding method
            assertIs<Ok<*>>(result)
            val binding = result.value

            assertEquals("kb-jwt", binding.bindingMethod)
            // Mock returns error, so verified should be false
            assertFalse(binding.verified)
        }

    @Test
    fun `test SD-JWT binding errors are captured`() =
        runTest {
            // Given: SD-JWT presentation (mock will return error)
            val sdJwtWithoutKb = "eyJhbGciOiJFUzI1NiJ9.payload.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~"

            val args =
                VerifyHolderBindingArgs(
                    presentation = sdJwtWithoutKb,
                    credentialFormat = CredentialFormat.SD_JWT_VC,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                )

            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val binding = result.value

            // Should have errors from mock verification
            assertFalse(binding.verified)
            assertEquals("kb-jwt", binding.bindingMethod)
            assertTrue(binding.errors.isNotEmpty())
        }

    @Test
    fun `test W3C VC secured with SD-JWT dispatches to SD-JWT holder binding`() =
        runTest {
            val sdJwt = "eyJhbGciOiJFUzI1NiJ9.payload.signature~disc1~eyJhbGciOiJFUzI1NiJ9.kb.sig"

            val args =
                VerifyHolderBindingArgs(
                    presentation = sdJwt,
                    credentialFormat = CredentialFormat.W3C_VC_SD_JWT,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                )

            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            assertEquals("kb-jwt", result.value.bindingMethod)
        }

    @Test
    fun `SD-JWT issuer JWT never treats embedded jwk as an issuer trust anchor`() =
        runTest {
            val attackerHeader =
                """{"alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"attacker","y":"attacker"}}"""
                    .encodeToByteArray()
                    .encodeToBase64Url()
            val sdJwt =
                "$attackerHeader.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3N1ZXIifQ.signature~"

            val result =
                command.execute(
                    VerifyHolderBindingArgs(
                        presentation = sdJwt,
                        credentialFormat = CredentialFormat.SD_JWT_VC,
                        expectedNonce = "nonce123",
                        expectedAudience = "https://verifier.example.com",
                    ),
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.verified)
            assertTrue(result.value.errors.any { it.contains("embedded jwk", ignoreCase = true) })
        }

    @Test
    fun `SD-JWT without KB is accepted only when Credential Query disables holder binding`() =
        runTest {
            val sdJwtWithoutKb =
                "eyJhbGciOiJFUzI1NiJ9." +
                    "eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIn0.signature~"
            val parsed = SdJwtCodec.parse(sdJwtWithoutKb).getOrElse { error(it.message.defaultMessage) }
            val verifier =
                createTestCommand(
                    FixedVerifySdJwtCommand(
                        SdJwtVerificationResult(
                            sdJwt = parsed,
                            signatureValid = true,
                            disclosuresValid = true,
                            keyBindingValid = true,
                        ),
                    ),
                )
            // Issuer authenticity is an independent verifier admission decision.  The
            // optional-KB assertion must therefore use an admitted external issuer source;
            // disabling holder binding must not turn an untrusted issuer into a valid VC.
            val issuerAuthentication =
                TrustedAuthenticationResolution(
                    controller = "https://issuer.example",
                    trustedJwks = testTrustedJwks(),
                    purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                )

            val optionalResult =
                verifier.execute(
                    VerifyHolderBindingArgs(
                        presentation = sdJwtWithoutKb,
                    credentialFormat = CredentialFormat.SD_JWT_VC,
                        expectedNonce = "nonce123",
                        expectedAudience = "https://verifier.example.com",
                        requireCryptographicHolderBinding = false,
                        trustedAuthentications = listOf(issuerAuthentication),
                    ),
                )
            val requiredResult =
                verifier.execute(
                    VerifyHolderBindingArgs(
                        presentation = sdJwtWithoutKb,
                    credentialFormat = CredentialFormat.SD_JWT_VC,
                        expectedNonce = "nonce123",
                        expectedAudience = "https://verifier.example.com",
                        trustedAuthentications = listOf(issuerAuthentication),
                    ),
                )

            assertIs<Ok<*>>(optionalResult)
            assertTrue(optionalResult.value.verified)
            assertEquals(null, optionalResult.value.bindingMethod)
            assertTrue(optionalResult.value.nonceValid)
            assertTrue(optionalResult.value.audienceValid)

            assertIs<Ok<*>>(requiredResult)
            assertFalse(requiredResult.value.verified)
            assertTrue(requiredResult.value.errors.any { it.contains("no Key Binding JWT") })

            val verifierOnlySource = verifier.execute(
                VerifyHolderBindingArgs(
                    presentation = sdJwtWithoutKb,
                    credentialFormat = CredentialFormat.SD_JWT_VC,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                    requireCryptographicHolderBinding = false,
                    trustedAuthentications = listOf(
                        issuerAuthentication.copy(purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.HOLDER),
                    ),
                ),
            )
            assertIs<Ok<*>>(verifierOnlySource)
            assertFalse(verifierOnlySource.value.verified)
            assertTrue(verifierOnlySource.value.errors.any { it.contains("exact configured authentication source") })
        }

    // ============================================================================
    // mDoc (DeviceAuth) Tests
    // ============================================================================

    @Test
    fun mdocDcApiJwtUsesRawOriginAndEncryptionKeyInHandover() = runTest {
        val thumbprint = ByteArray(32) { it.toByte() }
        var transcript: SessionTranscript? = null
        val captureDeviceAuth = object : DeviceAuthValidation by AlwaysPassDeviceAuthValidation {
            override suspend fun verifyDeviceAuth(
                document: Document,
                expectedSessionTranscript: SessionTranscript,
            ): VerifySignatureResultType<CoseKeyType> {
                transcript = expectedSessionTranscript
                return AlwaysPassDeviceAuthValidation.verifyDeviceAuth(document, expectedSessionTranscript)
            }
        }
        val command = commandForMdocResponse(
            DeviceResponse(documents = arrayOf(testDocument(MDL_DOC_TYPE)), original = null),
            deviceAuthValidation = captureDeviceAuth,
        )
        val args = mdocArgs().copy(
            expectedAudience = "origin:https://verifier.example.com",
            clientId = "origin:https://verifier.example.com",
            responseUri = null,
            responseMode = "dc_api.jwt",
            callerOrigin = "https://verifier.example.com",
            verifierEncryptionJwkThumbprint = thumbprint,
        )

        val result = command.execute(args)

        assertIs<Ok<*>>(result)
        assertTrue(result.value.verified)
        val handover = assertIs<OID4VPDCAPIHandover>(transcript?.handover)
        assertEquals("https://verifier.example.com", handover.origin)
        assertEquals("nonce456", handover.nonce)
        assertTrue(handover.jwkThumbprint?.contentEquals(thumbprint) == true)
    }

    @Test
    fun mdocDcApiJwtFailsClosedWithoutOriginOrEncryptionKey() = runTest {
        val command = commandForMdocResponse(DeviceResponse(documents = arrayOf(testDocument(MDL_DOC_TYPE)), original = null))
        val args = mdocArgs().copy(
            expectedAudience = "origin:https://verifier.example.com",
            clientId = "origin:https://verifier.example.com",
            responseUri = null,
            responseMode = "dc_api.jwt",
            callerOrigin = "https://verifier.example.com",
            verifierEncryptionJwkThumbprint = ByteArray(32),
        )

        val missingOrigin = command.execute(args.copy(callerOrigin = null))
        val missingKey = command.execute(args.copy(verifierEncryptionJwkThumbprint = null))

        assertIs<Ok<*>>(missingOrigin)
        assertFalse(missingOrigin.value.verified)
        assertTrue(missingOrigin.value.errors.any { it.contains("validated browser origin") })
        assertIs<Ok<*>>(missingKey)
        assertFalse(missingKey.value.verified)
        assertTrue(missingKey.value.errors.any { it.contains("JWK thumbprint") })
    }

    @Test
    fun `mDoc holder binding rejects bogus presentation when OID4VP context is supplied`() =
        runTest {
            // Bogus base64 — won't decode as a real DeviceResponse. The placeholder used to return
            // verified=true unconditionally; with real verification wired in, the stub
            // DeviceResponseCborCodec rejects this payload and the binding is invalid.
            val mdocPresentation = "o2d2ZXJzaW9uYzEuMGlkb2N1bWVudHOBo2dkb2NUeXBleBhvcmcuaXNvLjE4MDEzLjUuMS5tRExqaXNzdWVyU2lnbmVk"

            val args =
                VerifyHolderBindingArgs(
                    presentation = mdocPresentation,
                    credentialFormat = CredentialFormat.MSO_MDOC,
                    expectedNonce = "nonce456",
                    expectedAudience = "https://verifier.example.com",
                    clientId = "x509_san_dns:verifier.example.com",
                    responseUri = "https://verifier.example.com/oid4vp/auth/response",
                )

            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val binding = result.value

            assertEquals("mdoc-device-auth", binding.bindingMethod)
            assertFalse(binding.verified, "Bogus mdoc presentation must NOT verify")
            assertTrue(binding.errors.isNotEmpty(), "Errors should be reported for an invalid mdoc")
        }

    @Test
    fun `mDoc holder binding fails closed when the persisted query has no document type`() =
        runTest {
            val command = commandForMdocResponse(DeviceResponse(documents = arrayOf(testDocument(MDL_DOC_TYPE)), original = null))

            val result = command.execute(mdocArgs(expectedDocumentType = null))

            assertIs<Ok<*>>(result)
            assertFalse(result.value.verified)
            assertTrue(
                result.value.errors.any {
                    it == "mDoc document type validation requires the verifier's persisted DCQL meta.doctype_value."
                },
                "Missing persisted document type must be identified: ${result.value.errors}",
            )
        }

    @Test
    fun `mDoc holder binding rejects a clear Document with the wrong document type`() =
        runTest {
            val command = commandForMdocResponse(DeviceResponse(documents = arrayOf(testDocument(WRONG_DOC_TYPE)), original = null))

            val result = command.execute(mdocArgs())

            assertIs<Ok<*>>(result)
            assertFalse(result.value.verified)
            assertTrue(
                result.value.errors.any { it == "mDoc document type mismatch: expected '$MDL_DOC_TYPE', got '$WRONG_DOC_TYPE'" },
                "Clear Document mismatch must be identified: ${result.value.errors}",
            )
        }

    @Test
    fun `mDoc holder binding requires every clear Document to match the persisted document type`() =
        runTest {
            val allMatching =
                commandForMdocResponse(
                    DeviceResponse(
                        documents = arrayOf(testDocument(MDL_DOC_TYPE), testDocument(MDL_DOC_TYPE)),
                        original = null,
                    ),
                ).execute(mdocArgs())
            val oneMismatch =
                commandForMdocResponse(
                    DeviceResponse(
                        documents = arrayOf(testDocument(MDL_DOC_TYPE), testDocument(WRONG_DOC_TYPE)),
                        original = null,
                    ),
                ).execute(mdocArgs())

            assertIs<Ok<*>>(allMatching)
            assertTrue(allMatching.value.verified, "Every matching clear Document must remain accepted")
            assertIs<Ok<*>>(oneMismatch)
            assertFalse(oneMismatch.value.verified)
            assertTrue(
                oneMismatch.value.errors.any { it == "mDoc document type mismatch: expected '$MDL_DOC_TYPE', got '$WRONG_DOC_TYPE'" },
                "One mismatching Document must reject the whole response: ${oneMismatch.value.errors}",
            )
        }

    @Test
    fun `mDoc holder binding rejects an encrypted plaintext clear Document with the wrong document type`() =
        runTest {
            val encryption = testEncryptionContext(EncryptedDocumentsPlaintext(documents = listOf(testDocument(WRONG_DOC_TYPE))))
            val response =
                DeviceResponse(
                    documents = null,
                    encryptedDocuments = arrayOf(encryption.envelope),
                    original = null,
                )

            val result = commandForMdocResponse(response).execute(mdocArgs(encryption))

            assertIs<Ok<*>>(result)
            assertFalse(result.value.verified)
            assertTrue(
                result.value.errors.any { it == "mDoc document type mismatch: expected '$MDL_DOC_TYPE', got '$WRONG_DOC_TYPE'" },
                "Decrypted clear Document mismatch must be identified: ${result.value.errors}",
            )
        }

    @Test
    fun `mDoc holder binding rejects mixed clear and encrypted representations when one document type mismatches`() =
        runTest {
            val encryption = testEncryptionContext(EncryptedDocumentsPlaintext(documents = listOf(testDocument(WRONG_DOC_TYPE))))
            val response =
                DeviceResponse(
                    documents = arrayOf(testDocument(MDL_DOC_TYPE)),
                    encryptedDocuments = arrayOf(encryption.envelope),
                    original = null,
                )

            val result = commandForMdocResponse(response).execute(mdocArgs(encryption))

            assertIs<Ok<*>>(result)
            assertFalse(result.value.verified)
            assertTrue(
                result.value.errors.any { it == "mDoc document type mismatch: expected '$MDL_DOC_TYPE', got '$WRONG_DOC_TYPE'" },
                "A decrypted mismatch must reject an otherwise matching clear representation: ${result.value.errors}",
            )
        }

    @Test
    fun `mDoc holder binding routes requested ZKP documents to the configured provider`() =
        runTest {
            val systemId = "example-zk-system"
            val request =
                ZkRequest(
                    systemSpecs = listOf(ZkSystemSpec(zkSystemId = systemId, system = "example")),
                    zkRequired = true,
                )
            val zkDocument =
                ZkDocument(
                    documentData =
                        ZkDocumentData(
                            docType = DocType("org.iso.18013.5.1.mDL"),
                            zkSystemId = systemId,
                            timestamp = "2026-01-01",
                        ),
                    proof = byteArrayOf(0x01),
                )
            val response = DeviceResponse(documents = null, original = null, zkDocuments = arrayOf(zkDocument))
            val provider =
                object : ZkProofProvider {
                    override val supportedSystemIds: Set<String> = setOf(systemId)

                    override suspend fun createProof(
                        request: ZkRequest,
                        documentData: ZkDocumentData,
                        sessionTranscript: SessionTranscript?,
                    ): IdkResult<ByteArray, IdkError> = Ok(byteArrayOf(0x02))

                    override suspend fun verifyProof(
                        request: ZkRequest,
                        document: ZkDocument,
                        sessionTranscript: SessionTranscript?,
                    ): IdkResult<Boolean, IdkError> = Ok(document.proof.contentEquals(byteArrayOf(0x01)))
                }
            val command =
                createTestCommand(
                    verifySdJwtCommand = MockVerifySdJwtCommand(true),
                    verificationShouldSucceed = true,
                    deviceResponseCborCodec =
                        object : DeviceResponseCborCodec {
                            override fun encode(value: DeviceResponse): IdkResult<ByteArray, IdkError> = Ok(byteArrayOf(0x01))

                            override fun decode(bytes: ByteArray): IdkResult<DecodedMdoc<DeviceResponse>, IdkError> =
                                Ok(DecodedMdoc(response, bytes))
                        },
                )

            val result =
                command.execute(
                    VerifyHolderBindingArgs(
                        presentation = byteArrayOf(0x01).encodeToBase64Url(),
                        credentialFormat = CredentialFormat.MSO_MDOC,
                        expectedNonce = "nonce456",
                        expectedAudience = "https://verifier.example.com",
                        clientId = "x509_san_dns:verifier.example.com",
                        responseUri = "https://verifier.example.com/response",
                        expectedMdocDocumentType = "org.iso.18013.5.1.mDL",
                        mdocZkRequests = listOf(request),
                        mdocZkProofProviders = listOf(provider),
                    ),
                )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.verified, "A requested proof accepted by the configured provider must verify")
            assertTrue(result.value.signatureValid)
            assertTrue(result.value.nonceValid)
            assertTrue(result.value.audienceValid)
        }

    @Test
    fun `mDoc holder binding decrypts an encrypted response with verifier session context`() =
        runTest {
            val systemId = "encrypted-zk-system"
            val request =
                ZkRequest(
                    systemSpecs = listOf(ZkSystemSpec(zkSystemId = systemId, system = "example")),
                    zkRequired = true,
                )
            val zkDocument =
                ZkDocument(
                    documentData =
                        ZkDocumentData(
                            docType = DocType("org.iso.18013.5.1.mDL"),
                            zkSystemId = systemId,
                            timestamp = "2026-01-01",
                        ),
                    proof = byteArrayOf(0x01),
                )
            val response =
                DeviceResponse(
                    documents = null,
                    zkDocuments = null,
                    encryptedDocuments = arrayOf(EncryptedDocuments(enc = byteArrayOf(1), cipherText = byteArrayOf(2), docRequestID = 0u)),
                    original = null,
                )
            val key = CoseKey(kty = CborUInt(2))
            val parameters = EncryptionParameters(recipientPublicKey = key)
            val provider =
                object : DocumentResponseEncryptionProvider {
                    override fun supports(parameters: EncryptionParameters): Boolean = true

                    override suspend fun encrypt(
                        plaintext: EncryptedDocumentsPlaintext,
                        parameters: EncryptionParameters,
                        sessionTranscript: SessionTranscript,
                        docRequestID: UInt,
                    ): IdkResult<EncryptedDocuments, IdkError> = Err(IdkError.UNKNOWN_ERROR(message = "not used"))

                    override suspend fun decrypt(
                        encrypted: EncryptedDocuments,
                        recipientPrivateKey: CoseKey,
                        sessionTranscript: SessionTranscript,
                        parameters: EncryptionParameters,
                    ): IdkResult<EncryptedDocumentsPlaintext, IdkError> =
                        Ok(EncryptedDocumentsPlaintext(zkDocuments = listOf(zkDocument)))
                }
            val command =
                createTestCommand(
                    verifySdJwtCommand = MockVerifySdJwtCommand(true),
                    verificationShouldSucceed = true,
                    deviceResponseCborCodec =
                        object : DeviceResponseCborCodec {
                            override fun encode(value: DeviceResponse): IdkResult<ByteArray, IdkError> = Ok(byteArrayOf(0x01))

                            override fun decode(bytes: ByteArray): IdkResult<DecodedMdoc<DeviceResponse>, IdkError> =
                                Ok(DecodedMdoc(response, bytes))
                        },
                )

            val args =
                VerifyHolderBindingArgs(
                    presentation = byteArrayOf(0x01).encodeToBase64Url(),
                    credentialFormat = CredentialFormat.MSO_MDOC,
                    expectedNonce = "nonce456",
                    expectedAudience = "https://verifier.example.com",
                    clientId = "x509_san_dns:verifier.example.com",
                    responseUri = "https://verifier.example.com/response",
                    expectedMdocDocumentType = "org.iso.18013.5.1.mDL",
                    mdocZkRequests = listOf(request),
                    mdocZkProofProviders =
                        listOf(
                            object : ZkProofProvider {
                                override val supportedSystemIds: Set<String> = setOf(systemId)

                                override suspend fun createProof(
                                    request: ZkRequest,
                                    documentData: ZkDocumentData,
                                    sessionTranscript: SessionTranscript?,
                                ): IdkResult<ByteArray, IdkError> = Ok(byteArrayOf(0x02))

                                override suspend fun verifyProof(
                                    request: ZkRequest,
                                    document: ZkDocument,
                                    sessionTranscript: SessionTranscript?,
                                ): IdkResult<Boolean, IdkError> = Ok(document.proof.contentEquals(byteArrayOf(0x01)))
                            },
                        ),
                    mdocDocumentResponseDecryptionKey = key,
                    mdocDocumentResponseEncryptionParameters = mapOf(0u to parameters),
                    mdocDocumentResponseEncryptionProviders = listOf(provider),
                )
            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            assertTrue(result.value.verified)
            assertTrue(result.value.signatureValid)

            val mismatched = command.execute(args.copy(expectedMdocDocumentType = "org.iso.18013.5.1.wrong"))
            assertIs<Ok<*>>(mismatched)
            assertFalse(mismatched.value.verified)
            assertTrue(
                mismatched.value.errors.any {
                    it == "mDoc document type mismatch: expected 'org.iso.18013.5.1.wrong', got 'org.iso.18013.5.1.mDL'"
                },
            )
        }

    @Test
    fun `mDoc holder binding fails fast when OID4VP context is missing`() =
        runTest {
            // Without clientId / responseUri / mdoc_generated_nonce there is no SessionTranscript
            // to reconstruct — the command must surface a clear error rather than silently passing.
            val args =
                VerifyHolderBindingArgs(
                    presentation = "ignored",
                    credentialFormat = CredentialFormat.MSO_MDOC,
                    expectedNonce = "nonce789",
                    expectedAudience = "https://verifier.example.com",
                )

            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val binding = result.value
            assertEquals("mdoc-device-auth", binding.bindingMethod)
            assertFalse(binding.verified)
            assertTrue(binding.errors.any { it.contains("OID4VP context") })
        }

    // ============================================================================
    // JWT VP Tests
    // Note: These tests use a mock JWS command that returns success.
    // The tests verify claim validation logic (nonce, aud) which happens
    // in the command implementation before signature verification.
    // ============================================================================

    @Test
    fun `test JWT VP holder binding with valid claims`() =
        runTest {
            // Given: JWT VP presentation with valid aud and nonce claims
            // Header: {"alg":"ES256","typ":"JWT"}
            // Payload: {"aud":"https://verifier.example.com","nonce":"nonce123"}
            val jwtVp = v1VpJwt()

            val args =
                VerifyHolderBindingArgs(
                    presentation = jwtVp,
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                )

            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val binding = result.value

            assertEquals("jwt-proof", binding.bindingMethod)
            // Claims are validated before signature verification
            assertTrue(binding.nonceValid)
            assertTrue(binding.audienceValid)
            // Mock JWS verification returns error (real verification would check signature)
            // Overall verified is false because signature check failed (mock behavior)
            assertFalse(binding.signatureValid)
            assertFalse(binding.verified)
        }

    @Test
    fun `VCDM 2 JWT presentation uses the final jwt_vc_json-ld query format`() =
        runTest {
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v2VpJwt(),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                    trustedAuthentications = listOf(testHolderAuthentication()),
                ),
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.nonceValid)
            assertTrue(result.value.audienceValid)
        }

    @Test
    fun `VCDM 2 JWT presentation derives an omitted holder from the secured JWT issuer`() =
        runTest {
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v2VpJwt(includeHolder = false),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                    trustedAuthentications = listOf(testHolderAuthentication()),
                ),
            )

            assertIs<Ok<*>>(result)
            assertTrue(result.value.nonceValid)
            assertTrue(result.value.audienceValid)
            assertTrue(result.value.errors.any { it.contains("signature verification failed", ignoreCase = true) })
            assertFalse(result.value.errors.any { it.contains("holder/controller is required", ignoreCase = true) })
        }

    @Test
    fun `VCDM 2 JWT presentation accepts an omitted recommended typ header`() =
        runTest {
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v2VpJwt(header = "{\"alg\":\"ES256\"}"),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                    trustedAuthentications = listOf(testHolderAuthentication()),
                ),
            )

            assertTrue(result.isOk)
            // The default test verifier deliberately returns a verification error. The
            // omitted typ header is accepted by classification and claim validation; the
            // separate signature result remains false until a real verifier proves the JWS.
            assertFalse(result.value.verified)
            assertTrue(result.value.nonceValid)
            assertTrue(result.value.audienceValid)
        }

    @Test
    fun `VCDM 2 JWT presentation rejects a credential media type header`() =
        runTest {
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v2VpJwt(header = "{\"alg\":\"ES256\",\"typ\":\"vc+jwt\",\"cty\":\"vc\"}"),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                    trustedAuthentications = listOf(testHolderAuthentication()),
                ),
            )

            // VCDM classification rejects contradictory JOSE media types before holder
            // binding can run. This is the fail-closed contract for malformed envelopes.
            assertIs<Err<*>>(result)
            assertTrue(result.error.message.defaultMessage.contains("typ", ignoreCase = true))
        }

    @Test
    fun `VCDM 2 JWT presentation rejects a profile-invalid child before holder verification`() =
        runTest {
            val invalidPresentation =
                compact(
                    """{"@context":"https://www.w3.org/ns/credentials/v2","type":"VerifiablePresentation","holder":"https://holder.example","iss":"https://holder.example","aud":"https://verifier.example.com","nonce":"nonce123","verifiableCredential":["urn:example:not-an-enveloped-credential"]}""",
                    """{"alg":"ES256","typ":"vp+jwt","cty":"vp"}""",
                )

            val result =
                command.execute(
                    VerifyHolderBindingArgs(
                        presentation = invalidPresentation,
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                        expectedNonce = "nonce123",
                        expectedAudience = "https://verifier.example.com",
                        trustedAuthentications = listOf(testHolderAuthentication()),
                    ),
                )

            assertIs<Err<*>>(result)
            assertTrue(result.error.message.defaultMessage.contains("profile", ignoreCase = true))
        }

    @Test
    fun `VCDM 2 JWT presentation rejects a mismatched received presentation format`() =
        runTest {
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v2VpJwt(),
                    presentationFormat = PresentationFormat.LDP_VP,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                ),
            )

            assertIs<Err<*>>(result)
            assertTrue(result.error.message.defaultMessage.contains("does not match classified VCDM presentation format"))
        }

    @Test
    fun `VCDM 2 JWT presentation applies NumericDate validation`() =
        runTest {
            val now = Clock.System.now().epochSeconds.toDouble()
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v2VpJwt(timeClaims = "\"iat\":${now + 60},"),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                    trustedAuthentications = listOf(testHolderAuthentication()),
                ),
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.verified)
            assertTrue(result.value.errors.any { it.contains("future", ignoreCase = true) })
        }

    @Test
    fun `compact VCDM VP requires an exact configured holder authentication source`() =
        runTest {
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v1VpJwt(holder = "https://holder.example"),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                ),
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.verified)
            assertTrue(result.value.errors.any { it.contains("holder", ignoreCase = true) && it.contains("source", ignoreCase = true) })
        }

    @Test
    fun `compact VCDM VP passes the exact holder source to JWS verification`() =
        runTest {
            val jws = RecordingVerifyJwsCommand()
            val configured = TrustedAuthenticationResolution(
                controller = "https://holder.example",
                trustedJwks = testTrustedJwks(),
            )
            val result = createTestCommand(MockVerifySdJwtCommand(true), verifyJwsCommand = jws).execute(
                VerifyHolderBindingArgs(
                    presentation = v1VpJwt(holder = "https://holder.example"),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                    trustedAuthentications = listOf(configured),
                ),
            )

            assertIs<Ok<*>>(result)
            assertEquals(configured.trustedJwks, jws.lastArgs?.trustedJwks)
            assertFalse(result.value.verified)
        }

    @Test
    fun `compact VCDM VP rejects embedded JOSE key material without configured source`() =
        runTest {
            listOf(
                "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"attacker\",\"y\":\"attacker\"}}",
                "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"jku\":\"https://attacker.example/jwks\"}",
                "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"x5u\":\"https://attacker.example/cert\"}",
            ).forEach { header ->
                val result = command.execute(
                    VerifyHolderBindingArgs(
                        presentation = v1VpJwt(header = header),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                        expectedNonce = "nonce123",
                        expectedAudience = "https://verifier.example.com",
                    ),
                )

                assertIs<Ok<*>>(result)
                assertFalse(result.value.verified)
                assertTrue(
                    result.value.errors.any {
                        it.contains("trust", ignoreCase = true) || it.contains("configured", ignoreCase = true)
                    },
                )
            }
        }

    @Test
    fun `compact VCDM VP does not treat token x5c as trust without configured X509 source`() =
        runTest {
            val configuredJwks = TrustedAuthenticationResolution(
                controller = "https://holder.example",
                trustedJwks = testTrustedJwks(),
            )
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v1VpJwt(
                        holder = "https://holder.example",
                        header = "{\"alg\":\"ES256\",\"typ\":\"JWT\",\"x5c\":[\"ZmFrZQ\"]}",
                    ),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                    trustedAuthentications = listOf(configuredJwks),
                ),
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.verified)
            assertTrue(result.value.errors.any { it.contains("X.509", ignoreCase = true) })
        }

    @Test
    fun `compact VCDM VP requires token x5c to match the configured X509 chain`() =
        runTest {
            val jws = RecordingVerifyJwsCommand()
            val configuredX509 =
                TrustedAuthenticationResolution(
                    controller = "https://holder.example",
                    identifier = ExternalIdentifierX5cOpts(identifier = listOf("Y29uZmlndXJlZA")),
                )
            val result =
                createTestCommand(MockVerifySdJwtCommand(true), verifyJwsCommand = jws).execute(
                    VerifyHolderBindingArgs(
                        presentation =
                            v1VpJwt(
                                holder = "https://holder.example",
                                header = """{"alg":"ES256","typ":"JWT","x5c":["cHJlc2VudGVk"]}""",
                            ),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                        expectedNonce = "nonce123",
                        expectedAudience = "https://verifier.example.com",
                        trustedAuthentications = listOf(configuredX509),
                    ),
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.verified)
            assertTrue(result.value.errors.any { it.contains("does not match", ignoreCase = true) })
            assertTrue(jws.lastArgs == null, "mismatched certificate chains must fail before signature verification")
        }

    @Test
    fun `compact VCDM VP rejects x5c combined with kid`() =
        runTest {
            val jws = RecordingVerifyJwsCommand()
            val configuredX509 =
                TrustedAuthenticationResolution(
                    controller = "https://holder.example",
                    identifier = ExternalIdentifierX5cOpts(identifier = listOf("cHJlc2VudGVk")),
                )
            val result =
                createTestCommand(MockVerifySdJwtCommand(true), verifyJwsCommand = jws).execute(
                    VerifyHolderBindingArgs(
                        presentation =
                            v1VpJwt(
                                holder = "https://holder.example",
                                header = """{"alg":"ES256","typ":"JWT","kid":"holder-key","x5c":["cHJlc2VudGVk"]}""",
                            ),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                        expectedNonce = "nonce123",
                        expectedAudience = "https://verifier.example.com",
                        trustedAuthentications = listOf(configuredX509),
                    ),
                )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.verified)
            assertTrue(result.value.errors.any { it.contains("cannot be combined", ignoreCase = true) })
            assertTrue(jws.lastArgs == null, "x5c plus kid must fail before signature verification")
        }

    @Test
    fun `compact VCDM VP rejects duplicate exact holder authentication sources`() =
        runTest {
            val configured = TrustedAuthenticationResolution(
                controller = "https://holder.example",
                trustedJwks = testTrustedJwks(),
            )
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v1VpJwt(holder = "https://holder.example"),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                    trustedAuthentications = listOf(configured, configured.copy()),
                ),
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.verified)
            assertTrue(result.value.errors.any { it.contains("multiple", ignoreCase = true) })
        }

    @Test
    fun `compact VCDM VP rejects a source for a different controller`() =
        runTest {
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v1VpJwt(holder = "https://holder.example"),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                    trustedAuthentications = listOf(
                        TrustedAuthenticationResolution(
                            controller = "https://other-holder.example",
                            trustedJwks = testTrustedJwks(),
                        ),
                    ),
                ),
            )

            assertIs<Ok<*>>(result)
            assertFalse(result.value.verified)
            assertTrue(result.value.errors.any { it.contains("exact configured", ignoreCase = true) })
        }

    @Test
    fun `VCDM 2 JWT presentation rejects payload issuer that differs from holder`() =
        runTest {
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v2VpJwt(
                        holder = "https://holder.example",
                        issuer = "https://other-holder.example",
                    ),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                    trustedAuthentications = listOf(
                        TrustedAuthenticationResolution(
                            controller = "https://holder.example",
                            trustedJwks = testTrustedJwks(),
                        ),
                    ),
                ),
            )

            assertIs<Err<*>>(result)
            assertTrue(result.error.message.defaultMessage.contains("iss", ignoreCase = true))
        }

    @Test
    fun `test JWT VP with nonce mismatch`() =
        runTest {
            // Given: JWT VP with nonce that doesn't match expected
            // Payload: {"aud":"https://verifier.example.com","nonce":"wrong-nonce"}
            val jwtVp = v1VpJwt(nonce = "\"wrong-nonce\"")

            val args =
                VerifyHolderBindingArgs(
                    presentation = jwtVp,
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                )

            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val binding = result.value

            assertFalse(binding.verified)
            assertEquals("jwt-proof", binding.bindingMethod)
            assertFalse(binding.nonceValid)
            assertTrue(binding.errors.any { it.contains("nonce") })
        }

    @Test
    fun `test JWT VP with malformed JWT`() =
        runTest {
            // Given: Invalid JWT (only 2 parts instead of 3)
            val invalidJwt = "eyJhbGciOiJFUzI1NiJ9.payload"

            val args =
                VerifyHolderBindingArgs(
                    presentation = invalidJwt,
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                )

            val result = command.execute(args)

            assertIs<Err<*>>(result)
            assertTrue(result.error.message.defaultMessage.contains("classification", ignoreCase = true))
        }

    @Test
    fun `JWT VC is not routed through JWT VP holder binding`() =
        runTest {
            // A credential must not be interpreted as a presentation merely because it is JWT-shaped.
            val jwtVc = v1VcJwt()

            val args =
                VerifyHolderBindingArgs(
                    presentation = jwtVc,
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                )

            val result = command.execute(args)

            assertIs<Err<*>>(result)
            assertTrue(result.error.message.defaultMessage.contains("not a holder-bound presentation"))
        }

    @Test
    fun `arbitrary signed JWT is rejected even when caller requests the JWT VC query format`() =
        runTest {
            val arbitraryJwt = compact("{\"aud\":\"https://verifier.example.com\",\"nonce\":\"nonce123\"}")
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = arbitraryJwt,
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                ),
            )

            assertIs<Err<*>>(result)
            assertTrue(result.error.message.defaultMessage.contains("classification", ignoreCase = true))
        }

    @Test
    fun `JWT VP claim types are strict`() =
        runTest {
            val invalidNonces = listOf("123", "true", "null", "{\"value\":\"nonce123\"}")
            invalidNonces.forEach { nonce ->
                val result = command.execute(
                    VerifyHolderBindingArgs(
                        presentation = v1VpJwt(nonce = nonce),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                        expectedNonce = "nonce123",
                        expectedAudience = "https://verifier.example.com",
                    ),
                )
                assertIs<Ok<*>>(result)
                assertFalse(result.value.nonceValid, "nonce=$nonce must be rejected")
            }

            // Audience shape is part of VCDM classification, so malformed values are rejected
            // as an Err before a HolderBindingResult can be produced.
            val invalidAudiences = listOf("123", "true", "null", "{\"value\":\"https://verifier.example.com\"}", "[]", "[\"https://verifier.example.com\",1]")
            invalidAudiences.forEach { aud ->
                val result = command.execute(
                    VerifyHolderBindingArgs(
                        presentation = v1VpJwt(aud = aud),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                        expectedNonce = "nonce123",
                        expectedAudience = "https://verifier.example.com",
                    ),
                )
                assertIs<Err<*>>(result)
                assertTrue(result.error.message.defaultMessage.contains("aud", ignoreCase = true), "aud=$aud must be rejected")
            }

            listOf("[\"https://verifier.example.com\",\"https://verifier.example.com\"]", "[\"https://verifier.example.com\",\"\"]").forEach { aud ->
                val result = command.execute(
                    VerifyHolderBindingArgs(
                        presentation = v1VpJwt(aud = aud),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                        expectedNonce = "nonce123",
                        expectedAudience = "https://verifier.example.com",
                    ),
                )
                assertIs<Err<*>>(result)
                assertTrue(result.error.message.defaultMessage.contains("aud", ignoreCase = true), "aud=$aud must be rejected")
            }
        }

    @Test
    fun `compact VCDM VP rejects malformed and non-finite temporal NumericDate claims`() =
        runTest {
            listOf("\"not-a-number\"", "true", "null", "1e309").forEach { iat ->
                val result = command.execute(
                    VerifyHolderBindingArgs(
                        presentation = v1VpJwt(timeClaims = "\"iat\":$iat,"),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                        expectedNonce = "nonce123",
                        expectedAudience = "https://verifier.example.com",
                    ),
                )
                assertIs<Err<*>>(result)
                assertTrue(result.error.message.defaultMessage.contains("iat", ignoreCase = true))
            }
        }

    @Test
    fun `compact VCDM VP rejects future and expired temporal NumericDate claims`() =
        runTest {
            val now = Clock.System.now().epochSeconds.toDouble()
            val future = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v1VpJwt(timeClaims = "\"iat\":${now + 60},"),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                ),
            )
            assertIs<Ok<*>>(future)
            assertTrue(future.value.errors.any { it.contains("future", ignoreCase = true) })

            val expired = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v1VpJwt(timeClaims = "\"exp\":${now - 60},"),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                ),
            )
            assertIs<Ok<*>>(expired)
            assertTrue(expired.value.errors.any { it.contains("expired", ignoreCase = true) })
        }

    @Test
    fun `compact VCDM VP permits nbf before token issuance time`() =
        runTest {
            val now = Clock.System.now().epochSeconds.toDouble()
            val result = command.execute(
                VerifyHolderBindingArgs(
                    presentation = v1VpJwt(timeClaims = "\"iat\":${now - 10},\"nbf\":${now - 20},\"exp\":${now + 60},"),
                    presentationFormat = PresentationFormat.JWT_VP_JSON,
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                ),
            )
            assertIs<Ok<*>>(result)
            assertFalse(result.value.errors.any { it.contains("chronological", ignoreCase = true) })
        }

    // ============================================================================
    // Unsupported Format Tests
    // ============================================================================

    @Test
    fun `test unsupported format returns error`() =
        runTest {
            assertFailsWith<IllegalArgumentException> {
                VerifyHolderBindingArgs(
                    presentation = "some_presentation",
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                )
            }
        }

    @Test
    fun `test empty format returns error`() =
        runTest {
            assertFailsWith<IllegalArgumentException> {
                VerifyHolderBindingArgs(
                    presentation = "eyJhbGciOiJFUzI1NiJ9.payload.signature",
                    expectedNonce = "nonce123",
                    expectedAudience = "https://verifier.example.com",
                )
            }
        }

    private fun commandForMdocResponse(
        response: DeviceResponse,
        deviceAuthValidation: DeviceAuthValidation = AlwaysPassDeviceAuthValidation,
    ): VerifyHolderBindingCommandImpl =
        createTestCommand(
            verifySdJwtCommand = MockVerifySdJwtCommand(true),
            verificationShouldSucceed = true,
            mdocValidations = AlwaysPassMdocValidations,
            deviceAuthValidation = deviceAuthValidation,
            deviceResponseCborCodec =
                object : DeviceResponseCborCodec {
                    override fun encode(value: DeviceResponse): IdkResult<ByteArray, IdkError> = Ok(byteArrayOf(0x01))

                    override fun decode(bytes: ByteArray): IdkResult<DecodedMdoc<DeviceResponse>, IdkError> =
                        Ok(DecodedMdoc(response, bytes))
                },
        )

    private fun mdocArgs(
        encryption: TestEncryptionContext? = null,
        expectedDocumentType: String? = MDL_DOC_TYPE,
    ): VerifyHolderBindingArgs =
        VerifyHolderBindingArgs(
            presentation = byteArrayOf(0x01).encodeToBase64Url(),
            credentialFormat = CredentialFormat.MSO_MDOC,
            expectedNonce = "nonce456",
            expectedAudience = "https://verifier.example.com",
            clientId = "x509_san_dns:verifier.example.com",
            responseUri = "https://verifier.example.com/response",
            expectedMdocDocumentType = expectedDocumentType,
            mdocDocumentResponseDecryptionKey = encryption?.key,
            mdocDocumentResponseEncryptionParameters = encryption?.let { mapOf(it.envelope.docRequestID to it.parameters) }.orEmpty(),
            mdocDocumentResponseEncryptionProviders = encryption?.let { listOf(it.provider) }.orEmpty(),
        )

    private fun testDocument(docType: String): Document =
        Document(
            docType = DocType(docType),
            issuerSigned =
                com.sphereon.mdoc.data.device.IssuerSigned(
                    nameSpaces = emptyMap(),
                    issuerAuth =
                        CoseSign1<MobileSecurityObject>(
                            protectedHeader = com.sphereon.crypto.core.cose.CoseHeaderCbor(),
                            unprotectedHeader = null,
                            payload = null,
                            signature = com.sphereon.cbor.CborByteString(byteArrayOf(0x01)),
                        ),
                    original = null,
                ),
            deviceSigned = null,
            original = null,
        )

    private fun testEncryptionContext(plaintext: EncryptedDocumentsPlaintext): TestEncryptionContext {
        val key = CoseKey(kty = CborUInt(2))
        val parameters = EncryptionParameters(recipientPublicKey = key)
        val envelope = EncryptedDocuments(enc = byteArrayOf(0x01), cipherText = byteArrayOf(0x02), docRequestID = 0u)
        val provider =
            object : DocumentResponseEncryptionProvider {
                override fun supports(parameters: EncryptionParameters): Boolean = true

                override suspend fun encrypt(
                    plaintext: EncryptedDocumentsPlaintext,
                    parameters: EncryptionParameters,
                    sessionTranscript: SessionTranscript,
                    docRequestID: UInt,
                ): IdkResult<EncryptedDocuments, IdkError> = Err(IdkError.UNKNOWN_ERROR(message = "not used"))

                override suspend fun decrypt(
                    encrypted: EncryptedDocuments,
                    recipientPrivateKey: CoseKey,
                    sessionTranscript: SessionTranscript,
                    parameters: EncryptionParameters,
                ): IdkResult<EncryptedDocumentsPlaintext, IdkError> = Ok(plaintext)
            }
        return TestEncryptionContext(key, parameters, envelope, provider)
    }

    private data class TestEncryptionContext(
        val key: CoseKey,
        val parameters: EncryptionParameters,
        val envelope: EncryptedDocuments,
        val provider: DocumentResponseEncryptionProvider,
    )

    /**
     * Creates a test command with mock dependencies.
     *
     * @param verificationShouldSucceed If true, mock commands return successful verification.
     *                                   If false, they return failure.
     */
    private fun createTestCommand(verificationShouldSucceed: Boolean = true): VerifyHolderBindingCommandImpl {
        return createTestCommand(MockVerifySdJwtCommand(verificationShouldSucceed), verificationShouldSucceed)
    }

    private fun createTestCommand(
        verifySdJwtCommand: VerifySdJwtCommand,
        verificationShouldSucceed: Boolean = true,
        verifyJwsCommand: VerifyJwsCommand? = null,
        mdocValidations: MdocValidations = AlwaysFailMdocValidations,
        deviceAuthValidation: DeviceAuthValidation = AlwaysFailDeviceAuthValidation,
        deviceResponseCborCodec: DeviceResponseCborCodec = AlwaysFailDeviceResponseCborCodec,
        didResolverRegistry: DidResolverRegistry? = null,
    ): VerifyHolderBindingCommandImpl {
        val mockJwsCommand = verifyJwsCommand ?: MockVerifyJwsCommand(verificationShouldSucceed)

        return VerifyHolderBindingCommandImpl(
            execution = testContext.execution,
            verifySdJwtCommand = verifySdJwtCommand,
            verifyJwsCommand = mockJwsCommand,
            mdocValidations = mdocValidations,
            deviceAuthValidation = deviceAuthValidation,
            deviceResponseCborCodec = deviceResponseCborCodec,
            didResolverRegistryProvider = didResolverRegistry?.let { registry -> Provider { registry } },
        )
    }

    private fun v1VpJwt(
        aud: String = "\"https://verifier.example.com\"",
        nonce: String = "\"nonce123\"",
        holder: String = "did:example:holder",
        issuer: String = holder,
        header: String = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}",
        timeClaims: String = "",
    ): String =
        compact(
            """{"iss":"$issuer","aud":$aud,"nonce":$nonce,$timeClaims"vp":{"@context":["https://www.w3.org/2018/credentials/v1"],"type":["VerifiablePresentation"],"verifiableCredential":["urn:example:credential"]}}""",
            header,
        )

    private fun v1VcJwt(): String =
        compact(
            """{"iss":"did:example:issuer","sub":"did:example:subject","jti":"urn:uuid:credential-123","nbf":1700000000,"vc":{"@context":["https://www.w3.org/2018/credentials/v1"],"id":"urn:uuid:credential-123","type":["VerifiableCredential"],"credentialSubject":{"id":"did:example:subject"}}}""",
        )

    private fun v2VpJwt(
        timeClaims: String = "",
        holder: String = "https://holder.example",
        issuer: String = holder,
        header: String = "{\"alg\":\"ES256\",\"typ\":\"vp+jwt\",\"cty\":\"vp\"}",
        includeHolder: Boolean = true,
    ): String =
        compact(
            """{"@context":"https://www.w3.org/ns/credentials/v2","type":"VerifiablePresentation",${if (includeHolder) "\"holder\":\"$holder\"," else ""}"iss":"$issuer","aud":"https://verifier.example.com","nonce":"nonce123",$timeClaims"verifiableCredential":[{"@context":"https://www.w3.org/ns/credentials/v2","id":"data:application/vc+jwt,eyJhbGciOiJFUzI1NiJ9.e30.AQID","type":"EnvelopedVerifiableCredential"}]}""",
            header,
        )

    private fun testHolderAuthentication(): TrustedAuthenticationResolution =
        TrustedAuthenticationResolution(
            controller = "https://holder.example",
            trustedJwks = testTrustedJwks(),
        )

    private fun compact(payload: String, header: String = "{\"alg\":\"ES256\",\"typ\":\"JWT\"}"): String {
        return "${JwsUtils.encodeBytesToBase64Url(header.encodeToByteArray())}.${JwsUtils.encodeBytesToBase64Url(payload.encodeToByteArray())}.AQID"
    }

    private fun testTrustedJwks() =
        kotlinx.serialization.json.JsonObject(
            mapOf(
                "keys" to kotlinx.serialization.json.JsonArray(
                    listOf(
                        kotlinx.serialization.json.JsonObject(
                            mapOf(
                                "kty" to kotlinx.serialization.json.JsonPrimitive("EC"),
                                "crv" to kotlinx.serialization.json.JsonPrimitive("P-256"),
                                "x" to kotlinx.serialization.json.JsonPrimitive("WbbFpp0eS8_rJlvpuX_qEyU1J2PNmXYnqPCBJTqqiBA"),
                                "y" to kotlinx.serialization.json.JsonPrimitive("F8kbfVPRQc5M9kJA1fy3c_0Q6vCqHy1X7CZQC6XQy9I"),
                                "kid" to kotlinx.serialization.json.JsonPrimitive("holder-key"),
                            ),
                        ),
                    ),
                ),
            ),
        )


    @Test
    fun `a DID issuer kid is made absolute and must be an assertionMethod of the trusted DID`() =
        runTest {
            val recording = RecordingVerifySdJwtCommand()
            val command = createTestCommand(recording, didResolverRegistry = SingleDidRegistry(issuerDidDocument()))

            val accepted = command.execute(didIssuerArgs(didIssuerSdJwt(kid = "#assert-1")))

            assertIs<Ok<*>>(accepted)
            val identifier = assertIs<ExternalIdentifierDidOpts>(recording.received.single().identifier)
            assertEquals("$ISSUER_DID#assert-1", identifier.identifier)
        }

    @Test
    fun `a DID issuer kid outside assertionMethod, of another DID, or missing is refused`() =
        runTest {
            val recording = RecordingVerifySdJwtCommand()
            val command = createTestCommand(recording, didResolverRegistry = SingleDidRegistry(issuerDidDocument()))

            listOf(
                didIssuerSdJwt(kid = "#auth-1"),
                didIssuerSdJwt(kid = "did:example:other#assert-1"),
                didIssuerSdJwt(kid = null),
            ).forEach { presentation ->
                val result = command.execute(didIssuerArgs(presentation))
                assertIs<Ok<*>>(result)
                assertFalse(result.value.verified, "presentation must be refused: $presentation")
            }
            assertTrue(recording.received.isEmpty(), "a refused issuer key must never reach signature verification")
        }

    @Test
    fun `a DID-issued SD-JWT VC naming its federation entity is verified only with that entity's vc_issuer keys`() =
        runTest {
            val recording = RecordingVerifySdJwtCommand()
            val command = createTestCommand(recording)
            val source = federationEntitySource()

            val result = command.execute(federatedArgs(federatedSdJwt(), listOf(source)))

            assertIs<Ok<*>>(result)
            assertTrue(result.value.verified, result.value.errors.joinToString())
            val args = recording.received.single()
            assertEquals(source.trustedJwks, args.trustedJwks)
            assertEquals(null, args.identifier, "neither the DID document nor header key material is consulted")
        }

    @Test
    fun `a DID-issued SD-JWT VC naming a federation entity fails closed without exactly its admitted vc_issuer keys`() =
        runTest {
            val recording = RecordingVerifySdJwtCommand()
            val command = createTestCommand(recording, didResolverRegistry = SingleDidRegistry(federationDidDocument()))
            val source = federationEntitySource()

            listOf(
                // Ambiguous admission.
                federatedArgs(federatedSdJwt(), listOf(source, source.copy())),
                // No kid, a kid of another DID, or header key material.
                federatedArgs(federatedSdJwt(kid = null), listOf(source)),
                federatedArgs(federatedSdJwt(kid = "did:web:attacker.example#issuer-assertion-summa"), listOf(source)),
                federatedArgs(federatedSdJwt(extraHeader = ""","x5c":["Y2VydA"]"""), listOf(source)),
                federatedArgs(federatedSdJwt(extraHeader = ""","jwk":{"kty":"EC"}"""), listOf(source)),
            ).forEachIndexed { index, args ->
                val result = command.execute(args)
                assertIs<Ok<*>>(result)
                assertFalse(result.value.verified, "case $index must be refused")
            }
            assertTrue(recording.received.isEmpty(), "a refused federation issuer must never reach signature verification")
        }

    @Test
    fun `a federation entity the verifier does not admit leaves the SD-JWT VC on the DID path`() =
        runTest {
            val source = federationEntitySource()
            listOf(
                emptyList(),
                listOf(federationEntitySource(entity = "https://other.fed.example/issuer")),
                // Admitted only as an ordinary issuer, not as a federation entity.
                listOf(TrustedAuthenticationResolution(FEDERATION_ENTITY, trustedJwks = source.trustedJwks, purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.CREDENTIAL_ISSUER)),
            ).forEachIndexed { index, authentications ->
                val recording = RecordingVerifySdJwtCommand()
                val command = createTestCommand(recording, didResolverRegistry = SingleDidRegistry(federationDidDocument()))

                assertIs<Ok<*>>(command.execute(federatedArgs(federatedSdJwt(), authentications)))
                recording.received.forEach { args ->
                    assertEquals(null, args.trustedJwks, "case $index: the entity's vc_issuer keys must not be used")
                }
            }
        }

    @Test
    fun `a DID admitted directly keeps DID admission even when the SD-JWT VC names a federation entity`() =
        runTest {
            val recording = RecordingVerifySdJwtCommand()
            val command = createTestCommand(recording, didResolverRegistry = SingleDidRegistry(federationDidDocument()))

            val result = command.execute(
                federatedArgs(
                    federatedSdJwt(),
                    listOf(
                        TrustedAuthenticationResolution(
                            controller = FEDERATION_DID,
                            identifier = ExternalIdentifierDidOpts(identifier = FEDERATION_DID),
                            purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                        ),
                        federationEntitySource(),
                    ),
                ),
            )

            assertIs<Ok<*>>(result)
            val args = recording.received.single()
            assertEquals(null, args.trustedJwks)
            assertEquals(FEDERATION_KID, assertIs<ExternalIdentifierDidOpts>(args.identifier).identifier)
        }

    private fun federatedArgs(presentation: String, authentications: List<TrustedAuthenticationResolution>) =
        VerifyHolderBindingArgs(
            presentation = presentation,
            credentialFormat = CredentialFormat.SD_JWT_VC,
            expectedNonce = "nonce123",
            expectedAudience = "https://verifier.example.com",
            requireCryptographicHolderBinding = false,
            trustedAuthentications = authentications,
        )

    private fun federatedSdJwt(kid: String? = FEDERATION_KID, extraHeader: String = ""): String {
        val header = if (kid == null) """{"alg":"ES256"$extraHeader}""" else """{"alg":"ES256","kid":"$kid"$extraHeader}"""
        return header.encodeToByteArray().encodeToBase64Url() + "." +
            """{"iss":"$FEDERATION_DID","fed":"$FEDERATION_ENTITY","vct":"https://example.com/vct"}""".encodeToByteArray().encodeToBase64Url() +
            ".signature~"
    }

    private fun federationEntitySource(entity: String = FEDERATION_ENTITY) =
        TrustedAuthenticationResolution(
            controller = entity,
            trustedJwks = kotlinx.serialization.json.buildJsonObject {
                put(
                    "keys",
                    kotlinx.serialization.json.JsonArray(
                        listOf(
                            kotlinx.serialization.json.buildJsonObject {
                                put("kty", kotlinx.serialization.json.JsonPrimitive("EC"))
                                put("crv", kotlinx.serialization.json.JsonPrimitive("P-256"))
                                put("x", kotlinx.serialization.json.JsonPrimitive("WbbFpp0eS8_rJlvpuX_qEyU1J2PNmXYnqPCBJTqqiBA"))
                                put("y", kotlinx.serialization.json.JsonPrimitive("F8kbfVPRQc5M9kJA1fy3c_0Q6vCqHy1X7CZQC6XQy9I"))
                                put("kid", kotlinx.serialization.json.JsonPrimitive(FEDERATION_KID))
                            },
                        ),
                    ),
                )
            },
            purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
            controllerClaim = com.sphereon.openid.oid4vp.verifier.CredentialIssuerControllerClaim.FEDERATION_ENTITY,
        )

    private fun federationDidDocument(): DidDocument =
        DidDocument(
            id = FEDERATION_DID,
            verificationMethod = listOf(VerificationMethod(id = FEDERATION_KID, type = "JsonWebKey2020", controller = FEDERATION_DID)),
            assertionMethod = listOf(VerificationMethodOrReference.fromReference(FEDERATION_KID)),
        )

    private fun didIssuerArgs(presentation: String) =
        VerifyHolderBindingArgs(
            presentation = presentation,
            credentialFormat = CredentialFormat.SD_JWT_VC,
            expectedNonce = "nonce123",
            expectedAudience = "https://verifier.example.com",
            requireCryptographicHolderBinding = false,
            trustedAuthentications =
                listOf(
                    TrustedAuthenticationResolution(
                        controller = ISSUER_DID,
                        identifier = ExternalIdentifierDidOpts(identifier = ISSUER_DID),
                        purpose = com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                    ),
                ),
        )

    private fun didIssuerSdJwt(kid: String?): String {
        val header = if (kid == null) """{"alg":"ES256"}""" else """{"alg":"ES256","kid":"$kid"}"""
        return header.encodeToByteArray().encodeToBase64Url() + "." +
            """{"iss":"$ISSUER_DID"}""".encodeToByteArray().encodeToBase64Url() + ".signature~"
    }

    private fun issuerDidDocument(): DidDocument {
        fun method(fragment: String) = VerificationMethod(id = "$ISSUER_DID#$fragment", type = "JsonWebKey2020", controller = ISSUER_DID)
        return DidDocument(
            id = ISSUER_DID,
            verificationMethod = listOf(method("assert-1"), method("auth-1")),
            // assert-1 is referenced from assertionMethod; auth-1 only authenticates.
            assertionMethod = listOf(VerificationMethodOrReference.fromReference("$ISSUER_DID#assert-1")),
            authentication = listOf(VerificationMethodOrReference.fromReference("$ISSUER_DID#auth-1")),
        )
    }

    private class RecordingVerifySdJwtCommand : VerifySdJwtCommand {
        val received = mutableListOf<VerifySdJwtArgs>()
        override val id: String = "recording-verify-sdjwt"
        override val isEnabled: Boolean = true
        override val inputTypeToken: TypeToken<VerifySdJwtArgs> = typeToken<VerifySdJwtArgs>()
        override val outputTypeToken: TypeToken<SdJwtVerificationResult> = typeToken<SdJwtVerificationResult>()

        override suspend fun execute(args: VerifySdJwtArgs): IdkResult<SdJwtVerificationResult, IdkError> {
            received += args
            val parsed = SdJwtCodec.parse(args.sdJwt).getOrElse { return Err(it) }
            return Ok(SdJwtVerificationResult(sdJwt = parsed, signatureValid = true, disclosuresValid = true, keyBindingValid = true))
        }
    }

    private class SingleDidRegistry(private val document: DidDocument) : DidResolverRegistry {
        private val resolver =
            object : DidResolver {
                override val supportedMethods: List<String> = listOf("example")
                override val capabilities: DidMethodCapabilities = DidMethodCapabilities(method = "example")

                override suspend fun resolve(did: String, options: DidResolutionOptions): IdkResult<DidResolutionResult, IdkError> =
                    if (did == document.id) {
                        Ok(DidResolutionResult(didDocument = document, didResolutionMetadata = DidResolutionMetadata()))
                    } else {
                        Err(IdkError.NOT_FOUND_ERROR(resource = did))
                    }

                override suspend fun dereference(didUrl: String, options: DidDereferenceOptions): IdkResult<DidDereferenceResult, IdkError> =
                    Err(IdkError.NOT_FOUND_ERROR(resource = didUrl))
            }

        override fun getResolver(method: String): DidResolver? = resolver.takeIf { method == "example" }
        override fun getCapabilities(method: String): DidMethodCapabilities? = resolver.capabilities.takeIf { method == "example" }
        override fun getSupportedMethods(): List<String> = resolver.supportedMethods
        override suspend fun resolve(did: String, options: DidResolutionOptions): IdkResult<DidResolutionResult, IdkError> = resolver.resolve(did, options)
        override suspend fun dereference(didUrl: String, options: DidDereferenceOptions): IdkResult<DidDereferenceResult, IdkError> =
            resolver.dereference(didUrl, options)
        override fun hasResolver(method: String): Boolean = method == "example"
    }

    private class FixedVerifySdJwtCommand(
        private val result: SdJwtVerificationResult,
    ) : VerifySdJwtCommand {
        override val id: String = "fixed-verify-sdjwt"
        override val isEnabled: Boolean = true
        override val inputTypeToken: TypeToken<VerifySdJwtArgs> = typeToken<VerifySdJwtArgs>()
        override val outputTypeToken: TypeToken<SdJwtVerificationResult> = typeToken<SdJwtVerificationResult>()

        override suspend fun execute(args: VerifySdJwtArgs): IdkResult<SdJwtVerificationResult, IdkError> = Ok(result)
    }

    private object AlwaysPassMdocValidations : MdocValidations {
        override suspend fun fromDocument(
            document: Document,
            trustedCerts: Array<String>?,
            verificationTime: LocalDateTimeKMP?,
            keyInfo: KeyInfoType<CoseKeyType>?,
            allowNotYetValidDocuments: Boolean,
            allowExpiredDocuments: Boolean,
            dateTimeUtils: DateTimeUtils,
            timeZoneId: String?,
            clockSkewAllowedInSec: Int,
        ): VerifyResultsType<CoseKeyType> = pass()

        override suspend fun fromIssuerAuth(
            issuerAuth: CoseSign1<MobileSecurityObject>,
            keyInfo: KeyInfoType<CoseKeyType>?,
            trustedCerts: Array<String>?,
            verificationTime: LocalDateTimeKMP?,
            allowNotYetValidDocuments: Boolean,
            allowExpiredDocuments: Boolean,
            dateTimeUtils: DateTimeUtils,
            timeZoneId: String?,
            clockSkewAllowedInSec: Int,
        ): VerifyResultsType<CoseKeyType> = pass()

        override suspend fun withParams(
            issuerAuth: CoseSign1<MobileSecurityObject>?,
            document: Document?,
            mdocVerificationTypes: MdocVerificationTypes,
            keyInfo: KeyInfoType<CoseKeyType>?,
            trustedCerts: Array<String>?,
            verificationTime: LocalDateTimeKMP?,
            allowNotYetValidDocuments: Boolean?,
            allowExpiredDocuments: Boolean?,
            dateTimeUtils: DateTimeUtils,
            timeZoneId: String?,
            clockSkewAllowedInSec: Int,
        ): VerifyResultsType<CoseKeyType> = pass()

        private fun pass(): VerifyResults<CoseKeyType> = VerifyResults(error = false, keyInfo = null, verifications = emptyArray())
    }

    private object AlwaysPassDeviceAuthValidation : DeviceAuthValidation {
        override suspend fun verifyDeviceAuth(
            document: Document,
            expectedSessionTranscript: SessionTranscript,
        ): VerifySignatureResultType<CoseKeyType> =
            VerifySignatureResult<CoseKeyType>(
                error = false,
                critical = true,
                message = null,
                name = "test-device-auth",
            )
    }

    /**
     * Stub `MdocValidations` for unit tests. Returns a critical-error result so the holder-
     * binding command treats the (bogus, non-mdoc) test presentations as invalid — which is
     * the correct post-placeholder behaviour. End-to-end mdoc verification is exercised via
     * an integration test against `MdocOid4vpServiceImpl`.
     */
    private object AlwaysFailMdocValidations : MdocValidations {
        override suspend fun fromDocument(
            document: Document,
            trustedCerts: Array<String>?,
            verificationTime: LocalDateTimeKMP?,
            keyInfo: KeyInfoType<CoseKeyType>?,
            allowNotYetValidDocuments: Boolean,
            allowExpiredDocuments: Boolean,
            dateTimeUtils: DateTimeUtils,
            timeZoneId: String?,
            clockSkewAllowedInSec: Int,
        ): VerifyResultsType<CoseKeyType> = critical("stub MdocValidations.fromDocument: test never supplies a real mdoc")

        override suspend fun fromIssuerAuth(
            issuerAuth: CoseSign1<MobileSecurityObject>,
            keyInfo: KeyInfoType<CoseKeyType>?,
            trustedCerts: Array<String>?,
            verificationTime: LocalDateTimeKMP?,
            allowNotYetValidDocuments: Boolean,
            allowExpiredDocuments: Boolean,
            dateTimeUtils: DateTimeUtils,
            timeZoneId: String?,
            clockSkewAllowedInSec: Int,
        ): VerifyResultsType<CoseKeyType> = critical("stub MdocValidations.fromIssuerAuth")

        override suspend fun withParams(
            issuerAuth: CoseSign1<MobileSecurityObject>?,
            document: Document?,
            mdocVerificationTypes: MdocVerificationTypes,
            keyInfo: KeyInfoType<CoseKeyType>?,
            trustedCerts: Array<String>?,
            verificationTime: LocalDateTimeKMP?,
            allowNotYetValidDocuments: Boolean?,
            allowExpiredDocuments: Boolean?,
            dateTimeUtils: DateTimeUtils,
            timeZoneId: String?,
            clockSkewAllowedInSec: Int,
        ): VerifyResultsType<CoseKeyType> = critical("stub MdocValidations.withParams")

        private fun critical(reason: String): VerifyResults<CoseKeyType> = VerifyResults(error = true, keyInfo = null, verifications = emptyArray())
    }

    private object AlwaysFailDeviceAuthValidation : DeviceAuthValidation {
        override suspend fun verifyDeviceAuth(
            document: Document,
            expectedSessionTranscript: SessionTranscript,
        ): VerifySignatureResultType<CoseKeyType> =
            VerifySignatureResult(
                error = true,
                critical = true,
                message = "stub DeviceAuthValidation: test never supplies a real mdoc",
                name = "test-stub",
            )
    }

    private object AlwaysFailDeviceResponseCborCodec : DeviceResponseCborCodec {
        override fun encode(value: DeviceResponse): IdkResult<ByteArray, IdkError> = Err(IdkError.UNKNOWN_ERROR(message = "encode unsupported in test stub"))

        override fun decode(bytes: ByteArray): IdkResult<com.sphereon.mdoc.DecodedMdoc<DeviceResponse>, IdkError> =
            Err(IdkError.UNKNOWN_ERROR(message = "stub DeviceResponseCborCodec rejects every payload"))
    }

    /**
     * Mock SD-JWT verification command for testing.
     */
    private class MockVerifySdJwtCommand(
        private val shouldSucceed: Boolean,
    ) : VerifySdJwtCommand {
        override val id: String = "mock-verify-sdjwt"
        override val isEnabled: Boolean = true
        override val inputTypeToken: TypeToken<VerifySdJwtArgs> = typeToken<VerifySdJwtArgs>()
        override val outputTypeToken: TypeToken<SdJwtVerificationResult> = typeToken<SdJwtVerificationResult>()

        override suspend fun execute(args: VerifySdJwtArgs): IdkResult<SdJwtVerificationResult, IdkError> {
            // We can't create a valid SdJwtVerificationResult without a real SD-JWT parse
            // So we return an error to indicate this mock can't provide the result
            // The actual verification logic falls back to the error handling path
            return Err(
                IdkError.fromString(
                    if (shouldSucceed) {
                        "Mock success - verification passed"
                    } else {
                        "Mock failure - verification failed"
                    },
                ),
            )
        }
    }

    /**
     * Mock JWS verification command for testing.
     *
     * Note: Creating a real JwsValidationResult requires complex JWS types.
     * For unit tests, we return success or error based on shouldSucceed.
     * When shouldSucceed is true but we need a real JwsValidationResult,
     * we return an error with a specific message that the impl handles.
     *
     * Full integration tests with real JWS verification are in the integration test suite.
     */
    private class MockVerifyJwsCommand(
        private val shouldSucceed: Boolean,
    ) : VerifyJwsCommand {
        override val id: String = "mock-verify-jws"
        override val isEnabled: Boolean = true
        override val inputTypeToken: TypeToken<VerifyJwsArgs> = typeToken<VerifyJwsArgs>()
        override val outputTypeToken: TypeToken<JwsValidationResult> = typeToken<JwsValidationResult>()

        override suspend fun execute(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> {
            // For mocking purposes, we simulate success by returning an error with a specific message
            // The actual impl will receive this as an error but our test expectations are updated accordingly
            return if (shouldSucceed) {
                // To truly mock success, we'd need to construct complex JWS types
                // For now, return an error that indicates "mock success" for test validation
                Err(IdkError.fromString("Mock JWS - signature would pass"))
            } else {
                Err(IdkError.fromString("Mock JWS verification failed"))
            }
        }
    }

    private class RecordingVerifyJwsCommand : VerifyJwsCommand {
        override val id: String = "recording-verify-jws"
        override val isEnabled: Boolean = true
        override val inputTypeToken: TypeToken<VerifyJwsArgs> = typeToken<VerifyJwsArgs>()
        override val outputTypeToken: TypeToken<JwsValidationResult> = typeToken<JwsValidationResult>()
        var lastArgs: VerifyJwsArgs? = null

        override suspend fun execute(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> {
            lastArgs = args
            return Err(IdkError.fromString("recording verifier"))
        }
    }
}
