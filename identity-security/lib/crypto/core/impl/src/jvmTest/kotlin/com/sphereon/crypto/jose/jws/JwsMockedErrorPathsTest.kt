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

package com.sphereon.crypto.jose.jws

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.util.Base64
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyInfo
import com.sphereon.crypto.core.ResolvedKeyInfo
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.JwaCurve
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkType
import com.sphereon.crypto.core.jose.JwtHeader
import com.sphereon.crypto.core.kms.command.CreateRawSignatureCommand
import com.sphereon.crypto.core.kms.command.CreateRawSignatureResult
import com.sphereon.crypto.core.sign.SignatureService
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsCompactCommandImpl
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonFlattenedCommand
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonFlattenedCommandImpl
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonGeneralCommand
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonGeneralCommandImpl
import com.sphereon.crypto.jose.jws.command.CreateJwsOpts
import com.sphereon.crypto.jose.jws.command.PrepareJwsCommand
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.resolution.IdentifierContext
import com.sphereon.crypto.resolution.extern.ExternalIdentifierJwksUrlOpts
import com.sphereon.crypto.resolution.extern.ExternalIdentifierX5cOpts
import com.sphereon.crypto.resolution.extern.ExternalIdentifierResult
import com.sphereon.crypto.resolution.managed.ManagedIdentifierKeyResult
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Test class for JWS command error paths using mocks.
 * These tests cover the branches that are hard to reach through integration tests.
 */
class JwsMockedErrorPathsTest {
    // ========================================================================
    // CreateJwsCompactCommandImpl Error Path Tests
    // ========================================================================

    @Test
    fun testCreateJwsCompact_FlattenedResultFails() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockFlattenedCommand = mockk<CreateJwsJsonFlattenedCommand>()

            // Mock flattened command to return error
            coEvery { mockFlattenedCommand.execute(any()) } returns
                IdkResult.err(IdkError.fromString("Flattened JWS creation failed"))

            val command =
                CreateJwsCompactCommandImpl(
                    execution = mockExecution,
                    createJwsJsonFlattenedCommand = mockFlattenedCommand,
                )

            val args =
                CreateJwsArgs(
                    issuer = mockk(relaxed = true),
                    payload = "test payload",
                )

            val result = command.execute(args)

            assertTrue(result.isErr, "Should fail when flattened JWS creation fails")
            assertNotNull(result.error.message.defaultMessage)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("Flattened JWS creation failed"),
            )
        }

    // ========================================================================
    // CreateJwsJsonFlattenedCommandImpl Error Path Tests
    // ========================================================================

    @Test
    fun testCreateJwsJsonFlattened_GeneralResultFails() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockGeneralCommand = mockk<CreateJwsJsonGeneralCommand>()

            // Mock general command to return error
            coEvery { mockGeneralCommand.execute(any()) } returns
                IdkResult.err(IdkError.fromString("General JWS creation failed"))

            val command =
                CreateJwsJsonFlattenedCommandImpl(
                    execution = mockExecution,
                    createJwsJsonGeneralCommand = mockGeneralCommand,
                )

            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = "test payload",
                )

            val result = command.execute(args)

            assertTrue(result.isErr, "Should fail when general JWS creation fails")
            assertNotNull(result.error.message.defaultMessage)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("General JWS creation failed"),
            )
        }

    @Test
    fun testCreateJwsJsonFlattened_MultipleSignatures() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockGeneralCommand = mockk<CreateJwsJsonGeneralCommand>()

            // Mock general command to return JWS with multiple signatures
            val mockSignature1 =
                JwsJsonSignature(
                    protected = "eyJhbGciOiJFUzI1NiJ9",
                    header = null,
                    signature = "sig1",
                )
            val mockSignature2 =
                JwsJsonSignature(
                    protected = "eyJhbGciOiJFUzI1NiJ9",
                    header = null,
                    signature = "sig2",
                )
            val mockGeneral =
                JwsJsonGeneral(
                    payload = "dGVzdA",
                    signatures = listOf(mockSignature1, mockSignature2),
                )

            coEvery { mockGeneralCommand.execute(any()) } returns
                IdkResult.ok(mockGeneral)

            val command =
                CreateJwsJsonFlattenedCommandImpl(
                    execution = mockExecution,
                    createJwsJsonGeneralCommand = mockGeneralCommand,
                )

            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = "test payload",
                )

            val result = command.execute(args)

            assertTrue(result.isErr, "Should fail when there are multiple signatures")
            assertNotNull(result.error.message.defaultMessage)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("exactly one signature"),
            )
        }

    @Test
    fun testCreateJwsJsonFlattened_ZeroSignatures() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockGeneralCommand = mockk<CreateJwsJsonGeneralCommand>()

            // Mock general command to return JWS with zero signatures
            val mockGeneral =
                JwsJsonGeneral(
                    payload = "dGVzdA",
                    signatures = emptyList(),
                )

            coEvery { mockGeneralCommand.execute(any()) } returns
                IdkResult.ok(mockGeneral)

            val command =
                CreateJwsJsonFlattenedCommandImpl(
                    execution = mockExecution,
                    createJwsJsonGeneralCommand = mockGeneralCommand,
                )

            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = "test payload",
                )

            val result = command.execute(args)

            assertTrue(result.isErr, "Should fail when there are zero signatures")
            assertNotNull(result.error.message.defaultMessage)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("exactly one signature"),
            )
        }

    // ========================================================================
    // CreateJwsJsonGeneralCommandImpl Error Path Tests
    // ========================================================================

    @Test
    fun testCreateJwsJsonGeneral_PrepareResultFails() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockPrepareCommand = mockk<PrepareJwsCommand>()
            val mockSignatureCommand = mockk<CreateRawSignatureCommand>()

            // Mock prepare command to return error
            coEvery { mockPrepareCommand.execute(any()) } returns
                IdkResult.err(IdkError.fromString("Prepare JWS failed"))

            val command =
                CreateJwsJsonGeneralCommandImpl(
                    execution = mockExecution,
                    prepareJwsCommand = mockPrepareCommand,
                    createRawSignatureCommand = mockSignatureCommand,
                )

            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = "test payload",
                )

            val result = command.execute(args)

            assertTrue(result.isErr, "Should fail when prepare JWS fails")
            assertNotNull(result.error.message.defaultMessage)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("Prepare JWS failed"),
            )
        }

    @Test
    fun testCreateJwsJsonGeneral_SignatureCreationThrows() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockPrepareCommand = mockk<PrepareJwsCommand>()
            val mockSignatureCommand = mockk<CreateRawSignatureCommand>()

            // Create a proper ManagedIdentifierKeyResult
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            // Create mock prepared JWS with correct types
            val mockPreparedJws =
                PreparedJws(
                    protectedHeader = JwtHeader(JsonObject(mapOf("alg" to JsonPrimitive("ES256")))),
                    payload = "test".encodeToByteArray(),
                    unprotectedHeader = null,
                    existingSignatures = null,
                )
            val mockB64 =
                Base64UrlEncoded(
                    protectedHeader = "eyJhbGciOiJFUzI1NiJ9",
                    payload = "dGVzdA",
                )

            val mockPreparedObject =
                PreparedJwsObject(
                    jws = mockPreparedJws,
                    b64 = mockB64,
                    identifier = identifierResult,
                    signingInput = "${mockB64.protectedHeader}.${mockB64.payload}".encodeToByteArray(),
                )

            coEvery { mockPrepareCommand.execute(any()) } returns
                IdkResult.ok(mockPreparedObject)

            // Mock routed signature command to throw exception
            coEvery { mockSignatureCommand.execute(any()) } throws
                RuntimeException("Signature creation failed")

            val command =
                CreateJwsJsonGeneralCommandImpl(
                    execution = mockExecution,
                    prepareJwsCommand = mockPrepareCommand,
                    createRawSignatureCommand = mockSignatureCommand,
                )

            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = "test payload",
                )

            val result = command.execute(args)

            assertTrue(result.isErr, "Should fail when signature creation throws")
            assertNotNull(result.error.message.defaultMessage)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("Failed to create signature"),
            )
        }

    @Test
    fun testCreateJwsJsonGeneral_WithExistingSignatures() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockPrepareCommand = mockk<PrepareJwsCommand>()
            val mockSignatureCommand = mockk<CreateRawSignatureCommand>()

            // Create existing signature
            val existingSignature =
                JwsJsonSignature(
                    protected = "eyJhbGciOiJFUzM4NCJ9",
                    header = null,
                    signature = "existing-sig",
                )

            // Create a proper ManagedIdentifierKeyResult
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            // Create mock prepared JWS with existing signatures
            val mockPreparedJws =
                PreparedJws(
                    protectedHeader = JwtHeader(JsonObject(mapOf("alg" to JsonPrimitive("ES256")))),
                    payload = "test".encodeToByteArray(),
                    unprotectedHeader = null,
                    existingSignatures = listOf(existingSignature),
                )
            val mockB64 =
                Base64UrlEncoded(
                    protectedHeader = "eyJhbGciOiJFUzI1NiJ9",
                    payload = "dGVzdA",
                )

            val mockPreparedObject =
                PreparedJwsObject(
                    jws = mockPreparedJws,
                    b64 = mockB64,
                    identifier = identifierResult,
                    signingInput = "${mockB64.protectedHeader}.${mockB64.payload}".encodeToByteArray(),
                )

            coEvery { mockPrepareCommand.execute(any()) } returns
                IdkResult.ok(mockPreparedObject)

            // Mock routed signature command to return valid signature bytes
            coEvery { mockSignatureCommand.execute(any()) } returns
                IdkResult.ok(CreateRawSignatureResult(ByteArray(64) { it.toByte() }))

            val command =
                CreateJwsJsonGeneralCommandImpl(
                    execution = mockExecution,
                    prepareJwsCommand = mockPrepareCommand,
                    createRawSignatureCommand = mockSignatureCommand,
                )

            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = "test payload",
                )

            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with existing signatures")
            val jws = result.value
            // Should have 2 signatures: existing + new
            assertTrue(jws.signatures.size == 2, "Should have 2 signatures (existing + new)")
        }

    // ========================================================================
    // VerifyJwsCommandImpl Error Path Tests
    // ========================================================================

    @Test
    fun testVerifyJws_NullJws() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>(relaxed = true)
            val mockSignatureService = mockk<SignatureService>(relaxed = true)

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Test with null JWS
            val args = VerifyJwsArgs(jws = null, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isErr, "Should fail when JWS is null")
            assertTrue(
                result.error.message.defaultMessage
                    .contains("required"),
            )
        }

    @Test
    fun testVerifyJws_InvalidJwsFormat() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>(relaxed = true)
            val mockSignatureService = mockk<SignatureService>(relaxed = true)

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Test with invalid JWS format
            val args = VerifyJwsArgs(jws = JwsCompact("not-a-valid-jws"), identifier = null)
            val result = command.execute(args)

            assertTrue(result.isErr, "Should fail with invalid JWS format")
            assertTrue(
                result.error.message.defaultMessage
                    .contains("Invalid JWS format"),
            )
        }

    @Test
    fun testVerifyJws_NoneAlgorithmRejected() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>(relaxed = true)
            val mockSignatureService = mockk<SignatureService>(relaxed = true)

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS with "none" algorithm (base64url encoded header: {"alg":"none"})
            // eyJhbGciOiJub25lIn0 is base64url of {"alg":"none"}
            val noneJws = JwsCompact("eyJhbGciOiJub25lIn0.dGVzdA.")
            val args = VerifyJwsArgs(jws = noneJws, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should return result (with error messages in it)")
            assertTrue(
                result.value.errorMessages.any { it.contains("none") && it.contains("not allowed") },
                "Should report that 'none' algorithm is not allowed",
            )
        }

    @Test
    fun testVerifyJws_IdentifierResolutionError() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>(relaxed = true)

            // Mock identifier service to return error
            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.err(IdkError.fromString("Identifier resolution failed"))

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS with kid in header
            // eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2lkIn0 is base64url of {"alg":"ES256","kid":"test-kid"}
            val jwsWithKid = JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.dGVzdA.AAAA")
            val args = VerifyJwsArgs(jws = jwsWithKid, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should return result (with error messages)")
            assertTrue(
                result.value.errorMessages.any { it.contains("Failed to resolve identifier") },
                "Should report identifier resolution failure",
            )
        }

    @Test
    fun testVerifyJws_SignatureVerificationThrows() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            // Create a valid identifier result
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            // Mock signature service to throw exception
            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } throws
                RuntimeException("Verification failed unexpectedly")

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS with kid in header
            val jwsWithKid = JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithKid, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should return result (with error messages)")
            assertTrue(
                result.value.errorMessages.any { it.contains("Verification failed") },
                "Should report verification failure",
            )
        }

    @Test
    fun testVerifyJws_InvalidSignature() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            // Create a valid identifier result
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            // Mock signature service to return false (invalid signature)
            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns false

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS with kid in header
            val jwsWithKid = JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithKid, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should return result (with error messages)")
            assertTrue(
                result.value.errorMessages.any { it.contains("Invalid signature") },
                "Should report invalid signature",
            )
            assertTrue(!result.value.isValid, "isValid should be false")
        }

    @Test
    fun testVerifyJws_ValidSignature() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            // Create a valid identifier result
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            // Mock signature service to return true (valid signature)
            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns true

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS with kid in header
            val jwsWithKid = JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithKid, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should return result")
            assertTrue(result.value.errorMessages.isEmpty(), "Should have no error messages")
            assertTrue(result.value.isValid, "isValid should be true")
        }

    // ========================================================================
    // PrepareJwsCommandImpl Error Path Tests
    // ========================================================================

    @Test
    fun testPrepareJws_NullIssuer() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>(relaxed = true)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with null issuer
            val args =
                CreateJwsJsonArgs(
                    issuer = null,
                    payload = "test payload",
                )
            val result = command.execute(args)

            assertTrue(result.isErr, "Should fail when issuer is null")
            assertTrue(
                result.error.message.defaultMessage
                    .contains("Issuer is required"),
            )
        }

    @Test
    fun testPrepareJws_NullPayload() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>(relaxed = true)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with null payload
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = null,
                )
            val result = command.execute(args)

            assertTrue(result.isErr, "Should fail when payload is null")
            assertTrue(
                result.error.message.defaultMessage
                    .contains("Payload is required"),
            )
        }

    @Test
    fun testPrepareJws_IdentifierResolutionError() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Mock identifier service to return error
            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.err(IdkError.fromString("Identifier resolution failed"))

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = "test payload",
                )
            val result = command.execute(args)

            assertTrue(result.isErr, "Should fail when identifier resolution fails")
            assertTrue(
                result.error.message.defaultMessage
                    .contains("Identifier resolution failed"),
            )
        }

    // ========================================================================
    // PrepareJwsCommandImpl Branch Coverage Tests
    // ========================================================================

    @Test
    fun testPrepareJws_NoIdentifierInHeader() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a valid identifier result with a key that has signature algorithm
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with noIdentifierInHeader = true
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    opts = CreateJwsOpts(noIdentifierInHeader = true),
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with noIdentifierInHeader = true")
            // The protected header should NOT contain kid, jwk, or x5c
            val header = result.value.jws.protectedHeader.underlying
            assertTrue(
                !header.containsKey("kid") || header["kid"].toString() == "null",
                "Header should not contain kid when noIdentifierInHeader = true",
            )
            assertTrue(
                !header.containsKey("jwk"),
                "Header should not contain jwk when noIdentifierInHeader = true",
            )
            assertTrue(
                !header.containsKey("x5c"),
                "Header should not contain x5c when noIdentifierInHeader = true",
            )
        }

    @Test
    fun testPrepareJws_DIDMode() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a valid identifier result with a DID kid
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                    kid = "did:example:123#key-1",
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with DID mode
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.DID,
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with DID mode")
            val header = result.value.jws.protectedHeader.underlying
            assertTrue(header.containsKey("kid"), "Header should contain kid in DID mode")
            assertTrue(header["kid"].toString().contains("did:"), "kid should contain did: prefix")
        }

    @Test
    fun testPrepareJws_DIDMode_NonDIDKid() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a valid identifier result with a non-DID kid
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                    kid = "not-a-did-key",
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with DID mode but non-DID kid
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.DID,
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with DID mode even with non-DID kid")
            val header = result.value.jws.protectedHeader.underlying
            // In DID mode with non-DID kid, kid should NOT be added to header
            assertTrue(
                !header.containsKey("kid") || header["kid"].toString() == "null",
                "Header should not contain kid when kid doesn't start with did:",
            )
        }

    @Test
    fun testPrepareJws_JWKMode() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a valid identifier result with JWK
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with JWK mode
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.JWK,
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with JWK mode")
            val header = result.value.jws.protectedHeader.underlying
            assertTrue(header.containsKey("jwk"), "Header should contain jwk in JWK mode")
        }

    @Test
    fun testPrepareJws_KIDMode_WithKid() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a valid identifier result with kid
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                    kid = "my-key-id",
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with KID mode
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.KID,
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with KID mode and valid kid")
            val header = result.value.jws.protectedHeader.underlying
            assertTrue(header.containsKey("kid"), "Header should contain kid in KID mode")
            assertTrue(header["kid"].toString().contains("my-key-id"), "kid should match")
        }

    @Test
    fun testPrepareJws_KIDMode_WithoutKid() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a valid identifier result WITHOUT kid
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                    kid = null, // No kid
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with KID mode but no kid - should throw
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.KID,
                )

            try {
                command.execute(args)
                assertTrue(false, "Should have thrown IllegalArgumentException")
            } catch (e: IllegalArgumentException) {
                assertTrue(
                    e.message?.contains("Kid mode without an kid") == true,
                    "Exception message should mention Kid mode",
                )
            }
        }

    @Test
    fun testPrepareJws_AUTOMode_WithDIDKid() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a valid identifier result with a DID kid
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                    kid = "did:example:123#key-1",
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with AUTO mode and DID kid
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.AUTO,
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with AUTO mode and DID kid")
            val header = result.value.jws.protectedHeader.underlying
            assertTrue(header.containsKey("kid"), "Header should contain kid in AUTO mode with DID")
            assertTrue(header["kid"].toString().contains("did:"), "kid should contain did: prefix")
        }

    @Test
    fun testPrepareJws_AUTOMode_WithRegularKid() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a valid identifier result with a regular kid (not DID, no x5c)
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                    kid = "regular-key-id",
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with AUTO mode and regular kid
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.AUTO,
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with AUTO mode and regular kid")
            val header = result.value.jws.protectedHeader.underlying
            assertTrue(header.containsKey("kid"), "Header should contain kid in AUTO mode with regular kid")
            assertTrue(header["kid"].toString().contains("regular-key-id"), "kid should be the regular key id")
        }

    @Test
    fun testPrepareJws_WithClientIdAndScheme() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a valid identifier result
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                    kid = "test-kid",
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context =
                        IdentifierContext(
                            issuer = "https://example.com/issuer",
                            clientId = "test-client-id",
                            clientIdScheme = "pre-registered",
                        ),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Create issuer with context containing clientId and clientIdScheme
            val mockIssuer = mockk<com.sphereon.crypto.resolution.managed.ManagedIdentifierOpts>(relaxed = true)
            val mockContext =
                IdentifierContext(
                    clientId = "test-client-id",
                    clientIdScheme = "pre-registered",
                    issuer = "https://example.com/issuer",
                )
            coEvery { mockIssuer.context } returns mockContext

            val args =
                CreateJwsJsonArgs(
                    issuer = mockIssuer,
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.KID,
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed")
            // The payload should be updated with iss, client_id, and client_id_scheme
            val payloadStr = String(result.value.jws.payload)
            assertTrue(payloadStr.contains("iss"), "Payload should contain iss")
            assertTrue(payloadStr.contains("client_id"), "Payload should contain client_id")
            assertTrue(payloadStr.contains("client_id_scheme"), "Payload should contain client_id_scheme")
        }

    @Test
    fun testPrepareJws_ByteArrayPayload() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a valid identifier result
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                    kid = "test-kid",
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with ByteArray payload - updatePayloadWithIssuer should return the bytes as-is
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = "binary data".encodeToByteArray(),
                    mode = JwsIdentifierMode.KID,
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with ByteArray payload")
            // Payload should remain as bytes, not modified with iss
            val payloadStr = String(result.value.jws.payload)
            assertTrue(payloadStr == "binary data", "Payload should remain unchanged for ByteArray")
        }

    @Test
    fun testPrepareJws_StringPayload() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a valid identifier result
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                    kid = "test-kid",
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with String payload - updatePayloadWithIssuer should return the string as bytes
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = "plain text payload",
                    mode = JwsIdentifierMode.KID,
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with String payload")
            val payloadStr = String(result.value.jws.payload)
            assertTrue(payloadStr == "plain text payload", "Payload should remain unchanged for String")
        }

    @Test
    fun testPrepareJws_NoIssPayloadUpdate() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a valid identifier result
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                    kid = "test-kid",
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(issuer = "https://example.com/issuer"),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with noIssPayloadUpdate = true - iss should NOT be added to payload
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.KID,
                    opts = CreateJwsOpts(noIssPayloadUpdate = true),
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with noIssPayloadUpdate = true")
            val payloadStr = String(result.value.jws.payload)
            assertTrue(!payloadStr.contains("\"iss\""), "Payload should not contain iss when noIssPayloadUpdate = true")
        }

    // ========================================================================
    // VerifyJwsCommandImpl Additional Branch Coverage Tests
    // ========================================================================

    @Test
    fun testVerifyJws_WithProvidedIdentifier() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            // Create a valid identifier result
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            // The identifier will be resolved using the provided identifier, not from header
            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns true

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS and verify with explicit identifier
            val jwsWithKid = JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args =
                VerifyJwsArgs(
                    jws = jwsWithKid,
                    identifier = identifierResult, // Provide identifier explicitly
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed")
            assertTrue(result.value.isValid, "Should be valid")
        }

    @Test
    fun testVerifyJws_WithDIDKid() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            // Create a valid identifier result
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns true

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS with DID kid
            // eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOjEyMyNrZXktMSJ9 is base64url of {"alg":"ES256","kid":"did:example:123#key-1"}
            val jwsWithDidKid =
                JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDpleGFtcGxlOjEyMyNrZXktMSJ9.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithDidKid, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed")
            assertTrue(result.value.isValid, "Should be valid")
        }

    @Test
    fun testVerifyJws_WithEmbeddedJwk() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns true

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS with embedded JWK in header
            // Base64url of {"alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"test-x","y":"test-y"}}
            val headerWithJwk = "eyJhbGciOiJFUzI1NiIsImp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6InRlc3QteCIsInkiOiJ0ZXN0LXkifX0"
            val jwsWithEmbeddedJwk = JwsCompact("$headerWithJwk.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithEmbeddedJwk, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with embedded JWK")
            // Note: Whether it's valid depends on the mock signature service
            assertTrue(result.value.isValid, "Should be valid with mocked signature service")
        }

    @Test
    fun testVerifyJws_NoIdentifierInHeader() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>(relaxed = true)
            val mockSignatureService = mockk<SignatureService>(relaxed = true)

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS with no kid, jwk, or x5c in header
            // eyJhbGciOiJFUzI1NiJ9 is base64url of {"alg":"ES256"}
            val jwsNoIdentifier = JwsCompact("eyJhbGciOiJFUzI1NiJ9.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsNoIdentifier, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should return result")
            assertTrue(
                result.value.errorMessages.any { it.contains("Could not resolve identifier") },
                "Should report failure to resolve identifier from header",
            )
        }

    @Test
    fun testVerifyJws_UnsupportedIdentifierResultType() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>(relaxed = true)

            // Return an unexpected identifier result type (neither ManagedIdentifierKeyResult nor ExternalIdentifierResult)
            val unexpectedResult = mockk<com.sphereon.crypto.resolution.IdentifierOptsOrResult>(relaxed = true)
            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(unexpectedResult)

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            val jwsWithKid = JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithKid, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should return result")
            assertTrue(
                result.value.errorMessages.any { it.contains("Unsupported identifier result type") },
                "Should report unsupported identifier result type",
            )
        }

    @Test
    fun testVerifyJws_WithX5cCertChain() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>(relaxed = true)
            val mockSignatureService = mockk<SignatureService>()

            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns true

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS with x5c certificate chain in header
            // Base64url of {"alg":"ES256","x5c":["MIIB..."]}
            // Using a simplified test certificate
            @Suppress("ktlint:standard:max-line-length")
            val headerWithX5c =
                "eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlCK3pDQ0FhR2dBd0lCQWdJSkFJNjZkajdPUHRCV01Bb0dDQ3FHU000OUJBTUNNR294Q3pBSkJnTlZCQVlUQWs1TU1SVXdFd1lEVlFRS" +
                    "0RBeHRlVTl5WjJGdWFYcGhkR2x2YmpFUU1BNEdBMVVFQXd3SGRHVnpkRU5CTUJzR0NTcUdTSWIzRFFFSkFSWU9kR1Z6ZEVCMFpYTjBMbU52YlRBZUZ3MHlNakF4TWpBd01URXp" +
                    "NelJhRncweU16QXhNakF3TVRFek16UmFNR0F4Q3pBSkJnTlZCQVlUQWs1TU1SVXdFd1lEVlFRS0RBeHRlVTl5WjJGdWFYcGhkR2x2YmpFUU1BNEdBMVVFQXd3SFpXTnpRMmx5Z" +
                    "ERFb01DWUdDU3FHU0liM0RRRUpBUllaWldOekxYSmxaR2x5WldOMFFIUmxjM1F1WTI5dE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWZtajN5Mkt2RXFoN2x" +
                    "zUUg2VlIycGx3V2VnNXRkY0RxeTM1ck41RWNtSUpURDVYTmFGaURPK1MzRjVWd21mdUxNZ1JBelM4T1VmT00wdzd3YmVHMHFOTk1Fc3dDUVlEVlIwVEJBSXdBREFkQmdOVkhRN" +
                    "EVGZ1FVb0lsOVpGUHVXYTNmS1p0Y3RPOGUwZnRGU1VJd0h3WURWUjBqQkJnd0ZvQVVvSWw5WkZQdVdhM2ZLWnRjdE84ZTBmdEZTVUl3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUl" +
                    "oQUtQaE9icC9RQm1YWXhxYldGelowNGF1OU1DRnhZQkZiQ3dSMVBNelNEV1RBSUQ2MEZFWENXekFMVEF0R0N0bjhqQmxYVG5BZmZySmtGaU9RR0dNcnhOQT09Il19"
            val jwsWithX5c = JwsCompact("$headerWithX5c.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithX5c, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should return result for x5c verification")
        }

    @Test
    fun testVerifyJws_AlgorithmFallback() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            // Create identifier result with no signatureAlgorithm set on key
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                    signatureAlgorithm = null, // No signature algorithm set
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns true

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // The JWS header has alg set, but the key doesn't have signatureAlgorithm
            // The command should use the alg from header
            val jwsWithAlg = JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithAlg, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with algorithm fallback")
            assertTrue(result.value.isValid, "Should be valid")
        }

    @Test
    fun testPrepareJws_X5CMode_WithCertChain() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a mock key that returns a certificate chain from getX509CertificateChain()
            val testCertChain = arrayOf("MIIBtest-cert-1", "MIIBtest-cert-2")
            val mockKey = mockk<KeyType>(relaxed = true)
            every { mockKey.getX509CertificateChain() } returns testCertChain
            every { mockKey.getSignatureAlgorithm() } returns SignatureAlgorithm.ECDSA_SHA256

            @Suppress("UNCHECKED_CAST")
            val resolvedKeyInfo =
                ResolvedKeyInfo<KeyType>(
                    key = mockKey,
                    keyVisibility = KeyVisibility.PUBLIC,
                )
            val managedKeyInfo =
                ManagedKeyInfo<KeyType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                )

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = mockKey,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with X5C mode
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.X5C,
                )
            val result = command.execute(args)

            // The X5C mode should succeed and add x5c to header
            assertTrue(result.isOk, "Should succeed with X5C mode")
            val header = result.value.jws.protectedHeader.underlying
            assertTrue(header.containsKey("x5c"), "Header should contain x5c in X5C mode")
        }

    @Test
    fun testPrepareJws_X5CMode_NoCertChain() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a mock key that returns null from getX509CertificateChain()
            val mockKey = mockk<KeyType>(relaxed = true)
            every { mockKey.getX509CertificateChain() } returns null
            every { mockKey.getSignatureAlgorithm() } returns SignatureAlgorithm.ECDSA_SHA256

            @Suppress("UNCHECKED_CAST")
            val resolvedKeyInfo =
                ResolvedKeyInfo<KeyType>(
                    key = mockKey,
                    keyVisibility = KeyVisibility.PUBLIC,
                )
            val managedKeyInfo =
                ManagedKeyInfo<KeyType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                )

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = mockKey,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with X5C mode but no cert chain
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.X5C,
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with X5C mode even without cert chain")
            val header = result.value.jws.protectedHeader.underlying
            // Without cert chain, x5c should not be in header
            assertTrue(
                !header.containsKey("x5c") || header["x5c"].toString() == "null",
                "Header should not contain x5c when no cert chain",
            )
        }

    @Test
    fun testPrepareJws_AUTOMode_WithX5CChain() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create a mock key that returns a certificate chain (for AUTO mode to detect)
            // AUTO mode checks: 1) DID kid, 2) x5c chain, 3) regular kid
            // We want to test the x5c branch, so provide x5c chain but no DID kid
            val testCertChain = arrayOf("MIIBtest-cert-1", "MIIBtest-cert-2")
            val mockKey = mockk<KeyType>(relaxed = true)
            every { mockKey.getX509CertificateChain() } returns testCertChain
            every { mockKey.getSignatureAlgorithm() } returns SignatureAlgorithm.ECDSA_SHA256

            @Suppress("UNCHECKED_CAST")
            val resolvedKeyInfo =
                ResolvedKeyInfo<KeyType>(
                    key = mockKey,
                    keyVisibility = KeyVisibility.PUBLIC,
                    kid = null, // No DID kid, so AUTO mode should fall through to x5c check
                )
            val managedKeyInfo =
                ManagedKeyInfo<KeyType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                )

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = mockKey,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with AUTO mode - should detect x5c chain and include it
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.AUTO,
                )
            val result = command.execute(args)

            // The AUTO mode should succeed and detect x5c chain
            assertTrue(result.isOk, "Should succeed with AUTO mode and x5c chain")
            val header = result.value.jws.protectedHeader.underlying
            assertTrue(header.containsKey("x5c"), "Header should contain x5c in AUTO mode when x5c chain is present")
        }

    @Test
    fun testPrepareJws_JWKMode_NonJwkKey() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService>()

            // Create identifier result with a non-JWK key type (e.g., CoseKey)
            // For this test, we'll use a mock key that isn't a JwkType
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            val command =
                com.sphereon.crypto.jose.jws.command.PrepareJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                )

            // Test with JWK mode - should include jwk
            val args =
                CreateJwsJsonArgs(
                    issuer = mockk(relaxed = true),
                    payload = JsonObject(mapOf("test" to JsonPrimitive("data"))),
                    mode = JwsIdentifierMode.JWK,
                )
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed")
            val header = result.value.jws.protectedHeader.underlying
            assertTrue(header.containsKey("jwk"), "Header should contain jwk")
        }

    // ========================================================================
    // Additional VerifyJwsCommandImpl Branch Coverage Tests
    // ========================================================================

    @Test
    fun testVerifyJws_WithExternalIdentifierResult() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            // Create an ExternalIdentifierResult (different from ManagedIdentifierKeyResult)
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo = ResolvedKeyInfo.fromKey(ecJwk)
            val externalResult =
                com.sphereon.crypto.resolution.extern.ExternalIdentifierResult.Jwk(
                    identifierOpts =
                        com.sphereon.crypto.resolution.extern
                            .ExternalIdentifierJwkOpts(identifier = ecJwk),
                    jwks = arrayOf(resolvedKeyInfo),
                    keyInfo = resolvedKeyInfo,
                    x5c = null,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(externalResult)

            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns true

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            val jwsWithKid = JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithKid, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with ExternalIdentifierResult")
            assertTrue(result.value.isValid, "Should be valid")
        }

    @Test
    fun testVerifyJws_WithJwksUrlResultVerifiesWithoutSignatureService() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            val nimbusJwk =
                ECKeyGenerator(com.nimbusds.jose.jwk.Curve.P_256)
                    .keyID("platform-key")
                    .generate()
            val jwsObject =
                JWSObject(
                    JWSHeader
                        .Builder(JWSAlgorithm.ES256)
                        .keyID("platform-key")
                        .type(JOSEObjectType.JWT)
                        .build(),
                    Payload("""{"sub":"platform"}"""),
                )
            jwsObject.sign(ECDSASigner(nimbusJwk))

            val publicJwk = nimbusJwk.toPublicJWK()
            val sphereonJwk =
                Jwk(
                    kty = JwaKeyType.EC,
                    crv = JwaCurve.P_256,
                    x = publicJwk.x.toString(),
                    y = publicJwk.y.toString(),
                    kid = publicJwk.keyID,
                    alg = JwaAlgorithm.ES256,
                )
            val resolvedKeyInfo = ResolvedKeyInfo.fromKey(sphereonJwk)
            val jwksUrl = "https://platform.example/.well-known/jwks.json"
            val jwksOpts = ExternalIdentifierJwksUrlOpts(identifier = jwksUrl)
            val externalResult =
                ExternalIdentifierResult.JwksUrl(
                    identifierOpts = jwksOpts,
                    jwks = arrayOf(resolvedKeyInfo),
                    keyInfo = resolvedKeyInfo,
                    jwksUrl = jwksUrl,
                    selectedKid = "platform-key",
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(externalResult)
            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } throws
                IllegalStateException("JWKS URL verification must not require a configured KMS provider")

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            val result = command.execute(VerifyJwsArgs(jws = JwsCompact(jwsObject.serialize()), identifier = jwksOpts))

            assertTrue(result.isOk, "Should return a verification result")
            assertTrue(
                result.value.isValid,
                "JWKS URL public-key verification should succeed without consulting the tenant KMS provider: ${result.value.errorMessages}",
            )
            coVerify(exactly = 0) { mockSignatureService.isValidRawSignature(any(), any(), any()) }
        }

    @Test
    fun testVerifyJws_WithUnrecognizedAlgorithm() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            // Create a valid identifier result with no signatureAlgorithm
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                    signatureAlgorithm = null,
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns true

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS with an unrecognized algorithm
            // eyJhbGciOiJVTktOT1dOIiwia2lkIjoidGVzdC1raWQifQ is base64url of {"alg":"UNKNOWN","kid":"test-kid"}
            val jwsWithUnknownAlg = JwsCompact("eyJhbGciOiJVTktOT1dOIiwia2lkIjoidGVzdC1raWQifQ.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithUnknownAlg, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should return result even with unrecognized algorithm")
            // The algorithm fallback should handle the exception gracefully
        }

    @Test
    fun testVerifyJws_WithManagedKidWithoutAlgorithm() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            // Create a valid identifier result
            val ecJwk = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val resolvedKeyInfo =
                ResolvedKeyInfo<JwkType>(
                    key = ecJwk,
                    keyVisibility = KeyVisibility.PUBLIC,
                )

            @Suppress("UNCHECKED_CAST")
            val managedKeyInfo =
                ManagedKeyInfo<JwkType>(
                    alias = "test-key",
                    providerId = "test-provider",
                    resolvedKeyInfo = resolvedKeyInfo,
                ) as ManagedKeyInfo<KeyType>

            val identifierResult =
                ManagedIdentifierKeyResult(
                    context = IdentifierContext(),
                    keyInfo = managedKeyInfo,
                    identifier = ecJwk,
                )

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns true

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS with a managed kid (not DID) and no alg
            // eyJraWQiOiJtYW5hZ2VkLWtleS1pZCJ9 is base64url of {"kid":"managed-key-id"}
            // Actually, we need alg to be present but unrecognized/null for this test
            // Let's use a JWS without algorithm to test the null alg path
            // But JWS requires alg, so let's use a recognized alg to test the managed kid path
            val jwsWithManagedKid = JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6Im1hbmFnZWQta2V5LWlkIn0.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithManagedKid, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with managed kid")
            assertTrue(result.value.isValid, "Should be valid")
        }

    @Test
    fun testVerifyJws_X5cResolutionSuccess() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            // Chain resolution is mocked, but its public key and JWS signature must match mathematically.
            val nimbusJwk = ECKeyGenerator(Curve.P_256).generate()
            val publicJwk = nimbusJwk.toPublicJWK()
            val ecJwk = Jwk(
                kty = JwaKeyType.EC,
                crv = JwaCurve.P_256,
                x = publicJwk.x.toString(),
                y = publicJwk.y.toString(),
                alg = JwaAlgorithm.ES256,
            )
            val resolvedKeyInfo = ResolvedKeyInfo.fromKey(ecJwk)
            val externalResult = mockk<ExternalIdentifierResult.X5c>(relaxed = true)
            every { externalResult.keyInfo } returns resolvedKeyInfo
            every { externalResult.identifierOpts } returns ExternalIdentifierX5cOpts(listOf("cert1", "cert2"), verify = true)
            every { externalResult.verificationResult.error } returns false
            every { externalResult.verificationResult.critical } returns false
            every { externalResult.verificationResult.message } returns "Certificate chain validated"
            every { externalResult.verificationResult.publicKey } returns ecJwk

            // Mock for x5c resolution
            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.extern.ExternalIdentifierX5cOpts>()) } returns
                IdkResult.ok(externalResult)

            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } throws
                IllegalStateException("X.509 verification must not require a configured KMS provider")

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            val signed = JWSObject(
                JWSHeader.Builder(JWSAlgorithm.ES256)
                    .x509CertChain(listOf(Base64("cert1"), Base64("cert2")))
                    .build(),
                Payload("test"),
            ).apply { sign(ECDSASigner(nimbusJwk)) }
            val jwsWithX5c = JwsCompact(signed.serialize())
            val args = VerifyJwsArgs(jws = jwsWithX5c, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with x5c resolution")
            assertTrue(result.value.isValid, "Should be valid")
            coVerify(exactly = 1) {
                mockIdentifierService.resolve(
                    match<ExternalIdentifierX5cOpts> {
                        it.identifier == listOf("cert1", "cert2") && it.verify == true
                    },
                )
            }
            val parts = signed.serialize().split('.')
            val signature = parts[2].decodeFromBase64Url().apply {
                this[0] = (this[0].toInt() xor 1).toByte()
            }
            val tampered = command.execute(args.copy(
                jws = JwsCompact("${parts[0]}.${parts[1]}.${signature.encodeToBase64Url()}"),
            ))
            assertTrue(tampered.isOk, "A tampered signature must produce a verification result")
            assertFalse(tampered.value.isValid, "Successful chain resolution must not accept a tampered JWS")
            coVerify(exactly = 0) { mockSignatureService.isValidRawSignature(any(), any(), any()) }
        }

    @Test
    fun testVerifyJws_RejectsX5cWhenVerificationIsDisabled() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()
            val key = Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "test-x", y = "test-y")
            val keyInfo = ResolvedKeyInfo.fromKey(key)
            val x5cResult = mockk<ExternalIdentifierResult.X5c>(relaxed = true)
            every { x5cResult.keyInfo } returns keyInfo
            every { x5cResult.identifierOpts } returns ExternalIdentifierX5cOpts(listOf("cert1"), verify = false)
            every { x5cResult.verificationResult.error } returns false
            every { x5cResult.verificationResult.critical } returns false
            every { x5cResult.verificationResult.message } returns "X509 verification has been disabled"
            every { x5cResult.verificationResult.publicKey } returns key
            coEvery { mockIdentifierService.resolve(any<ExternalIdentifierX5cOpts>()) } returns IdkResult.ok(x5cResult)
            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns true
            val command = com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(mockExecution, mockIdentifierService, mockSignatureService)

            val result = command.execute(VerifyJwsArgs(
                jws = JwsCompact("eyJhbGciOiJFUzI1NiIsIng1YyI6WyJjZXJ0MSJdfQ.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                identifier = null,
            ))

            assertTrue(result.isOk)
            assertTrue(result.value.errorMessages.any { it.contains("chain validation", ignoreCase = true) })
            assertTrue(!result.value.isValid)
            coVerify(exactly = 0) { mockSignatureService.isValidRawSignature(any(), any(), any()) }
        }

    @Test
    fun testVerifyJws_X5cResolutionFailure() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>(relaxed = true)

            // Mock for x5c resolution to return error
            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.extern.ExternalIdentifierX5cOpts>()) } returns
                IdkResult.err(IdkError.fromString("X5c resolution failed"))

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            // Create a JWS with x5c in header
            val jwsWithX5c = JwsCompact("eyJhbGciOiJFUzI1NiIsIng1YyI6WyJjZXJ0MSIsImNlcnQyIl19.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithX5c, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should return result even with x5c resolution failure")
            assertTrue(
                result.value.errorMessages.any { it.contains("Failed to resolve identifier") },
                "Should report x5c resolution failure",
            )
        }

    @Test
    fun testVerifyJws_GeneralExceptionInLoop() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            // Make identifier service throw to trigger the outer catch block
            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } throws
                RuntimeException("Unexpected exception during processing")

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            val jwsWithKid = JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithKid, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should return result even with unexpected exception")
            assertTrue(
                result.value.errorMessages.any { it.contains("Unexpected error") },
                "Should report unexpected error",
            )
        }

    @Test
    fun testVerifyJws_RejectsDeactivatedDidBeforeCrypto() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()
            val didResult = mockk<ExternalIdentifierResult.Did>(relaxed = true)

            every { didResult.didResolutionResult.didDocumentMetadata } returns mapOf("deactivated" to "true")
            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(didResult)
            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns true

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )
            val result =
                command.execute(
                    VerifyJwsArgs(
                        jws = JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
                        identifier = null,
                    ),
                )

            assertTrue(result.isOk, "deactivated DID rejection must remain a structured validation result")
            assertFalse(result.value.isValid)
            assertTrue(result.value.errorMessages.any { it.contains("DID is deactivated", ignoreCase = true) })
            assertFalse(result.value.trustEstablished)
            assertEquals(null, result.value.cryptoVerified)
            coVerify(exactly = 0) { mockSignatureService.isValidRawSignature(any(), any(), any()) }
        }

    @Test
    fun testVerifyJws_NonResolvedKeyInfo() =
        runTest {
            val mockExecution = mockk<SessionExecution>(relaxed = true)
            val mockIdentifierService = mockk<com.sphereon.crypto.resolution.IdentifierService>()
            val mockSignatureService = mockk<SignatureService>()

            // Create a ManagedIdentifierKeyResult with a non-ResolvedKeyInfo keyInfo
            // Use a mocked ManagedKeyInfo that is NOT a ResolvedKeyInfo
            val mockManagedKeyInfo = mockk<ManagedKeyInfo<KeyType>>(relaxed = true)
            every { mockManagedKeyInfo.signatureAlgorithm } returns null
            every { mockManagedKeyInfo.key } returns mockk(relaxed = true)

            val identifierResult = mockk<ManagedIdentifierKeyResult>(relaxed = true)
            every { identifierResult.keyInfo } returns mockManagedKeyInfo

            coEvery { mockIdentifierService.resolve(any<com.sphereon.crypto.resolution.IdentifierOptsOrResult>()) } returns
                IdkResult.ok(identifierResult)

            coEvery { mockSignatureService.isValidRawSignature(any(), any(), any()) } returns true

            val command =
                com.sphereon.crypto.jose.jws.command.VerifyJwsCommandImpl(
                    execution = mockExecution,
                    identifierService = mockIdentifierService,
                    signatureService = mockSignatureService,
                )

            val jwsWithKid = JwsCompact("eyJhbGciOiJFUzI1NiIsImtpZCI6InRlc3Qta2lkIn0.dGVzdA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            val args = VerifyJwsArgs(jws = jwsWithKid, identifier = null)
            val result = command.execute(args)

            assertTrue(result.isOk, "Should succeed with non-ResolvedKeyInfo")
            // This test exercises the else branch in the when clause for keyInfo update
        }
}
