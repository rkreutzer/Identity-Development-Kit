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
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.jose.jws.JwsJsonGeneralWithIdentifiers
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.common.vpTokenOf
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejectionReason
import com.sphereon.openid.oid4vp.verifier.HolderBindingResult
import com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse
import com.sphereon.openid.oid4vp.verifier.ValidateAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.verifier.ValidationResult
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerificationArgs
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerificationResult
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerifier
import com.sphereon.openid.oid4vp.verifier.VerifyHolderBindingArgs
import com.sphereon.openid.oid4vp.verifier.VerifyHolderBindingCommand
import com.sphereon.openid.oid4vp.verifier.impl.testutil.Oid4vpVerifierTestContext
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.statuslist.CredentialStatusPolicy
import com.sphereon.statuslist.CredentialStatusReference
import com.sphereon.statuslist.ResolvedStatus
import com.sphereon.statuslist.StatusValues
import com.sphereon.statuslist.spi.CredentialStatusVerifier
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * A credential discarded on credential-status grounds must reach the caller as a typed
 * [com.sphereon.openid.oid4vp.verifier.CredentialValidationRejection], beside - not instead of -
 * the existing prose error.
 */
class CredentialRejectionReportingTest {
    private val testContext = Oid4vpVerifierTestContext("credential-rejection-reporting-test", this)

    @Test
    fun revokedCredentialReportsATypedRejection() =
        runTest {
            val before = Clock.System.now().toEpochMilliseconds()
            val result = validateSdJwtWithStatus("revoked-rejection", FixedResolvedStatusVerifier(StatusValues.INVALID))
            val after = Clock.System.now().toEpochMilliseconds()

            assertIs<Ok<ValidationResult>>(result)
            assertFalse(result.value.valid)
            val rejection = result.value.rejections.single()
            assertEquals("identity_credential", rejection.credentialQueryId)
            assertEquals(CredentialValidationRejectionReason.REVOKED, rejection.reason)
            assertEquals(StatusValues.INVALID, rejection.statusValue)
            assertTrue(rejection.checkedAtEpochMillis in before..after)
            // The prose error is kept beside the typed rejection.
            assertTrue(result.value.errors.any { error -> error == "identity_credential is revoked" })
        }

    @Test
    fun suspendedCredentialReportsSuspended() =
        runTest {
            val result = validateSdJwtWithStatus("suspended-rejection", FixedResolvedStatusVerifier(StatusValues.SUSPENDED))

            assertIs<Ok<ValidationResult>>(result)
            assertFalse(result.value.valid)
            val rejection = result.value.rejections.single()
            assertEquals(CredentialValidationRejectionReason.SUSPENDED, rejection.reason)
            assertEquals(StatusValues.SUSPENDED, rejection.statusValue)
        }

    @Test
    fun unresolvableStatusReportsStatusUnresolvable() =
        runTest {
            val result = validateSdJwtWithStatus("unresolvable-rejection", UnresolvableStatusVerifier())

            assertIs<Ok<ValidationResult>>(result)
            assertFalse(result.value.valid)
            val rejection = result.value.rejections.single()
            assertEquals(CredentialValidationRejectionReason.STATUS_UNRESOLVABLE, rejection.reason)
            // An unresolvable reference has no status value to report.
            assertNull(rejection.statusValue)
            // The status list URI never leaks into the rejection channel.
            assertFalse(rejection.toString().contains("https://"))
        }

    @Test
    fun nonAcceptedApplicationStatusReportsStatusNotAccepted() =
        runTest {
            // An issuer-defined multi-bit state the policy does not accept. It asserts neither
            // revocation nor suspension, so it must not be reported as a revocation.
            val applicationStatusValue = 3
            val result = validateSdJwtWithStatus("not-accepted-rejection", FixedResolvedStatusVerifier(applicationStatusValue))

            assertIs<Ok<ValidationResult>>(result)
            assertFalse(result.value.valid)
            val rejection = result.value.rejections.single()
            assertEquals(CredentialValidationRejectionReason.STATUS_NOT_ACCEPTED, rejection.reason)
            assertEquals(applicationStatusValue, rejection.statusValue)
            assertTrue(result.value.errors.any { error -> error == "identity_credential is status 3" })
        }

    @Test
    fun requiredButAbsentStatusReportsStatusRequiredButAbsent() =
        runTest {
            val result =
                validateSdJwtWithStatus(
                    correlationState = "required-but-absent-rejection",
                    statusVerifier = NoStatusReferenceVerifier(),
                    credentialStatusPolicies = mapOf("identity_credential" to CredentialStatusPolicy(requireStatus = true)),
                )

            assertIs<Ok<ValidationResult>>(result)
            assertFalse(result.value.valid)
            val rejection = result.value.rejections.single()
            assertEquals(CredentialValidationRejectionReason.STATUS_REQUIRED_BUT_ABSENT, rejection.reason)
            assertNull(rejection.statusValue)
        }

    private suspend fun validateSdJwtWithStatus(
        correlationState: String,
        statusVerifier: CredentialStatusVerifier,
        credentialStatusPolicies: Map<String, CredentialStatusPolicy>? = null,
    ): IdkResult<ValidationResult, IdkError> {
        val sdJwt = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlIiwidmN0IjoidXJuOnRlc3Q6aWRlbnRpdHkifQ.signature~WyJhYmMxMjMiLCJmaXJzdF9uYW1lIiwiSm9obiJd~eyJhbGciOiJFUzI1NiJ9.kb.sig"
        val originalRequest =
            AuthorizationRequest(
                clientId = "https://verifier.example.com",
                redirectUri = "https://verifier.example.com/callback",
                state = correlationState,
            )
        val args =
            ValidateAuthorizationResponseArgs(
                parsedResponse =
                    ParsedAuthorizationResponse(
                        vpToken = vpTokenOf("identity_credential", sdJwt),
                        state = correlationState,
                        rawVpToken = """{"identity_credential":["$sdJwt"]}""",
                    ),
                originalRequest = originalRequest,
                dcqlQuery =
                    DcqlQuery(
                        credentials =
                            listOf(
                                DcqlCredentialQuery(id = "identity_credential", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity")),
                            ),
                    ),
                expectedNonce = "nonce123",
            )
        val authorizationSessionStore = TestAuthorizationSessionStore()
        val now = Clock.System.now().toEpochMilliseconds()
        val session =
            AuthorizationSession(
                instanceId = "verifier-instance-$correlationState",
                sessionId = "validation-session-$correlationState",
                correlationId = correlationState,
                dcqlQuery = args.dcqlQuery,
                authorizationRequest = originalRequest,
                status = AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_RECEIVED,
                parsedResponse = args.parsedResponse,
                credentialStatusPolicies = credentialStatusPolicies,
                createdAt = now,
                updatedAt = now,
                expiresAt = now + 600_000,
            )
        assertIs<Ok<*>>(authorizationSessionStore.put(correlationState, session, ttlSeconds = 600))

        val builtInLoader =
            com.sphereon.jsonld.loader.BuiltInContextLinkedDataDocumentLoader(
                com.sphereon.jsonld.loader
                    .DefaultBuiltInContextRegistry(),
            )
        return ValidateAuthorizationResponseCommandImpl(
            execution = testContext.execution,
            authorizationSessionStore = authorizationSessionStore,
            businessAuthorizations = emptySet(),
            credentialTypeMatcher = com.sphereon.openid.oid4vp.verifier.impl.testutil.testCredentialTypeMatcher(),
            verifyHolderBindingCommand = VerifiedHolderBindingCommand,
            verifyJwsCommand = InvalidVerifyJwsCommand,
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
            vcdmDataIntegrityVerifier = UnusedVcdmDataIntegrityVerifier,
            credentialStatusVerifiers = setOf(statusVerifier),
            credentialTrustValidators = emptySet(),
        ).validateAuthorizationResponse(args)
    }
}

/** Reports one status reference and resolves it to a fixed value, without a parseable status token. */
private class FixedResolvedStatusVerifier(
    private val value: Int,
) : CredentialStatusVerifier {
    override val mechanism: String = "test"

    override fun references(credentialClaims: JsonObject) =
        listOf(CredentialStatusReference(mechanism = mechanism, uri = "https://issuer.example.com/sl", index = 0))

    override suspend fun resolve(reference: CredentialStatusReference) =
        Ok(ResolvedStatus(value = value, valid = value == StatusValues.VALID, statusListUri = reference.uri))
}

/** Recognizes no status reference at all, driving the require-but-absent policy arm. */
private class NoStatusReferenceVerifier : CredentialStatusVerifier {
    override val mechanism: String = "test"

    override fun references(credentialClaims: JsonObject): List<CredentialStatusReference> = emptyList()

    override suspend fun resolve(reference: CredentialStatusReference): IdkResult<ResolvedStatus, IdkError> =
        Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "no reference is ever reported"))
}

/** Reports a status reference that cannot be resolved, driving the fail-closed policy default. */
private class UnresolvableStatusVerifier : CredentialStatusVerifier {
    override val mechanism: String = "test"

    override fun references(credentialClaims: JsonObject) =
        listOf(CredentialStatusReference(mechanism = mechanism, uri = "https://issuer.example.com/sl", index = 7))

    override suspend fun resolve(reference: CredentialStatusReference): IdkResult<ResolvedStatus, IdkError> =
        Err(IdkError.NOT_FOUND_ERROR(resource = "statusList:${reference.uri}", message = "status list is unavailable"))
}

private object VerifiedHolderBindingCommand : VerifyHolderBindingCommand {
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

private object InvalidVerifyJwsCommand : VerifyJwsCommand {
    override val commandId: String = VerifyJwsCommand.COMMAND_ID
    override val inputTypeToken: TypeToken<VerifyJwsArgs> = typeToken<VerifyJwsArgs>()
    override val outputTypeToken: TypeToken<JwsValidationResult> = typeToken<JwsValidationResult>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is VerifyJwsArgs

    override suspend fun execute(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> =
        Ok(
            JwsValidationResult(
                jws = JwsJsonGeneralWithIdentifiers(payload = "", signatures = emptyList()),
                isValid = false,
                errorMessages = listOf("invalid issuer signature"),
                parsedPayload = JsonObject(emptyMap()),
                trustEstablished = true,
                cryptoVerified = false,
            ),
        )
}

private object UnusedVcdmDataIntegrityVerifier : VcdmDataIntegrityVerifier {
    override suspend fun verify(args: VcdmDataIntegrityVerificationArgs): IdkResult<VcdmDataIntegrityVerificationResult, IdkError> =
        Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Data Integrity test stub was not configured"))
}
