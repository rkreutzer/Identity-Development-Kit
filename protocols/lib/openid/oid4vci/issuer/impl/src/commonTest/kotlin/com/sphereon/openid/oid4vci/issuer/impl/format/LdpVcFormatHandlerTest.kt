/*
 * Copyright 2026 Sphereon International B.V.
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

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.dataintegrity.command.AddProofInput
import com.sphereon.crypto.dataintegrity.command.AddProofOutput
import com.sphereon.crypto.dataintegrity.command.AddProofServiceCommand
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vc.common.vcdm.VcdmProfiles
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialDefinition
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import com.sphereon.statuslist.StatusListBinding
import com.sphereon.statuslist.StatusListSpec
import com.sphereon.statuslist.spi.CredentialStatusEnricher
import com.sphereon.statuslist.spi.ReservedStatus
import com.sphereon.statuslist.spi.StatusClaimMergeTarget
import com.sphereon.statuslist.spi.StatusEnrichmentContext
import com.sphereon.statuslist.spi.StatusReservationHandle
import dev.zacsweers.metro.Provider
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Instant

class LdpVcFormatHandlerTest {
    @Test
    fun issuesBareVcdm11CredentialAndAddsDataIntegrityProof() = runTest {
        val command = RecordingAddProofCommand()
        val handler = LdpVcFormatHandler(command)
        val result = handler.issueCredential(CredentialRequest(format = CredentialFormat.LDP_VC.value), context(VcdmProfiles.V1_1_CONTEXT))

        assertTrue(result.isOk, "issuance must succeed: ${if (result.isErr) result.error else ""}")
        val credential = result.value.credential.jsonObject
        assertEquals(CredentialFormat.LDP_VC.value, result.value.format)
        assertEquals(listOf(VcdmProfiles.V1_1_CONTEXT), credential["@context"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertEquals(listOf("VerifiableCredential", "ExampleCredential"), credential["type"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertNotNull(credential["issuanceDate"])
        assertFalse(credential.containsKey("validFrom"))
        assertEquals("did:example:issuer", credential["issuer"]!!.jsonPrimitive.content)
        assertEquals(
            setOf("@context", "type", "issuer", "issuanceDate", "credentialSubject"),
            command.lastInput!!.unsecuredDocument.keys,
        )
        assertEquals("eddsa-jcs-2022", command.lastInput!!.proofs.single().cryptosuite)
        assertEquals("https://issuer.example/keys#assertion", command.lastInput!!.proofs.single().verificationMethod)
        assertEquals("kms:tenant:issuer", command.lastInput!!.proofs.single().signingKeyRef)
        assertEquals("assertionMethod", command.lastInput!!.proofs.single().proofPurpose.value)
        assertEquals("Alice", credential["credentialSubject"]!!.jsonObject["name"]!!.jsonPrimitive.content)
        assertFalse(credential["credentialSubject"]!!.jsonObject.containsKey("id"))
        assertFalse(credential.toString().contains("did:example:holder"))
        assertNotNull(credential["proof"], "AddProofServiceCommand must attach the proof")
    }

    @Test
    fun issuesBareVcdm20CredentialAndPreservesConfiguredContextAndTypes() = runTest {
        val command = RecordingAddProofCommand()
        val handler = LdpVcFormatHandler(command)
        val context = context(VcdmProfiles.V2_0_CONTEXT, extraContext = "https://example.com/credentials/context")
        val result = handler.issueCredential(CredentialRequest(format = CredentialFormat.LDP_VC.value), context)

        assertTrue(result.isOk, "issuance must succeed: ${if (result.isErr) result.error else ""}")
        val credential = result.value.credential.jsonObject
        assertEquals(
            listOf(VcdmProfiles.V2_0_CONTEXT, "https://example.com/credentials/context"),
            credential["@context"]!!.jsonArray.map { it.jsonPrimitive.content },
        )
        assertEquals(listOf("VerifiableCredential", "ExampleCredential"), credential["type"]!!.jsonArray.map { it.jsonPrimitive.content })
        assertNotNull(credential["validFrom"])
        assertFalse(credential.containsKey("issuanceDate"))
        assertEquals(
            setOf("@context", "type", "issuer", "validFrom", "credentialSubject"),
            command.lastInput!!.unsecuredDocument.keys,
        )
    }

    @Test
    fun keepsCredentialIdIndependentFromMultipleCredentialSubjectsAndAuthorizationSubject() = runTest {
        for (baseContext in listOf(VcdmProfiles.V1_1_CONTEXT, VcdmProfiles.V2_0_CONTEXT)) {
            val command = RecordingAddProofCommand()
            val result =
                LdpVcFormatHandler(command).issueCredential(
                    CredentialRequest(format = CredentialFormat.LDP_VC.value),
                    context(baseContext).copy(
                        subject = "opaque-authorization-subject",
                        attributes = emptyMap(),
                        credentialId = "https://example.com/credentials/42",
                        credentialSubjects =
                            listOf(
                                buildJsonObject {
                                    put("id", "https://example.com/subjects/alice")
                                    put("name", "Alice")
                                },
                                buildJsonObject {
                                    put("id", "https://example.com/subjects/bob")
                                    put("name", "Bob")
                                },
                            ),
                    ),
                )

            assertTrue(result.isOk, "VCDM $baseContext issuance must succeed: ${if (result.isErr) result.error else ""}")
            val credential = result.value.credential.jsonObject
            assertEquals("https://example.com/credentials/42", credential["id"]!!.jsonPrimitive.content)
            assertEquals(
                listOf("https://example.com/subjects/alice", "https://example.com/subjects/bob"),
                credential["credentialSubject"]!!.jsonArray.map { it.jsonObject["id"]!!.jsonPrimitive.content },
            )
            assertFalse(credential.toString().contains("opaque-authorization-subject"))
            assertFalse(
                credential["credentialSubject"]!!.jsonArray.any {
                    it.jsonObject["id"]?.jsonPrimitive?.content == credential["id"]!!.jsonPrimitive.content
                },
            )
        }
    }

    @Test
    fun rejectsAmbiguousSubjectInputsAndMalformedIndependentIdentifiersBeforeProof() = runTest {
        val command = RecordingAddProofCommand()
        val handler = LdpVcFormatHandler(command)
        val explicitSubject = buildJsonObject { put("name", "Alice") }

        val ambiguous =
            handler.issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V2_0_CONTEXT).copy(credentialSubjects = listOf(explicitSubject)),
            )
        val badCredentialId =
            handler.issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V2_0_CONTEXT).copy(credentialId = "not a URI"),
            )
        val badSubjectId =
            handler.issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V2_0_CONTEXT).copy(
                    attributes = emptyMap(),
                    credentialSubjects = listOf(buildJsonObject { put("id", 42) }),
                ),
            )

        assertTrue(ambiguous.isErr)
        assertTrue(badCredentialId.isErr)
        assertTrue(badSubjectId.isErr)
        assertEquals(0, command.calls)
    }

    @Test
    fun preservesFutureSemanticValidityWithoutConfusingItWithProofCreationTime() = runTest {
        val futureStart = Instant.parse("2099-01-02T03:04:05Z")
        val futureEnd = Instant.parse("2099-02-03T04:05:06Z")

        for (baseContext in listOf(VcdmProfiles.V1_1_CONTEXT, VcdmProfiles.V2_0_CONTEXT)) {
            val command = RecordingAddProofCommand()
            val result =
                LdpVcFormatHandler(command).issueCredential(
                    CredentialRequest(format = CredentialFormat.LDP_VC.value),
                    context(baseContext).copy(validFrom = futureStart, validUntil = futureEnd),
                )

            assertTrue(result.isOk, "future VCDM validity is structurally valid")
            val credential = result.value.credential.jsonObject
            if (baseContext == VcdmProfiles.V1_1_CONTEXT) {
                assertEquals(futureStart.toString(), credential["issuanceDate"]!!.jsonPrimitive.content)
                assertEquals(futureEnd.toString(), credential["expirationDate"]!!.jsonPrimitive.content)
            } else {
                assertEquals(futureStart.toString(), credential["validFrom"]!!.jsonPrimitive.content)
                assertEquals(futureEnd.toString(), credential["validUntil"]!!.jsonPrimitive.content)
            }
            assertTrue(command.lastInput!!.proofs.single().created != futureStart.toString())
        }
    }

    @Test
    fun mergesVcdmPropertiesBeforeIssuingBothVcdmVersions() = runTest {
        val v1Command = RecordingAddProofCommand()
        val v1Result =
            LdpVcFormatHandler(v1Command).issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V1_1_CONTEXT).copy(
                    vcdmProperties = buildJsonObject {
                        put("evidence", buildJsonObject { put("type", "DocumentVerification") })
                        put("https://example.com/extension", "preserved")
                    },
                ),
            )
        val v2Command = RecordingAddProofCommand()
        val v2Result =
            LdpVcFormatHandler(v2Command).issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V2_0_CONTEXT).copy(
                    vcdmProperties = buildJsonObject {
                        put("name", "Employee credential")
                        put("description", "A credential")
                        put("https://example.com/extension", "preserved")
                    },
                ),
            )

        assertTrue(v1Result.isOk)
        assertEquals("preserved", v1Command.lastInput!!.unsecuredDocument["https://example.com/extension"]!!.jsonPrimitive.content)
        assertNotNull(v1Command.lastInput!!.unsecuredDocument["evidence"])
        assertTrue(v2Result.isOk)
        assertEquals("Employee credential", v2Command.lastInput!!.unsecuredDocument["name"]!!.jsonPrimitive.content)
        assertEquals("A credential", v2Command.lastInput!!.unsecuredDocument["description"]!!.jsonPrimitive.content)
    }

    @Test
    fun federationEntityIssuerSignsOpenIdFederationTermsOfUseForBothVcdmVersions() = runTest {
        for (baseContext in listOf(VcdmProfiles.V1_1_CONTEXT, VcdmProfiles.V2_0_CONTEXT)) {
            val command = RecordingAddProofCommand()
            val result =
                LdpVcFormatHandler(command).issueCredential(
                    CredentialRequest(format = CredentialFormat.LDP_VC.value),
                    context(baseContext).copy(federationEntityIdentifier = "https://issuer.example/oid4vci"),
                )

            assertTrue(result.isOk, "VCDM $baseContext issuance must succeed: ${if (result.isErr) result.error else ""}")
            val expected =
                buildJsonObject {
                    put("type", "OpenIDFederation")
                    put("policyId", "https://issuer.example/oid4vci")
                }
            // Part of the document handed to AddProof, so the proof covers it.
            assertEquals(expected, command.lastInput!!.unsecuredDocument["termsOfUse"])
            assertEquals("did:example:issuer", result.value.credential.jsonObject["issuer"]!!.jsonPrimitive.content)
        }
    }

    @Test
    fun rejectsProtectedVcdmPropertyBeforeStatusReservationOrProof() = runTest {
        val command = RecordingAddProofCommand()
        val status = RecordingStatusEnricher()
        val result =
            LdpVcFormatHandler(command, Provider { status }).issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V2_0_CONTEXT).copy(
                    statusListBinding = StatusListBinding("status-list", StatusListSpec.BITSTRING_STATUS_LIST),
                    vcdmProperties = buildJsonObject { put("issuer", "did:example:attacker") },
                ),
            )

        assertTrue(result.isErr)
        assertEquals("invalid_vcdm_credential", result.error.code)
        assertEquals(0, command.calls)
        assertEquals(0, status.reserveCalls)
    }

    @Test
    fun reservesEmbedsAndBindsCredentialStatusUsingTheIssuedUri() = runTest {
        val command = RecordingAddProofCommand()
        val status = RecordingStatusEnricher()
        val result =
            LdpVcFormatHandler(command, Provider { status }).issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V2_0_CONTEXT).copy(
                    statusListBinding = StatusListBinding("status-list", StatusListSpec.BITSTRING_STATUS_LIST),
                ),
            )

        assertTrue(result.isOk, "status-enabled issuance must succeed: ${if (result.isErr) result.error else ""}")
        val credential = result.value.credential.jsonObject
        val credentialId = credential["id"]!!.jsonPrimitive.content
        assertTrue(credentialId.startsWith("urn:uuid:"))
        assertEquals(1, status.reserveCalls)
        assertNotNull(credential["credentialStatus"])
        assertEquals(credentialId, status.boundCredentialId)
        assertEquals(status.handle, status.boundHandle)
        assertNull(status.cancelledHandle)
        assertEquals(credentialId, command.lastInput!!.unsecuredDocument["id"]!!.jsonPrimitive.content)
        assertNotNull(command.lastInput!!.unsecuredDocument["credentialStatus"])
        assertEquals(
            listOf(VcdmProfiles.V2_0_CONTEXT),
            command.lastInput!!.unsecuredDocument["@context"]!!.jsonArray.map { it.jsonPrimitive.content },
        )
        assertFalse(command.lastInput!!.unsecuredDocument.containsKey("proof"))
    }

    @Test
    fun rejectsTokenStatusListWithoutReservingAnEntry() = runTest {
        val command = RecordingAddProofCommand()
        val status = RecordingStatusEnricher()
        val result =
            LdpVcFormatHandler(command, Provider { status }).issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V1_1_CONTEXT).copy(
                    statusListBinding = StatusListBinding("status-list", StatusListSpec.TOKEN_STATUS_LIST),
                ),
            )

        assertTrue(result.isErr)
        assertEquals(0, status.reserveCalls)
        assertEquals(0, command.calls)
    }

    @Test
    fun vcdm11StatusAddsTheBitstringVocabularyBeforeProof() = runTest {
        val command = RecordingAddProofCommand()
        val status = RecordingStatusEnricher()
        val result =
            LdpVcFormatHandler(command, Provider { status }).issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V1_1_CONTEXT).copy(
                    statusListBinding = StatusListBinding("status-list", StatusListSpec.BITSTRING_STATUS_LIST),
                ),
            )

        assertTrue(result.isOk)
        assertEquals(
            listOf(VcdmProfiles.V1_1_CONTEXT, "https://www.w3.org/ns/credentials/status/v1"),
            command.lastInput!!.unsecuredDocument["@context"]!!.jsonArray.map { it.jsonPrimitive.content },
        )
    }

    @Test
    fun rejectsNonVcStatusMergeTargetAndCancelsItsReservation() = runTest {
        val command = RecordingAddProofCommand()
        val status = RecordingStatusEnricher(mergeTarget = StatusClaimMergeTarget.MDOC_STATUS)
        val result =
            LdpVcFormatHandler(command, Provider { status }).issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V2_0_CONTEXT).copy(
                    statusListBinding = StatusListBinding("status-list", StatusListSpec.BITSTRING_STATUS_LIST),
                ),
            )

        assertTrue(result.isErr)
        assertEquals(0, command.calls)
        assertEquals(status.handle, status.cancelledHandle)
    }

    @Test
    fun signingFailureCancelsReservedStatusAndPreservesProofError() = runTest {
        val proofError = IdkError.fromString(code = "PROOF_FAILED", message = "test signing failure")
        val command = RecordingAddProofCommand(proofError)
        val status = RecordingStatusEnricher()
        val result =
            LdpVcFormatHandler(command, Provider { status }).issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V1_1_CONTEXT).copy(
                    statusListBinding = StatusListBinding("status-list", StatusListSpec.BITSTRING_STATUS_LIST),
                ),
            )

        assertTrue(result.isErr)
        assertEquals("PROOF_FAILED", result.error.code)
        assertEquals(status.handle, status.cancelledHandle)
        assertNull(status.boundHandle)
    }

    @Test
    fun postMergeValidationFailureCancelsReservedStatusBeforeProof() = runTest {
        val command = RecordingAddProofCommand()
        val status = RecordingStatusEnricher(claim = buildJsonObject { put("id", "https://issuer.example/status#9") })
        val result =
            LdpVcFormatHandler(command, Provider { status }).issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V1_1_CONTEXT).copy(
                    statusListBinding = StatusListBinding("status-list", StatusListSpec.BITSTRING_STATUS_LIST),
                ),
            )

        assertTrue(result.isErr)
        assertEquals(status.handle, status.cancelledHandle)
        assertEquals(0, command.calls)
    }

    @Test
    fun bindingFailureCancelsReservedStatusAndPreservesBindError() = runTest {
        val bindError = IdkError.fromString(code = "STATUS_BIND_FAILED", message = "test bind failure")
        val command = RecordingAddProofCommand()
        val status = RecordingStatusEnricher(bindError = bindError)
        val result =
            LdpVcFormatHandler(command, Provider { status }).issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V2_0_CONTEXT).copy(
                    statusListBinding = StatusListBinding("status-list", StatusListSpec.BITSTRING_STATUS_LIST),
                ),
            )

        assertTrue(result.isErr)
        assertEquals("STATUS_BIND_FAILED", result.error.code)
        assertEquals(status.handle, status.cancelledHandle)
        assertEquals(status.handle, status.boundHandle)
    }

    @Test
    fun acceptsHttpsControlledIdentifierWithoutDIDVerificationMethodAssumption() = runTest {
        val command = RecordingAddProofCommand()
        val handler = LdpVcFormatHandler(command)
        val result =
            handler.issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(
                    VcdmProfiles.V2_0_CONTEXT,
                    issuer = "https://issuer.example",
                    verificationMethod = "https://keys.example/jwks#issuer-key",
                ),
            )

        assertTrue(result.isOk, "HTTPS controlled identifiers must be accepted")
        assertEquals("https://keys.example/jwks#issuer-key", command.lastInput!!.proofs.single().verificationMethod)
    }

    @Test
    fun rejectsMissingOrAmbiguousVcdmDefinitionBeforeProofCommand() = runTest {
        val command = RecordingAddProofCommand()
        val handler = LdpVcFormatHandler(command)

        val missingDefinition = handler.issueCredential(CredentialRequest(format = CredentialFormat.LDP_VC.value), contextWithDefinition(null))
        val ambiguousContext =
            handler.issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                contextWithDefinition(
                    CredentialDefinition(
                        context = listOf(VcdmProfiles.V1_1_CONTEXT, VcdmProfiles.V2_0_CONTEXT),
                        type = listOf("VerifiableCredential", "ExampleCredential"),
                    ),
                ),
            )
        val malformedContext =
            handler.issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                contextWithDefinition(
                    CredentialDefinition(
                        context = listOf(VcdmProfiles.V2_0_CONTEXT, "not-an-iri"),
                        type = listOf("VerifiableCredential", "ExampleCredential"),
                    ),
                ),
            )

        assertFalse(missingDefinition.isOk)
        assertFalse(ambiguousContext.isOk)
        assertFalse(malformedContext.isOk)
        assertEquals(0, command.calls)
    }

    @Test
    fun rejectsMalformedTypesIdentifiersAndMissingExplicitSigningInputs() = runTest {
        val command = RecordingAddProofCommand()
        val handler = LdpVcFormatHandler(command)

        val noVerifiableCredential =
            handler.issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                contextWithDefinition(
                    CredentialDefinition(
                        context = listOf(VcdmProfiles.V2_0_CONTEXT),
                        type = listOf("ExampleCredential"),
                    ),
                ),
            )
        val missingVerificationMethod =
            handler.issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V2_0_CONTEXT).copy(signingVerificationMethodId = null),
            )
        val missingCryptosuite =
            handler.issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                context(VcdmProfiles.V2_0_CONTEXT).copy(dataIntegrityCryptosuite = null),
            )

        assertFalse(noVerifiableCredential.isOk)
        assertFalse(missingVerificationMethod.isOk)
        assertFalse(missingCryptosuite.isOk)
        assertEquals(0, command.calls)
    }

    private fun context(
        baseContext: String,
        extraContext: String? = null,
        issuer: String = "did:example:issuer",
        verificationMethod: String = "https://issuer.example/keys#assertion",
    ): IssuanceContext =
        contextWithDefinition(
            CredentialDefinition(
                context = listOfNotNull(baseContext, extraContext),
                type = listOf("VerifiableCredential", "ExampleCredential"),
            ),
        ).copy(
            issuerIdentifier = issuer,
            signingVerificationMethodId = verificationMethod,
        )

    private fun contextWithDefinition(definition: CredentialDefinition?): IssuanceContext =
        IssuanceContext(
            subject = "did:example:holder",
            clientId = "client-1",
            issuerIdentifier = "did:example:issuer",
            credentialConfigurationId = "example-ldp-vc",
            credentialConfiguration =
                CredentialConfigurationSupported(
                    format = CredentialFormat.LDP_VC.value,
                    credentialDefinition = definition,
                ),
            holderBindingKey = null,
            attributes = mapOf("name" to JsonPrimitive("Alice")),
            signingKeyAlias = "kms:tenant:issuer",
            signingVerificationMethodId = "https://issuer.example/keys#assertion",
            dataIntegrityCryptosuite = "eddsa-jcs-2022",
        )
}

private class RecordingAddProofCommand(
    private val failure: IdkError? = null,
) : AddProofServiceCommand {
    var calls: Int = 0
    var lastInput: AddProofInput? = null

    override val inputTypeToken: TypeToken<AddProofInput> = typeToken<AddProofInput>()
    override val outputTypeToken: TypeToken<AddProofOutput> = typeToken<AddProofOutput>()
    override val isEnabled: Boolean = true

    override suspend fun execute(args: AddProofInput): com.sphereon.core.api.IdkResult<AddProofOutput, IdkError> {
        calls++
        lastInput = args
        failure?.let { return Err(it) }
        val option = args.proofs.single()
        val secured =
            JsonObject(
                args.unsecuredDocument +
                    ("proof" to
                        buildJsonObject {
                            put("type", "DataIntegrityProof")
                            put("cryptosuite", option.cryptosuite)
                            put("proofPurpose", option.proofPurpose.value)
                            put("verificationMethod", option.verificationMethod)
                            put("proofValue", "ztest-proof")
                        }),
            )
        return Ok(AddProofOutput(securedDocument = secured))
    }
}

private class RecordingStatusEnricher(
    private val claim: JsonObject = buildJsonObject {
        put("id", "https://issuer.example/status#9")
        put("type", "BitstringStatusListEntry")
        put("statusPurpose", "revocation")
        put("statusListIndex", "9")
        put("statusListCredential", "https://issuer.example/status")
    },
    private val mergeTarget: StatusClaimMergeTarget = StatusClaimMergeTarget.VC_CREDENTIAL_STATUS,
    private val bindError: IdkError? = null,
) : CredentialStatusEnricher {
    val handle = StatusReservationHandle("status-list", 9)
    var reserveCalls = 0
    var boundHandle: StatusReservationHandle? = null
    var boundCredentialId: String? = null
    var cancelledHandle: StatusReservationHandle? = null

    override suspend fun reserve(context: StatusEnrichmentContext): IdkResult<ReservedStatus, IdkError> {
        reserveCalls++
        return Ok(ReservedStatus(handle = handle, claim = claim, mergeTarget = mergeTarget))
    }

    override suspend fun bind(
        handle: StatusReservationHandle,
        credentialId: String?,
        credentialHash: String?,
    ): IdkResult<Unit, IdkError> {
        boundHandle = handle
        boundCredentialId = credentialId
        return bindError?.let { Err(it) } ?: Ok(Unit)
    }

    override suspend fun cancel(handle: StatusReservationHandle): IdkResult<Unit, IdkError> {
        cancelledHandle = handle
        return Ok(Unit)
    }
}
