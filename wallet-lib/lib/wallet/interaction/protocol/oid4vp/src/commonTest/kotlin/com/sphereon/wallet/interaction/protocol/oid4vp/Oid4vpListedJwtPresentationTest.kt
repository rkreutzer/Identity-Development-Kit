/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.wallet.interaction.protocol.oid4vp

import com.sphereon.core.api.*
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkSet
import com.sphereon.crypto.core.jose.tryGenerateJwkThumbprint
import com.sphereon.crypto.core.CoseJoseKeyMappingService
import com.sphereon.crypto.core.cose.CoseKeyCborCodec
import com.sphereon.crypto.core.cose.DecodedCbor
import com.sphereon.cbor.CborByteString
import com.sphereon.cbor.CborUInt
import com.sphereon.crypto.core.cose.CoseAlgorithm
import com.sphereon.crypto.core.cose.CoseCurve
import com.sphereon.crypto.core.cose.CoseKey
import com.sphereon.crypto.core.cose.CoseKeyTypeEnum
import com.sphereon.mdoc.PreparedMdocDeviceAuthenticationSigning
import com.sphereon.wallet.wsca.Wsca
import com.sphereon.wallet.wsca.WscaSigningRequest
import com.sphereon.wallet.wsca.WscaPreparedSigning
import com.sphereon.wallet.wsca.WscaPreparedSigningFactory
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.oauth2.common.model.AuthorizationResponse
import com.sphereon.openid.oid4vp.common.*
import com.sphereon.openid.oid4vp.holder.*
import com.sphereon.wallet.interaction.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*
import kotlin.test.*

class Oid4vpListedJwtPresentationTest {
    @Test fun jwtAndJwtLdFreezeBytesBeforeApprovalAndRestartWithoutPreparingAgain() = runTest {
        for (format in listOf(CredentialFormat.JWT_VC_JSON, CredentialFormat.JWT_VC_JSON_LD)) {
            val f = Fixture(format)
            val preparation = assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(f.executor().preparePresentation(f.context, f.state))
            assertEquals(listOf(WalletApprovalOperation("credential-key", "test-digest")), preparation.operations)
            assertTrue(f.wsca.signCalls.isEmpty())
            val saved = f.saved()
            f.now += 15
            assertEquals(preparation, f.executor().preparePresentation(f.context, f.state))
            assertEquals(1, f.holder.preparations)
            assertIs<Oid4vpPresentationExecutionResult.Submitted>(f.executor().submitPresentation(f.context, f.state))
            assertEquals(saved.signing.single().protectedSegment + "." + saved.signing.single().payloadSegment,
                f.wsca.signCalls.single().signingInput.decodeToString())
            assertTrue(f.holder.finalResponsePersistedBeforePost)
            assertEquals(1, f.holder.submissions)
        }
    }

    @Test fun mixedSdJwtAndJwtShareOneListedApprovalAndRetainFixedKeyBindingTime() = runTest {
        val f = Fixture()
        f.credentials += SelectedCredential("sd", "sd-credential", JsonPrimitive("sdjwt~"), CredentialFormat.SD_JWT_VC)
        val approval = assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(f.executor().preparePresentation(f.context, f.state))
        assertEquals(listOf("sd-key", "credential-key"), approval.operations.map { it.keyRef })
        val fixedTime = f.sdPreparedAt
        f.now += 20
        assertIs<Oid4vpPresentationExecutionResult.Submitted>(f.executor().submitPresentation(f.context, f.state))
        assertEquals(fixedTime, f.sdAppliedAt)
        assertEquals(listOf(CredentialFormat.JWT_VC_JSON, CredentialFormat.SD_JWT_VC), f.holder.composed.map { it.credentialFormat })
        assertTrue(f.holder.composed.last().sdJwtKeyBindingApplied)
    }

    @Test fun realSdJwtAndJwtSignExactlyTheApprovedHashesWithOriginalKeyBindingIat() = runTest {
        val f = Fixture(realSd = true)
        f.holder.resolved = f.holder.resolved.copy(dcqlQuery = com.sphereon.openid.oid4vp.dcql.DcqlQuery(credentials = listOf(
            com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery(id = "sd", format = "dc+sd-jwt", meta = com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta("urn:test:sdjwt")),
        )))
        val jwk = Json.parseToJsonElement(Fixture.SD_KEY)
        val sdHeader = "{\"alg\":\"ES256\",\"typ\":\"dc+sd-jwt\"}".encodeToByteArray().encodeToBase64Url()
        val sdPayload = buildJsonObject { put("iss", "https://issuer.example"); put("sub", "subject"); put("cnf", buildJsonObject { put("jwk", jwk) }) }
            .toString().encodeToByteArray().encodeToBase64Url()
        f.credentials += SelectedCredential("sd", "sd-credential", JsonPrimitive("$sdHeader.$sdPayload.issuer-signature~"),
            CredentialFormat.SD_JWT_VC, holderKeyRef = "sd-key")
        val approval = assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(f.executor().preparePresentation(f.context, f.state))
        assertEquals(2, approval.operations.size)
        assertEquals(2, approval.operations.map { it.operationHash }.distinct().size)
        assertTrue(f.wsca.signCalls.isEmpty())
        f.digestWsca.approved += approval.operations
        val frozenIat = f.saved().issuedAt
        f.now += 30
        assertIs<Oid4vpPresentationExecutionResult.Submitted>(f.executor().submitPresentation(f.context, f.state))
        val actuallySigned = f.wsca.signCalls.map { call ->
            WalletApprovalOperation(call.keyRef.keyRef ?: call.keyRef.keyId, "sha256:" + hash(call.signingInput, DigestAlg.SHA256).encodeToHex())
        }
        assertEquals(approval.operations, actuallySigned)
        assertTrue(f.digestWsca.approved.isEmpty())
        val kbPayload = Json.parseToJsonElement(f.wsca.signCalls.first().signingInput.decodeToString().split('.')[1].decodeFromBase64Url().decodeToString()).jsonObject
        assertEquals(frozenIat, kbPayload.getValue("iat").jsonPrimitive.long)
        assertEquals("nonce", kbPayload.getValue("nonce").jsonPrimitive.content)
        assertEquals("verifier", kbPayload.getValue("aud").jsonPrimitive.content)
        assertTrue(f.holder.finalResponsePersistedBeforePost)
        assertIs<Oid4vpPresentationExecutionResult.Failed>(f.executor().submitPresentation(f.context, f.state))
        assertEquals(2, f.wsca.signCalls.size)
        assertEquals(1, f.holder.submissions)
    }

    @Test fun missingCorruptOrExpiredPrivatePreparationNeverFallsThroughToSigning() = runTest {
        for (mutation in listOf<(Fixture) -> Unit>(
            { it.values.remove("jwt_vp.prepared") },
            { it.values["jwt_vp.prepared"] = "corrupt" },
            { it.now += 120 },
            { it.values.clear() },
        )) {
            val f = Fixture()
            f.executor().preparePresentation(f.context, f.state)
            mutation(f)
            assertIs<Oid4vpPresentationExecutionResult.Failed>(f.executor().submitPresentation(f.context, f.state))
            assertTrue(f.wsca.signCalls.isEmpty())
            assertEquals(0, f.holder.ordinaryCreations)
            assertEquals(0, f.holder.submissions)
        }
    }

    @Test fun changedSelectionKeyAndOwnerAreRejectedBeforeSigning() = runTest {
        for (mutation in listOf<(Fixture) -> Unit>(
            { it.credentials = it.credentials.map { c -> c.copy(credentialId = "changed") } },
            { it.credentials = it.credentials.map { c -> c.copy(holderKeyRef = "another-key") } },
            { it.context = it.context.copy(walletUnitId = "other-unit") },
            { it.values["selected_credential_ids_by_requirement"] = "{\"jwt\":[\"different\"]}" },
        )) {
            val f = Fixture()
            f.executor().preparePresentation(f.context, f.state)
            mutation(f)
            assertIs<Oid4vpPresentationExecutionResult.Failed>(f.executor().submitPresentation(f.context, f.state))
            assertTrue(f.wsca.signCalls.isEmpty())
        }
    }

    @Test fun incompletePreparationCannotRegenerateAndMissingBackendSignerFailsClosed() = runTest {
        val f = Fixture()
        f.values["jwt_vp.intent"] = "true"
        assertIs<Oid4vpPresentationPreparation.Failed>(f.executor().preparePresentation(f.context, f.state))
        assertEquals(0, f.holder.preparations)
        val missing = Fixture()
        assertIs<Oid4vpPresentationPreparation.Failed>(missing.executor(withSigner = false).preparePresentation(missing.context, missing.state))
        assertTrue(missing.wsca.ensureAliases.isEmpty())
    }

    @Test fun replayCannotSignOrPostAgain() = runTest {
        val f = Fixture()
        f.executor().preparePresentation(f.context, f.state)
        assertIs<Oid4vpPresentationExecutionResult.Submitted>(f.executor().submitPresentation(f.context, f.state))
        assertIs<Oid4vpPresentationExecutionResult.Failed>(f.executor().submitPresentation(f.context, f.state))
        assertEquals(1, f.wsca.signCalls.size)
        assertEquals(1, f.holder.submissions)
        assertIs<Oid4vpPresentationPreparation.Failed>(f.executor().preparePresentation(f.context, f.state))
    }

    @Test fun interruptedPreparationSigningAndDispatchAreTerminalAndDiagnosed() = runTest {
        for (phase in listOf("intent", "signing", "dispatch")) {
            val f = Fixture()
            if (phase == "intent") f.values["jwt_vp.intent"] = "true" else {
                assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(f.executor().preparePresentation(f.context, f.state))
                f.values[if (phase == "signing") "jwt_vp.signing_started" else "jwt_vp.dispatch_started"] = "true"
            }
            // Known terminal state must be classified before a transient resolver error can offer retry.
            f.resolutionFailure = IllegalStateException("resolver must not be called")
            val preparation = assertIs<Oid4vpPresentationPreparation.Failed>(f.executor().preparePresentation(f.context, f.state))
            val submission = assertIs<Oid4vpPresentationExecutionResult.Failed>(f.executor().submitPresentation(f.context, f.state))
            assertFalse(preparation.retryable)
            assertFalse(submission.retryable)
            assertEquals(2, f.diagnostics.size)
            assertTrue(f.diagnostics.all { it.second["cause.type"] == "IllegalStateException" })
            assertTrue(f.diagnostics.none { it.second["cause.message"] == "resolver must not be called" })
            assertTrue(f.wsca.signCalls.isEmpty())
            assertEquals(0, f.holder.submissions)
        }
    }

    @Test fun thrownResolverFailuresRetainTheirCauseAndCancellationEscapes() = runTest {
        val f = Fixture()
        f.resolutionFailure = IllegalStateException("resolution failed", IllegalArgumentException("invalid local fixture"))
        assertIs<Oid4vpPresentationPreparation.Failed>(f.executor().preparePresentation(f.context, f.state))
        assertIs<Oid4vpPresentationExecutionResult.Failed>(f.executor().submitPresentation(f.context, f.state))
        assertEquals(2, f.diagnostics.size)
        assertTrue(f.diagnostics.all { it.first == "oid4vp.resolve_selected_credentials_failed" })
        assertTrue(f.diagnostics.all { it.second["cause.cause1.type"] == "IllegalArgumentException" })
        f.diagnostics.clear()
        val cancelled = CancellationException("cancel fixture")
        f.resolutionFailure = cancelled
        assertSame(cancelled, assertFailsWith<CancellationException> { f.executor().preparePresentation(f.context, f.state) })
        assertSame(cancelled, assertFailsWith<CancellationException> { f.executor().submitPresentation(f.context, f.state) })
        assertTrue(f.diagnostics.isEmpty(), "cancellation must not be mapped or logged as a protocol failure")
        assertTrue(f.wsca.signCalls.isEmpty())
        assertEquals(0, f.holder.submissions)
    }

    @Test fun plainSdJwtUnexpectedFailuresKeepTheirOriginalPropagationAndCanBeRetried() = runTest {
        for (phase in listOf("prepare", "create", "post")) {
            val f = Fixture(CredentialFormat.SD_JWT_VC)
            val failure = IllegalStateException("temporary presentation transport failure")
            f.failurePhase = phase
            f.injectedFailure = failure
            if (phase == "prepare") {
                assertSame(failure, assertFailsWith<IllegalStateException> { f.executor().preparePresentation(f.context, f.state) })
            } else {
                assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(f.executor().preparePresentation(f.context, f.state))
                assertSame(failure, assertFailsWith<IllegalStateException> { f.executor().submitPresentation(f.context, f.state) })
            }
            assertEquals(1, f.diagnostics.size)
            assertEquals(failure.message, f.diagnostics.single().second["cause.message"])
            assertNull(f.values["jwt_vp.intent"])
            assertNull(f.values["jwt_vp.dispatch_started"])
            f.injectedFailure = null
            assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(f.executor().preparePresentation(f.context, f.state))
            assertIs<Oid4vpPresentationExecutionResult.Submitted>(f.executor().submitPresentation(f.context, f.state))
        }
    }

    @Test fun stagedJwtPostFailureRemainsTerminalAndCannotRepeatSigningOrDispatch() = runTest {
        val f = Fixture()
        assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(f.executor().preparePresentation(f.context, f.state))
        f.failurePhase = "post"
        f.injectedFailure = IllegalStateException("ambiguous staged dispatch failure")
        assertFalse(assertIs<Oid4vpPresentationExecutionResult.Failed>(f.executor().submitPresentation(f.context, f.state)).retryable)
        val signs = f.wsca.signCalls.size
        val posts = f.holder.submissions
        assertEquals(1, signs)
        assertEquals(1, posts)
        f.injectedFailure = null
        assertFalse(assertIs<Oid4vpPresentationExecutionResult.Failed>(f.executor().submitPresentation(f.context, f.state)).retryable)
        assertEquals(signs, f.wsca.signCalls.size)
        assertEquals(posts, f.holder.submissions)
    }

    @Test fun mixedSdJwtMdocAndJwtUseOneOrderedApprovalAndCombinedHolderResponse() = runTest {
        val f = Fixture()
        f.holder.resolved = encryptedRequest(f.holder.resolved)
        f.credentials += SelectedCredential("sd", "sd-credential", JsonPrimitive("sdjwt~"), CredentialFormat.SD_JWT_VC)
        val mdoc = mdocRecord("mdoc-credential", encrypted = true)
        f.credentials += SelectedCredential("mdoc-query", mdoc.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        f.holder.mdocRecord = mdoc
        val mdocProvider = RecordingMdocSigningProvider(mdoc)
        val approval = assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(f.executor(mdocHolderSigningProvider = mdocProvider).preparePresentation(f.context, f.state))
        assertEquals(listOf("sd-key", "mdoc-key-id", "credential-key"), approval.operations.map { it.keyRef })
        assertEquals(listOf("sd-hash", "mdoc-hash"), approval.operations.take(2).map { it.operationHash })
        // The backend-owned approval names the wallet account its prepared holder keys belong to.
        assertEquals("account", approval.walletAccountId)
        assertTrue(approval.operations.last().operationHash.isNotBlank())
        assertTrue(f.wsca.signCalls.isEmpty())
        assertEquals(listOf(mdoc.credentialId), f.saved().mdocSigning.map { it.signing.credentialId })

        assertIs<Oid4vpPresentationExecutionResult.Submitted>(f.executor(mdocHolderSigningProvider = mdocProvider).submitPresentation(f.context, f.state))
        assertEquals(1, mdocProvider.validateCalls)
        assertEquals(1, mdocProvider.finalizeCalls)
        assertEquals(listOf(mdoc.credentialId), f.holder.combinedMdocSignings.map { it.credentialId })
        assertEquals(1, f.holder.combinedJwtSignatures.size)
        assertEquals(f.credentials.map { it.credentialId }, f.holder.composed.map { it.credentialId })
        assertEquals(mdoc.recipientBinding, f.holder.submittedJweRecipientBinding)
    }

    @Test fun encryptedMdocPreparationWithoutRecipientBindingFailsBeforeApproval() = runTest {
        val f = Fixture()
        f.holder.resolved = encryptedRequest(f.holder.resolved)
        val mdoc = mdocRecord("mdoc-credential", encrypted = true).copy(recipientBinding = null)
        f.credentials += SelectedCredential("mdoc-query", mdoc.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        f.holder.mdocRecord = mdoc
        val signer = RecordingMdocSigningProvider(mdoc)

        val result = f.executor(mdocHolderSigningProvider = signer).preparePresentation(f.context, f.state)

        assertIs<Oid4vpPresentationPreparation.Failed>(result)
        assertNull(f.values["jwt_vp.prepared"])
        assertTrue(f.wsca.signCalls.isEmpty())
        assertEquals(0, signer.finalizeCalls)
    }

    @Test fun changedPreparedJweRecipientBindingFailsBeforeMdocSignature() = runTest {
        val f = Fixture()
        f.holder.resolved = encryptedRequest(f.holder.resolved)
        val mdoc = mdocRecord("mdoc-credential", encrypted = true)
        f.credentials += SelectedCredential("mdoc-query", mdoc.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        f.holder.mdocRecord = mdoc
        val signer = RecordingMdocSigningProvider(mdoc)
        val executor = f.executor(mdocHolderSigningProvider = signer)
        assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(executor.preparePresentation(f.context, f.state))
        val originalPlan = f.saved()
        val tamperedSigning = originalPlan.mdocSigning.single().signing.copy(
            recipientBinding = checkNotNull(mdoc.recipientBinding).copy(rfc7638Thumbprint = "different-thumbprint"),
        )
        f.values["jwt_vp.prepared"] = Json.encodeToString(
            originalPlan.copy(mdocSigning = listOf(originalPlan.mdocSigning.single().copy(signing = tamperedSigning))).sealed(),
        )

        assertIs<Oid4vpPresentationExecutionResult.Failed>(executor.submitPresentation(f.context, f.state))
        assertEquals(1, signer.validateCalls)
        assertEquals(0, signer.finalizeCalls)
        assertTrue(f.wsca.signCalls.isEmpty())
    }

    // OID4VP 1.0 Annex B.2.6.1: the mdoc handover carries the verifier encryption-key thumbprint only
    // when the response is encrypted; under plain direct_post there is no recipient to bind.
    @Test fun plainDirectPostMdocWithoutRecipientBindingSubmitsUnencrypted() = runTest {
        val f = Fixture()
        val mdoc = mdocRecord("mdoc-credential")
        f.credentials += SelectedCredential("mdoc-query", mdoc.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        f.holder.mdocRecord = mdoc
        val signer = RecordingMdocSigningProvider(mdoc)
        val executor = f.executor(mdocHolderSigningProvider = signer)
        assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(executor.preparePresentation(f.context, f.state))

        assertIs<Oid4vpPresentationExecutionResult.Submitted>(executor.submitPresentation(f.context, f.state))
        assertEquals(1, signer.finalizeCalls)
        assertNull(f.holder.submittedJweRecipientBinding)
    }

    @Test fun plainDirectPostMdocCarryingARecipientBindingFailsBeforeApproval() = runTest {
        val f = Fixture()
        val mdoc = mdocRecord("mdoc-credential", encrypted = true)
        f.credentials += SelectedCredential("mdoc-query", mdoc.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        f.holder.mdocRecord = mdoc
        val signer = RecordingMdocSigningProvider(mdoc)

        assertIs<Oid4vpPresentationPreparation.Failed>(f.executor(mdocHolderSigningProvider = signer).preparePresentation(f.context, f.state))
        assertNull(f.values["jwt_vp.prepared"])
        assertEquals(0, signer.finalizeCalls)
        assertTrue(f.wsca.signCalls.isEmpty())
    }

    @Test fun encryptedMdocBoundToAKeyOutsideTheRequestJwksFailsBeforeMdocSignature() = runTest {
        val f = Fixture()
        f.holder.resolved = encryptedRequest(f.holder.resolved)
        // A self-consistent binding (the thumbprint matches its JWK) to a key the verifier never offered.
        val foreignKey = Jwk.fromJsonObject(Json.parseToJsonElement(FOREIGN_EC_JWK).jsonObject)
        val mdoc = mdocRecord("mdoc-credential", encrypted = true).let {
            it.copy(recipientBinding = checkNotNull(it.recipientBinding).copy(
                publicJwkJson = FOREIGN_EC_JWK,
                rfc7638Thumbprint = tryGenerateJwkThumbprint(foreignKey).getOrThrow(),
                keyEncryptionAlgorithm = "ECDH-ES",
            ))
        }
        f.credentials += SelectedCredential("mdoc-query", mdoc.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        f.holder.mdocRecord = mdoc
        val signer = RecordingMdocSigningProvider(mdoc)
        val executor = f.executor(mdocHolderSigningProvider = signer)
        assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(executor.preparePresentation(f.context, f.state))

        assertIs<Oid4vpPresentationExecutionResult.Failed>(executor.submitPresentation(f.context, f.state))
        assertEquals(0, signer.finalizeCalls)
        assertEquals(0, f.holder.submissions)
        assertTrue(f.wsca.signCalls.isEmpty())
    }

    @Test fun listedApprovalNamesTheSinglePreparedWalletAccountOrNoneAndRefusesMixedAccounts() = runTest {
        val f = Fixture()
        f.holder.resolved = encryptedRequest(f.holder.resolved)
        val mdoc = mdocRecord("mdoc-credential", encrypted = true)
        f.credentials += SelectedCredential("mdoc-query", mdoc.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        f.holder.mdocRecord = mdoc
        val executor = f.executor(mdocHolderSigningProvider = RecordingMdocSigningProvider(mdoc))
        val approval = assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(executor.preparePresentation(f.context, f.state))
        assertEquals("account", approval.walletAccountId)
        val saved = f.saved()

        val unnamed = saved.copy(
            signing = saved.signing.map { it.copy(walletAccountId = null) },
            mdocSigning = saved.mdocSigning.map { it.copy(walletAccountId = null) },
        )
        assertNull(checkNotNull(unnamed.approvalRequired()).walletAccountId)
        // One named account among unnamed signings still names that account.
        assertEquals("account", checkNotNull(unnamed.copy(mdocSigning = saved.mdocSigning).approvalRequired()).walletAccountId)

        val mixed = saved.copy(
            signing = saved.signing.map { it.copy(walletAccountId = "account") },
            mdocSigning = saved.mdocSigning.map { it.copy(walletAccountId = "other-account") },
        )
        assertNull(mixed.approvalRequired())
        f.values["jwt_vp.prepared"] = Json.encodeToString(mixed.sealed())
        assertIs<Oid4vpPresentationPreparation.Failed>(executor.preparePresentation(f.context, f.state))
        assertTrue(f.wsca.signCalls.isEmpty())
    }

    @Test fun realSdJwtBindingDoesNotChangeTheMdocValidationSelection() = runTest {
        val f = Fixture(realSd = true)
        f.holder.resolved = f.holder.resolved.copy(dcqlQuery = com.sphereon.openid.oid4vp.dcql.DcqlQuery(credentials = listOf(
            com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery(
                id = "sd", format = "dc+sd-jwt", meta = com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta("urn:test:sdjwt"),
            ),
        )))
        val sdHeader = "{\"alg\":\"ES256\",\"typ\":\"dc+sd-jwt\"}".encodeToByteArray().encodeToBase64Url()
        val sdPayload = buildJsonObject {
            put("iss", "https://issuer.example")
            put("sub", "subject")
            put("cnf", buildJsonObject { put("jwk", Json.parseToJsonElement(Fixture.SD_KEY)) })
        }.toString().encodeToByteArray().encodeToBase64Url()
        f.credentials += SelectedCredential(
            "sd", "sd-credential", JsonPrimitive("$sdHeader.$sdPayload.issuer-signature~"), CredentialFormat.SD_JWT_VC, holderKeyRef = "sd-key",
        )
        // Plain direct_post: the holder prepares no JWE recipient binding (OID4VP 1.0 section 8.3 applies only to .jwt modes).
        val mdoc = mdocRecord("mdoc-credential")
        f.credentials += SelectedCredential("mdoc-query", mdoc.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        f.holder.mdocRecord = mdoc
        val mdocProvider = RecordingMdocSigningProvider(mdoc)
        val executor = f.executor(mdocHolderSigningProvider = mdocProvider)
        val approval = assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(executor.preparePresentation(f.context, f.state))
        f.digestWsca.approved += approval.operations

        assertIs<Oid4vpPresentationExecutionResult.Submitted>(executor.submitPresentation(f.context, f.state))
        assertEquals(mdocProvider.validatedRequest, mdocProvider.finalizedRequest)
        assertTrue(f.holder.composed.single { it.credentialId == "sd-credential" }.sdJwtKeyBindingApplied)
        assertEquals(3, approval.operations.size)
    }

    @Test fun plainResponseModeRefusesAnEncryptedRecipientBindingBeforeApproval() = runTest {
        val f = Fixture()
        val mdoc = mdocRecord("mdoc-credential", encrypted = true)
        f.credentials += SelectedCredential("mdoc-query", mdoc.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        f.holder.mdocRecord = mdoc
        val signer = RecordingMdocSigningProvider(mdoc)

        assertIs<Oid4vpPresentationPreparation.Failed>(f.executor(mdocHolderSigningProvider = signer).preparePresentation(f.context, f.state))
        assertNull(f.values["jwt_vp.prepared"])
        assertEquals(0, signer.validateCalls)
        assertEquals(0, signer.finalizeCalls)
        assertTrue(f.wsca.signCalls.isEmpty())
    }

    @Test fun secureComponentMdocValidationRejectsAChangedRecipientBindingBeforeWsca() = runTest {
        val f = Fixture()
        f.holder.resolved = f.holder.resolved.copy(request = f.holder.resolved.request.copy(responseMode = ResponseMode.DIRECT_POST_JWT.value))
        val record = mdocRecord("mdoc-credential", encrypted = true)
        f.holder.mdocRecord = record
        val credential = SelectedCredential("mdoc-query", record.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        val publicKey = mdocCoseKey()
        val wsca = RecordingWsca(publicKeyJwks = mapOf("mdoc-key" to CoseJoseKeyMappingService.toJoseJwk(publicKey).toJsonString()))
        val provider = SecureComponentOid4vpMdocHolderSigningProvider(f.holder, wsca, FixtureCoseKeyCodec(publicKey))
        val request = Oid4vpMdocHolderSigningRequest("unit", "binding", f.holder.resolved, listOf(credential))
        val plan = assertIs<Ok<List<Oid4vpPreparedMdocSigning>>>(provider.prepare(request)).value
        assertIs<Ok<Oid4vpMdocSigningValidation>>(provider.validate(request, plan))

        val tampered = plan.map {
            it.copy(signing = it.signing.copy(recipientBinding = checkNotNull(it.signing.recipientBinding).copy(rfc7638Thumbprint = "different-thumbprint")))
        }
        assertIs<Err<IdkError>>(provider.validate(request, tampered))
        assertTrue(wsca.signCalls.isEmpty())
    }

    @Test fun jwtOnlyUsesLegacyHolderResponseOverride() = runTest {
        val f = Fixture()
        f.holder.rejectCombinedResponse = true
        val executor = f.executor()
        assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(executor.preparePresentation(f.context, f.state))
        assertIs<Oid4vpPresentationExecutionResult.Submitted>(executor.submitPresentation(f.context, f.state))
        assertEquals(1, f.holder.legacyPreparedResponseCalls)
        assertEquals(0, f.holder.combinedPreparedResponseCalls)
    }

    @Test fun changedMdocSnapshotAndExpiredCombinedApprovalFailBeforeAnySignature() = runTest {
        val f = Fixture()
        val mdoc = mdocRecord("mdoc-credential")
        f.credentials += SelectedCredential("mdoc-query", mdoc.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        f.holder.mdocRecord = mdoc
        val mdocProvider = RecordingMdocSigningProvider(mdoc)
        val executor = f.executor(mdocHolderSigningProvider = mdocProvider)
        assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(executor.preparePresentation(f.context, f.state))
        val changed = f.saved().copy(mdocSigning = emptyList()).sealed()
        f.values["jwt_vp.prepared"] = Json.encodeToString(changed)
        assertIs<Oid4vpPresentationExecutionResult.Failed>(executor.submitPresentation(f.context, f.state))
        assertEquals(0, mdocProvider.validateCalls)
        assertEquals(0, mdocProvider.finalizeCalls)
        assertTrue(f.wsca.signCalls.isEmpty())

        val expired = Fixture()
        expired.credentials += SelectedCredential("mdoc-query", mdoc.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        expired.holder.mdocRecord = mdoc
        val expiredProvider = RecordingMdocSigningProvider(mdoc)
        val expiredExecutor = expired.executor(mdocHolderSigningProvider = expiredProvider)
        assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(expiredExecutor.preparePresentation(expired.context, expired.state))
        expired.now += 120
        assertIs<Oid4vpPresentationExecutionResult.Failed>(expiredExecutor.submitPresentation(expired.context, expired.state))
        assertEquals(0, expiredProvider.validateCalls)
        assertEquals(0, expiredProvider.finalizeCalls)
        assertTrue(expired.wsca.signCalls.isEmpty())
    }

    @Test fun mdocValidationTokenIsProviderAndRequestBoundBeforeSigning() = runTest {
        val f = Fixture()
        val record = mdocRecord("mdoc-credential", encrypted = true)
        val credential = SelectedCredential("mdoc-query", record.credentialId, JsonPrimitive("mdoc-presentation"), CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key")
        f.holder.mdocRecord = record
        val publicKey = mdocCoseKey()
        val keyJwk = CoseJoseKeyMappingService.toJoseJwk(publicKey).toJsonString()
        val wsca = RecordingWsca(publicKeyJwks = mapOf("mdoc-key" to keyJwk))
        val codec = FixtureCoseKeyCodec(publicKey)
        val provider = SecureComponentOid4vpMdocHolderSigningProvider(f.holder, wsca, codec)
        val request = Oid4vpMdocHolderSigningRequest("unit", "binding", f.holder.resolved, listOf(credential))
        val plan = assertIs<Ok<List<Oid4vpPreparedMdocSigning>>>(provider.prepare(request)).value
        val validation = assertIs<Ok<Oid4vpMdocSigningValidation>>(provider.validate(request, plan)).value

        val alteredRequest = request.copy(request = request.request.copy(request = request.request.request.copy(nonce = "changed")))
        assertIs<Err<IdkError>>(provider.finalize(alteredRequest, plan, validation))
        val foreignProvider = SecureComponentOid4vpMdocHolderSigningProvider(f.holder, wsca, codec)
        assertIs<Err<IdkError>>(foreignProvider.finalize(request, plan, validation))
        assertTrue(wsca.signCalls.isEmpty())

        val differentPublicKey = publicKey.copy(x = CborByteString(ByteArray(32) { 0x44 }))
        val mismatchedWsca = RecordingWsca(
            publicKeyJwks = mapOf("mdoc-key" to CoseJoseKeyMappingService.toJoseJwk(differentPublicKey).toJsonString()),
        )
        val mismatchedProvider = SecureComponentOid4vpMdocHolderSigningProvider(f.holder, mismatchedWsca, codec)
        assertIs<Err<IdkError>>(mismatchedProvider.prepare(request))
        assertEquals(listOf("mdoc-key"), mismatchedWsca.ensureAliases)
        assertTrue(mismatchedWsca.signCalls.isEmpty(), "WSCA key mismatch must fail before any signing request")
    }

    @Test fun mdocPublicKeySnapshotRejectsPrivateMalformedAndNonCanonicalBytesBeforeWsca() = runTest {
        val publicKey = mdocCoseKey()
        val codec = FixtureCoseKeyCodec(publicKey)
        val canonicalRecord = mdocRecord("mdoc-credential", encrypted = true)
        val mismatch = Fixture()
        mismatch.holder.mdocRecord = canonicalRecord.copy(keyReference = "different-key")
        val mismatchWsca = RecordingWsca(publicKeyJwks = mapOf("mdoc-key" to CoseJoseKeyMappingService.toJoseJwk(publicKey).toJsonString()))
        val mismatchProvider = SecureComponentOid4vpMdocHolderSigningProvider(mismatch.holder, mismatchWsca, codec)
        val credential = SelectedCredential(
            "mdoc-query", canonicalRecord.credentialId, JsonPrimitive("mdoc-presentation"),
            CredentialFormat.MSO_MDOC, holderKeyRef = "mdoc-key",
        )
        val mismatchRequest = Oid4vpMdocHolderSigningRequest("unit", "binding", mismatch.holder.resolved, listOf(credential))
        assertIs<Err<IdkError>>(mismatchProvider.prepare(mismatchRequest))
        assertTrue(mismatchWsca.ensureAliases.isEmpty())

        val invalidKeyEncodings = listOf(
            FixtureCoseKeyCodec.PRIVATE_KEY_BYTES,
            FixtureCoseKeyCodec.NON_CANONICAL_PUBLIC_KEY_BYTES,
            FixtureCoseKeyCodec.MALFORMED_BYTES,
        )
        for (keyBytes in invalidKeyEncodings) {
            val f = Fixture()
            f.holder.mdocRecord = canonicalRecord.copy(
                signing = canonicalRecord.signing.copy(publicDeviceKeyCbor = keyBytes),
            )
            val keyJwk = CoseJoseKeyMappingService.toJoseJwk(publicKey).toJsonString()
            val wsca = RecordingWsca(publicKeyJwks = mapOf("mdoc-key" to keyJwk))
            val provider = SecureComponentOid4vpMdocHolderSigningProvider(f.holder, wsca, codec)
            val request = Oid4vpMdocHolderSigningRequest("unit", "binding", f.holder.resolved, listOf(credential))

            assertIs<Err<IdkError>>(provider.prepare(request))
            assertTrue(wsca.ensureAliases.isEmpty())
            assertTrue(wsca.signCalls.isEmpty())
        }
    }

    @Test fun requestExpiryCapsPrivatePreparation() = runTest {
        val f = Fixture()
        f.holder.resolved = f.holder.resolved.copy(request = f.holder.resolved.request.copy(additionalParameters = mapOf("exp" to JsonPrimitive(f.now + 10))))
        assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(f.executor().preparePresentation(f.context, f.state))
        assertEquals(f.now + 10, f.saved().expiresAt)
        f.now += 10
        assertIs<Oid4vpPresentationExecutionResult.Failed>(f.executor().submitPresentation(f.context, f.state))
        assertTrue(f.wsca.signCalls.isEmpty())
    }

    @Test fun sdJwtOnlyAndWalletAppRetainExistingExecutionPaths() = runTest {
        val sd = Fixture(CredentialFormat.SD_JWT_VC)
        assertIs<Oid4vpPresentationPreparation.ApprovalRequired>(sd.executor(withSigner = false).preparePresentation(sd.context, sd.state))
        assertIs<Oid4vpPresentationExecutionResult.Submitted>(sd.executor(withSigner = false).submitPresentation(sd.context, sd.state))
        assertEquals(1, sd.holder.ordinaryCreations)
        assertNull(sd.values["jwt_vp.intent"])
        val app = Fixture()
        app.context = app.context.copy(executionOwner = ProtocolExecutionOwner.WALLET_APP)
        assertIs<Oid4vpPresentationPreparation.Ready>(app.executor(withSigner = false).preparePresentation(app.context, app.state))
        assertIs<Oid4vpPresentationExecutionResult.Submitted>(app.executor(withSigner = false).submitPresentation(app.context, app.state))
        assertEquals(1, app.holder.ordinaryCreations)
        assertNull(app.values["jwt_vp.intent"])
    }

    private class Fixture(format: CredentialFormat = CredentialFormat.JWT_VC_JSON, val realSd: Boolean = false) {
        var now = 1234L
        val values = mutableMapOf("entry_point.raw" to "request", Oid4vpWalletInteractionProtocolAdapter.SECURITY_OPERATION_BINDING_PRIVATE_KEY to "binding")
        val store = object : WalletInteractionPrivateSessionStore {
            override suspend fun put(sessionId: WalletInteractionSessionId, data: WalletInteractionPrivateSessionData) { values.clear(); values.putAll(data.values) }
            override suspend fun get(sessionId: WalletInteractionSessionId, namespace: String) = WalletInteractionPrivateSessionData(namespace, values.toMap())
            override suspend fun remove(sessionId: WalletInteractionSessionId, namespace: String) { values.clear() }
            override suspend fun removeSession(sessionId: WalletInteractionSessionId) { values.clear() }
        }
        val diagnostics = mutableListOf<Pair<String, Map<String, String>>>()
        var resolutionFailure: Exception? = null
        var failurePhase: String? = null
        var injectedFailure: Exception? = null
        var context = WalletInteractionContext(WalletInteractionSessionId("session"), "unit", ProtocolExecutionOwner.WALLET_BACKEND,
            privateSessionStore = store, diagnostics = object : WalletInteractionDiagnostics {
                override fun warn(event: String, sessionId: WalletInteractionSessionId?, details: Map<String, String>) {
                    diagnostics += event to details
                }
            })
        val state = WalletInteractionState(sessionId = context.sessionId, walletUnitId = "unit", status = WalletInteractionStatus.Sharing,
            flowKind = WalletInteractionFlowKind.CredentialPresent, protocol = WalletProtocol.OID4VP, adapterId = Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID)
        var credentials = listOf(SelectedCredential("jwt", "credential", JsonPrimitive("credential-compact"), format,
            holderKeyRef = "credential-key", holderId = "did:example:holder",
            holderJwtVpSigningIdentifier = HolderJwtVpSigningIdentifier.ManagedKid("public-kid"), holderSigningAlgorithm = SignatureAlgorithm.ED25519))
        val wsca = RecordingWsca(resolvedKeyId = "internal-id-distinct-from-reference", publicKeyJwks = mapOf("sd-key" to SD_KEY))
        val digestWsca = DigestWsca(wsca)
        val signingSurface: Wsca = if (realSd) digestWsca else wsca
        val holder = Holder(this)
        var sdPreparedAt: Long? = null
        var sdAppliedAt: Long? = null
        val sd = object : Oid4vpSdJwtHolderBindingProvider {
            override suspend fun prepareHolderBinding(request: Oid4vpSdJwtHolderBindingRequest): IdkResult<List<WalletApprovalOperation>, IdkError> {
                if (failurePhase == "prepare") injectedFailure?.let { throw it }
                sdPreparedAt = request.issuedAtEpochSeconds
                return Ok(if (request.selectedCredentials.any { it.credentialFormat.isSdJwt }) listOf(WalletApprovalOperation("sd-key", "sd-hash")) else emptyList())
            }
            override suspend fun applyHolderBinding(request: Oid4vpSdJwtHolderBindingRequest): IdkResult<List<SelectedCredential>, IdkError> {
                sdAppliedAt = request.issuedAtEpochSeconds
                return Ok(request.selectedCredentials.map { if (it.credentialFormat.isSdJwt) it.copy(sdJwtKeyBindingApplied = true) else it })
            }
        }
        fun executor(withSigner: Boolean = true, mdocHolderSigningProvider: Oid4vpMdocHolderSigningProvider? = null) = Oid4vpHolderPresentationExecutor(holder,
            object : Oid4vpSelectedCredentialResolver {
                override suspend fun resolveSelectedCredentials(context: WalletInteractionContext, state: WalletInteractionState,
                    resolvedRequest: ResolvedOid4vpRequest, selectedCredentialIdsByRequirement: Map<String, List<String>>): List<SelectedCredential> {
                    resolutionFailure?.let { throw it }
                    return credentials
                }
            }, if (realSd) SecureComponentOid4vpSdJwtHolderBindingProvider(signingSurface) else sd,
            preparedJwtSigningProvider = if (withSigner) SecureComponentOid4vpJwtVpSigningProvider(signingSurface) else null,
            mdocHolderSigningProvider = mdocHolderSigningProvider,
            nowEpochSeconds = { now })
        fun saved(): Oid4vpPreparedJwtPresentation = Json.decodeFromString(values.getValue("jwt_vp.prepared"))
        companion object { const val SD_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"first-x\",\"y\":\"first-y\"}" }
    }

    /** Computes real signing-input digests and refuses any signature absent from the returned approval. */
    private class DigestWsca(private val delegate: RecordingWsca) : Wsca by delegate {
        private val factory = WscaPreparedSigningFactory.create()
        val approved = mutableListOf<WalletApprovalOperation>()
        override suspend fun prepareSign(request: WscaSigningRequest): IdkResult<WscaPreparedSigning, IdkError> = Ok(factory.mint(
            walletUnitId = request.walletUnitId, keyRef = request.keyRef, walletAccountId = request.walletAccountId,
            operationBinding = request.operationBinding, operationType = "test.sign",
            digestBinding = "sha256:" + hash(request.signingInput, DigestAlg.SHA256).encodeToHex(),
            nonce = request.nonce ?: "test-nonce", audience = request.audience ?: request.operationBinding, signingInput = request.signingInput,
        ))
        override suspend fun sign(prepared: WscaPreparedSigning, request: WscaSigningRequest): IdkResult<ByteArray, IdkError> {
            val entry = WalletApprovalOperation(request.keyRef.keyRef ?: request.keyRef.keyId,
                "sha256:" + hash(request.signingInput, DigestAlg.SHA256).encodeToHex())
            check(approved.remove(entry)) { "Signing bytes or key were not in the approved list" }
            return delegate.sign(prepared, request)
        }
    }

    private class Holder(val fixture: Fixture) : Oid4vpHolderService {
        var preparations = 0
        var submissions = 0
        var ordinaryCreations = 0
        var finalResponsePersistedBeforePost = false
        var composed = emptyList<SelectedCredential>()
        var mdocRecord: PreparedMdocCredentialSigning? = null
        var combinedMdocSignings = emptyList<PreparedMdocCredentialSigning>()
        var combinedJwtSignatures = emptyList<HolderJwtVpSigningResult>()
        var submittedJweRecipientBinding: PreparedOid4vpJweRecipientBinding? = null
        var rejectCombinedResponse = false
        var legacyPreparedResponseCalls = 0
        var combinedPreparedResponseCalls = 0
        var resolved = ResolvedOid4vpRequest(AuthorizationRequest(clientId = "verifier", responseType = "vp_token", nonce = "nonce"),
            verifierInfo = VerifierInfo("verifier", ClientIdScheme.PRE_REGISTERED))
        override suspend fun parseAuthorizationRequest(requestUri: String, walletConfig: WalletConfig?) = Ok(resolved.request)
        override suspend fun parseDigitalCredentialsAuthorizationRequest(request: DigitalCredentialsAuthorizationRequest, walletConfig: WalletConfig?) = Ok(resolved.request)
        override suspend fun resolveAuthorizationRequest(request: AuthorizationRequest) = Ok(resolved)
        override suspend fun prepareJwtVpResponse(request: ResolvedOid4vpRequest, selectedCredentials: List<SelectedCredential>): IdkResult<HolderPreparedJwtVpResponse, IdkError> {
            preparations++
            return Ok(HolderPreparedJwtVpResponse(request.request.state, selectedCredentials.map { credential ->
                HolderPreparedJwtVp(credential.credentialQueryId, credential.credentialId,
                    HolderJwtVpSigningRequest(payload = buildJsonObject { put("iat", fixture.now); put("aud", "verifier"); put("nonce", "nonce"); put("credential", credential.presentation) },
                        keyReference = credential.holderKeyRef!!, signatureAlgorithm = credential.holderSigningAlgorithm!!,
                        identifier = credential.holderJwtVpSigningIdentifier!!, protectedHeader = buildJsonObject { put("typ", "JWT") },
                        walletUnitId = credential.holderJwtVpWalletUnitId, operationBinding = credential.holderJwtVpOperationBinding))
            }))
        }
        override suspend fun prepareMdocDeviceAuthenticationSignatures(request: ResolvedOid4vpRequest, selectedCredentials: List<SelectedCredential>): IdkResult<List<PreparedMdocCredentialSigning>, IdkError> =
            mdocRecord?.let { Ok(listOf(it)) } ?: Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "mdoc test record missing"))
        override suspend fun createAuthorizationResponse(request: ResolvedOid4vpRequest, selectedCredentials: List<SelectedCredential>, preparedPresentations: List<PreparedPresentation>): IdkResult<AuthorizationResponse, IdkError> {
            ordinaryCreations++
            if (fixture.failurePhase == "create") fixture.injectedFailure?.let { throw it }
            return Ok(AuthorizationResponse(code = ""))
        }
        override suspend fun createAuthorizationResponseWithPreparedJwtVp(request: ResolvedOid4vpRequest, selectedCredentials: List<SelectedCredential>,
            preparedPresentations: List<PreparedPresentation>, preparedJwtVp: HolderPreparedJwtVpResponse, signatures: List<HolderJwtVpSigningResult>): IdkResult<AuthorizationResponse, IdkError> {
            legacyPreparedResponseCalls++
            composed = selectedCredentials
            assertEquals(preparedJwtVp.presentations.size, signatures.size)
            return Ok(AuthorizationResponse(code = "", additionalParameters = mapOf("vp_token" to JsonPrimitive(signatures.single().compactJws))))
        }
        override suspend fun createAuthorizationResponseWithPreparedSignatures(
            request: ResolvedOid4vpRequest,
            selectedCredentials: List<SelectedCredential>,
            preparedPresentations: List<PreparedPresentation>,
            preparedJwtVp: HolderPreparedJwtVpResponse?,
            jwtSignatures: List<HolderJwtVpSigningResult>,
            preparedMdocSignings: List<PreparedMdocCredentialSigning>,
            mdocSignatures: List<MdocCredentialSigningSignature>,
        ): IdkResult<AuthorizationResponse, IdkError> {
            combinedPreparedResponseCalls++
            if (preparedMdocSignings.isEmpty()) {
                if (rejectCombinedResponse) return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "test holder only supports legacy JWT response override"))
                return createAuthorizationResponseWithPreparedJwtVp(
                    request, selectedCredentials, preparedPresentations, checkNotNull(preparedJwtVp), jwtSignatures,
                )
            }
            composed = selectedCredentials
            combinedMdocSignings = preparedMdocSignings
            combinedJwtSignatures = jwtSignatures
            assertEquals(preparedMdocSignings.map { it.credentialId }, mdocSignatures.map { it.credentialId })
            assertEquals(preparedJwtVp?.presentations?.size ?: 0, jwtSignatures.size)
            return Ok(AuthorizationResponse(code = "", additionalParameters = mapOf("vp_token" to JsonPrimitive("combined"))))
        }
        override suspend fun submitAuthorizationResponse(
            resolvedRequest: ResolvedOid4vpRequest,
            response: AuthorizationResponse,
            responseMode: ResponseMode?,
            jarmOptions: JarmOptions?,
        ): IdkResult<SubmissionResult, IdkError> = recordSubmission(response, null)

        override suspend fun submitAuthorizationResponse(
            resolvedRequest: ResolvedOid4vpRequest,
            response: AuthorizationResponse,
            responseMode: ResponseMode?,
            jarmOptions: JarmOptions?,
            preparedOid4vpJweRecipientBinding: PreparedOid4vpJweRecipientBinding,
        ): IdkResult<SubmissionResult, IdkError> = recordSubmission(response, preparedOid4vpJweRecipientBinding)

        private suspend fun recordSubmission(
            response: AuthorizationResponse,
            preparedOid4vpJweRecipientBinding: PreparedOid4vpJweRecipientBinding?,
        ): IdkResult<SubmissionResult, IdkError> {
            submissions++
            submittedJweRecipientBinding = preparedOid4vpJweRecipientBinding
            if (fixture.failurePhase == "post") fixture.injectedFailure?.let { throw it }
            finalResponsePersistedBeforePost = fixture.values["jwt_vp.final_response"]?.let { Json.decodeFromString<AuthorizationResponse>(it) == response } == true
            return Ok(SubmissionResult.Success())
        }
    }

    private class RecordingMdocSigningProvider(private val record: PreparedMdocCredentialSigning) : Oid4vpMdocHolderSigningProvider {
        var finalizeCalls = 0
        var validateCalls = 0
        var preparedRequest: Oid4vpMdocHolderSigningRequest? = null
        var validatedRequest: Oid4vpMdocHolderSigningRequest? = null
        var finalizedRequest: Oid4vpMdocHolderSigningRequest? = null
        override suspend fun prepare(request: Oid4vpMdocHolderSigningRequest): IdkResult<List<Oid4vpPreparedMdocSigning>, IdkError> =
            run {
                preparedRequest = request
                Ok(listOf(Oid4vpPreparedMdocSigning(
                    signing = record,
                    operation = WalletApprovalOperation("mdoc-key-id", "mdoc-hash"),
                    walletUnitId = request.walletUnitId,
                    walletAccountId = "account",
                    operationBinding = checkNotNull(request.operationBinding),
                    audience = request.request.verifierInfo.clientId,
                    nonce = checkNotNull(request.request.request.nonce),
                )))
            }

        override suspend fun finalize(
            request: Oid4vpMdocHolderSigningRequest,
            prepared: List<Oid4vpPreparedMdocSigning>,
            validation: Oid4vpMdocSigningValidation,
        ): IdkResult<List<MdocCredentialSigningSignature>, IdkError> {
            finalizeCalls++
            finalizedRequest = request
            if (request != validatedRequest || request != preparedRequest) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "test mdoc request changed after validation"))
            }
            return Ok(listOf(MdocCredentialSigningSignature(record.credentialId, byteArrayOf(7, 8))))
        }

        override suspend fun validate(
            request: Oid4vpMdocHolderSigningRequest,
            prepared: List<Oid4vpPreparedMdocSigning>,
        ): IdkResult<Oid4vpMdocSigningValidation, IdkError> {
            validateCalls++
            validatedRequest = request
            // Same contract as SecureComponentOid4vpMdocHolderSigningProvider.validate: the approved snapshot must
            // still equal the holder's freshly derived signing facts, including the JWE recipient binding.
            if (prepared.map { Json.encodeToString(it.signing) } != listOf(Json.encodeToString(record))) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "test mdoc signing facts changed after approval"))
            }
            return Ok(Oid4vpMdocSigningValidation.issue(this, request, prepared, emptyList()))
        }
    }

    /** A `direct_post.jwt` request whose client metadata offers the RFC 7638 section 3.1 key for response encryption. */
    private fun encryptedRequest(resolved: ResolvedOid4vpRequest): ResolvedOid4vpRequest = resolved.copy(
        request = resolved.request.copy(responseMode = ResponseMode.DIRECT_POST_JWT.value),
        clientMetadata = ClientMetadata(jwks = JwkSet.fromJsonString("{\"keys\":[$VERIFIER_ENCRYPTION_JWK]}")),
    )

    /** Records under plain `direct_post` carry no recipient binding; encrypted ones bind the verifier key. */
    private fun mdocRecord(credentialId: String, encrypted: Boolean = false): PreparedMdocCredentialSigning {
        val key = mdocCoseKey()
        val publicKeyBytes = FixtureCoseKeyCodec(key).encode(key).getOrThrow()
        return PreparedMdocCredentialSigning(
            credentialId = credentialId,
            credentialQueryId = "mdoc-query",
            docType = "org.iso.18013.5.1.mDL",
            keyReference = "mdoc-key",
            signing = PreparedMdocDeviceAuthenticationSigning(
                docType = "org.iso.18013.5.1.mDL",
                keyReference = "mdoc-key",
                algorithm = CoseAlgorithm.ES256,
                sessionTranscriptCbor = byteArrayOf(1, 2),
                deviceAuthenticationPayload = byteArrayOf(3, 4),
                protectedHeaderCbor = byteArrayOf(0xA0.toByte()),
                publicDeviceKeyCbor = publicKeyBytes,
                sigStructure = byteArrayOf(5, 6),
            ),
            recipientBinding = if (!encrypted) null else PreparedOid4vpJweRecipientBinding(
                publicJwkJson = VERIFIER_ENCRYPTION_JWK,
                rfc7638Thumbprint = VERIFIER_ENCRYPTION_JWK_THUMBPRINT,
                keyEncryptionAlgorithm = "RSA-OAEP-256",
                contentEncryptionAlgorithm = "A256GCM",
                responseMode = ResponseMode.DIRECT_POST_JWT.value,
                clientId = "verifier",
                authorizationRequestNonce = "nonce",
            ),
        )
    }

    private fun mdocCoseKey(privateMaterial: Boolean = false): CoseKey {
        val key = CoseKey(
            kty = CborUInt(CoseKeyTypeEnum.EC2.value.toLong()),
            kid = CborByteString("mdoc-key".encodeToByteArray()),
            alg = CborUInt(CoseAlgorithm.ES256.value.toLong()),
            crv = CborUInt(CoseCurve.P_256.value.toLong()),
            x = CborByteString(ByteArray(32) { 0x11 }),
            y = CborByteString(ByteArray(32) { 0x22 }),
        )
        return if (privateMaterial) key.copy(d = CborByteString(ByteArray(32) { 0x33 })) else key
    }

    private class FixtureCoseKeyCodec(private val publicKey: CoseKey) : CoseKeyCborCodec {
        override fun encode(value: CoseKey): IdkResult<ByteArray, IdkError> = Ok(
            value.original ?: if (value.d == null) PUBLIC_KEY_BYTES else PRIVATE_KEY_BYTES,
        )

        override fun decode(bytes: ByteArray): IdkResult<DecodedCbor<CoseKey>, IdkError> = when {
            bytes.contentEquals(PUBLIC_KEY_BYTES) -> Ok(DecodedCbor(publicKey.copy(original = bytes), bytes))
            bytes.contentEquals(PRIVATE_KEY_BYTES) -> Ok(DecodedCbor(publicKey.copy(d = CborByteString(ByteArray(32) { 0x33 }), original = bytes), bytes))
            bytes.contentEquals(NON_CANONICAL_PUBLIC_KEY_BYTES) -> Ok(DecodedCbor(publicKey.copy(original = bytes), bytes))
            else -> Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Malformed fixture COSE key"))
        }

        companion object {
            val PUBLIC_KEY_BYTES = byteArrayOf(0x01)
            val PRIVATE_KEY_BYTES = byteArrayOf(0x02)
            val NON_CANONICAL_PUBLIC_KEY_BYTES = byteArrayOf(0x03)
            val MALFORMED_BYTES = byteArrayOf(0x04)
        }
    }
}

private const val VERIFIER_ENCRYPTION_JWK_N =
    "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"

/** The RFC 7638 section 3.1 example key, offered by the verifier as its response-encryption key. */
private const val VERIFIER_ENCRYPTION_JWK =
    "{\"kty\":\"RSA\",\"use\":\"enc\",\"alg\":\"RSA-OAEP-256\",\"e\":\"AQAB\",\"n\":\"$VERIFIER_ENCRYPTION_JWK_N\"}"

/** RFC 7638 section 3.1 known-answer thumbprint of [VERIFIER_ENCRYPTION_JWK]. */
private const val VERIFIER_ENCRYPTION_JWK_THUMBPRINT = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"

private const val FOREIGN_EC_JWK =
    "{\"kty\":\"EC\",\"use\":\"enc\",\"alg\":\"ECDH-ES\",\"crv\":\"P-256\"," +
        "\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}"
