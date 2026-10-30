/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vci

import com.sphereon.cbor.CborByteString
import com.sphereon.cbor.TDate
import com.sphereon.cbor.tDateToEpochSeconds
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.log.AsyncLogService
import com.sphereon.core.api.log.LogMessage
import com.sphereon.core.api.log.LogService
import com.sphereon.core.api.log.LoggerConfig
import com.sphereon.core.api.log.SessionLogManager
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.core.events.EncryptedPart
import com.sphereon.core.events.Event
import com.sphereon.core.events.EventBuilder
import com.sphereon.core.events.EventHub
import com.sphereon.core.events.SessionEventService
import com.sphereon.core.events.UserEventService
import com.sphereon.core.events.impl.DefaultEventBuilder
import com.sphereon.core.events.impl.EventHubImpl
import com.sphereon.crypto.core.cose.CoseAlgorithm
import com.sphereon.crypto.core.cose.CoseCurve
import com.sphereon.crypto.core.cose.CoseHeaderCbor
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.cose.CoseKeyJson
import com.sphereon.crypto.core.cose.CoseKeyTypeEnum
import com.sphereon.crypto.core.cose.CoseSign1
import com.sphereon.crypto.dataintegrity.model.ProofPurpose
import com.sphereon.crypto.jose.jws.JwsCompact
import com.sphereon.crypto.jose.jws.JwsJsonGeneralWithIdentifiers
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.data.store.blob.BlobStore
import com.sphereon.data.store.blob.DefaultTempUrlPolicy
import com.sphereon.data.store.blob.InMemoryBlobStoreConfig
import com.sphereon.data.store.blob.impl.BlobStoreService
import com.sphereon.data.store.blob.impl.DefaultBlobService
import com.sphereon.data.store.blob.impl.DefaultRetentionPolicyService
import com.sphereon.data.store.blob.impl.KvBlobMetadataIndex
import com.sphereon.data.store.blob.memory.InMemoryBlobBackingStorageImpl
import com.sphereon.data.store.blob.memory.InMemoryBlobStoreFactoryImpl
import com.sphereon.data.store.kv.InMemoryKvStoreConfig
import com.sphereon.data.store.kv.KvStore
import com.sphereon.data.store.kv.KvStoreScopeBinding
import com.sphereon.data.store.kv.impl.KvStoreService
import com.sphereon.data.store.kv.memory.InMemoryKvBackingStorageImpl
import com.sphereon.data.store.kv.memory.InMemoryKvStoreFactoryImpl
import com.sphereon.data.store.party.model.IdentifierType
import com.sphereon.di.context.NoOpSessionContext
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionContextManager
import com.sphereon.mdoc.data.device.DocType
import com.sphereon.mdoc.data.device.IssuerSigned
import com.sphereon.mdoc.data.device.IssuerSignedCborCodecImpl
import com.sphereon.mdoc.data.mso.DeviceKeyInfo
import com.sphereon.mdoc.data.mso.DigestAlgorithm
import com.sphereon.mdoc.data.mso.MobileSecurityObject
import com.sphereon.mdoc.data.mso.MobileSecurityObjectCborCodecImpl
import com.sphereon.mdoc.data.mso.MsoVersion
import com.sphereon.mdoc.data.mso.ValidityInfo
import com.sphereon.openid.oid4vc.common.DisplayProperties
import com.sphereon.openid.oid4vc.common.vcdm.VcdmProfiles
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialDefinition
import com.sphereon.openid.oid4vci.common.model.CredentialIssuerMetadata
import com.sphereon.openid.oid4vci.common.model.CredentialMetadata
import com.sphereon.openid.oid4vci.common.model.CredentialOffer
import com.sphereon.openid.oid4vci.common.model.CredentialOfferGrants
import com.sphereon.openid.oid4vci.common.model.CredentialResponse
import com.sphereon.openid.oid4vci.common.model.CredentialResponseItem
import com.sphereon.openid.oid4vci.common.model.PreAuthorizedCodeOfferGrant
import com.sphereon.openid.oid4vci.holder.ResolvedCredentialOffer
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerificationArgs
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerificationResult
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerifier
import com.sphereon.sdjwt.vc.command.VerifySdJwtVcCommand
import com.sphereon.wallet.credential.BodyStorageKind
import com.sphereon.wallet.credential.BodyStorageRef
import com.sphereon.wallet.credential.CredentialFormat
import com.sphereon.wallet.credential.CredentialInstance
import com.sphereon.wallet.credential.CredentialLifecycleState
import com.sphereon.wallet.credential.CredentialMetadataFilter
import com.sphereon.wallet.credential.CredentialRecord
import com.sphereon.wallet.credential.CredentialRefreshMethod
import com.sphereon.wallet.credential.CredentialTypeRef
import com.sphereon.wallet.credential.CredentialTypeRefKind
import com.sphereon.wallet.credential.CredentialTypeRefSource
import com.sphereon.wallet.credential.IdentifierRef
import com.sphereon.wallet.credential.IssuanceDiagnosticCode
import com.sphereon.wallet.credential.IssuanceProvenance
import com.sphereon.wallet.credential.IssuanceSession
import com.sphereon.wallet.credential.IssuanceSessionStatus
import com.sphereon.wallet.credential.KeyRef
import com.sphereon.wallet.credential.RefreshPolicy
import com.sphereon.wallet.credential.RefreshState
import com.sphereon.wallet.credential.SecretRef
import com.sphereon.wallet.credential.WalletIssuanceSessionStore
import com.sphereon.wallet.WalletHolderVerificationMethodResolver
import com.sphereon.wallet.credential.WalletHolderIdentifierKind
import com.sphereon.wallet.credential.WalletHolderVerificationMethod
import com.sphereon.wallet.credential.store.BlobWalletCredentialStore
import com.sphereon.wallet.credential.WalletCredentialStore
import com.sphereon.wallet.credential.store.WalletCredentialBodyProtector
import com.sphereon.wallet.credential.store.WalletCredentialProtectedDocumentRole
import com.sphereon.wallet.impl.CredentialSubjectExtractorImpl
import com.sphereon.wallet.interaction.WalletInteractionContext
import com.sphereon.wallet.interaction.WalletInteractionDiagnostics
import com.sphereon.wallet.interaction.ProtocolExecutionOwner
import com.sphereon.wallet.interaction.WalletInteractionFlowKind
import com.sphereon.wallet.interaction.WalletInteractionPrivateSessionData
import com.sphereon.wallet.interaction.WalletInteractionPrivateSessionStore
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.interaction.WalletProtocol
import com.sphereon.wallet.interaction.WalletIssuerAuthenticationProvenance
import com.sphereon.wallet.interaction.WalletIssuerAuthenticationResult
import com.sphereon.wallet.interaction.WalletIssuerAuthenticationRequest
import com.sphereon.wallet.interaction.WalletIssuerAuthenticationResolver
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.time.Clock
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Builds a minimal SD-JWT compact serialization (`<issuer-jwt>~`) whose issuer-JWT payload is the
 * given JSON. No real signature/disclosures are used - [Oid4vciIssuedCredentialAcceptance] only
 * needs the structure to be valid for `SdJwtCodec.parse` to read the `vct`/`sub` claims.
 */
internal fun buildTestSdJwt(payloadJson: String): String {
    val header = """{"alg":"ES256","typ":"dc+sd-jwt"}""".encodeToByteArray().encodeToBase64Url()
    val payload = payloadJson.encodeToByteArray().encodeToBase64Url()
    return "$header.$payload.fakesig~"
}

internal fun buildTestCompactJwt(payloadJson: String): String {
    val header = """{"alg":"ES256","typ":"vc+jwt"}""".encodeToByteArray().encodeToBase64Url()
    val payload = payloadJson.encodeToByteArray().encodeToBase64Url()
    return "$header.$payload.fakesig"
}

/**
 * Builds a minimal, real (base64url-encoded CBOR) mdoc `IssuerSigned` structure carrying
 * [doctype] in its MSO, so [Oid4vciIssuedCredentialAcceptance.actualTypeRefs]'s mdoc branch can
 * decode a real doctype instead of failing to derive one.
 */
internal fun buildTestMdocCredential(doctype: String): String {
    val mobileSecurityObjectCodec = MobileSecurityObjectCborCodecImpl()
    val issuerSignedCodec = IssuerSignedCborCodecImpl()
    val now = TDate("2025-01-20T12:00:00Z")
    val mso =
        MobileSecurityObject(
            version = MsoVersion("1.0"),
            digestAlgorithm = DigestAlgorithm("SHA-256"),
            valueDigests = emptyMap(),
            deviceKeyInfo =
                DeviceKeyInfo(
                    deviceKey =
                        CoseKeyJson
                            .Builder()
                            .withKty(CoseKeyTypeEnum.EC2)
                            .withCrv(CoseCurve.P_256)
                            .withX("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
                            .withY("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
                            .build()
                            .toCbor(),
                    keyAuthorizations = null,
                    keyInfo = null,
                    original = null,
                ),
            docType = DocType(doctype),
            validityInfo =
                ValidityInfo(
                    signed = now,
                    validFrom = now,
                    validUntil = now,
                    expectedUpdate = null,
                ),
            original = null,
        )
    val issuerSigned =
        IssuerSigned(
            nameSpaces = emptyMap(),
            issuerAuth =
                CoseSign1<MobileSecurityObject>(
                    protectedHeader = CoseHeaderCbor(alg = CoseAlgorithm.ES256),
                    unprotectedHeader = CoseHeaderCbor(),
                    payload = CborByteString(mobileSecurityObjectCodec.encodeTag24(mso).getOrThrow()),
                    signature = CborByteString(ByteArray(64) { it.toByte() }),
                ),
            original = null,
        )
    return issuerSignedCodec.encode(issuerSigned).getOrThrow().encodeToBase64Url()
}

/**
 * Real [Oid4vciIssuedCredentialAcceptance] backed by the real [CredentialSubjectExtractorImpl] and
 * [TestPassThroughWalletIdentityResolver], plus a caller-supplied verification command which
 * defaults to an always-accepting fake.
 */
private fun testAcceptance(
    verify: VerifySdJwtVcCommand = FakeVerifySdJwtVcCommand(accept = true),
    verifyJws: VerifyJwsCommand? = ReceiverVerifyJwsCommand,
    vcdmDataIntegrityVerifier: VcdmDataIntegrityVerifier? = null,
): Oid4vciIssuedCredentialAcceptance =
    Oid4vciIssuedCredentialAcceptance(
        verifySdJwtVcCommand = verify,
        verifyJwsCommand = verifyJws,
        subjectExtractor = CredentialSubjectExtractorImpl(),
        identityResolver = TestPassThroughWalletIdentityResolver,
        vcdmDataIntegrityVerifier = vcdmDataIntegrityVerifier,
    )

/** Controlled cryptographic seam for receiver unit tests; compact-JWS shape alone is not trusted. */
private object ReceiverVerifyJwsCommand : VerifyJwsCommand {
    override val commandId: String = VerifyJwsCommand.COMMAND_ID
    override val inputTypeToken: TypeToken<VerifyJwsArgs> = typeToken<VerifyJwsArgs>()
    override val outputTypeToken: TypeToken<JwsValidationResult> = typeToken<JwsValidationResult>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is VerifyJwsArgs

    override suspend fun execute(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> {
        val compact = args.jws as? JwsCompact ?: return IdkResult.err(IdkError.fromString("compact JWS required"))
        val payload = compact.value.split(".").getOrNull(1)?.decodeFromBase64Url()?.decodeToString()
            ?: return IdkResult.err(IdkError.fromString("payload required"))
        return Ok(
            JwsValidationResult(
                jws = JwsJsonGeneralWithIdentifiers(payload = "", signatures = emptyList()),
                isValid = true,
                parsedPayload = Json.parseToJsonElement(payload).jsonObject,
            ),
        )
    }
}

class WalletStoreOid4vciCredentialResponseReceiverTest {
    /**
     * Encodes [state] as the single typed OID4VCI private session state blob under the "state"
     * key, matching how the executor/adapter persist it in production.
     */
    private fun oid4vciStateValues(state: Oid4vciPrivateSessionState): Map<String, String> =
        mapOf("state" to Json.encodeToString(Oid4vciPrivateSessionState.serializer(), state))

    @Test
    fun receiverRoutesVcdm20WireFormatToDistinctWalletFormatAndPreservesRootCredential() =
        runTest {
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val receiver =
                WalletStoreOid4vciCredentialResponseReceiver(
                    credentialStore,
                    FakeWalletIssuanceSessionStore(),
                    testAcceptance(),
                    WalletHolderVerificationMethodResolver { _, keyRef ->
                        if (keyRef.alias == "wallet-holder-key-vcdm20") {
                            WalletHolderVerificationMethod(
                                value = "https://wallet.example/jwks#holder-vcdm20",
                                controller = "https://wallet.example/holders/vcdm20",
                                kind = WalletHolderIdentifierKind.JWKS_KID,
                                signingAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                            )
                        } else {
                            null
                        }
                    },
                )
            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-vcdm20-route-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-vcdm20"),
                            ),
                        ),
                ),
            )
            val failureDetails = mutableListOf<Map<String, String>>()
            val receiverDiagnostics = object : WalletInteractionDiagnostics {
                override fun warn(event: String, sessionId: WalletInteractionSessionId?, details: Map<String, String>) {
                    assertEquals("oid4vci.credential_receive.failed", event)
                    assertEquals("oid4vci-receiver-vcdm20-route-test", sessionId?.value)
                    failureDetails += details
                }
            }
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                    diagnostics = receiverDiagnostics,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    issuerAuthentication =
                        WalletIssuerAuthenticationResult(
                            issuer = "https://issuer.example",
                            trustedJwks = Json.parseToJsonElement("""{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y","kid":"issuer-vcdm20"}]}""").jsonObject,
                            provenance = listOf(WalletIssuerAuthenticationProvenance("test", "vcdm20")),
                        ),
                )
            val rawCredential =
                buildTestCompactJwt(
                    """{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential","EmployeeCredential"],"issuer":"https://issuer.example","validFrom":"2026-01-01T00:00:00Z","credentialSubject":{"id":"did:example:v2-holder","degree":"BSc"}}""",
                )

            val response = CredentialResponse(credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(rawCredential))))
            suspend fun receiveWith(resolver: WalletHolderVerificationMethodResolver?, store: WalletCredentialStore = credentialStore, acceptance: Oid4vciIssuedCredentialAcceptance = testAcceptance()) =
                WalletStoreOid4vciCredentialResponseReceiver(store, FakeWalletIssuanceSessionStore(), acceptance, resolver)
                    .receiveCredentialResponse(context, state, resolvedVcdm20Offer(), response)

            assertFailsWith<IllegalStateException> { receiveWith(null) }
            assertEquals("holder-verification-method", failureDetails.last()["stage"])
            assertEquals("holder_resolver_missing", failureDetails.last()["reason"])
            assertFailsWith<IllegalStateException> { receiveWith(WalletHolderVerificationMethodResolver { _, _ -> null }) }
            assertEquals("holder_association_missing", failureDetails.last()["reason"])
            val resolverFailure = IllegalStateException("private-token-and-key-material")
            val thrown = assertFailsWith<IllegalStateException> {
                receiveWith(WalletHolderVerificationMethodResolver { _, _ -> throw resolverFailure })
            }
            assertTrue(thrown === resolverFailure, "logging must preserve the original failure")
            assertEquals("holder-verification-method", failureDetails.last()["stage"])
            assertEquals("IllegalStateException", failureDetails.last()["causeType"])
            failureDetails.last()["failureSite"]?.let { site ->
                assertTrue(Regex("""[A-Z][\w$]*\.[\w$<>-]+""").matches(site), "failure site is a closed Class.method: $site")
                assertTrue("private" !in site, "failure site never carries the failure message")
            }
            val cancellation = CancellationException("private-cancellation-details")
            val warningCount = failureDetails.size
            assertTrue(assertFailsWith<CancellationException> {
                receiveWith(WalletHolderVerificationMethodResolver { _, _ -> throw cancellation })
            } === cancellation)
            assertEquals(warningCount, failureDetails.size, "cancellation is not a receive failure")
            assertTrue(credentialStore.listMetadata(WALLET_UNIT_ID).getOrThrow().isEmpty())

            val methodResolver = WalletHolderVerificationMethodResolver { _, _ ->
                WalletHolderVerificationMethod(
                    value = "https://wallet.example/jwks#holder-vcdm20",
                    controller = "https://wallet.example/holders/vcdm20",
                    kind = WalletHolderIdentifierKind.JWKS_KID,
                    signingAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                )
            }
            assertFailsWith<IllegalStateException> {
                receiveWith(methodResolver, acceptance = testAcceptance(verifyJws = null))
            }
            assertEquals("credential-signature-verification", failureDetails.last()["stage"])
            assertEquals("jws_command_missing", failureDetails.last()["reason"])
            val providerFailure = IdkError.fromString(
                code = "TEST_JWS_PROVIDER_REFUSED", message = "private-parser-payload",
                exception = IllegalArgumentException("private-parser-key"),
            )
            val rejectingVerifier = object : VerifyJwsCommand by ReceiverVerifyJwsCommand {
                override suspend fun execute(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> = Err(providerFailure)
            }
            assertFailsWith<IllegalStateException> {
                receiveWith(methodResolver, acceptance = testAcceptance(verifyJws = rejectingVerifier))
            }
            assertEquals("credential-signature-verification", failureDetails.last()["stage"])
            assertEquals("jws_command_failed", failureDetails.last()["reason"])
            assertEquals("ISSUED_CREDENTIAL_VERIFICATION_FAILED", failureDetails.last()["providerErrorCode"])
            assertEquals("TEST_JWS_PROVIDER_REFUSED", failureDetails.last()["providerCause1Code"])
            assertEquals("IllegalArgumentException", failureDetails.last()["providerCause1Type"])
            val failingStore = object : WalletCredentialStore by credentialStore {
                override suspend fun putCredential(walletUnitId: String, record: CredentialRecord): IdkResult<CredentialRecord, IdkError> =
                    Err(IdkError.fromString(code = "TEST_STORE_REFUSED", message = "private-storage-payload"))
            }
            assertFailsWith<IllegalStateException> { receiveWith(methodResolver, failingStore) }
            assertEquals("credential-store", failureDetails.last()["stage"])
            assertEquals("TEST_STORE_REFUSED", failureDetails.last()["providerErrorCode"])
            val logged = failureDetails.toString()
            listOf(rawCredential, "private-token-and-key-material", "private-storage-payload", "private-parser-payload", "private-parser-key", "wallet-holder-key-vcdm20").forEach {
                assertTrue(it !in logged, "receive diagnostics must not contain credentials, aliases, or exception messages")
            }
            assertTrue(credentialStore.listMetadata(WALLET_UNIT_ID).getOrThrow().isEmpty())

            val previews =
                receiver.receiveCredentialResponse(
                    context = context,
                    state = state,
                    resolvedOffer = resolvedVcdm20Offer(),
                    credentialResponse =
                        CredentialResponse(
                            credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(rawCredential))),
                        ),
                )

            assertEquals(1, previews.size)
            assertEquals(CredentialFormat.JWT_VC_JSON_LD.value, previews.single().format)
            val metadata = credentialStore.listMetadata(WALLET_UNIT_ID, CredentialMetadataFilter(credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID)).getOrThrow().single()
            assertEquals(CredentialFormat.JWT_VC_JSON_LD, metadata.format)
            assertTrue(metadata.credentialTypeRefs.any { it.value == "EmployeeCredential" && it.format == CredentialFormat.JWT_VC_JSON_LD })
            val stored = credentialStore.getCredential(WALLET_UNIT_ID, metadata.credentialRecordId).getOrThrow()
            assertNotNull(stored)
            assertEquals(rawCredential, stored.instances.single().raw)
            assertEquals(listOf("did:example:v2-holder"), stored.subjectRefs.map { it.value })
        }

    @Test
    fun receiverResolvesKeysForTheDidIssuerOfADidSignedVcdmCredential() =
        runTest {
            // OID4VCI 1.0 §14.4: the Credential Issuer Identifier is the HTTPS URL; a DID-signed
            // VCDM credential names its DID, whose keys are resolved for that DID.
            val did = "did:web:issuer.example"
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val methodResolver = WalletHolderVerificationMethodResolver { _, _ ->
                WalletHolderVerificationMethod(
                    value = "https://wallet.example/jwks#holder-did-issuer",
                    controller = "https://wallet.example/holders/did-issuer",
                    kind = WalletHolderIdentifierKind.JWKS_KID,
                    signingAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                )
            }
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-did-issuer-test")
            val privateStore = ReceiverTestPrivateSessionStore()
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values = oid4vciStateValues(
                        Oid4vciPrivateSessionState(
                            credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                            holderKeyAliases = listOf("wallet-holder-key-did-issuer"),
                        ),
                    ),
                ),
            )
            val requested = mutableListOf<String>()
            var didAuthentication: WalletIssuerAuthenticationResult? =
                WalletIssuerAuthenticationResult(
                    issuer = did,
                    trustedJwks = Json.parseToJsonElement("""{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y","kid":"$did#key-1"}]}""").jsonObject,
                    provenance = listOf(WalletIssuerAuthenticationProvenance("test", "did-issuer")),
                )
            val failureDetails = mutableListOf<Map<String, String>>()
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                    sensitiveInputAuthority = Oid4vciTestSensitiveInputAuthority,
                    issuerAuthenticationResolver = object : WalletIssuerAuthenticationResolver {
                        override suspend fun resolve(input: WalletIssuerAuthenticationRequest): WalletIssuerAuthenticationResult? {
                            requested += input.counterparty.identifier
                            return didAuthentication
                        }
                    },
                    diagnostics = object : WalletInteractionDiagnostics {
                        override fun warn(event: String, sessionId: WalletInteractionSessionId?, details: Map<String, String>) {
                            failureDetails += details
                        }
                    },
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    // The offer-time authentication is bound to the HTTPS Credential Issuer; it must
                    // not be used for a credential that names a different (DID) issuer.
                    issuerAuthentication =
                        WalletIssuerAuthenticationResult(
                            issuer = "https://issuer.example",
                            trustedJwks = Json.parseToJsonElement("""{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y","kid":"issuer-url"}]}""").jsonObject,
                            provenance = listOf(WalletIssuerAuthenticationProvenance("test", "url-issuer")),
                        ),
                )
            val rawCredential =
                buildTestCompactJwt(
                    """{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential","EmployeeCredential"],"issuer":"$did","iss":"$did","validFrom":"2026-01-01T00:00:00Z","credentialSubject":{"id":"did:example:did-issuer-holder","degree":"BSc"}}""",
                )
            val response = CredentialResponse(credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(rawCredential))))
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, FakeWalletIssuanceSessionStore(), testAcceptance(), methodResolver)

            didAuthentication = null
            assertFailsWith<IllegalStateException> { receiver.receiveCredentialResponse(context, state, resolvedVcdm20Offer(), response) }
            assertEquals("issuer_keys_missing", failureDetails.last()["reason"])
            assertTrue(credentialStore.listMetadata(WALLET_UNIT_ID).getOrThrow().isEmpty())

            didAuthentication =
                WalletIssuerAuthenticationResult(
                    issuer = did,
                    trustedJwks = Json.parseToJsonElement("""{"keys":[{"kty":"EC","crv":"P-256","x":"x","y":"y","kid":"$did#key-1"}]}""").jsonObject,
                    provenance = listOf(WalletIssuerAuthenticationProvenance("test", "did-issuer")),
                )
            val previews = receiver.receiveCredentialResponse(context, state, resolvedVcdm20Offer(), response)

            assertEquals(listOf(did, did), requested)
            assertEquals(1, previews.size)
            assertEquals(1, credentialStore.listMetadata(WALLET_UNIT_ID).getOrThrow().size)
        }

    @Test
    fun receiverAcceptsRawLdpVcObjectVerifiesBeforeStorageAndPreservesLdpVcMetadata() =
        runTest {
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val verifier = ReceiverRecordingVcdmDataIntegrityVerifier()
            val receiver =
                WalletStoreOid4vciCredentialResponseReceiver(
                    credentialStore,
                    FakeWalletIssuanceSessionStore(),
                    testAcceptance(vcdmDataIntegrityVerifier = verifier),
                    WalletHolderVerificationMethodResolver { _, keyRef ->
                        if (keyRef.alias == "wallet-holder-key-ldp-vc") {
                            WalletHolderVerificationMethod(
                                value = "https://wallet.example/jwks#holder-1",
                                controller = "https://wallet.example/holders/1",
                                kind = WalletHolderIdentifierKind.JWKS_KID,
                                signingAlgorithm = SignatureAlgorithm.ED25519,
                            )
                        } else {
                            null
                        }
                    },
                )
            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-ldp-vc-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-ldp-vc"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                )
            val rawCredential: JsonObject =
                Json.parseToJsonElement(
                    """{"@context":["https://www.w3.org/ns/credentials/v2"],"type":["VerifiableCredential","EmployeeCredential"],"issuer":"https://issuer.example","validFrom":"2026-01-01T00:00:00Z","credentialSubject":{"id":"https://holder.example/subject","degree":"BSc"},"proof":{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022","proofPurpose":"assertionMethod","verificationMethod":"https://issuer.example/keys#assertion","created":"2026-08-26T10:00:00Z","proofValue":"zvalid"}}""",
                ).jsonObject

            val previews =
                receiver.receiveCredentialResponse(
                    context = context,
                    state = state,
                    resolvedOffer = resolvedLdpVcOffer(),
                    credentialResponse =
                        CredentialResponse(
                            credentials = listOf(CredentialResponseItem(credential = rawCredential)),
                        ),
                )

            assertEquals(1, previews.size)
            assertEquals(CredentialFormat.LDP_VC.value, previews.single().format)
            assertEquals(rawCredential, verifier.lastArgs?.document)
            assertEquals(ProofPurpose.ASSERTION_METHOD, verifier.lastArgs?.expectedProofPurpose)
            val metadata =
                credentialStore
                    .listMetadata(WALLET_UNIT_ID, CredentialMetadataFilter(credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID))
                    .getOrThrow()
                    .single()
            assertEquals(CredentialFormat.LDP_VC, metadata.format)
            assertTrue(metadata.credentialTypeRefs.any { it.value == "EmployeeCredential" && it.format == CredentialFormat.LDP_VC })
            val stored = credentialStore.getCredential(WALLET_UNIT_ID, metadata.credentialRecordId).getOrThrow()
            val nonNullStored = assertNotNull(stored)
            assertEquals(rawCredential, Json.parseToJsonElement(assertNotNull(nonNullStored.instances.single().raw)).jsonObject)
            assertEquals("https://wallet.example/jwks#holder-1", nonNullStored.instances.single().holderKeyRef?.kid)
            assertEquals(listOf("https://holder.example/subject"), nonNullStored.subjectRefs.map { it.value })
        }

    @Test
    fun receiverStoresCredentialResponseInWalletStoreWithoutPuttingBodyInMetadata() =
        runTest {
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, FakeWalletIssuanceSessionStore(), testAcceptance())
            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-store-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-1"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                )
            val rawCredential = buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:holder-store-test","vct":"$EMPLOYEE_VCT"}""")

            val previews =
                receiver.receiveCredentialResponse(
                    context = context,
                    state = state,
                    resolvedOffer = resolvedOffer(),
                    credentialResponse =
                        CredentialResponse(
                            credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(rawCredential))),
                            notificationId = "notification-1",
                        ),
                )

            assertEquals(1, previews.size)
            assertEquals("Employee Credential", previews.single().name)
            assertEquals(CredentialFormat.SD_JWT_VC.value, previews.single().format)
            assertEquals("#003399", previews.single().branding?.backgroundColor)
            assertEquals("#FFFFFF", previews.single().branding?.textColor)

            val metadata =
                credentialStore
                    .listMetadata(
                        WALLET_UNIT_ID,
                        CredentialMetadataFilter(credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID),
                    ).getOrThrow()
                    .single()

            assertEquals(CREDENTIAL_CONFIGURATION_ID, metadata.credentialConfigurationId)
            assertEquals("https://issuer.example", metadata.issuerRef.value)
            assertEquals(1, metadata.instanceCount)
            assertEquals(1, metadata.activeInstanceCount)
            assertTrue(
                metadata.credentialTypeRefs.any { ref ->
                    ref.format == CredentialFormat.SD_JWT_VC &&
                        ref.kind == CredentialTypeRefKind.SD_JWT_VCT &&
                        // credentialTypeRefs holds the ACTUAL (payload-derived) set, not the
                        // expected (issuer-metadata) set.
                        ref.source == CredentialTypeRefSource.CREDENTIAL_PAYLOAD &&
                        ref.value == EMPLOYEE_VCT
                },
            )
            assertFalse(metadata.toString().contains(rawCredential), "Credential body must not be present in metadata sidecars")

            val stored =
                credentialStore
                    .getCredential(WALLET_UNIT_ID, metadata.credentialRecordId)
                    .getOrThrow()
            assertNotNull(stored)
            assertEquals(rawCredential, stored.instances.single().raw)
            assertEquals("Employee Credential", stored.display.credentialDisplay.single().name)
            assertEquals("#003399", stored.display.credentialDisplay.single().backgroundColor)
            assertEquals("#FFFFFF", stored.display.credentialDisplay.single().textColor)
            assertEquals(
                "wallet-holder-key-1",
                stored.instances
                    .single()
                    .holderKeyRef
                    ?.alias
            )
            assertEquals(CREDENTIAL_CONFIGURATION_ID, stored.issuanceProvenance?.credentialConfigurationId)
            assertEquals(sessionId.value, stored.issuanceProvenance?.issuanceSessionId)
            assertEquals(emptyList(), stored.issuanceProvenance?.diagnostics, "issued vct matches issuer metadata; no mismatch diagnostic expected")
        }

    @Test
    fun receiverKeepsMdocCredentialConfigurationIdSeparateFromDoctype() =
        runTest {
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, FakeWalletIssuanceSessionStore(), testAcceptance())
            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-mdoc-store-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = MDOC_CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-mdoc-holder-key-1"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                )
            val rawMdocCredential = buildTestMdocCredential(MDOC_DOCTYPE)

            receiver.receiveCredentialResponse(
                context = context,
                state = state,
                resolvedOffer = resolvedMdocOffer(),
                credentialResponse =
                    CredentialResponse(
                        credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(rawMdocCredential))),
                    ),
            )

            val metadata =
                credentialStore
                    .listMetadata(
                        WALLET_UNIT_ID,
                        CredentialMetadataFilter(credentialConfigurationId = MDOC_CREDENTIAL_CONFIGURATION_ID),
                    ).getOrThrow()
                    .single()

            assertEquals(MDOC_CREDENTIAL_CONFIGURATION_ID, metadata.credentialConfigurationId)
            assertEquals(CredentialFormat.MSO_MDOC, metadata.format)
            assertTrue(
                metadata.credentialTypeRefs.any { ref ->
                    ref.format == CredentialFormat.MSO_MDOC &&
                        ref.kind == CredentialTypeRefKind.MDOC_DOCTYPE &&
                        // credentialTypeRefs holds the ACTUAL (payload-derived) set, not the
                        // expected (issuer-metadata) set.
                        ref.source == CredentialTypeRefSource.CREDENTIAL_PAYLOAD &&
                        ref.value == MDOC_DOCTYPE &&
                        ref.primary
                },
            )
            assertFalse(
                metadata.credentialTypeRefs.any { ref -> ref.value == MDOC_CREDENTIAL_CONFIGURATION_ID },
                "The credential configuration id must not be reused as the mdoc credential type reference.",
            )

            val stored =
                credentialStore
                    .getCredential(WALLET_UNIT_ID, metadata.credentialRecordId)
                    .getOrThrow()
            assertNotNull(stored)
            assertEquals(rawMdocCredential, stored.instances.single().raw)
            val expectedValidity = TDate("2025-01-20T12:00:00Z").tDateToEpochSeconds()
            assertEquals(expectedValidity, stored.instances.single().validity.validFrom?.epochSeconds)
            assertEquals(expectedValidity, stored.instances.single().validity.validUntil?.epochSeconds)
            assertEquals(MDOC_CREDENTIAL_CONFIGURATION_ID, stored.issuanceProvenance?.credentialConfigurationId)
            assertEquals(
                MDOC_DOCTYPE,
                stored.issuanceProvenance
                    ?.expectedCredentialTypeRefs
                    ?.single()
                    ?.value
            )
        }

    @Test
    fun receiverPersistsRefreshTokenAndSetsRefreshStateWhenPresent() =
        runTest {
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val issuanceSessionStore = FakeWalletIssuanceSessionStore()
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, issuanceSessionStore, testAcceptance())
            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-refresh-token-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-refresh"),
                                tokens =
                                    Oid4vciPrivateSessionState.TokenLeg(
                                        accessToken = "unused-test-access-token",
                                        refreshToken = "refresh-token-value",
                                    ),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                )

            receiver.receiveCredentialResponse(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer(),
                credentialResponse =
                    CredentialResponse(
                        credentials =
                            listOf(
                                CredentialResponseItem(
                                    credential =
                                        JsonPrimitive(
                                            buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:holder-refresh","vct":"$EMPLOYEE_VCT"}"""),
                                        ),
                                ),
                            ),
                    ),
            )

            assertEquals(1, issuanceSessionStore.storedRefreshTokens.size)
            val metadata =
                credentialStore
                    .listMetadata(
                        WALLET_UNIT_ID,
                        CredentialMetadataFilter(credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID),
                    ).getOrThrow()
                    .single()
            val stored =
                credentialStore
                    .getCredential(WALLET_UNIT_ID, metadata.credentialRecordId)
                    .getOrThrow()
            assertNotNull(stored)
            val refreshState = assertNotNull(stored.refreshState, "refreshState must be set when a refresh_token is present")
            assertEquals(CredentialRefreshMethod.OID4VCI_REISSUANCE, refreshState.refreshMethod)
            assertNotNull(refreshState.refreshTokenRef)
            assertEquals("refresh-token-value", issuanceSessionStore.storedRefreshTokens[metadata.credentialRecordId])
        }

    @Test
    fun receiverLeavesRefreshStateNullWhenNoRefreshTokenPresent() =
        runTest {
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val issuanceSessionStore = FakeWalletIssuanceSessionStore()
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, issuanceSessionStore, testAcceptance())
            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-no-refresh-token-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-no-refresh"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                )

            receiver.receiveCredentialResponse(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer(),
                credentialResponse =
                    CredentialResponse(
                        credentials =
                            listOf(
                                CredentialResponseItem(
                                    credential =
                                        JsonPrimitive(
                                            buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:holder-no-refresh","vct":"$EMPLOYEE_VCT"}"""),
                                        ),
                                ),
                            ),
                    ),
            )

            assertTrue(issuanceSessionStore.storedRefreshTokens.isEmpty())
            val metadata =
                credentialStore
                    .listMetadata(
                        WALLET_UNIT_ID,
                        CredentialMetadataFilter(credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID),
                    ).getOrThrow()
                    .single()
            val stored =
                credentialStore
                    .getCredential(WALLET_UNIT_ID, metadata.credentialRecordId)
                    .getOrThrow()
            assertNotNull(stored)
            assertEquals(null, stored.refreshState)
        }

    // -----------------------------------------------------------------------------------------
    // Coverage: issuer-verification gate, type-ref reconciliation, and subject extraction on
    // credential receipt.
    // -----------------------------------------------------------------------------------------

    @Test
    fun receiverRejectsCredentialWhenIssuerVerificationFails() =
        runTest {
            // The receiver verifies the issued SD-JWT VC on receipt; when issuer-signature
            // verification fails it must NOT store the credential and must surface an error.
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val receiver =
                WalletStoreOid4vciCredentialResponseReceiver(
                    credentialStore,
                    FakeWalletIssuanceSessionStore(),
                    testAcceptance(verify = FakeVerifySdJwtVcCommand(accept = false)),
                )
            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-verification-failed-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-verify-fail"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                )
            val rawCredential = buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:holder-verify-fail","vct":"$EMPLOYEE_VCT"}""")

            val thrown =
                assertFailsWith<IllegalStateException> {
                    receiver.receiveCredentialResponse(
                        context = context,
                        state = state,
                        resolvedOffer = resolvedOffer(),
                        credentialResponse =
                            CredentialResponse(credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(rawCredential)))),
                    )
                }
            assertTrue(
                thrown.message.orEmpty().contains("issuer-signature verification failed"),
                "expected an issuer-signature verification failure message, got: ${thrown.message}",
            )
            assertEquals(0, credentialStore.listMetadata(WALLET_UNIT_ID).getOrThrow().size, "no document should have been stored")
        }

    @Test
    fun receiverKeepsActualTypeRefsCanonicalAndRecordsMismatchDiagnostic() =
        runTest {
            val actualVct = "https://credentials.example.com/employee-v2"
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, FakeWalletIssuanceSessionStore(), testAcceptance())
            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-mismatch-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-mismatch"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                )
            val rawCredential = buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:holder-mismatch","vct":"$actualVct"}""")

            receiver.receiveCredentialResponse(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer(),
                credentialResponse = CredentialResponse(credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(rawCredential)))),
            )

            val metadata =
                credentialStore
                    .listMetadata(WALLET_UNIT_ID, CredentialMetadataFilter(credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID))
                    .getOrThrow()
                    .single()
            val stored = credentialStore.getCredential(WALLET_UNIT_ID, metadata.credentialRecordId).getOrThrow()
            assertNotNull(stored)
            assertEquals(setOf(actualVct), stored.credentialTypeRefs.map { it.value }.toSet())
            assertEquals(
                setOf(EMPLOYEE_VCT),
                stored.issuanceProvenance
                    ?.expectedCredentialTypeRefs
                    ?.map { it.value }
                    ?.toSet(),
            )
            val diagnostic = stored.issuanceProvenance?.diagnostics?.single()
            assertEquals(IssuanceDiagnosticCode.CREDENTIAL_TYPE_REF_MISMATCH, diagnostic?.code)
            assertEquals(setOf(EMPLOYEE_VCT), diagnostic?.expectedCredentialTypeRefs?.map { it.value }?.toSet())
            assertEquals(setOf(actualVct), diagnostic?.actualCredentialTypeRefs?.map { it.value }?.toSet())
        }

    @Test
    fun receiverRejectsIssuedCredentialWithoutPayloadTypeRefs() =
        runTest {
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, FakeWalletIssuanceSessionStore(), testAcceptance())
            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-missing-vct-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-missing-vct"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                )
            val rawCredential = buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:holder-missing-vct"}""")

            assertFailsWith<IllegalStateException> {
                receiver.receiveCredentialResponse(
                    context = context,
                    state = state,
                    resolvedOffer = resolvedOffer(),
                    credentialResponse =
                        CredentialResponse(credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(rawCredential)))),
                )
            }
            assertEquals(0, credentialStore.listMetadata(WALLET_UNIT_ID).getOrThrow().size, "no document should have been stored")
        }

    @Test
    fun receiverOnlyUsesExpectedTypeRefsForSelectedFormat() =
        runTest {
            // Issuer metadata carries vct + doctype + W3C type noise on the SAME configuration;
            // only the vct branch (matching the selected dc+sd-jwt format) may participate in the
            // expected refs, so a payload whose vct matches produces no mismatch diagnostic.
            val noisyOffer =
                ResolvedCredentialOffer(
                    offer =
                        CredentialOffer(
                            credentialIssuer = "https://issuer.example",
                            credentialConfigurationIds = listOf(CREDENTIAL_CONFIGURATION_ID),
                            grants = CredentialOfferGrants(preAuthorizedCode = PreAuthorizedCodeOfferGrant(preAuthorizedCode = "pre-authorized-code")),
                        ),
                    issuerMetadata =
                        CredentialIssuerMetadata(
                            credentialIssuer = "https://issuer.example",
                            credentialEndpoint = "https://issuer.example/credential",
                            credentialConfigurationsSupported =
                                mapOf(
                                    CREDENTIAL_CONFIGURATION_ID to
                                        CredentialConfigurationSupported(
                                            format = CredentialFormat.SD_JWT_VC.value,
                                            vct = EMPLOYEE_VCT,
                                            doctype = MDOC_DOCTYPE,
                                            credentialDefinition = CredentialDefinition(type = listOf("VerifiableCredential", "WrongCredential")),
                                            display = listOf(DisplayProperties(name = "Employee Credential")),
                                        ),
                                ),
                        ),
                )
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, FakeWalletIssuanceSessionStore(), testAcceptance())
            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-format-scoped-expected-refs-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-noisy"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                )
            val rawCredential = buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:holder-noisy","vct":"$EMPLOYEE_VCT"}""")

            receiver.receiveCredentialResponse(
                context = context,
                state = state,
                resolvedOffer = noisyOffer,
                credentialResponse = CredentialResponse(credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(rawCredential)))),
            )

            val metadata =
                credentialStore
                    .listMetadata(WALLET_UNIT_ID, CredentialMetadataFilter(credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID))
                    .getOrThrow()
                    .single()
            val stored = credentialStore.getCredential(WALLET_UNIT_ID, metadata.credentialRecordId).getOrThrow()
            assertNotNull(stored)
            assertEquals(
                setOf(EMPLOYEE_VCT),
                stored.issuanceProvenance
                    ?.expectedCredentialTypeRefs
                    ?.map { it.value }
                    ?.toSet(),
            )
            assertEquals(emptyList(), stored.issuanceProvenance?.diagnostics)
        }

    @Test
    fun receiverPopulatesSubjectsFromCredential() =
        runTest {
            val subjectDid = "did:example:holder-subject-42"
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, FakeWalletIssuanceSessionStore(), testAcceptance())
            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-subjects-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-subject"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                )
            val rawCredential = buildTestSdJwt("""{"iss":"https://issuer.example","sub":"$subjectDid","vct":"$EMPLOYEE_VCT"}""")

            receiver.receiveCredentialResponse(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer(),
                credentialResponse = CredentialResponse(credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(rawCredential)))),
            )

            val metadata =
                credentialStore
                    .listMetadata(WALLET_UNIT_ID, CredentialMetadataFilter(credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID))
                    .getOrThrow()
                    .single()
            val stored = credentialStore.getCredential(WALLET_UNIT_ID, metadata.credentialRecordId).getOrThrow()
            assertNotNull(stored)
            assertEquals(1, stored.subjectRefs.size, "expected one subject extracted from credential")
            assertEquals(IdentifierType.DID, stored.subjectRefs[0].type)
            assertEquals(subjectDid, stored.subjectRefs[0].value)
            // The test-only resolver returns the ref unchanged, so identityIdentifierId stays null.
            assertEquals(null, stored.subjectRefs[0].identityIdentifierId)
        }

    @Test
    fun receiverAppendsInstancesToExistingRecordAndKeepsActualTypeRefsCanonical() =
        runTest {
            // A second receiveCredentialResponse call for the same issuer+credentialConfigurationId
            // must append an instance to the existing record rather than create a new one, and
            // credentialTypeRefs on append reflects the ACTUAL (payload-derived) set, not the
            // static expected/metadata set.
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, FakeWalletIssuanceSessionStore(), testAcceptance())
            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-append-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-append-1"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                )
            val firstRaw = buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:holder-append-1","vct":"$EMPLOYEE_VCT"}""")

            receiver.receiveCredentialResponse(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer(),
                credentialResponse = CredentialResponse(credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(firstRaw)))),
            )
            val firstMetadata =
                credentialStore
                    .listMetadata(WALLET_UNIT_ID, CredentialMetadataFilter(credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID))
                    .getOrThrow()
                    .single()
            assertEquals(1, firstMetadata.instanceCount)

            // Second obtain against the SAME session (same credential configuration + issuer):
            // resets holderKeyAliases for the second response item and re-issues a second instance.
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-append-2"),
                            ),
                        ),
                ),
            )
            val secondRaw = buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:holder-append-2","vct":"$EMPLOYEE_VCT"}""")

            receiver.receiveCredentialResponse(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer(),
                credentialResponse = CredentialResponse(credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(secondRaw)))),
            )

            val metadata =
                credentialStore
                    .listMetadata(WALLET_UNIT_ID, CredentialMetadataFilter(credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID))
                    .getOrThrow()
                    .single()
            assertEquals(firstMetadata.credentialRecordId, metadata.credentialRecordId, "second obtain must append to the same record")
            assertEquals(2, metadata.instanceCount)
            val stored = credentialStore.getCredential(WALLET_UNIT_ID, metadata.credentialRecordId).getOrThrow()
            assertNotNull(stored)
            assertEquals(2, stored.instances.size)
            assertEquals(setOf(firstRaw, secondRaw), stored.instances.map { it.raw }.toSet())
            assertEquals(setOf(EMPLOYEE_VCT), stored.credentialTypeRefs.map { it.value }.toSet())
            assertEquals(emptyList(), stored.issuanceProvenance?.diagnostics)
        }

    // -----------------------------------------------------------------------------------------
    // Coverage: wallet-initiated refresh supersede semantics.
    // -----------------------------------------------------------------------------------------

    @Test
    fun receiverSupersedesPreviousActiveInstanceOnWalletInitiatedRefresh() =
        runTest {
            // A wallet-initiated refresh targets an EXISTING record by id
            // (sessionState.refreshTargetCredentialRecordId), unlike normal issuance top-up which
            // matches by issuer+credentialConfigurationId. Storage must SUPERSEDE the previously
            // ACTIVE instance (not append a top-up instance), preserve the record's EXISTING refresh
            // policy across a rotated refresh token, and leave issuanceProvenance untouched.
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val issuanceSessionStore = FakeWalletIssuanceSessionStore()
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, issuanceSessionStore, testAcceptance())
            val now = Clock.System.now()
            val recordId = "refresh-target-record"
            val originalInstanceId = "refresh-target-instance-original"
            val originalRaw =
                buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:holder-refresh","vct":"$EMPLOYEE_VCT","credential_id":"vc-initial"}""")
            val originalInstance =
                CredentialInstance(
                    id = originalInstanceId,
                    walletUnitId = WALLET_UNIT_ID,
                    credentialRecordId = recordId,
                    format = CredentialFormat.SD_JWT_VC,
                    raw = originalRaw,
                    bodyStorageRef = BodyStorageRef(kind = BodyStorageKind.WALLET_STORE, path = "placeholder"),
                    holderKeyRef = KeyRef(alias = "wallet-holder-key-refresh"),
                    lifecycleState = CredentialLifecycleState.ACTIVE,
                    storedAt = now,
                    updatedAt = now,
                )
            val existingRecord =
                CredentialRecord(
                    id = recordId,
                    walletUnitId = WALLET_UNIT_ID,
                    issuerRef = IdentifierRef(type = IdentifierType("https"), value = "https://issuer.example"),
                    format = CredentialFormat.SD_JWT_VC,
                    credentialTypeRefs =
                        setOf(
                            CredentialTypeRef(
                                format = CredentialFormat.SD_JWT_VC,
                                kind = CredentialTypeRefKind.SD_JWT_VCT,
                                value = EMPLOYEE_VCT,
                                source = CredentialTypeRefSource.CREDENTIAL_PAYLOAD,
                                primary = true,
                            ),
                        ),
                    instances = listOf(originalInstance),
                    issuanceProvenance = IssuanceProvenance(credentialIssuerUrl = "https://issuer.example", credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID, issuedAt = now),
                    refreshState =
                        RefreshState(
                            refreshMethod = CredentialRefreshMethod.OID4VCI_REISSUANCE,
                            policy = RefreshPolicy(lowWatermark = 2, supersedePreviousActiveInstance = true),
                        ),
                    createdAt = now,
                    updatedAt = now,
                )
            assertTrue(credentialStore.putCredential(WALLET_UNIT_ID, existingRecord).isOk)

            val privateStore = ReceiverTestPrivateSessionStore()
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-refresh-supersede-test")
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-holder-key-refresh"),
                                refreshTargetCredentialRecordId = recordId,
                                tokens =
                                    Oid4vciPrivateSessionState.TokenLeg(
                                        accessToken = "unused-refresh-access-token",
                                        refreshToken = "rotated-refresh-token",
                                    ),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    status = WalletInteractionStatus.Completed,
                    flowKind = WalletInteractionFlowKind.CredentialReceive,
                    protocol = WalletProtocol.OID4VCI,
                    adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                )
            val refreshedRaw =
                buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:holder-refresh","vct":"$EMPLOYEE_VCT","credential_id":"vc-refreshed"}""")

            receiver.receiveCredentialResponse(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer(),
                credentialResponse = CredentialResponse(credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(refreshedRaw)))),
            )

            val stored = credentialStore.getCredential(WALLET_UNIT_ID, recordId).getOrThrow()
            assertNotNull(stored)
            assertEquals(2, stored.instances.size, "refresh keeps the superseded instance alongside the new one, it does not replace the list")
            val oldInstance = stored.instances.single { it.id == originalInstanceId }
            val newInstance = stored.instances.single { it.id != originalInstanceId }
            assertEquals(CredentialLifecycleState.SUPERSEDED, oldInstance.lifecycleState, "the previously ACTIVE instance must be superseded")
            assertEquals(CredentialLifecycleState.ACTIVE, newInstance.lifecycleState)
            assertEquals(originalInstanceId, newInstance.replacesInstanceId)
            assertEquals(refreshedRaw, newInstance.raw)
            assertEquals(originalRaw, oldInstance.raw, "the superseded instance body must be preserved, not overwritten")

            val refreshState = assertNotNull(stored.refreshState)
            assertNotNull(refreshState.lastRefreshAt, "withRefreshedInstance must stamp lastRefreshAt")
            assertEquals(emptyList(), refreshState.diagnostics, "same vct on reissue must not produce a refresh diagnostic")
            assertEquals(2, refreshState.policy.lowWatermark, "the existing record's refresh policy must be preserved across a token rotation, not reset to defaults")
            assertEquals(true, refreshState.policy.supersedePreviousActiveInstance)
            assertNotNull(refreshState.refreshTokenRef, "a rotated refresh token must produce an updated refreshTokenRef")
            assertEquals("rotated-refresh-token", issuanceSessionStore.storedRefreshTokens[recordId])

            // issuanceProvenance is untouched by refresh, unlike normal issuance top-up which
            // appends type-ref diagnostics.
            assertEquals(existingRecord.issuanceProvenance?.issuedAt, stored.issuanceProvenance?.issuedAt)
            assertEquals(emptyList(), stored.issuanceProvenance?.diagnostics)
        }

    @Test
    fun receiverRefreshesBatchByExactAliasAndPreservesUntargetedActiveSibling() =
        runTest {
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val issuanceSessionStore = FakeWalletIssuanceSessionStore()
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, issuanceSessionStore, testAcceptance())
            val now = Clock.System.now()
            val recordId = "refresh-targeted-record"
            val first = refreshReceiverInstance(recordId, "instance-a", "wallet-key-a", "did:example:a")
            val sibling = refreshReceiverInstance(recordId, "instance-b", "wallet-key-b", "did:example:b")
            val untargeted = refreshReceiverInstance(recordId, "instance-c", "wallet-key-c", "did:example:c")
            val existing = refreshReceiverRecord(recordId, listOf(first, sibling, untargeted), now)
            credentialStore.putCredential(WALLET_UNIT_ID, existing)
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-targeted-refresh-test")
            val privateStore = ReceiverTestPrivateSessionStore()
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-key-a", "wallet-key-b"),
                                refreshTargetCredentialRecordId = recordId,
                                refreshTargetCredentialInstanceIds = listOf("instance-a", "instance-b"),
                                tokens = Oid4vciPrivateSessionState.TokenLeg(accessToken = "access", refreshToken = "rotated"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val state = receiverTestState(sessionId)
            val refreshedRaw = buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:a","vct":"$EMPLOYEE_VCT","credential_id":"refreshed-a"}""")
            val refreshedSiblingRaw = buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:b","vct":"$EMPLOYEE_VCT","credential_id":"refreshed-b"}""")

            receiver.receiveCredentialResponse(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer(),
                credentialResponse =
                    CredentialResponse(
                        credentials =
                            listOf(
                                CredentialResponseItem(credential = JsonPrimitive(refreshedRaw)),
                                CredentialResponseItem(credential = JsonPrimitive(refreshedSiblingRaw)),
                            ),
                    ),
            )

            val stored = assertNotNull(credentialStore.getCredential(WALLET_UNIT_ID, recordId).getOrThrow())
            assertEquals(CredentialLifecycleState.SUPERSEDED, stored.instances.single { it.id == "instance-a" }.lifecycleState)
            assertEquals(CredentialLifecycleState.SUPERSEDED, stored.instances.single { it.id == "instance-b" }.lifecycleState)
            assertEquals(CredentialLifecycleState.ACTIVE, stored.instances.single { it.id == "instance-c" }.lifecycleState)
            val replacementA = stored.instances.single { it.raw == refreshedRaw }
            val replacementB = stored.instances.single { it.raw == refreshedSiblingRaw }
            assertEquals("wallet-key-a", replacementA.holderKeyRef?.alias)
            assertEquals("instance-a", replacementA.replacesInstanceId)
            assertEquals("wallet-key-b", replacementB.holderKeyRef?.alias)
            assertEquals("instance-b", replacementB.replacesInstanceId)
        }

    @Test
    fun receiverRejectsPartialRefreshResponseWithoutMutatingRecordOrRefreshToken() =
        runTest {
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val issuanceSessionStore = FakeWalletIssuanceSessionStore()
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, issuanceSessionStore, testAcceptance())
            val now = Clock.System.now()
            val recordId = "refresh-partial-record"
            val first = refreshReceiverInstance(recordId, "instance-a", "wallet-key-a", "did:example:a")
            val sibling = refreshReceiverInstance(recordId, "instance-b", "wallet-key-b", "did:example:b")
            val existing = refreshReceiverRecord(recordId, listOf(first, sibling), now)
            credentialStore.putCredential(WALLET_UNIT_ID, existing)
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-partial-refresh-test")
            val privateStore = ReceiverTestPrivateSessionStore()
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-key-a", "wallet-key-b"),
                                refreshTargetCredentialRecordId = recordId,
                                refreshTargetCredentialInstanceIds = listOf("instance-a", "instance-b"),
                                tokens = Oid4vciPrivateSessionState.TokenLeg(accessToken = "access", refreshToken = "must-not-store"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )

            assertFailsWith<IllegalStateException> {
                receiver.receiveCredentialResponse(
                    context = context,
                    state = receiverTestState(sessionId),
                    resolvedOffer = resolvedOffer(),
                    credentialResponse = CredentialResponse(credentials = listOf(CredentialResponseItem(credential = JsonPrimitive("only-one")))),
                )
            }
            val stored = assertNotNull(credentialStore.getCredential(WALLET_UNIT_ID, recordId).getOrThrow())
            assertEquals(existing.instances.map { it.id to it.lifecycleState }, stored.instances.map { it.id to it.lifecycleState })
            assertEquals(emptyMap(), issuanceSessionStore.storedRefreshTokens)
        }

    @Test
    fun receiverFailsClosedWhenRotatedRefreshTokenCannotBePersisted() =
        runTest {
            val credentialStore =
                BlobWalletCredentialStore(
                    blobService = createOid4vciReceiverTestBlobService(),
                    credentialBodyProtector = ReceiverTestCredentialBodyProtector,
                )
            val issuanceSessionStore = FakeWalletIssuanceSessionStore(failRefreshTokenPersistence = true)
            val receiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, issuanceSessionStore, testAcceptance())
            val now = Clock.System.now()
            val recordId = "refresh-token-persistence-failure-record"
            val original = refreshReceiverInstance(recordId, "instance-a", "wallet-key-a", "did:example:a")
            val existing = refreshReceiverRecord(recordId, listOf(original), now)
            assertTrue(credentialStore.putCredential(WALLET_UNIT_ID, existing).isOk)
            val sessionId = WalletInteractionSessionId("oid4vci-receiver-refresh-token-persistence-failure-test")
            val privateStore = ReceiverTestPrivateSessionStore()
            privateStore.put(
                sessionId,
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        oid4vciStateValues(
                            Oid4vciPrivateSessionState(
                                credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID,
                                holderKeyAliases = listOf("wallet-key-a"),
                                refreshTargetCredentialRecordId = recordId,
                                refreshTargetCredentialInstanceIds = listOf("instance-a"),
                                tokens = Oid4vciPrivateSessionState.TokenLeg(accessToken = "access", refreshToken = "rotated"),
                            ),
                        ),
                ),
            )
            val context =
                WalletInteractionContext(
                    sessionId = sessionId,
                    walletUnitId = WALLET_UNIT_ID,
                    executionOwner = ProtocolExecutionOwner.WALLET_BACKEND,
                    privateSessionStore = privateStore,
                )
            val refreshedRaw =
                buildTestSdJwt("""{"iss":"https://issuer.example","sub":"did:example:a","vct":"$EMPLOYEE_VCT","credential_id":"refreshed"}""")

            assertFailsWith<IllegalStateException> {
                receiver.receiveCredentialResponse(
                    context = context,
                    state = receiverTestState(sessionId),
                    resolvedOffer = resolvedOffer(),
                    credentialResponse = CredentialResponse(credentials = listOf(CredentialResponseItem(credential = JsonPrimitive(refreshedRaw)))),
                )
            }

            val stored = assertNotNull(credentialStore.getCredential(WALLET_UNIT_ID, recordId).getOrThrow())
            assertEquals(existing.instances.map { it.id to it.lifecycleState }, stored.instances.map { it.id to it.lifecycleState })
            assertEquals(emptyMap(), issuanceSessionStore.storedRefreshTokens)
        }

    private fun refreshReceiverInstance(recordId: String, instanceId: String, alias: String, subject: String): CredentialInstance =
        CredentialInstance(
            id = instanceId,
            walletUnitId = WALLET_UNIT_ID,
            credentialRecordId = recordId,
            format = CredentialFormat.SD_JWT_VC,
            raw = "existing-$instanceId-$subject",
            bodyStorageRef = BodyStorageRef(kind = BodyStorageKind.WALLET_STORE, path = "placeholder/$instanceId"),
            holderKeyRef = KeyRef(alias = alias),
            lifecycleState = CredentialLifecycleState.ACTIVE,
            storedAt = Clock.System.now(),
            updatedAt = Clock.System.now(),
        )

    private fun refreshReceiverRecord(recordId: String, instances: List<CredentialInstance>, now: kotlin.time.Instant): CredentialRecord =
        CredentialRecord(
            id = recordId,
            walletUnitId = WALLET_UNIT_ID,
            issuerRef = IdentifierRef(type = IdentifierType("https"), value = "https://issuer.example"),
            format = CredentialFormat.SD_JWT_VC,
            credentialTypeRefs =
                setOf(
                    CredentialTypeRef(
                        format = CredentialFormat.SD_JWT_VC,
                        kind = CredentialTypeRefKind.SD_JWT_VCT,
                        value = EMPLOYEE_VCT,
                        source = CredentialTypeRefSource.CREDENTIAL_PAYLOAD,
                        primary = true,
                    ),
                ),
            instances = instances,
            issuanceProvenance = IssuanceProvenance(credentialIssuerUrl = "https://issuer.example", credentialConfigurationId = CREDENTIAL_CONFIGURATION_ID, issuedAt = now),
            refreshState = RefreshState(refreshMethod = CredentialRefreshMethod.OID4VCI_REISSUANCE),
            createdAt = now,
            updatedAt = now,
        )

    private fun receiverTestState(sessionId: WalletInteractionSessionId): WalletInteractionState =
        WalletInteractionState(
            sessionId = sessionId,
            walletUnitId = WALLET_UNIT_ID,
            status = WalletInteractionStatus.Completed,
            flowKind = WalletInteractionFlowKind.CredentialReceive,
            protocol = WalletProtocol.OID4VCI,
            adapterId = Oid4vciWalletInteractionProtocolAdapter.ADAPTER_ID,
        )

    private fun resolvedOffer(): ResolvedCredentialOffer =
        ResolvedCredentialOffer(
            offer =
                CredentialOffer(
                    credentialIssuer = "https://issuer.example",
                    credentialConfigurationIds = listOf(CREDENTIAL_CONFIGURATION_ID),
                    grants =
                        CredentialOfferGrants(
                            preAuthorizedCode =
                                PreAuthorizedCodeOfferGrant(
                                    preAuthorizedCode = "pre-authorized-code",
                                ),
                        ),
                ),
            issuerMetadata =
                CredentialIssuerMetadata(
                    credentialIssuer = "https://issuer.example",
                    credentialEndpoint = "https://issuer.example/credential",
                    notificationEndpoint = "https://issuer.example/notification",
                    credentialConfigurationsSupported =
                        mapOf(
                            CREDENTIAL_CONFIGURATION_ID to
                                CredentialConfigurationSupported(
                                    format = CredentialFormat.SD_JWT_VC.value,
                                    vct = EMPLOYEE_VCT,
                                    display = listOf(DisplayProperties(name = "Offer metadata must not drive the received result")),
                                    credentialMetadata =
                                        CredentialMetadata(
                                            display =
                                                listOf(
                                                    DisplayProperties(
                                                        name = "Employee Credential",
                                                        backgroundColor = "#003399",
                                                        textColor = "#FFFFFF",
                                                    ),
                                                ),
                                        ),
                                ),
                        ),
                    display = listOf(DisplayProperties(name = "Example Issuer")),
                ),
        )

    private fun resolvedVcdm20Offer(): ResolvedCredentialOffer {
        val base = resolvedOffer()
        val baseConfiguration = base.issuerMetadata.credentialConfigurationsSupported.getValue(CREDENTIAL_CONFIGURATION_ID)
        return base.copy(
            issuerMetadata =
                base.issuerMetadata.copy(
                    credentialConfigurationsSupported =
                        mapOf(
                            CREDENTIAL_CONFIGURATION_ID to
                                baseConfiguration.copy(
                                    format = CredentialFormat.JWT_VC_JSON_LD.value,
                                    vct = null,
                                    credentialDefinition = CredentialDefinition(type = listOf("VerifiableCredential", "EmployeeCredential")),
                                ),
                        ),
                ),
        )
    }

    private fun resolvedLdpVcOffer(): ResolvedCredentialOffer {
        val base = resolvedOffer()
        val baseConfiguration = base.issuerMetadata.credentialConfigurationsSupported.getValue(CREDENTIAL_CONFIGURATION_ID)
        return base.copy(
            issuerMetadata =
                base.issuerMetadata.copy(
                    credentialConfigurationsSupported =
                        mapOf(
                            CREDENTIAL_CONFIGURATION_ID to
                                baseConfiguration.copy(
                                    format = CredentialFormat.LDP_VC.value,
                                    vct = null,
                                    credentialDefinition =
                                        CredentialDefinition(
                                            type = listOf("VerifiableCredential", "EmployeeCredential"),
                                            context = listOf(VcdmProfiles.V2_0_CONTEXT),
                                        ),
                                ),
                        ),
                ),
        )
    }

    private fun resolvedMdocOffer(): ResolvedCredentialOffer =
        ResolvedCredentialOffer(
            offer =
                CredentialOffer(
                    credentialIssuer = "https://issuer.example",
                    credentialConfigurationIds = listOf(MDOC_CREDENTIAL_CONFIGURATION_ID),
                    grants =
                        CredentialOfferGrants(
                            preAuthorizedCode =
                                PreAuthorizedCodeOfferGrant(
                                    preAuthorizedCode = "pre-authorized-code",
                                ),
                        ),
                ),
            issuerMetadata =
                CredentialIssuerMetadata(
                    credentialIssuer = "https://issuer.example",
                    credentialEndpoint = "https://issuer.example/credential",
                    credentialConfigurationsSupported =
                        mapOf(
                            MDOC_CREDENTIAL_CONFIGURATION_ID to
                                CredentialConfigurationSupported(
                                    format = CredentialFormat.MSO_MDOC.value,
                                    doctype = MDOC_DOCTYPE,
                                    display = listOf(DisplayProperties(name = "Mobile Driving Licence")),
                                ),
                        ),
                ),
        )

    private companion object {
        const val WALLET_UNIT_ID = "wallet-oid4vci-receiver"
        const val CREDENTIAL_CONFIGURATION_ID = "EmployeeCredential"
        const val EMPLOYEE_VCT = "https://credentials.example.com/employee"
        const val MDOC_CREDENTIAL_CONFIGURATION_ID = "MobileDrivingLicence"
        const val MDOC_DOCTYPE = "org.iso.18013.5.1.mDL"
    }
}

private class ReceiverRecordingVcdmDataIntegrityVerifier : VcdmDataIntegrityVerifier {
    var lastArgs: VcdmDataIntegrityVerificationArgs? = null

    override suspend fun verify(
        args: VcdmDataIntegrityVerificationArgs,
    ): IdkResult<VcdmDataIntegrityVerificationResult, IdkError> {
        lastArgs = args
        return Ok(VcdmDataIntegrityVerificationResult(verifiedDocument = JsonObject(args.document - "proof"), proofCount = 1))
    }
}

private class ReceiverTestBlobStoreService(
    private val store: BlobStore,
    private val storeId: String = "memory",
) : BlobStoreService {
    override fun getStoreIds(): Array<String> = arrayOf(storeId)

    override fun getStoreConfig(storeId: String) = InMemoryBlobStoreConfig(id = storeId)

    override fun getStore(storeId: String) = store
}

private class ReceiverTestKvStoreService(
    private val store: KvStore,
) : KvStoreService {
    override fun getStoreIds(): Array<String> = arrayOf(KvBlobMetadataIndex.STORE_ID)

    override fun getStoreConfig(storeId: String) = InMemoryKvStoreConfig(id = storeId, scopeBinding = KvStoreScopeBinding.APP)

    override fun getStore(storeId: String) = store
}

private class ReceiverTestSessionExecution : com.sphereon.core.api.context.SessionExecution {
    override val sessionContext: SessionContext = NoOpSessionContext
    override val sessionContextManager: SessionContextManager
        get() = throw NotImplementedError("Not needed for receiver store tests")
    override val log: SessionLogService = ReceiverTestNoOpLogService(sessionContext)
    override val conf: com.sphereon.core.api.context.ContextConfig
        get() = throw NotImplementedError("Not needed for receiver store tests")
}

private class ReceiverTestNoOpLogService(
    override val sessionContext: SessionContext,
) : SessionLogService {
    override val id: String = "oid4vci-receiver-test-log"
    override val isEnabled: Boolean = false
    override val scope = com.sphereon.core.api.context.IdkScope.SESSION
    override val logManager: SessionLogManager
        get() = throw NotImplementedError("Not needed for receiver store tests")

    override suspend fun setConfig(config: LoggerConfig): LogService = this

    override fun executeAsync(message: LogMessage): IdkResult<Unit, com.sphereon.core.api.error.IdkErrorType> = Ok(Unit)

    override fun toAsync(): AsyncLogService = throw NotImplementedError("Not needed for receiver store tests")
}

private class ReceiverTestSessionEventService : SessionEventService {
    private val hub = EventHubImpl()
    override val scope: com.sphereon.core.api.context.IdkScope = com.sphereon.core.api.context.IdkScope.SESSION
    override val eventHub: EventHub = hub
    override val parent: UserEventService
        get() = throw NotImplementedError("Not needed for receiver store tests")
    override val sessionContext: SessionContext = NoOpSessionContext

    override suspend fun emit(event: Event) {
        hub.publish(event)
    }

    override suspend fun emit(
        event: Event,
        sign: Boolean,
        encrypt: Boolean,
        keyAlias: String?,
        encryptionKeyAlias: String?,
        encryptParts: Set<EncryptedPart>,
    ) {
        hub.publish(event)
    }

    override fun eventBuilder(): EventBuilder = DefaultEventBuilder(com.sphereon.core.api.context.IdkScope.SESSION)
}

private object ReceiverTestCredentialBodyProtector : WalletCredentialBodyProtector {
    override suspend fun protect(
        walletUnitId: String,
        credentialRecordId: String,
        credentialInstanceId: String,
        plaintext: ByteArray,
        documentRole: WalletCredentialProtectedDocumentRole,
    ): IdkResult<ByteArray, IdkError> = Ok("receiver-test-protected:${plaintext.decodeToString().reversed()}".encodeToByteArray())

    override suspend fun open(
        walletUnitId: String,
        credentialRecordId: String,
        credentialInstanceId: String,
        protectedBody: ByteArray,
        documentRole: WalletCredentialProtectedDocumentRole,
    ): IdkResult<ByteArray, IdkError> {
        val envelope = protectedBody.decodeToString()
        if (!envelope.startsWith("receiver-test-protected:")) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Unsupported receiver test credential body envelope"))
        }
        return Ok(envelope.removePrefix("receiver-test-protected:").reversed().encodeToByteArray())
    }
}

/**
 * Minimal fake of [WalletIssuanceSessionStore] for receiver tests: records refresh tokens passed to
 * [storeRefreshToken] in [storedRefreshTokens] and returns a stable [SecretRef]; every other method is
 * unsupported/no-op since the receiver under test does not exercise them.
 */
private class FakeWalletIssuanceSessionStore(
    private val failRefreshTokenPersistence: Boolean = false,
) : WalletIssuanceSessionStore {
    val storedRefreshTokens: MutableMap<String, String> = mutableMapOf()

    override suspend fun putSession(
        walletUnitId: String,
        session: IssuanceSession,
    ): IdkResult<IssuanceSession, IdkError> = Ok(session)

    override suspend fun getSession(
        walletUnitId: String,
        issuanceSessionId: String,
    ): IdkResult<IssuanceSession?, IdkError> = Ok(null)

    override suspend fun listSessions(
        walletUnitId: String,
        statuses: Set<IssuanceSessionStatus>,
    ): IdkResult<List<IssuanceSession>, IdkError> = Ok(emptyList())

    override suspend fun storeDeferredAccessToken(
        walletUnitId: String,
        issuanceSessionId: String,
        accessToken: String,
    ): IdkResult<SecretRef, IdkError> = Err(IdkError.fromString(code = "FAKE_UNSUPPORTED", message = "Not used by receiver tests"))

    override suspend fun getDeferredAccessToken(
        walletUnitId: String,
        issuanceSessionId: String,
    ): IdkResult<String?, IdkError> = Ok(null)

    override suspend fun storeRefreshToken(
        walletUnitId: String,
        credentialRecordId: String,
        refreshToken: String,
    ): IdkResult<SecretRef, IdkError> {
        if (failRefreshTokenPersistence) {
            return Err(IdkError.fromString(code = "FAKE_REFRESH_TOKEN_PERSISTENCE_FAILED", message = "Refresh token persistence failed"))
        }
        storedRefreshTokens[credentialRecordId] = refreshToken
        return Ok(SecretRef(id = "secret:test"))
    }

    override suspend fun getRefreshToken(
        walletUnitId: String,
        credentialRecordId: String,
    ): IdkResult<String?, IdkError> = Ok(null)

    override suspend fun deleteSession(
        walletUnitId: String,
        issuanceSessionId: String,
    ): IdkResult<Boolean, IdkError> = Ok(true)
}

private class ReceiverTestPrivateSessionStore : WalletInteractionPrivateSessionStore {
    private val records = mutableMapOf<Pair<WalletInteractionSessionId, String>, WalletInteractionPrivateSessionData>()

    override suspend fun put(
        sessionId: WalletInteractionSessionId,
        data: WalletInteractionPrivateSessionData,
    ) {
        records[sessionId to data.namespace] = data
    }

    override suspend fun get(
        sessionId: WalletInteractionSessionId,
        namespace: String,
    ): WalletInteractionPrivateSessionData? = records[sessionId to namespace]

    override suspend fun remove(
        sessionId: WalletInteractionSessionId,
        namespace: String,
    ) {
        records.remove(sessionId to namespace)
    }

    override suspend fun removeSession(sessionId: WalletInteractionSessionId) {
        records.keys.filter { it.first == sessionId }.forEach { records.remove(it) }
    }
}

private fun createOid4vciReceiverTestBlobService(): DefaultBlobService {
    val blobBackingStorage = InMemoryBlobBackingStorageImpl()
    val blobFactory = InMemoryBlobStoreFactoryImpl(blobBackingStorage)
    val memoryStore = blobFactory.create(InMemoryBlobStoreConfig(id = "memory"))

    val kvBackingStorage = InMemoryKvBackingStorageImpl()
    val kvFactory = InMemoryKvStoreFactoryImpl(kvBackingStorage)
    val kvStore = kvFactory.create(InMemoryKvStoreConfig(id = KvBlobMetadataIndex.STORE_ID, scopeBinding = KvStoreScopeBinding.APP))

    return DefaultBlobService(
        blobStoreService = ReceiverTestBlobStoreService(memoryStore),
        metadataIndex = KvBlobMetadataIndex(ReceiverTestKvStoreService(kvStore)),
        retentionPolicyService = DefaultRetentionPolicyService(),
        tempUrlPolicy = DefaultTempUrlPolicy(),
        eventService = ReceiverTestSessionEventService(),
        execution = ReceiverTestSessionExecution(),
    )
}
