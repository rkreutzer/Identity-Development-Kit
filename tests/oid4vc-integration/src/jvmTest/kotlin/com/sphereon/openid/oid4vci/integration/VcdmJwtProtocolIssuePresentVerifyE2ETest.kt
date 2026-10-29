/*
 * (c) 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.openid.oid4vci.integration

import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.DefaultPrincipalMapPropertySource
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.core.api.http.command.HttpEndpointCommandRegistry
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteSelection
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteSelector
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.jose.generateJwkThumbprintUri
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.data.store.blob.BlobService
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vc.common.PresentationFormat
import com.sphereon.openid.oid4vc.common.vcdm.VcdmClassifier
import com.sphereon.openid.oid4vci.issuer.attribute.CredentialAttributeContribution
import com.sphereon.openid.oid4vci.issuer.command.CreateCredentialOfferArgs
import com.sphereon.openid.oid4vp.common.VpToken
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.w3cVcMeta
import com.sphereon.openid.oid4vp.universal.CreateAuthorizationRequestInput
import com.sphereon.openid.oid4vp.universal.CreateAuthorizationRequestOutput
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.sdjwt.vc.command.VerifySdJwtVcCommand
import com.sphereon.wallet.WalletHolderIdentityResolver
import com.sphereon.wallet.WalletHolderVerificationMethodResolver
import com.sphereon.wallet.WalletIdentityResolver
import com.sphereon.wallet.credential.CredentialLifecycleState
import com.sphereon.wallet.credential.CredentialSubjectExtractor
import com.sphereon.wallet.credential.KeyRef
import com.sphereon.wallet.credential.WalletCredentialStore
import com.sphereon.wallet.credential.WalletHolderIdentifierKind
import com.sphereon.wallet.credential.WalletHolderVerificationMethod
import com.sphereon.wallet.credential.WalletIssuanceSessionStore
import com.sphereon.wallet.credential.store.BlobWalletCredentialStore
import com.sphereon.wallet.credential.store.WalletCredentialBodyProtector
import com.sphereon.wallet.interaction.DispatchWalletInteractionActionBody
import com.sphereon.wallet.interaction.StartWalletInteractionBody
import com.sphereon.wallet.interaction.WalletCounterpartySummary
import com.sphereon.wallet.interaction.WalletCredentialSelection
import com.sphereon.wallet.interaction.WalletEntryPoint
import com.sphereon.wallet.interaction.WalletInteractionAction
import com.sphereon.wallet.interaction.WalletInteractionApiConstants
import com.sphereon.wallet.interaction.WalletInteractionDiagnostics
import com.sphereon.wallet.interaction.WalletInteractionInput
import com.sphereon.wallet.interaction.WalletInteractionSession
import com.sphereon.wallet.interaction.WalletInteractionSessionEnvelope
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionStateEnvelope
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.interaction.WalletIssuerAuthenticationProvenance
import com.sphereon.wallet.interaction.WalletIssuerAuthenticationRequest
import com.sphereon.wallet.interaction.WalletIssuerAuthenticationResolver
import com.sphereon.wallet.interaction.WalletIssuerAuthenticationResult
import com.sphereon.wallet.interaction.WalletProtocol
import com.sphereon.wallet.interaction.WalletSecurityGate
import com.sphereon.wallet.interaction.WalletSecurityGateRequest
import com.sphereon.wallet.interaction.WalletSecurityGateResult
import com.sphereon.wallet.interaction.WalletSecurityGrant
import com.sphereon.wallet.interaction.actionsPath
import com.sphereon.wallet.interaction.client.rest.DispatchWalletInteractionActionHttpEndpointCommandImpl
import com.sphereon.wallet.interaction.client.rest.GetWalletInteractionStateHttpEndpointCommandImpl
import com.sphereon.wallet.interaction.client.rest.ResumeWalletInteractionHttpEndpointCommandImpl
import com.sphereon.wallet.interaction.client.rest.StartWalletInteractionHttpEndpointCommandImpl
import com.sphereon.wallet.interaction.client.rest.WalletInteractionHttpAdapter
import com.sphereon.wallet.interaction.client.rest.defaultWalletInteractionJson
import com.sphereon.wallet.interaction.impl.DefaultWalletInteractionEngine
import com.sphereon.wallet.interaction.impl.GetWalletInteractionStateCommandImpl
import com.sphereon.wallet.interaction.impl.InMemoryWalletInteractionPrivateSessionStore
import com.sphereon.wallet.interaction.impl.InMemoryWalletInteractionSessionStore
import com.sphereon.wallet.interaction.impl.ResumeWalletInteractionCommandImpl
import com.sphereon.wallet.interaction.impl.StartWalletInteractionCommandImpl
import com.sphereon.wallet.interaction.impl.SubmitWalletInteractionActionCommandImpl
import com.sphereon.wallet.interaction.impl.WscdAwareExecutionPlanner
import com.sphereon.wallet.interaction.impl.WscdExecutionProfileSource
import com.sphereon.wallet.interaction.interactionsPath
import com.sphereon.wallet.interaction.protocol.oid4vci.HolderServiceOid4vciCredentialRequestProofProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.HolderServiceOid4vciRefreshTokenGrantProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciHolderIssuanceExecutor
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciHolderIssuanceOptions
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciIssuanceOptionsProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciIssuedCredentialAcceptance
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciWalletInteractionProtocolAdapter
import com.sphereon.wallet.interaction.protocol.oid4vci.SecureComponentOid4vciKeyAttestationProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.WalletStoreOid4vciCredentialResponseReceiver
import com.sphereon.wallet.interaction.protocol.oid4vp.Oid4vpDataIntegrityHolderBindingProvider
import com.sphereon.wallet.interaction.protocol.oid4vp.Oid4vpPresentationSecurityAttributes
import com.sphereon.wallet.interaction.protocol.oid4vp.Oid4vpSdJwtHolderBindingProvider
import com.sphereon.wallet.interaction.protocol.oid4vp.Oid4vpWalletConfigProvider
import com.sphereon.wallet.interaction.protocol.oid4vp.Oid4vpWalletInteractionProtocolAdapter
import com.sphereon.wallet.interaction.resumePath
import com.sphereon.wallet.interaction.statePath
import com.sphereon.wallet.wsca.Wsca
import dev.zacsweers.metro.ContributesTo
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import com.sphereon.wallet.credential.CredentialFormat as WalletCredentialFormat

@ContributesTo(SessionScope::class)
interface VcdmJwtProtocolStoreGraph {
    val walletCredentialStore: WalletCredentialStore
    val blobService: BlobService
    val credentialBodyProtector: WalletCredentialBodyProtector
    val walletIssuanceSessionStore: WalletIssuanceSessionStore
    val walletIdentityResolver: WalletIdentityResolver
    val credentialSubjectExtractor: CredentialSubjectExtractor
    val verifySdJwtVcCommand: VerifySdJwtVcCommand
    val verifyJwsCommand: VerifyJwsCommand
}

@ContributesTo(SessionScope::class)
interface VcdmJwtProtocolWscaGraph {
    val wsca: Wsca
}

/**
 * Protocol-only VCDM JWT proof.  Both issuer legs run through OID4VCI HTTP commands and the
 * resulting records are selected by the wallet OID4VP adapter; no issuer format handler or holder
 * authorization-response command is called directly by this test.
 */
class VcdmJwtProtocolIssuePresentVerifyE2ETest {
    companion object {
        private const val V11 = "ProtocolVcdm11Jwt"
        private const val V20 = "ProtocolVcdm20JwtLd"
        private const val ISSUER_KEY = "protocol-vcdm-issuer-key"
        private const val HOLDER_KEY = "protocol-vcdm-holder-key"
        private const val WALLET_ID = "protocol-vcdm-jwt-wallet"

        // The in-process HTTP fixture routes the canonical issuer/verifier hosts.
        private const val ISSUER = "https://issuer.example.com"
        private const val VERIFIER = "https://verifier.example.com"
        private const val HOLDER = "https://wallet.example.com"
        private const val V11_TYPE = "ProtocolVcdm11Credential"
        private const val V20_TYPE = "ProtocolVcdm20Credential"
        private const val V11_CREDENTIAL_ID = "https://credentials.example.com/protocol/v11"
        private const val V20_CREDENTIAL_ID = "https://credentials.example.com/protocol/v20"
        private const val V11_SUBJECT_ID = "https://subjects.example.com/protocol/alice"
        private const val V20_SUBJECT_ID = "https://subjects.example.com/protocol/bob"
        private const val PRESENTATION_OPERATION_BINDING = "test:vcdm-jwt-presentation"

        init {
            DefaultPrincipalMapPropertySource.addProperty("oid4vci.issuer.credentialConfigurationIds", "$V11,$V20")
            configure("oid4vci.issuer", V11, CredentialFormat.JWT_VC_JSON.value, V11_TYPE)
            configure("oid4vci.issuer", V20, CredentialFormat.JWT_VC_JSON_LD.value, V20_TYPE)
            // The protocol HTTP adapter resolves the active issuer resource before serving the
            // credential-offer URI. Mirror the fixture configuration under that routed UUID.
            DefaultPrincipalMapPropertySource.addProperty("oid4vci.routing.issuerResourceId", OID4VCI_TEST_ISSUER_INSTANCE_ID)
            val issuerRoot = "oid4vci.issuers.$OID4VCI_TEST_ISSUER_INSTANCE_ID"
            val authorizationServerId = "00000000-0000-4000-8000-000000000002"
            DefaultPrincipalMapPropertySource.addProperty("$issuerRoot.identifier", ISSUER)
            DefaultPrincipalMapPropertySource.addProperty("$issuerRoot.credentialConfigurationIds", "$V11,$V20")
            // Resource-backed issuer metadata requires the complete immutable authorization
            // policy projection; these values mirror OID4VCI_TEST_AUTHORIZATION_POLICY_SNAPSHOT.
            DefaultPrincipalMapPropertySource.addProperty("$issuerRoot.issuerCapabilityId", "00000000-0000-4000-8000-000000000003")
            DefaultPrincipalMapPropertySource.addProperty("$issuerRoot.authorizationServerIds", authorizationServerId)
            DefaultPrincipalMapPropertySource.addProperty("$issuerRoot.profile", "OID4VCI_1_0_FINAL")
            DefaultPrincipalMapPropertySource.addProperty("$issuerRoot.profileRevision", "7")
            val authorizationServerRoot = "$issuerRoot.authorizationServers.$authorizationServerId"
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.tenantId", OID4VCI_TEST_TENANT_ID)
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.issuerIdentifier", ISSUER)
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.enabled", "true")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.default", "true")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.lifecycle", "ACTIVE")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.deployment", "HOSTED")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.credentialIssuancePurpose", "true")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.allowedGrants", "PRE_AUTHORIZED_CODE")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.revision", "11")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.runtimeServerKey", "default")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.jwksUri", "$ISSUER/.well-known/jwks.json")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.tokenEndpoint", "$ISSUER/token")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.discoveryCurrent", "true")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.bindingRevision", "13")
            configure(issuerRoot, V11, CredentialFormat.JWT_VC_JSON.value, V11_TYPE)
            configure(issuerRoot, V20, CredentialFormat.JWT_VC_JSON_LD.value, V20_TYPE)
            DefaultPrincipalMapPropertySource.addProperty("kv.stores.blob.metadata.type", "memory")
            DefaultPrincipalMapPropertySource.addProperty("kv.stores.blob.metadata.scopeBinding", "TENANT")
            DefaultPrincipalMapPropertySource.addProperty("blob.stores.default.type", "memory")
            DefaultPrincipalMapPropertySource.addProperty("blob.stores.default.scopeBinding", "TENANT")
        }

        private fun configure(
            root: String,
            id: String,
            format: String,
            type: String
        ) {
            val prefix = "$root.credentials.[$id]"
            DefaultPrincipalMapPropertySource.addProperty("$prefix.format", format)
            DefaultPrincipalMapPropertySource.addProperty("$prefix.scope", id.lowercase())
            DefaultPrincipalMapPropertySource.addProperty("$prefix.bindingMethods", "did:key,did:jwk,jwk")
            DefaultPrincipalMapPropertySource.addProperty("$prefix.signingAlgorithms", "ES256")
            DefaultPrincipalMapPropertySource.addProperty("$prefix.proofTypes.jwt.signingAlgorithms", "ES256")
            DefaultPrincipalMapPropertySource.addProperty("$prefix.signingKeyMode", "jwk-thumbprint")
            DefaultPrincipalMapPropertySource.addProperty("$prefix.validityPeriod", "P365D")
            DefaultPrincipalMapPropertySource.addProperty("$prefix.credentialDefinition.types", "VerifiableCredential,$type")
        }
    }

    private val ctx = Oid4vciTestContext(this, credentialConfigurationIds = listOf(V11, V20))
    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = false
        }

    @Test
    fun v11AndV20JwtCredentialsTraverseOid4vciStoreAndOid4vpVerifier() =
        runTest {
            WalletE2ETestRequestObjectSigningConfig.enableDidJwkSigning()
            try {
                ctx.ensureAsSigningKey()
                val holderKey = ensureHolderKey()
                ensureVerifierSigningKey()
                val issuerKey = ensureIssuerKey()
                WalletE2ETestTrustedAuthenticationResolver.enable(
                    listOf(
                        TrustedAuthenticationResolution(
                            controller = HOLDER,
                            purpose = TrustedAuthenticationPurpose.HOLDER,
                            trustedJwks = jwks(holderKey.copy(kid = "$HOLDER/keys/$HOLDER_KEY")),
                        ),
                        TrustedAuthenticationResolution(
                            controller = ISSUER,
                            purpose = TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                            trustedJwks =
                                jwks(
                                    Jwk
                                        .fromJsonObject(issuerKey.publicJwk)
                                        .copy(kid = generateJwkThumbprintUri(Jwk.fromJsonObject(issuerKey.publicJwk))),
                                ),
                        ),
                    ),
                )
                WalletE2ETestCredentialAttributeContributor.enable(
                    mapOf(
                        V11 to semanticIdentityContribution(V11_CREDENTIAL_ID, V11_SUBJECT_ID, "Alice"),
                        V20 to semanticIdentityContribution(V20_CREDENTIAL_ID, V20_SUBJECT_ID, "Bob"),
                    ),
                )
                val issueStore = (ctx.session.graph as VcdmJwtProtocolStoreGraph).walletCredentialStore
                val v11 = issue(V11, CredentialFormat.JWT_VC_JSON, issuerKey)
                val v20 = issue(V20, CredentialFormat.JWT_VC_JSON_LD, issuerKey)

                assertJwtShape(v11.raw, CredentialFormat.JWT_VC_JSON, V11_TYPE, V11_CREDENTIAL_ID, V11_SUBJECT_ID)
                assertJwtShape(v20.raw, CredentialFormat.JWT_VC_JSON_LD, V20_TYPE, V20_CREDENTIAL_ID, V20_SUBJECT_ID)
                assertEquals(CredentialLifecycleState.ACTIVE, v11.lifecycleState)
                assertEquals(CredentialLifecycleState.ACTIVE, v20.lifecycleState)

                val store = reloadCredentialStore()
                assertFalse(store === issueStore, "presentation must use a reconstructed credential-store instance")
                val metadata = store.listMetadata(WALLET_ID).also { assertTrue(it.isOk) }.value
                assertEquals(setOf(V11, V20), metadata.mapNotNull { it.credentialConfigurationId }.toSet())
                val verifierRequest = createVerifierRequest()
                presentAndAssertVerified(verifierRequest, store, setOf(v11.id, v20.id))
            } finally {
                WalletE2ETestCredentialAttributeContributor.disable()
                WalletE2ETestTrustedAuthenticationResolver.disable()
                WalletE2ETestRequestObjectSigningConfig.disable()
            }
        }

    @Test
    fun eachJwtVersionRejectsTamperedCredentialAtProtocolIngestion() =
        runTest {
            ctx.ensureAsSigningKey()
            ensureHolderKey()
            val issuerKey = ensureIssuerKey()
            val store = (ctx.session.graph as VcdmJwtProtocolStoreGraph).walletCredentialStore
            for ((id, format) in listOf(V11 to CredentialFormat.JWT_VC_JSON, V20 to CredentialFormat.JWT_VC_JSON_LD)) {
                val beforeMatchingRecordIds =
                    store
                        .listMetadata(WALLET_ID)
                        .also { assertTrue(it.isOk) }
                        .value
                        .filter { it.credentialConfigurationId == id }
                        .map { it.credentialRecordId }
                        .sorted()
                val offer = createOffer(id)
                val engine = issuanceEngine(store, issuerKey, tamper = true)
                val started = engine.start(WalletInteractionInput(WALLET_ID, WalletEntryPoint.rawQr(offer)))
                assertEquals(WalletInteractionStatus.TrustReview, started.state.status, "OID4VCI tamper start failed: ${json.encodeToString(started.state)}")
                engine.dispatch(started.sessionId, WalletInteractionAction.continueFlow())
                val review = engine.observe(started.sessionId).value
                engine.dispatch(started.sessionId, WalletInteractionAction.selectCredentials(WalletCredentialSelection(mapOf("oid4vci-offer" to review.credentialOffer!!.credentialConfigurationIds))))
                val failed = engine.observe(started.sessionId).value
                assertEquals(WalletProtocol.OID4VCI, failed.protocol)
                assertEquals(WalletInteractionStatus.Failed, failed.status, "tampered $format must not be stored")
                assertNotNull(failed.error, "tampered $format must produce an explicit verification error")
                val afterMatchingRecordIds =
                    store
                        .listMetadata(WALLET_ID)
                        .also { assertTrue(it.isOk) }
                        .value
                        .filter { it.credentialConfigurationId == id }
                        .map { it.credentialRecordId }
                        .sorted()
                assertEquals(beforeMatchingRecordIds.size, afterMatchingRecordIds.size, "tampered $format must not change matching record count")
                assertEquals(beforeMatchingRecordIds, afterMatchingRecordIds, "tampered $format must not create or replace matching records")
            }
        }

    private suspend fun issue(
        id: String,
        format: CredentialFormat,
        issuerKey: IssuerKey
    ): Stored {
        val store = (ctx.session.graph as VcdmJwtProtocolStoreGraph).walletCredentialStore
        val offer = createOffer(id)
        val engine = issuanceEngine(store, issuerKey, tamper = false)
        val rest = walletInteractionRest(engine)
        val started = rest.start(WalletInteractionInput(WALLET_ID, WalletEntryPoint.rawQr(offer)))
        assertEquals(WalletInteractionStatus.TrustReview, started.state.status, "OID4VCI start failed: ${json.encodeToString(started.state)}")
        assertEquals(started.state, rest.state(started.sessionId))
        val resumed = rest.resume(started.sessionId)
        assertEquals(started.sessionId, resumed.sessionId)
        val review = rest.continueFlow(started.sessionId)
        assertEquals(WalletInteractionStatus.CredentialOfferReview, review.status)
        val done = rest.select(started.sessionId, mapOf("oid4vci-offer" to review.credentialOffer!!.credentialConfigurationIds))
        assertEquals(WalletInteractionStatus.Completed, done.status, "OID4VCI $id should complete: $done")
        val meta =
            store
                .listMetadata(WALLET_ID)
                .also { assertTrue(it.isOk) }
                .value
                .single { it.credentialConfigurationId == id }
        val record = store.getCredential(WALLET_ID, meta.credentialRecordId).also { assertTrue(it.isOk) }.value!!
        val instance = record.instances.single()
        assertEquals(format.value, instance.format.value)
        assertEquals(HOLDER_KEY, instance.holderKeyRef?.alias)
        return Stored(assertNotNull(record.id), assertNotNull(instance.id), assertNotNull(instance.raw), instance.lifecycleState)
    }

    private suspend fun createOffer(id: String): String {
        val issuer = (ctx.session.graph as Oid4vciIssuanceTestGraph).oid4vciIssuerService
        val selector = (ctx.session.graph as Oid4vciIssuerInstanceOverrideSessionGraph).mutableOid4vciIssuerInstanceIdProvider
        val previous = selector.currentInstanceId()
        selector.setCurrentInstanceId(OID4VCI_TEST_ISSUER_INSTANCE_ID)
        val result =
            try {
                issuer.createCredentialOffer(
                    CreateCredentialOfferArgs(
                        instanceId = OID4VCI_TEST_ISSUER_INSTANCE_ID,
                        issuerId = ISSUER,
                        credentialConfigurationIds = listOf(id),
                        preAuthorizedCodeGrant = true,
                        authorizationPolicySnapshot = OID4VCI_TEST_AUTHORIZATION_POLICY_SNAPSHOT,
                    )
                )
            } finally {
                if (previous == null) selector.clearCurrentInstanceId() else selector.setCurrentInstanceId(previous)
            }
        assertTrue(result.isOk, "OID4VCI offer creation failed")
        return result.value.offerUri
    }

    private suspend fun issuanceEngine(
        store: WalletCredentialStore,
        issuerKey: IssuerKey,
        tamper: Boolean
    ): DefaultWalletInteractionEngine {
        val graph = ctx.session.graph as Oid4vciIssuanceTestGraph
        val wallet = ctx.session.graph as VcdmJwtProtocolStoreGraph
        val wsca = (ctx.session.graph as VcdmJwtProtocolWscaGraph).wsca
        val resolver = holderVerificationResolver()
        val acceptance =
            Oid4vciIssuedCredentialAcceptance(
                verifySdJwtVcCommand = wallet.verifySdJwtVcCommand,
                verifyJwsCommand = wallet.verifyJwsCommand,
                subjectExtractor = wallet.credentialSubjectExtractor,
                identityResolver = wallet.walletIdentityResolver,
            )
        val receiver =
            WalletStoreOid4vciCredentialResponseReceiver(
                store,
                wallet.walletIssuanceSessionStore,
                acceptance,
                resolver,
            )
        val adapter =
            Oid4vciWalletInteractionProtocolAdapter(
                holder = graph.oid4vciHolder,
                issuanceExecutor =
                    Oid4vciHolderIssuanceExecutor(
                        holder = graph.oid4vciHolder,
                        optionsProvider =
                            object : Oid4vciIssuanceOptionsProvider {
                                override suspend fun options(
                                    context: com.sphereon.wallet.interaction.WalletInteractionContext,
                                    state: com.sphereon.wallet.interaction.WalletInteractionState,
                                    resolvedOffer: com.sphereon.openid.oid4vci.holder.ResolvedCredentialOffer,
                                    existingHolderKeyAliases: List<String>
                                ) = Oid4vciHolderIssuanceOptions(
                                    signingKeyIds = listOf(HOLDER_KEY),
                                    operationBinding = "test:vcdm-jwt-request-proof",
                                    signingAlgorithm = "ES256",
                                    clientId = "https://wallet.example",
                                    credentialConfigurationId = resolvedOffer.offer.credentialConfigurationIds.single(),
                                )
                            },
                        credentialReceiver = if (!tamper) receiver else TamperingReceiver(receiver),
                        nestedPresentationExecutor = com.sphereon.wallet.interaction.WalletNestedPresentationExecutor.notConfigured,
                        credentialStore = store,
                        issuanceSessionStore = wallet.walletIssuanceSessionStore,
                        refreshTokenGrantProvider = HolderServiceOid4vciRefreshTokenGrantProvider(graph.oid4vciHolder),
                        keyAttestationProvider = SecureComponentOid4vciKeyAttestationProvider(wsca),
                        credentialRequestProofProvider = HolderServiceOid4vciCredentialRequestProofProvider(graph.oid4vciHolder),
                    ),
            )
        return DefaultWalletInteractionEngine(
            sensitiveInputAuthority = integrationSensitiveInputAuthority(),
            privateSessionStore = InMemoryWalletInteractionPrivateSessionStore(),
            sessionStore = InMemoryWalletInteractionSessionStore(),
            launchAuthorities = setOf(integrationOrdinaryLaunchAuthority()),
            securityGate = WalletSecurityGate.allow,
            adapters = listOf(adapter),
            issuerAuthenticationResolver = issuerAuthenticationResolver(issuerKey.publicJwk),
            diagnostics = WalletInteractionDiagnostics.none,
        )
    }

    private suspend fun createVerifierRequest(): VerifierRequest {
        val body =
            json.encodeToString(
                CreateAuthorizationRequestInput.serializer(),
                CreateAuthorizationRequestInput(
                    dcqlQuery =
                        DcqlQuery(
                            credentials =
                                listOf(
                                    DcqlCredentialQuery("v11", CredentialFormat.JWT_VC_JSON.value, meta = w3cVcMeta(listOf("VerifiableCredential", V11_TYPE))),
                                    DcqlCredentialQuery("v20", CredentialFormat.JWT_VC_JSON_LD.value, meta = w3cVcMeta(listOf("VerifiableCredential", V20_TYPE))),
                                )
                        ),
                    clientId = VERIFIER,
                    responseUri = "$VERIFIER/oid4vp/auth/response",
                    state = "vcdm-jwt-protocol-state",
                )
            )
        val response =
            ctx.dispatchInProcessHttp(
                com.sphereon.core.api.http.GenericHttpRequest.withTextBody(
                    "POST",
                    "/oid4vp/backend/auth/requests",
                    body,
                    headers =
                        mapOf("Content-Type" to "application/json")
                )
            )
        assertEquals(201, response.statusCode, response.body)
        val out = json.decodeFromString(CreateAuthorizationRequestOutput.serializer(), assertNotNull(response.body))
        val correlationId = assertNotNull(out.correlationId)
        val persisted =
            (ctx.session.graph as Oid4vpPresentationTestGraph)
                .oid4vpVerifierService
                .authorizationSessionStore
                .getByCorrelationId(correlationId)
        assertTrue(persisted.isOk, "Verifier session lookup must succeed for $correlationId: $persisted")
        assertEquals(
            AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED,
            assertNotNull(persisted.value).status,
            "request_uri must reference a freshly persisted verifier session",
        )
        return VerifierRequest(
            correlationId = correlationId,
            requestUri = assertNotNull(out.requestUri),
            nonce = assertNotNull(assertNotNull(persisted.value).authorizationRequest.nonce),
            audience = assertNotNull(assertNotNull(persisted.value).authorizationRequest.clientId),
        )
    }

    private fun reloadCredentialStore(): WalletCredentialStore {
        val graph = ctx.session.graph as VcdmJwtProtocolStoreGraph
        return BlobWalletCredentialStore(graph.blobService, graph.credentialBodyProtector)
    }

    private suspend fun ensureVerifierSigningKey() {
        val result =
            ctx.session.graph
                .asKeyManagerServiceGraph()
                .keyManagerService
                .generateKeyResult(
                    alias = WalletE2ETestRequestObjectSigningConfig.SIGNING_KEY_ALIAS,
                    use = JwkUse.sig,
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                )
        assertTrue(
            result.isOk,
            "Verifier JAR signing key generation should succeed: ${if (result.isErr) result.error.message.defaultMessage else ""}",
        )
    }

    private suspend fun presentAndAssertVerified(
        request: VerifierRequest,
        store: WalletCredentialStore,
        ids: Set<String>
    ) {
        val adapter =
            Oid4vpWalletInteractionProtocolAdapter.walletStoreBacked(
                holder = (ctx.session.graph as VcdmJwtProtocolVpGraph).oid4vpHolder,
                credentialStore = store,
                sdJwtHolderBindingProvider = Oid4vpSdJwtHolderBindingProvider { Ok(it.selectedCredentials) },
                dataIntegrityHolderBindingProvider = Oid4vpDataIntegrityHolderBindingProvider.none,
                holderIdentityResolver = WalletHolderIdentityResolver { _, _ -> HOLDER },
                holderVerificationMethodResolver = holderVerificationResolver(),
                walletConfigProvider =
                    object : Oid4vpWalletConfigProvider {
                        override suspend fun walletConfig(
                            context: com.sphereon.wallet.interaction.WalletInteractionContext,
                            state: com.sphereon.wallet.interaction.WalletInteractionState
                        ) = com.sphereon.openid.oid4vp.holder
                            .WalletConfig(audience = HOLDER)
                    },
            )
        val engine =
            DefaultWalletInteractionEngine(
                sensitiveInputAuthority = integrationSensitiveInputAuthority(),
                privateSessionStore = InMemoryWalletInteractionPrivateSessionStore(),
                sessionStore = InMemoryWalletInteractionSessionStore(),
                launchAuthorities = setOf(integrationOrdinaryLaunchAuthority()),
                securityGate = PresentationSecurityGate(),
                protocolExecutor = WscdAwareExecutionPlanner(WscdExecutionProfileSource { null }),
                adapters = listOf(adapter),
                diagnostics = WalletInteractionDiagnostics.none,
            )
        val rest = walletInteractionRest(engine)
        WalletTestInProcessHttpCapture.clear()
        val started =
            rest.start(
                WalletInteractionInput(
                    WALLET_ID,
                    WalletEntryPoint.rawQr(request.requestUri),
                    metadata =
                        mapOf(
                            Oid4vpPresentationSecurityAttributes.WALLET_UNIT_ID to WALLET_ID,
                            Oid4vpPresentationSecurityAttributes.WALLET_ACCOUNT_ID to "protocol-vcdm-jwt-account",
                            Oid4vpPresentationSecurityAttributes.ACTIVATION_DECISION_ID to "protocol-vcdm-jwt-activation",
                            Oid4vpPresentationSecurityAttributes.OPERATION_TYPE to "wallet.sign",
                            Oid4vpPresentationSecurityAttributes.OPERATION_BINDING to PRESENTATION_OPERATION_BINDING,
                            Oid4vpPresentationSecurityAttributes.OPERATION_HASH to "sha256:protocol-vcdm-jwt-presentation",
                            Oid4vpPresentationSecurityAttributes.NONCE to "protocol-vcdm-jwt-security-nonce",
                        ),
                ),
            )
        assertEquals(
            WalletInteractionStatus.TrustReview,
            started.state.status,
            "OID4VP request resolution should reach trust review: ${started.state}",
        )
        assertEquals(started.state, rest.state(started.sessionId))
        rest.resume(started.sessionId)
        val selection = rest.continueFlow(started.sessionId)
        assertEquals(WalletInteractionStatus.CredentialSelection, selection.status)
        val selected = selection.credentialSelection!!.requirements.associate { it.id to it.candidateCredentialIds.filter { id -> id in ids } }
        val done = rest.select(started.sessionId, selected)
        assertEquals(WalletInteractionStatus.Completed, done.status, "OID4VP should complete: $done")
        val directPost =
            WalletTestInProcessHttpCapture.snapshot().singleOrNull {
                it.method.equals("POST", ignoreCase = true) && it.path == "/oid4vp/auth/response"
            }
        assertNotNull(directPost, "holder must submit the authorization response to the verifier/RP REST endpoint")
        assertEquals(200, directPost.response.statusCode, "verifier/RP direct_post must succeed: ${directPost.response}")
        assertTrue(directPost.body?.contains("vp_token=") == true, "direct_post must carry vp_token")
        val status =
            ctx.dispatchInProcessHttp(
                com.sphereon.core.api.http
                    .GenericHttpRequest("GET", "/oid4vp/backend/auth/requests/${request.correlationId}")
            )
        val output = json.decodeFromString(GetAuthorizationRequestStatusOutput.serializer(), assertNotNull(status.body))
        assertEquals(AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED, output.status)
        val verifiedData = assertNotNull(output.verifiedData, "verified status must include authoritative verifier data")
        val verifiedCredentials = assertNotNull(verifiedData.credentialClaims)
        assertEquals(2, verifiedCredentials.size, "exactly two credentials must be verified")
        assertEquals(setOf("v11", "v20"), verifiedCredentials.map { it.id }.toSet())
        assertEquals(
            setOf(CredentialFormat.JWT_VC_JSON.value, CredentialFormat.JWT_VC_JSON_LD.value),
            verifiedCredentials.map { it.type }.toSet(),
        )
        val vpToken = VpToken.fromJson(assertNotNull(verifiedData.authorizationResponse?.get("vp_token")))
        assertEquals(setOf("v11", "v20"), vpToken.queryIds)
        assertEquals(2, vpToken.presentationCount, "one VP artifact per selected credential")
        assertTrue(vpToken.presentationElements.values.all { it.size == 1 })
        vpToken.allPresentationElements.forEach { element ->
            assertTrue(element is JsonPrimitive, "JWT VP artifacts must be compact strings")
            val compactVp = element.jsonPrimitive.content
            val vp = assertNotNull(VcdmClassifier.classifyCompactJws(compactVp).getOrNull())
            assertEquals(PresentationFormat.JWT_VP_JSON, vp.presentationFormat)
            val outerPayload = decodeCompactJwsPayload(compactVp)
            assertEquals(request.nonce, outerPayload["nonce"]?.jsonPrimitive?.content)
            assertEquals(request.audience, outerPayload["aud"]?.jsonPrimitive?.content)
        }
    }

    /**
     * Builds the same command-backed adapter used by the wallet product and drives it with full
     * HTTP route matches. The protocol engine remains behind the endpoint command boundary: this
     * proof never calls engine.start/dispatch/observe for the issue or presentation lifecycle.
     */
    private fun walletInteractionRest(engine: DefaultWalletInteractionEngine): WalletInteractionRestHarness {
        val execution = ctx.session.asCoreApiServiceGraph().serviceExecution
        val productionRegistry = (ctx.session.graph as HttpEndpointCommandRegistry.Graph).httpEndpointCommandRegistry
        val start = StartWalletInteractionCommandImpl(execution, engine)
        val resume = ResumeWalletInteractionCommandImpl(execution, engine)
        val submit = SubmitWalletInteractionActionCommandImpl(execution, engine)
        val state = GetWalletInteractionStateCommandImpl(execution, engine)
        val overrides =
            listOf<HttpEndpointCommand>(
                StartWalletInteractionHttpEndpointCommandImpl(execution, start),
                ResumeWalletInteractionHttpEndpointCommandImpl(execution, resume),
                DispatchWalletInteractionActionHttpEndpointCommandImpl(execution, submit, state),
                GetWalletInteractionStateHttpEndpointCommandImpl(execution, state),
            ).associateBy { it.id }
        val registry =
            object : HttpEndpointCommandRegistry {
                override fun get(handlerCommandId: String): HttpEndpointCommand? = overrides[handlerCommandId] ?: productionRegistry.get(handlerCommandId)

                override fun listHandlerCommandIds(): Set<String> = productionRegistry.listHandlerCommandIds() + overrides.keys
            }
        return WalletInteractionRestHarness(
            adapter = WalletInteractionHttpAdapter(execution, registry),
            routeSelector = (ctx.app as HttpAdapterRouteSelector.Graph).httpAdapterRouteSelector,
            json = defaultWalletInteractionJson,
        )
    }

    private class WalletInteractionRestHarness(
        private val adapter: WalletInteractionHttpAdapter,
        private val routeSelector: HttpAdapterRouteSelector,
        private val json: Json,
    ) {
        suspend fun start(input: WalletInteractionInput): WalletInteractionSession {
            val response =
                request(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = WalletInteractionApiConstants.interactionsPath(input.walletUnitId),
                        body = json.encodeToString(StartWalletInteractionBody.serializer(), StartWalletInteractionBody(input)),
                    ),
                )
            check(response.statusCode == 201) { "Wallet interaction REST start failed: $response" }
            return json.decodeFromString(WalletInteractionSessionEnvelope.serializer(), requireNotNull(response.body)).session
        }

        suspend fun resume(sessionId: WalletInteractionSessionId): WalletInteractionSession {
            val response =
                request(
                    GenericHttpRequest(
                        method = "POST",
                        path = WalletInteractionApiConstants.resumePath("protocol-vcdm-jwt-wallet", sessionId),
                    ),
                )
            check(response.statusCode == 200) { "Wallet interaction REST resume failed: $response" }
            return json.decodeFromString(WalletInteractionSessionEnvelope.serializer(), requireNotNull(response.body)).session
        }

        suspend fun state(sessionId: WalletInteractionSessionId): WalletInteractionState {
            val response =
                request(
                    GenericHttpRequest(
                        method = "GET",
                        path = WalletInteractionApiConstants.statePath("protocol-vcdm-jwt-wallet", sessionId),
                    ),
                )
            check(response.statusCode == 200) { "Wallet interaction REST state failed: $response" }
            return json.decodeFromString(WalletInteractionStateEnvelope.serializer(), requireNotNull(response.body)).state
        }

        suspend fun continueFlow(sessionId: WalletInteractionSessionId): WalletInteractionState = action(sessionId, WalletInteractionAction.continueFlow())

        suspend fun select(
            sessionId: WalletInteractionSessionId,
            idsByRequirement: Map<String, List<String>>,
        ): WalletInteractionState =
            action(
                sessionId,
                WalletInteractionAction.selectCredentials(WalletCredentialSelection(idsByRequirement)),
            )

        private suspend fun action(
            sessionId: WalletInteractionSessionId,
            action: WalletInteractionAction
        ): WalletInteractionState {
            val response =
                request(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = WalletInteractionApiConstants.actionsPath("protocol-vcdm-jwt-wallet", sessionId),
                        body =
                            json.encodeToString(
                                DispatchWalletInteractionActionBody.serializer(),
                                DispatchWalletInteractionActionBody(action),
                            ),
                    ),
                )
            check(response.statusCode == 200) { "Wallet interaction REST action failed: $response" }
            return json.decodeFromString(WalletInteractionStateEnvelope.serializer(), requireNotNull(response.body)).state
        }

        private suspend fun request(request: GenericHttpRequest): GenericHttpResponse =
            when (val selection = routeSelector.select(request.method, request.path, setOf(adapter.id))) {
                is HttpAdapterRouteSelection.Selected -> {
                    check(selection.match.adapterId == adapter.id)
                    adapter.handleResolvedRequest(selection.match.applyTo(request), selection.match)
                }

                is HttpAdapterRouteSelection.NotFound -> {
                    GenericHttpResponse(404, emptyMap(), "Wallet interaction REST route not found")
                }

                is HttpAdapterRouteSelection.Ambiguous -> {
                    GenericHttpResponse(500, emptyMap(), "Ambiguous wallet interaction route")
                }

                is HttpAdapterRouteSelection.Misconfigured -> {
                    GenericHttpResponse(500, emptyMap(), selection.message)
                }
            }
    }

    private fun assertJwtShape(
        raw: String,
        format: CredentialFormat,
        type: String,
        expectedCredentialId: String,
        expectedSubjectId: String,
    ) {
        val parts = raw.split('.')
        assertEquals(3, parts.size)
        val header = json.parseToJsonElement(parts[0].decodeFromBase64Url().decodeToString()).jsonObject
        val payload = json.parseToJsonElement(parts[1].decodeFromBase64Url().decodeToString()).jsonObject
        assertEquals("ES256", header["alg"]?.jsonPrimitive?.content)
        assertNotNull(header["kid"]?.jsonPrimitive?.content)
        assertEquals(ISSUER, payload["iss"]?.jsonPrimitive?.content)
        assertEquals(expectedCredentialId, payload["jti"]?.jsonPrimitive?.content)
        assertNotEquals(expectedCredentialId, expectedSubjectId)
        assertNotEquals(ISSUER, expectedSubjectId)
        assertNotEquals(HOLDER, expectedSubjectId)
        val credential: JsonObject
        when (format) {
            CredentialFormat.JWT_VC_JSON -> {
                credential = assertNotNull(payload["vc"] as? JsonObject)
                assertTrue(credential["type"].toString().contains(type))
                assertEquals(expectedSubjectId, payload["sub"]?.jsonPrimitive?.content)
            }

            CredentialFormat.JWT_VC_JSON_LD -> {
                credential = payload
                assertTrue(payload["@context"] is JsonArray)
                assertTrue(payload["type"].toString().contains(type))
                assertFalse(payload.containsKey("vc"))
                assertFalse(payload.containsKey("sub"), "VCDM 2.0 must not synthesize JWT sub from credentialSubject.id")
            }

            else -> {
                error("unexpected JWT format")
            }
        }
        assertEquals(expectedCredentialId, credential["id"]?.jsonPrimitive?.content)
        assertEquals(
            expectedSubjectId,
            credential["credentialSubject"]
                ?.jsonObject
                ?.get("id")
                ?.jsonPrimitive
                ?.content,
        )
        assertNotEquals(credential["id"], credential["credentialSubject"]?.jsonObject?.get("id"))
        val holderJwk = payload["cnf"]?.jsonObject?.get("jwk")?.jsonObject
        assertNotNull(holderJwk, "holder cnf.jwk must remain independent of credentialSubject claims")
    }

    private fun decodeCompactJwsPayload(compactJws: String): JsonObject {
        val parts = compactJws.split('.')
        assertEquals(3, parts.size, "JWT VP must be a compact three-part JWS")
        return json.parseToJsonElement(parts[1].decodeFromBase64Url().decodeToString()).jsonObject
    }

    private fun semanticIdentityContribution(
        credentialId: String,
        subjectId: String,
        name: String,
    ) = CredentialAttributeContribution(
        attributes = emptyMap(),
        credentialId = credentialId,
        credentialSubjects =
            listOf(
                buildJsonObject {
                    put("id", subjectId)
                    put("name", name)
                },
            ),
    )

    private fun issuerAuthenticationResolver(jwk: JsonObject): WalletIssuerAuthenticationResolver {
        val publicJwk = Jwk.fromJsonObject(jwk).toPublicKey()
        val publishedJwk =
            publicJwk
                .copy(kid = generateJwkThumbprintUri(publicJwk))
                .toJsonObject()
        return object : WalletIssuerAuthenticationResolver {
            override suspend fun resolve(input: WalletIssuerAuthenticationRequest): WalletIssuerAuthenticationResult? =
                if (input.counterparty.identifier == ISSUER) {
                    WalletIssuerAuthenticationResult(
                        issuer = ISSUER,
                        trustedJwks = JsonObject(mapOf("keys" to JsonArray(listOf(publishedJwk)))),
                        provenance = listOf(WalletIssuerAuthenticationProvenance("test-pinned-jwks", "generated:$ISSUER_KEY")),
                    )
                } else {
                    null
                }
        }
    }

    private fun holderVerificationResolver() =
        WalletHolderVerificationMethodResolver { _, ref ->
            if (ref.alias == HOLDER_KEY) {
                WalletHolderVerificationMethod(
                    value = "$HOLDER/keys/$HOLDER_KEY",
                    controller = HOLDER,
                    kind = WalletHolderIdentifierKind.MANAGED_KID,
                    signingAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                )
            } else {
                null
            }
        }

    private suspend fun ensureIssuerKey(): IssuerKey {
        val kms =
            ctx.session.graph
                .asKeyManagerServiceGraph()
                .keyManagerService
        val result = kms.generateKeyResult(alias = ISSUER_KEY, use = JwkUse.sig, alg = SignatureAlgorithm.ECDSA_SHA256)
        assertTrue(result.isOk, "issuer key generation failed")
        val managed = assertNotNull(result.value.keyPair?.joseToManagedKeyInfo(KeyVisibility.PRIVATE))
        val public = assertNotNull(managed.toManagedPublicKeyInfo().key as? Jwk)
        ctx.registerIssuerSigningKey(ISSUER_KEY)
        return IssuerKey(public.toJsonObject() as JsonObject)
    }

    private suspend fun ensureHolderKey(): Jwk {
        val kms =
            ctx.session.graph
                .asKeyManagerServiceGraph()
                .keyManagerService
        val result =
            kms.generateKeyResult(
                alias = HOLDER_KEY,
                use = JwkUse.sig,
                alg = SignatureAlgorithm.ECDSA_SHA256,
                walletUnitId = WALLET_ID,
            )
        assertTrue(result.isOk, "holder key generation failed")
        val managed = assertNotNull(result.value.keyPair?.joseToManagedKeyInfo(KeyVisibility.PRIVATE))
        return assertNotNull(managed.toManagedPublicKeyInfo().key as? Jwk)
    }

    private fun jwks(jwk: Jwk): JsonObject = JsonObject(mapOf("keys" to JsonArray(listOf(jwk.toPublicKey().toJsonObject()))))

    private class PresentationSecurityGate : WalletSecurityGate {
        override suspend fun authorize(request: WalletSecurityGateRequest): WalletSecurityGateResult =
            WalletSecurityGateResult.Authorized(
                WalletSecurityGrant(
                    grantId = request.operationId,
                    assurance = request.requiredAssurance,
                    evidence = mapOf("operation_binding" to PRESENTATION_OPERATION_BINDING),
                ),
            )
    }

    private data class IssuerKey(
        val publicJwk: JsonObject
    )

    private data class Stored(
        val id: String,
        val instanceId: String,
        val raw: String,
        val lifecycleState: CredentialLifecycleState
    )

    private data class VerifierRequest(
        val correlationId: String,
        val requestUri: String,
        val nonce: String?,
        val audience: String
    )
}

@ContributesTo(SessionScope::class)
interface VcdmJwtProtocolVpGraph {
    val oid4vpHolder: com.sphereon.openid.oid4vp.holder.Oid4vpHolder
}

/** Mutates only the wire credential response, proving receiver-side JWT verification is fail-closed. */
private class TamperingReceiver(
    private val delegate: com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciCredentialResponseReceiver
) : com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciCredentialResponseReceiver by delegate {
    override suspend fun receiveCredentialResponse(
        context: com.sphereon.wallet.interaction.WalletInteractionContext,
        state: com.sphereon.wallet.interaction.WalletInteractionState,
        resolvedOffer: com.sphereon.openid.oid4vci.holder.ResolvedCredentialOffer,
        credentialResponse: com.sphereon.openid.oid4vci.common.model.CredentialResponse
    ): List<com.sphereon.wallet.interaction.WalletCredentialPreview> {
        val items =
            credentialResponse.credentials!!.map { item ->
                item.copy(
                    credential =
                        JsonPrimitive(
                            item.credential!!.jsonPrimitive.content.let { jwt ->
                                val parts = jwt.split('.').toMutableList()
                                val sig = parts[2].toCharArray()
                                sig[0] = if (sig[0] == 'A') 'B' else 'A'
                                parts[2] = sig.concatToString()
                                parts.joinToString(".")
                            }
                        )
                )
            }
        return delegate.receiveCredentialResponse(context, state, resolvedOffer, credentialResponse.copy(credentials = items))
    }
}
