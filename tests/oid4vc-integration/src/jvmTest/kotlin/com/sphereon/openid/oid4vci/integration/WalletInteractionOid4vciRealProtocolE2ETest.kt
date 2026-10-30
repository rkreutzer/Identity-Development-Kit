/*
 * (c) 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.openid.oid4vci.integration

import com.sphereon.core.api.conf.DefaultPrincipalMapPropertySource
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vci.issuer.command.CreateCredentialOfferArgs
import com.sphereon.openid.oid4vci.issuer.command.IssueNonceArgs
import com.sphereon.openid.oid4vci.issuer.config.ResolvedWalletProviderTrust
import com.sphereon.openid.oid4vci.issuer.config.WalletProviderAdmission
import com.sphereon.openid.oid4vci.issuer.config.WalletProviderVerifierMaterial
import com.sphereon.openid.oid4vci.issuer.impl.proof.KeyAttestationVerifier
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferInput
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStatus
import com.sphereon.openid.oid4vci.rest.GetCredentialOfferStatusInput
import com.sphereon.openid.oid4vci.rest.GetCredentialOfferStatusServiceCommand
import com.sphereon.openid.oid4vci.rest.Oid4vciRestErrorCodes
import com.sphereon.sdjwt.vc.command.VerifySdJwtVcCommand
import com.sphereon.wallet.WalletIdentityResolver
import com.sphereon.wallet.credential.CredentialLifecycleState
import com.sphereon.wallet.credential.CredentialSubjectExtractor
import com.sphereon.wallet.credential.WalletCredentialStore
import com.sphereon.wallet.credential.WalletIssuanceSessionStore
import com.sphereon.wallet.interaction.WalletCredentialSelection
import com.sphereon.wallet.interaction.WalletEntryPoint
import com.sphereon.wallet.interaction.WalletInteractionAction
import com.sphereon.wallet.interaction.WalletInteractionDiagnostics
import com.sphereon.wallet.interaction.WalletInteractionInput
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.interaction.WalletProtocol
import com.sphereon.wallet.interaction.WalletSecurityGate
import com.sphereon.wallet.interaction.impl.DefaultWalletInteractionEngine
import com.sphereon.wallet.interaction.impl.InMemoryWalletInteractionPrivateSessionStore
import com.sphereon.wallet.interaction.impl.InMemoryWalletInteractionSessionStore
import com.sphereon.wallet.interaction.protocol.oid4vci.HolderServiceOid4vciCredentialRequestProofProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.HolderServiceOid4vciRefreshTokenGrantProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciHolderIssuanceExecutor
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciHolderIssuanceOptions
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciIssuanceOptionsProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciIssuedCredentialAcceptance
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciTokenEndpointProofsProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciWalletInteractionProtocolAdapter
import com.sphereon.wallet.interaction.protocol.oid4vci.SecureComponentOid4vciKeyAttestationProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.WalletStoreOid4vciCredentialResponseReceiver
import com.sphereon.wallet.unit.SecureComponentUsage
import com.sphereon.wallet.unit.attestation.KeyAttestationIssueRequest
import com.sphereon.wallet.unit.attestation.WalletUnitAttestationProfile
import com.sphereon.wallet.wsca.Wsca
import dev.zacsweers.metro.ContributesTo
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@ContributesTo(SessionScope::class)
interface WalletInteractionOid4vciStoreTestGraph {
    val walletCredentialStore: WalletCredentialStore
    val walletIssuanceSessionStore: WalletIssuanceSessionStore
    val walletIdentityResolver: WalletIdentityResolver
    val credentialSubjectExtractor: CredentialSubjectExtractor
    val verifySdJwtVcCommand: VerifySdJwtVcCommand
}

@ContributesTo(SessionScope::class)
interface WalletInteractionOid4vciOfferStatusTestGraph {
    val getCredentialOfferStatusServiceCommand: GetCredentialOfferStatusServiceCommand
}

class WalletInteractionOid4vciRealProtocolE2ETest {
    companion object {
        private const val CREDENTIAL_CONFIG_ID = "NeutralOid4vciDegreeSdJwt"
        private const val SD_JWT_VCT = "https://issuer.example.com/public/schema/vct/NeutralOid4vciDegreeSdJwt"
        private const val ISSUER_SIGNING_KEY_ALIAS = "neutral-oid4vci-issuer-signing-key"
        private const val HOLDER_SIGNING_KEY_ALIAS = "neutral-oid4vci-holder-proof-key"
        private const val WALLET_UNIT_ID = "wallet-interaction-oid4vci-e2e"
        private const val WALLET_CLIENT_ID = "https://wallet.example.com"
        private const val TRUST_DIGEST = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

        init {
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentialConfigurationIds",
                CREDENTIAL_CONFIG_ID,
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$CREDENTIAL_CONFIG_ID].format",
                "dc+sd-jwt",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$CREDENTIAL_CONFIG_ID].vct",
                SD_JWT_VCT,
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$CREDENTIAL_CONFIG_ID].scope",
                "neutral_oid4vci_degree",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$CREDENTIAL_CONFIG_ID].bindingMethods",
                "did:key,did:jwk,jwk",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$CREDENTIAL_CONFIG_ID].signingAlgorithms",
                "ES256",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$CREDENTIAL_CONFIG_ID].proofTypes.jwt.signingAlgorithms",
                "ES256",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$CREDENTIAL_CONFIG_ID].validityPeriod",
                "P365D",
            )

            // The offer endpoint is resolved through the registry-backed issuer resource.
            // Keep the legacy singular fixture above for the protocol builder, but also expose
            // the canonical routed resource that serves the wallet's credential_offer_uri.
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.routing.issuerResourceId",
                OID4VCI_TEST_ISSUER_INSTANCE_ID,
            )
            val issuerRoot = "oid4vci.issuers.$OID4VCI_TEST_ISSUER_INSTANCE_ID"
            val authorizationServerId = "00000000-0000-4000-8000-000000000002"
            DefaultPrincipalMapPropertySource.addProperty("$issuerRoot.identifier", OID4VCI_TEST_ISSUER_URL)
            DefaultPrincipalMapPropertySource.addProperty(
                "$issuerRoot.credentialConfigurationIds",
                CREDENTIAL_CONFIG_ID,
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "$issuerRoot.issuerCapabilityId",
                "00000000-0000-4000-8000-000000000003",
            )
            DefaultPrincipalMapPropertySource.addProperty("$issuerRoot.authorizationServerIds", authorizationServerId)
            DefaultPrincipalMapPropertySource.addProperty("$issuerRoot.profile", "OID4VCI_1_0_FINAL")
            DefaultPrincipalMapPropertySource.addProperty("$issuerRoot.profileRevision", "7")
            val authorizationServerRoot = "$issuerRoot.authorizationServers.$authorizationServerId"
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.tenantId", OID4VCI_TEST_TENANT_ID)
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.issuerIdentifier", OID4VCI_TEST_ISSUER_URL)
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.enabled", "true")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.default", "true")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.lifecycle", "ACTIVE")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.deployment", "HOSTED")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.credentialIssuancePurpose", "true")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.allowedGrants", "PRE_AUTHORIZED_CODE")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.revision", "11")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.runtimeServerKey", "default")
            DefaultPrincipalMapPropertySource.addProperty(
                "$authorizationServerRoot.jwksUri",
                "${OID4VCI_TEST_ISSUER_URL}/.well-known/jwks.json",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "$authorizationServerRoot.tokenEndpoint",
                "${OID4VCI_TEST_ISSUER_URL}/token",
            )
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.discoveryCurrent", "true")
            DefaultPrincipalMapPropertySource.addProperty("$authorizationServerRoot.bindingRevision", "13")
            val credentialRoot = "$issuerRoot.credentials.[$CREDENTIAL_CONFIG_ID]"
            DefaultPrincipalMapPropertySource.addProperty("$credentialRoot.format", "dc+sd-jwt")
            DefaultPrincipalMapPropertySource.addProperty("$credentialRoot.vct", SD_JWT_VCT)
            DefaultPrincipalMapPropertySource.addProperty("$credentialRoot.scope", "neutral_oid4vci_degree")
            DefaultPrincipalMapPropertySource.addProperty("$credentialRoot.bindingMethods", "did:key,did:jwk,jwk")
            DefaultPrincipalMapPropertySource.addProperty("$credentialRoot.signingAlgorithms", "ES256")
            DefaultPrincipalMapPropertySource.addProperty("$credentialRoot.proofTypes.jwt.signingAlgorithms", "ES256")
            DefaultPrincipalMapPropertySource.addProperty("$credentialRoot.signingKeyMode", "jwk-thumbprint")
            DefaultPrincipalMapPropertySource.addProperty("$credentialRoot.validityPeriod", "P365D")
            DefaultPrincipalMapPropertySource.addProperty(
                "$credentialRoot.credentialDefinition.types",
                "VerifiableCredential,NeutralOid4vciDegreeCredential",
            )
            DefaultPrincipalMapPropertySource.addProperty("kv.stores.blob.metadata.type", "memory")
            DefaultPrincipalMapPropertySource.addProperty("kv.stores.blob.metadata.scopeBinding", "TENANT")
            DefaultPrincipalMapPropertySource.addProperty("blob.stores.default.type", "memory")
            DefaultPrincipalMapPropertySource.addProperty("blob.stores.default.scopeBinding", "TENANT")
            // A correlation id is claimed on this store, which the deployment must declare. A memory store is private to its
            // process, so the claim is refused unless the deployment states that one process serves it, as this test does.
            DefaultPrincipalMapPropertySource.addProperty("kv.stores.oid4vci.rest.sessions.type", "memory")
            DefaultPrincipalMapPropertySource.addProperty("kv.stores.oid4vci.rest.sessions.scopeBinding", "TENANT")
            DefaultPrincipalMapPropertySource.addProperty("oid4vci.rest.requests.allowProcessLocalStore", "true")
        }
    }

    private val ctx = Oid4vciTestContext(this, credentialConfigurationIds = listOf(CREDENTIAL_CONFIG_ID))
    private val issuerUrl = "https://issuer.example.com"
    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = false
        }

    @Test
    fun neutralInteractionEngineReceivesOid4vciCredentialEndToEnd() =
        runTest {
            ctx.ensureAsSigningKey()
            ensureIssuerSigningKey()

            val graph = ctx.session.graph as Oid4vciIssuanceTestGraph
            val issuer = graph.oid4vciIssuerService
            val credentialStore = (ctx.session.graph as WalletInteractionOid4vciStoreTestGraph).walletCredentialStore
            val offerResult =
                issuer.createCredentialOffer(
                    CreateCredentialOfferArgs(
                        instanceId = OID4VCI_TEST_ISSUER_INSTANCE_ID,
                        issuerId = issuerUrl,
                        credentialConfigurationIds = listOf(CREDENTIAL_CONFIG_ID),
                        preAuthorizedCodeGrant = true,
                        authorizationPolicySnapshot = OID4VCI_TEST_AUTHORIZATION_POLICY_SNAPSHOT,
                    ),
                )
            assertTrue(
                offerResult.isOk,
                "Offer creation should succeed: ${if (offerResult.isErr) offerResult.error.message.defaultMessage else ""}",
            )
            val preAuthorizedCode =
                offerResult.value.offer.grants!!
                    .preAuthorizedCode!!
                    .preAuthorizedCode

            ctx.ensurePublicWalletClient(WALLET_CLIENT_ID)
            val engine = newWalletEngine(clientId = WALLET_CLIENT_ID)

            val session =
                engine.start(
                    WalletInteractionInput(
                        walletUnitId = WALLET_UNIT_ID,
                        entryPoint = WalletEntryPoint.rawQr(offerResult.value.offerUri),
                    ),
                )
            val startStateJson = json.encodeToString(session.state)

            assertEquals(WalletProtocol.OID4VCI, session.state.protocol)
            // A first interaction with this issuer surfaces the trust review step before the offer.
            assertEquals(
                WalletInteractionStatus.TrustReview,
                session.state.status,
                "Unexpected initial wallet state: ${session.state.error?.code ?: "no-error"}; " +
                    WalletTestInProcessHttpCapture.snapshot().joinToString(" | ") {
                        "${it.method} ${it.path} -> ${it.response.statusCode}: ${it.response.body?.take(180)}"
                    },
            )
            assertFalse(startStateJson.contains(preAuthorizedCode))

            engine.dispatch(session.sessionId, WalletInteractionAction.continueFlow())
            val offerState = engine.observe(session.sessionId).value
            assertEquals(WalletInteractionStatus.CredentialOfferReview, offerState.status)

            engine.dispatch(
                session.sessionId,
                WalletInteractionAction.selectCredentials(
                    WalletCredentialSelection(
                        selectedCredentialIdsByRequirement =
                            mapOf("oid4vci-offer" to offerState.credentialOffer!!.credentialConfigurationIds),
                    ),
                ),
            )
            val completedState = engine.observe(session.sessionId).value
            val completedStateJson = json.encodeToString(completedState)

            assertEquals(WalletInteractionStatus.Completed, completedState.status)
            assertTrue(completedState.terminal)
            assertFalse(completedStateJson.contains("access_token"))
            assertFalse(completedStateJson.contains(preAuthorizedCode))

            val metadataResult = credentialStore.listMetadata(WALLET_UNIT_ID)
            assertTrue(
                metadataResult.isOk,
                "Stored credential metadata should be readable: ${if (metadataResult.isErr) metadataResult.error.message.defaultMessage else ""}",
            )
            val storedMetadata = metadataResult.value.single()
            assertEquals(CredentialLifecycleState.ACTIVE, storedMetadata.lifecycleSummary.lifecycleState)
            assertEquals(CREDENTIAL_CONFIG_ID, storedMetadata.credentialConfigurationId)
            assertEquals(setOf(SD_JWT_VCT), storedMetadata.credentialTypeRefs.map { it.value }.toSet())

            val recordResult = credentialStore.getCredential(WALLET_UNIT_ID, storedMetadata.credentialRecordId)
            assertTrue(
                recordResult.isOk,
                "Stored credential should be readable: ${if (recordResult.isErr) recordResult.error.message.defaultMessage else ""}",
            )
            val storedRecord = assertNotNull(recordResult.value)
            assertEquals(
                HOLDER_SIGNING_KEY_ALIAS,
                storedRecord.instances
                    .single()
                    .holderKeyRef
                    ?.alias
            )
        }

    @Test
    fun shouldIssueOneCredentialToARealWalletForAnOfferRequestedRepeatedlyUnderOneCorrelationId() =
        runTest {
            ctx.ensureAsSigningKey()
            ensureIssuerSigningKey()
            val createOffer = (ctx.session.graph as StaticOfferTestGraph).createCredentialOfferServiceCommand
            val readStatus = (ctx.session.graph as WalletInteractionOid4vciOfferStatusTestGraph).getCredentialOfferStatusServiceCommand
            val credentialStore = (ctx.session.graph as WalletInteractionOid4vciStoreTestGraph).walletCredentialStore
            val correlationId = "request-1"
            val request =
                CreateCredentialOfferInput(
                    credentialConfigurationIds = listOf(CREDENTIAL_CONFIG_ID),
                    issuerId = issuerUrl,
                    correlationId = correlationId,
                )

            val first = createOffer.execute(request)
            assertTrue(first.isOk, "Offer creation should succeed: ${if (first.isErr) first.error.message.defaultMessage else ""}")
            val replayed = createOffer.execute(request)
            assertTrue(replayed.isOk, "A repeated request should replay the offer: ${if (replayed.isErr) replayed.error.message.defaultMessage else ""}")
            assertEquals(correlationId, first.value.correlationId)
            assertEquals(first.value.offerUri, replayed.value.offerUri)
            assertEquals(first.value.sessionId, replayed.value.sessionId)
            assertEquals(CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED, readStatus.execute(GetCredentialOfferStatusInput(correlationId)).value.status)

            val engine = newWalletEngine(clientId = null)
            val session =
                engine.start(
                    WalletInteractionInput(walletUnitId = WALLET_UNIT_ID, entryPoint = WalletEntryPoint.rawQr(first.value.offerUri)),
                )
            engine.dispatch(session.sessionId, WalletInteractionAction.continueFlow())
            val offerState = engine.observe(session.sessionId).value
            assertEquals(WalletInteractionStatus.CredentialOfferReview, offerState.status)
            engine.dispatch(
                session.sessionId,
                WalletInteractionAction.selectCredentials(
                    WalletCredentialSelection(
                        selectedCredentialIdsByRequirement = mapOf("oid4vci-offer" to offerState.credentialOffer!!.credentialConfigurationIds),
                    ),
                ),
            )
            assertEquals(WalletInteractionStatus.Completed, engine.observe(session.sessionId).value.status)

            assertEquals(1, credentialStore.listMetadata(WALLET_UNIT_ID).value.size)
            assertEquals(CredentialOfferSessionStatus.CREDENTIAL_ISSUED, readStatus.execute(GetCredentialOfferStatusInput(correlationId)).value.status)
            (ctx.session.graph as Oid4vciIssuerInstanceOverrideSessionGraph)
                .mutableOid4vciIssuerInstanceIdProvider
                .setCurrentInstanceId(OID4VCI_TEST_ISSUER_INSTANCE_ID)
            val afterIssuance = createOffer.execute(request)
            assertTrue(afterIssuance.isOk, "A repeat after issuance should still replay: ${if (afterIssuance.isErr) afterIssuance.error.message.defaultMessage else ""}")
            assertEquals(first.value.sessionId, afterIssuance.value.sessionId)
            assertEquals(1, credentialStore.listMetadata(WALLET_UNIT_ID).value.size)

            val other = createOffer.execute(request.copy(ttlSeconds = 60))
            assertTrue(other.isErr)
            assertEquals(Oid4vciRestErrorCodes.CORRELATION_ID_CONFLICT, other.error.code)
        }

    private fun newWalletEngine(clientId: String?): DefaultWalletInteractionEngine {
        val holder = (ctx.session.graph as Oid4vciIssuanceTestGraph).oid4vciHolder
        val wsca = (ctx.session.graph as WalletInteractionOid4vciWscaTestGraph).wsca
        val storeGraph = ctx.session.graph as WalletInteractionOid4vciStoreTestGraph
        val credentialStore = storeGraph.walletCredentialStore
        val issuanceSessionStore = storeGraph.walletIssuanceSessionStore
        val acceptance =
            Oid4vciIssuedCredentialAcceptance(
                verifySdJwtVcCommand = storeGraph.verifySdJwtVcCommand,
                subjectExtractor = storeGraph.credentialSubjectExtractor,
                identityResolver = storeGraph.walletIdentityResolver,
            )
        val adapter =
            Oid4vciWalletInteractionProtocolAdapter(
                holder = holder,
                issuanceExecutor =
                    Oid4vciHolderIssuanceExecutor(
                        holder = holder,
                        tokenEndpointProofsProvider = clientId?.let { integrationPublicWalletTokenEndpointProofs(it) } ?: Oid4vciTokenEndpointProofsProvider.none,
                        optionsProvider =
                            object : Oid4vciIssuanceOptionsProvider {
                                override suspend fun options(
                                    context: com.sphereon.wallet.interaction.WalletInteractionContext,
                                    state: com.sphereon.wallet.interaction.WalletInteractionState,
                                    resolvedOffer: com.sphereon.openid.oid4vci.holder.ResolvedCredentialOffer,
                                    existingHolderKeyAliases: List<String>,
                                ): Oid4vciHolderIssuanceOptions =
                                    Oid4vciHolderIssuanceOptions(
                                        signingKeyIds = existingHolderKeyAliases.ifEmpty { listOf(HOLDER_SIGNING_KEY_ALIAS) },
                                        operationBinding = "test:oid4vci-credential-request-proof",
                                        signingAlgorithm = "ES256",
                                        clientId = clientId,
                                        credentialConfigurationId = CREDENTIAL_CONFIG_ID,
                                    )
                            },
                        credentialReceiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, issuanceSessionStore, acceptance),
                        nestedPresentationExecutor = com.sphereon.wallet.interaction.WalletNestedPresentationExecutor.notConfigured,
                        credentialStore = credentialStore,
                        issuanceSessionStore = issuanceSessionStore,
                        refreshTokenGrantProvider = HolderServiceOid4vciRefreshTokenGrantProvider(holder),
                        keyAttestationProvider = SecureComponentOid4vciKeyAttestationProvider(wsca),
                        // The holder service provisions and uses this alias exclusively through
                        // WSCA -> selected WSCD. The WSCD owns its configured KMS.
                        credentialRequestProofProvider = HolderServiceOid4vciCredentialRequestProofProvider(holder),
                    ),
            )
        return DefaultWalletInteractionEngine(
            sensitiveInputAuthority = integrationSensitiveInputAuthority(),
            privateSessionStore = InMemoryWalletInteractionPrivateSessionStore(),
            sessionStore = InMemoryWalletInteractionSessionStore(),
            // Promptless protocol test: the attended security ceremony is exercised by the
            // wallet-product/runner suites, not here.
            securityGate = WalletSecurityGate.allow,
            launchAuthorities = setOf(integrationLaunchAuthority()),
            adapters = listOf(adapter),
            diagnostics = WalletInteractionDiagnostics.none,
        )
    }

    /**
     * KA-on-demand acceptance leg. [CREDENTIAL_CONFIG_ID] declares NO
     * `key_attestations_required` at all (see the class init block): a non-null
     * `KeyAttestationsRequired` policy triggers `KeyAttestationEvidenceEnforcer`'s full hard-coded
     * production gate (x5c-bound signer, `iso_18045_high`, `non_exportable`), which a Software-
     * profile custody can never honestly satisfy - proving REQUIRED-policy acceptance with an OSS
     * wallet is a contradiction in terms, so this leg does not attempt it (the "required -> attach"
     * BRANCHING logic is covered by `lib-wallet-interaction-protocol-oid4vci`'s own unit tests
     * instead). This leg proves the voluntary-attachment half: a real OSS wallet that VOLUNTARILY
     * attaches a key attestation minted by [LocalWsca.attestKeys] (the exact production KA-minting
     * surface [com.sphereon.wallet.provider.local.LocalWalletProvider] and the runner's
     * `RunnerOid4vciKeyAttestationProvider` both route through) onto a REAL credential-request proof
     * built by the production `CreateCredentialRequestProofCommandImpl` (proving the wire shape - the
     * `key_attestation` JOSE header - round-trips correctly), and that the resulting KA is fully
     * verified and ACCEPTED by the real issuer's
     * [com.sphereon.openid.oid4vci.issuer.impl.proof.KeyAttestationVerifier] under the permissive
     * `policy = null` path (mirroring `WalletProviderProvisioningE2ETest`'s pinned-trust-anchor
     * pattern in idk wallet-runner, since this ad hoc WSCA identity is not pre-registered with the
     * real issuer's own trust-anchor resolution).
     */
    @Test
    fun keyAttestationVoluntarilyAttachedToARealCredentialRequestProofIsAcceptedUnderPermissivePolicy() =
        runTest {
            ctx.ensureAsSigningKey()
            ensureIssuerSigningKey()

            val graph = ctx.session.graph as Oid4vciIssuanceTestGraph
            val issuer = graph.oid4vciIssuerService
            val holder = graph.oid4vciHolder
            val keyAttestationVerifier = (ctx.session.graph as KeyAttestationVerifierTestGraph).keyAttestationVerifier

            // Use the same graph-provided WSCA as the production holder command. WSCA selects the
            // WSCD, and the selected WSCD owns its configured KMS.
            val wsca = (ctx.session.graph as WalletInteractionOid4vciWscaTestGraph).wsca
            val holderKey =
                wsca
                    .createCredentialKey(WALLET_UNIT_ID, SecureComponentUsage.WALLET_CREDENTIAL_PROOF, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "createCredentialKey failed: ${if (it.isErr) it.error.message.defaultMessage else ""}")
                        it.value
                    }
            val holderSigningKeyId = holderKey.keyRef ?: holderKey.keyId

            val nonceResult = issuer.issueNonce(IssueNonceArgs(ttlSeconds = 300))
            assertTrue(nonceResult.isOk, "Nonce issuance should succeed")
            val cNonce = nonceResult.value.cNonce

            val kaResult =
                wsca.attestKeys(
                    KeyAttestationIssueRequest(
                        walletUnitId = WALLET_UNIT_ID,
                        walletAccountId = WALLET_UNIT_ID,
                        operationBinding = "test:oid4vci:key-attestation",
                        profile = WalletUnitAttestationProfile.TS03_JWT,
                        attestedKeys = listOf(holderKey),
                        audience = issuerUrl,
                        nonce = cNonce,
                    ),
                )
            assertTrue(kaResult.isOk, "Key attestation issuance should succeed: ${if (kaResult.isErr) kaResult.error.message.defaultMessage else ""}")
            val kaJwt = kaResult.value.artifact.material.value

            // Attach through the REAL, production holder-proof command - the same
            // holder.createCredentialRequestProof(keyAttestationJwt = ...) call
            // Oid4vciHolderIssuanceExecutor makes.
            val proofResult =
                holder.createCredentialRequestProof(
                    walletUnitId = WALLET_UNIT_ID,
                    operationBinding = "key-attestation-proof",
                    issuerUrl = issuerUrl,
                    cNonce = cNonce,
                    signingKeyIds = listOf(holderSigningKeyId),
                    signingAlgorithm = "ES256",
                    keyAttestationJwt = kaJwt,
                )
            assertTrue(proofResult.isOk, "Proof creation should succeed: ${if (proofResult.isErr) proofResult.error.message.defaultMessage else ""}")
            val proofJwt =
                (
                    proofResult.value.proofs.proofValues
                        .single() as JsonPrimitive
                ).content
            val proofHeader = Json.parseToJsonElement(proofJwt.split('.')[0].decodeFromBase64Url().decodeToString()).jsonObject
            assertEquals(kaJwt, proofHeader["key_attestation"]?.jsonPrimitive?.content, "the produced proof JWT must carry the KA verbatim in its key_attestation header")

            // The signer of the KA is LocalWsca's OWN attestation key (ensureKey(usage =
            // WALLET_ATTESTATION), resolved deterministically per walletUnitId since no explicit
            // signer was requested) - mirrors LocalWalletProvider.trustAnchor()'s KDoc: same call,
            // same key, since attestKeys() resolved it internally the same way.
            val signerKey =
                wsca
                    .ensureKey(WALLET_UNIT_ID, SecureComponentUsage.WALLET_ATTESTATION, SignatureAlgorithm.ECDSA_SHA256)
                    .let {
                        assertTrue(it.isOk, "ensureKey failed")
                        it.value
                    }
            val kaHeader = Json.parseToJsonElement(kaJwt.split('.')[0].decodeFromBase64Url().decodeToString()).jsonObject
            val kaKid = kaHeader["kid"]?.jsonPrimitive?.content
            assertNotNull(kaKid, "the KA must carry a kid header (no x5c was requested)")
            val pinnedTrustAnchor = Json.decodeFromString(Jwk.serializer(), signerKey.publicKeyJwk!!).copy(kid = kaKid)

            val permissive =
                keyAttestationVerifier.verify(
                    keyAttestationJwt = kaJwt,
                    walletProviderTrust =
                        ResolvedWalletProviderTrust(
                            policyDigest = TRUST_DIGEST,
                            admission = WalletProviderAdmission.RESTRICTED,
                            verifierMaterials = listOf(WalletProviderVerifierMaterial.Jwk(pinnedTrustAnchor, TRUST_DIGEST)),
                            requireWalletUnitEvidence = false,
                        ),
                    policy = null,
                )
            assertTrue(
                permissive.isOk,
                "the issuer's KeyAttestationVerifier must accept an honest Software-backed key attestation under a " +
                    "permissive/dev policy: ${if (permissive.isErr) permissive.error.message.defaultMessage else ""}",
            )
        }

    private suspend fun ensureIssuerSigningKey() {
        val kms =
            ctx.session.graph
                .asKeyManagerServiceGraph()
                .keyManagerService
        val result =
            kms.generateKeyResult(
                alias = ISSUER_SIGNING_KEY_ALIAS,
                use = JwkUse.sig,
                alg = SignatureAlgorithm.ECDSA_SHA256,
            )
        assertTrue(
            result.isOk,
            "Issuer signing key generation should succeed: ${if (result.isErr) result.error.message.defaultMessage else ""}",
        )
        ctx.registerIssuerSigningKey(ISSUER_SIGNING_KEY_ALIAS)
    }
}

/**
 * Session-graph accessor for [KeyAttestationVerifier], scoped to this test file only - mirrors
 * `WalletProviderProvisioningE2ETest`'s locally-declared `KeyAttestationVerifierGraph` (idk
 * wallet-runner). The issuer module contributes no such accessor itself since nothing in its own
 * production code needs one (issuer-internal callers inject [KeyAttestationVerifier] directly).
 */
@ContributesTo(SessionScope::class)
interface KeyAttestationVerifierTestGraph {
    val keyAttestationVerifier: KeyAttestationVerifier
}

@ContributesTo(SessionScope::class)
interface WalletInteractionOid4vciWscaTestGraph {
    val wsca: Wsca
}
