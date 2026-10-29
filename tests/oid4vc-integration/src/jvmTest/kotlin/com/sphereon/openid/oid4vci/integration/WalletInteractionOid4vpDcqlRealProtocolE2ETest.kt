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

package com.sphereon.openid.oid4vci.integration

import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.DefaultPrincipalMapPropertySource
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.defaults.random.defaultSecureRandom
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.command.DpopProofAssembly
import com.sphereon.openid.oid4vc.common.QrCodeOptions
import com.sphereon.openid.oid4vci.issuer.command.CreateCredentialOfferArgs
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider
import com.sphereon.openid.oid4vp.dcql.DcqlClaimQuery
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.claimsPathPointer
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.universal.CreateAuthorizationRequestInput
import com.sphereon.openid.oid4vp.universal.CreateAuthorizationRequestOutput
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.sdjwt.vc.command.VerifySdJwtVcCommand
import com.sphereon.wallet.WalletIdentityResolver
import com.sphereon.wallet.credential.CredentialLifecycleState
import com.sphereon.wallet.credential.CredentialRecord
import com.sphereon.wallet.credential.CredentialSubjectExtractor
import com.sphereon.wallet.credential.WalletCredentialStore
import com.sphereon.wallet.credential.WalletIssuanceSessionStore
import com.sphereon.wallet.interaction.ProtocolExecutionOwner
import com.sphereon.wallet.interaction.WalletCredentialSelection
import com.sphereon.wallet.interaction.WalletEntryPoint
import com.sphereon.wallet.interaction.WalletInteractionAction
import com.sphereon.wallet.interaction.WalletInteractionClient
import com.sphereon.wallet.interaction.WalletInteractionDiagnostics
import com.sphereon.wallet.interaction.WalletInteractionInput
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.interaction.WalletProtocol
import com.sphereon.wallet.interaction.WalletSecurityAssurance
import com.sphereon.wallet.interaction.WalletSecurityGate
import com.sphereon.wallet.interaction.WalletSecurityGateRequest
import com.sphereon.wallet.interaction.WalletSecurityGateResult
import com.sphereon.wallet.interaction.WalletSecurityGrant
import com.sphereon.wallet.interaction.WalletSecurityOperation
import com.sphereon.wallet.interaction.impl.DefaultWalletInteractionEngine
import com.sphereon.wallet.interaction.impl.InMemoryWalletInteractionPrivateSessionStore
import com.sphereon.wallet.interaction.impl.InMemoryWalletInteractionSessionStore
import com.sphereon.wallet.interaction.impl.WscdAwareExecutionPlanner
import com.sphereon.wallet.interaction.impl.WscdExecutionProfileSource
import com.sphereon.wallet.interaction.protocol.oid4vci.HolderServiceOid4vciCredentialRequestProofProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.HolderServiceOid4vciRefreshTokenGrantProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciHolderIssuanceExecutor
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciHolderIssuanceOptions
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciIssuanceOptionsProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciIssuedCredentialAcceptance
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciWalletInteractionProtocolAdapter
import com.sphereon.wallet.interaction.protocol.oid4vci.SecureComponentOid4vciKeyAttestationProvider
import com.sphereon.wallet.interaction.protocol.oid4vci.WalletStoreOid4vciCredentialResponseReceiver
import com.sphereon.wallet.interaction.protocol.oid4vp.Oid4vpPresentationSecurityAttributes
import com.sphereon.wallet.interaction.protocol.oid4vp.Oid4vpWalletConfigProvider
import com.sphereon.wallet.interaction.protocol.oid4vp.Oid4vpWalletInteractionProtocolAdapter
import com.sphereon.wallet.interaction.protocol.oid4vp.SecureComponentOid4vpSdJwtHolderBindingProvider
import com.sphereon.wallet.unit.attestation.LocalWalletProviderAttestationSignerResolver
import com.sphereon.wallet.wsca.Wsca
import com.sphereon.wallet.wsca.impl.LocalWsca
import com.sphereon.wallet.wsca.impl.WalletUserAuthenticator
import com.sphereon.wallet.wscd.ActivationProof
import com.sphereon.wallet.wscd.ActivationProofKind
import com.sphereon.wallet.wscd.Wscd
import dev.zacsweers.metro.ContributesTo
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import com.sphereon.openid.oid4vp.holder.WalletConfig as Oid4vpWalletConfig

@ContributesTo(SessionScope::class)
interface WalletInteractionOid4vpStoreTestGraph {
    val walletCredentialStore: WalletCredentialStore
    val walletIssuanceSessionStore: WalletIssuanceSessionStore
    val walletIdentityResolver: WalletIdentityResolver
    val credentialSubjectExtractor: CredentialSubjectExtractor
    val verifySdJwtVcCommand: VerifySdJwtVcCommand
}

@ContributesTo(SessionScope::class)
interface WalletInteractionOid4vpWscdTestGraph {
    val wscd: Wscd
}

@ContributesTo(SessionScope::class)
interface WalletInteractionOid4vpIssuerConfigTestGraph {
    val oid4vciIssuerConfigProvider: Oid4vciIssuerConfigProvider
}

class WalletInteractionOid4vpDcqlRealProtocolE2ETest {
    companion object {
        private const val CREDENTIAL_CONFIG_ID = "UniversityDegree"
        private const val SD_JWT_CONFIG_ID = "UniversityDegreeSdJwt"
        private const val SD_JWT_VCT = "https://issuer.example.com/public/schema/vct/UniversityDegreeSdJwt"
        private const val ISSUER_SIGNING_KEY_ALIAS = "issuer-vc-signing-key"
        private const val HOLDER_SIGNING_KEY_ALIAS = "wallet-interaction-oid4vp-holder-proof-key"
        private const val VERIFIER_SIGNING_KEY_ALIAS = "verifier-jar-signing-key"
        private const val WALLET_CLIENT_ID = "https://wallet.example.com"
        private const val SESSION_WALLET_UNIT_ID = "wallet-interaction-oid4vp-e2e"
        private const val WALLET_UNIT_ID = "wallet-unit-oid4vp-e2e"
        private const val WALLET_ACCOUNT_ID = "wallet-account-oid4vp-e2e"
        private const val ACTIVATION_DECISION_ID = "activation-oid4vp-e2e"
        private const val HSM_OPERATION_TYPE = "wallet.sign"
        private const val HSM_OPERATION_HASH = "sha256:oid4vp-real-protocol-e2e"
        private const val HSM_NONCE = "nonce-oid4vp-e2e"
        private const val HSM_OPERATION_BINDING = "test:oid4vp-dcql-presentation"

        init {
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentialConfigurationIds",
                "$CREDENTIAL_CONFIG_ID,$SD_JWT_CONFIG_ID",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$CREDENTIAL_CONFIG_ID].format",
                "jwt_vc_json",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$CREDENTIAL_CONFIG_ID].scope",
                "degree",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$CREDENTIAL_CONFIG_ID].bindingMethods",
                "did:key,did:jwk",
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
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$CREDENTIAL_CONFIG_ID].credentialDefinition.types",
                "VerifiableCredential,UniversityDegreeCredential",
            )

            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$SD_JWT_CONFIG_ID].format",
                "dc+sd-jwt",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$SD_JWT_CONFIG_ID].vct",
                SD_JWT_VCT,
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$SD_JWT_CONFIG_ID].scope",
                "degree_sdjwt",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$SD_JWT_CONFIG_ID].bindingMethods",
                "did:key,did:jwk,jwk",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$SD_JWT_CONFIG_ID].signingAlgorithms",
                "ES256",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$SD_JWT_CONFIG_ID].proofTypes.jwt.signingAlgorithms",
                "ES256",
            )
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.issuer.credentials.[$SD_JWT_CONFIG_ID].validityPeriod",
                "P365D",
            )

            // The registry-backed provider selects the issuer resource by the mutable canonical
            // UUID selector. Mirror the full fixture under that resource namespace; the legacy
            // singular namespace above is not authoritative for this test.
            DefaultPrincipalMapPropertySource.addProperty(
                "oid4vci.routing.issuerResourceId",
                OID4VCI_TEST_ISSUER_INSTANCE_ID,
            )
            val issuerRoot = "oid4vci.issuers.$OID4VCI_TEST_ISSUER_INSTANCE_ID"
            val authorizationServerId = "00000000-0000-4000-8000-000000000002"
            DefaultPrincipalMapPropertySource.addProperty("$issuerRoot.identifier", OID4VCI_TEST_ISSUER_URL)
            DefaultPrincipalMapPropertySource.addProperty(
                "$issuerRoot.credentialConfigurationIds",
                "$CREDENTIAL_CONFIG_ID,$SD_JWT_CONFIG_ID",
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
            configureIssuerCredential(issuerRoot, CREDENTIAL_CONFIG_ID, "jwt_vc_json", "degree", "VerifiableCredential,UniversityDegreeCredential")
            configureIssuerCredential(issuerRoot, SD_JWT_CONFIG_ID, "dc+sd-jwt", "degree_sdjwt", "VerifiableCredential,UniversityDegreeCredential", SD_JWT_VCT)

            DefaultPrincipalMapPropertySource.addProperty("kv.stores.blob.metadata.type", "memory")
            DefaultPrincipalMapPropertySource.addProperty("kv.stores.blob.metadata.scopeBinding", "TENANT")
            DefaultPrincipalMapPropertySource.addProperty("blob.stores.default.type", "memory")
            DefaultPrincipalMapPropertySource.addProperty("blob.stores.default.scopeBinding", "TENANT")
        }

        private fun configureIssuerCredential(
            issuerRoot: String,
            credentialConfigurationId: String,
            format: String,
            scope: String,
            types: String,
            vct: String? = null,
        ) {
            val prefix = "$issuerRoot.credentials.[$credentialConfigurationId]"
            DefaultPrincipalMapPropertySource.addProperty("$prefix.format", format)
            if (vct != null) DefaultPrincipalMapPropertySource.addProperty("$prefix.vct", vct)
            DefaultPrincipalMapPropertySource.addProperty("$prefix.scope", scope)
            DefaultPrincipalMapPropertySource.addProperty("$prefix.bindingMethods", "did:key,did:jwk,jwk")
            DefaultPrincipalMapPropertySource.addProperty("$prefix.signingAlgorithms", "ES256")
            DefaultPrincipalMapPropertySource.addProperty("$prefix.proofTypes.jwt.signingAlgorithms", "ES256")
            DefaultPrincipalMapPropertySource.addProperty("$prefix.signingKeyMode", "jwk-thumbprint")
            DefaultPrincipalMapPropertySource.addProperty("$prefix.validityPeriod", "P365D")
            DefaultPrincipalMapPropertySource.addProperty("$prefix.credentialDefinition.types", types)
        }
    }

    private val ctx = Oid4vciTestContext(this, credentialConfigurationIds = listOf(CREDENTIAL_CONFIG_ID, SD_JWT_CONFIG_ID))
    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = false
        }

    private val issuerUrl = "https://issuer.example.com"
    private val verifierClientId = "https://verifier.example.com"

    @Test
    fun neutralInteractionEnginePresentsDcqlCredentialEndToEnd() =
        runTest {
            WalletE2ETestRequestObjectSigningConfig.enableDidJwkSigning()
            try {
                ctx.ensureAsSigningKey()
                val issuerPublicJwk = ensureIssuerSigningKey()
                ensureVerifierSigningKey()

                val credentialStore = (ctx.session.graph as WalletInteractionOid4vpStoreTestGraph).walletCredentialStore
                val wsca = createPromptlessWsca()
                val sdJwtRecord = issueSdJwtCredential(credentialStore, wsca)
                // The verifier must receive an explicit issuer trust root. The issuer JWT only
                // carries its key identifier; accepting the token-supplied JWK would make this
                // proof meaningless. Keep the trust decision outside the credential itself.
                WalletE2ETestTrustedAuthenticationResolver.enable(
                    listOf(
                        TrustedAuthenticationResolution(
                            controller = issuerUrl,
                            purpose = TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                            trustedJwks =
                                JsonObject(
                                    mapOf(
                                        "keys" to
                                            JsonArray(
                                                listOf(
                                                    issuerPublicJwk
                                                        .copy(kid = issuerJwtKid(sdJwtRecord.instances.single().requireRaw()))
                                                        .toJsonObject(),
                                                ),
                                            ),
                                    ),
                                ),
                        ),
                    ),
                )
                val request = createVerifierAuthorizationRequest()

                val holder = (ctx.session.graph as Oid4vpPresentationTestGraph).oid4vpHolder
                val adapter =
                    Oid4vpWalletInteractionProtocolAdapter.walletStoreBacked(
                        holder = holder,
                        credentialStore = credentialStore,
                        sdJwtHolderBindingProvider = SecureComponentOid4vpSdJwtHolderBindingProvider(wsca),
                        walletConfigProvider =
                            object : Oid4vpWalletConfigProvider {
                                override suspend fun walletConfig(
                                    context: com.sphereon.wallet.interaction.WalletInteractionContext,
                                    state: com.sphereon.wallet.interaction.WalletInteractionState,
                                ): Oid4vpWalletConfig = Oid4vpWalletConfig(audience = WALLET_CLIENT_ID)
                            },
                    )
                val securityGate = RecordingSecurityGate()
                val engine =
                    DefaultWalletInteractionEngine(
                        sensitiveInputAuthority = integrationSensitiveInputAuthority(),
                        privateSessionStore = InMemoryWalletInteractionPrivateSessionStore(),
                        sessionStore = InMemoryWalletInteractionSessionStore(),
                        launchAuthorities = setOf(integrationLaunchAuthority()),
                        adapters = listOf(adapter),
                        protocolExecutor =
                            WscdAwareExecutionPlanner(
                                // No WSCD profile is known for this holder key in-process; the
                                // delegate's default SPLIT decision (PRESENT_CREDENTIALS /
                                // USER_PRESENT) stands, matching production when the profile
                                // source has no capability-derived hint for the request.
                                profileSource = WscdExecutionProfileSource { null },
                            ),
                        securityGate = securityGate,
                        diagnostics = WalletInteractionDiagnostics.none,
                    )

                val input =
                    WalletInteractionInput(
                        walletUnitId = SESSION_WALLET_UNIT_ID,
                        entryPoint = WalletEntryPoint.rawQr(request.requestUri),
                        executionOwner = ProtocolExecutionOwner.WALLET_APP,
                        metadata =
                            mapOf(
                                Oid4vpPresentationSecurityAttributes.WALLET_UNIT_ID to WALLET_UNIT_ID,
                                Oid4vpPresentationSecurityAttributes.WALLET_ACCOUNT_ID to WALLET_ACCOUNT_ID,
                                Oid4vpPresentationSecurityAttributes.ACTIVATION_DECISION_ID to ACTIVATION_DECISION_ID,
                                Oid4vpPresentationSecurityAttributes.OPERATION_TYPE to HSM_OPERATION_TYPE,
                                Oid4vpPresentationSecurityAttributes.OPERATION_BINDING to HSM_OPERATION_BINDING,
                                Oid4vpPresentationSecurityAttributes.OPERATION_HASH to HSM_OPERATION_HASH,
                                Oid4vpPresentationSecurityAttributes.NONCE to HSM_NONCE,
                            ),
                    )
                val session = engine.start(input)

                assertEquals(ProtocolExecutionOwner.WALLET_APP, input.executionOwner)
                assertEquals(WalletProtocol.OID4VP, session.state.protocol)
                // A first interaction with this verifier surfaces the trust review step before
                // credential selection.
                assertEquals(WalletInteractionStatus.TrustReview, session.state.status)
                engine.dispatch(session.sessionId, WalletInteractionAction.continueFlow())
                val selectionState = engine.observe(session.sessionId).value
                assertEquals(WalletInteractionStatus.CredentialSelection, selectionState.status)
                val requirement =
                    assertNotNull(
                        selectionState.credentialSelection
                            ?.requirements
                            ?.singleOrNull()
                    )
                assertEquals(SD_JWT_CONFIG_ID, requirement.id)
                assertEquals(listOf(sdJwtRecord.id), requirement.candidateCredentialIds)

                engine.dispatch(
                    session.sessionId,
                    WalletInteractionAction.selectCredentials(
                        WalletCredentialSelection(
                            selectedCredentialIdsByRequirement = mapOf(requirement.id to listOf(sdJwtRecord.id)),
                        ),
                    ),
                )
                val completedState = engine.observe(session.sessionId).value
                assertEquals(WalletInteractionStatus.Completed, completedState.status, "Final interaction state: $completedState")
                assertTrue(completedState.terminal, "Wallet interaction session should be terminal after successful direct_post submission")
                assertEquals(WalletSecurityOperation.PRESENT_CREDENTIALS, securityGate.lastRequest?.operation)
                assertEquals(WalletSecurityAssurance.USER_PRESENT, securityGate.lastRequest?.requiredAssurance)
                assertEquals(HOLDER_SIGNING_KEY_ALIAS, securityGate.lastRequest?.keyRef)
                assertEquals(WALLET_UNIT_ID, securityGate.lastRequest?.walletUnitId)
                assertEquals(WALLET_ACCOUNT_ID, securityGate.lastRequest?.walletAccountId)
                assertEquals(ACTIVATION_DECISION_ID, securityGate.lastRequest?.activationDecisionId)
                assertEquals(HSM_OPERATION_TYPE, securityGate.lastRequest?.operationType)
                assertEquals(HSM_OPERATION_HASH, securityGate.lastRequest?.operationHash)
                assertEquals(HSM_NONCE, securityGate.lastRequest?.nonce)

                val postPresentMetaResult = credentialStore.findByCredentialTypeRef(SESSION_WALLET_UNIT_ID, sdJwtRecord.credentialTypeRefs.first())
                assertTrue(
                    postPresentMetaResult.isOk,
                    "findByCredentialTypeRef after interaction should succeed: ${if (postPresentMetaResult.isErr) postPresentMetaResult.error.message.defaultMessage else ""}",
                )
                val sdJwtMeta = postPresentMetaResult.value.single()
                assertEquals(1, sdJwtMeta.boundInstanceCount, "neutral OID4VP adapter should record one presentation binding")
                assertEquals(CredentialLifecycleState.ACTIVE, sdJwtMeta.lifecycleSummary.lifecycleState)

                assertVerifierVerified(request.correlationId)
            } finally {
                WalletE2ETestTrustedAuthenticationResolver.disable()
                WalletE2ETestRequestObjectSigningConfig.disable()
            }
        }

    private suspend fun issueSdJwtCredential(
        credentialStore: WalletCredentialStore,
        wsca: Wsca,
    ): CredentialRecord {
        val issuer = (ctx.session.graph as Oid4vciIssuanceTestGraph).oid4vciIssuerService
        val holder = (ctx.session.graph as Oid4vciIssuanceTestGraph).oid4vciHolder
        val storeGraph = ctx.session.graph as WalletInteractionOid4vpStoreTestGraph
        val issuanceSessionStore = storeGraph.walletIssuanceSessionStore
        val acceptance =
            Oid4vciIssuedCredentialAcceptance(
                verifySdJwtVcCommand = storeGraph.verifySdJwtVcCommand,
                subjectExtractor = storeGraph.credentialSubjectExtractor,
                identityResolver = storeGraph.walletIdentityResolver,
            )
        val offerResult =
            issuer.createCredentialOffer(
                CreateCredentialOfferArgs(
                    instanceId = OID4VCI_TEST_ISSUER_INSTANCE_ID,
                    issuerId = issuerUrl,
                    credentialConfigurationIds = listOf(SD_JWT_CONFIG_ID),
                    preAuthorizedCodeGrant = true,
                    authorizationPolicySnapshot = OID4VCI_TEST_AUTHORIZATION_POLICY_SNAPSHOT,
                    // Test data for the issued credential. The RP independently requests
                    // this claim through DCQL; nothing here is derived from the RP query.
                    preSeededAttributes = mapOf("degree" to JsonPrimitive("Bachelor of Science")),
                ),
            )
        assertTrue(offerResult.isOk, "Offer creation should succeed")

        val adapter =
            Oid4vciWalletInteractionProtocolAdapter(
                holder = holder,
                issuanceExecutor =
                    Oid4vciHolderIssuanceExecutor(
                        holder = holder,
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
                                        operationBinding = "test:oid4vp-dcql-credential-request-proof",
                                        signingAlgorithm = "ES256",
                                        clientId = WALLET_CLIENT_ID,
                                        credentialConfigurationId = SD_JWT_CONFIG_ID,
                                    )
                            },
                        credentialReceiver = WalletStoreOid4vciCredentialResponseReceiver(credentialStore, issuanceSessionStore, acceptance),
                        nestedPresentationExecutor = com.sphereon.wallet.interaction.WalletNestedPresentationExecutor.notConfigured,
                        credentialStore = credentialStore,
                        issuanceSessionStore = issuanceSessionStore,
                        refreshTokenGrantProvider = HolderServiceOid4vciRefreshTokenGrantProvider(holder),
                        keyAttestationProvider = SecureComponentOid4vciKeyAttestationProvider(wsca),
                        credentialRequestProofProvider = HolderServiceOid4vciCredentialRequestProofProvider(holder),
                    ),
            )
        val engine =
            DefaultWalletInteractionEngine(
                sensitiveInputAuthority = integrationSensitiveInputAuthority(),
                privateSessionStore = InMemoryWalletInteractionPrivateSessionStore(),
                sessionStore = InMemoryWalletInteractionSessionStore(),
                launchAuthorities = setOf(integrationLaunchAuthority()),
                // Promptless protocol test: the attended security ceremony is exercised by the
                // wallet-product/runner suites, not here.
                securityGate = WalletSecurityGate.allow,
                adapters = listOf(adapter),
                diagnostics = WalletInteractionDiagnostics.none,
            )

        val session =
            engine.start(
                WalletInteractionInput(
                    walletUnitId = SESSION_WALLET_UNIT_ID,
                    entryPoint = WalletEntryPoint.rawQr(offerResult.value.offerUri),
                ),
            )
        assertEquals(WalletProtocol.OID4VCI, session.state.protocol)
        // A first interaction with this issuer surfaces the trust review step before the offer.
        assertEquals(WalletInteractionStatus.TrustReview, session.state.status)
        engine.dispatch(session.sessionId, WalletInteractionAction.continueFlow())
        assertEquals(WalletInteractionStatus.CredentialOfferReview, engine.observe(session.sessionId).value.status)

        engine.dispatch(
            session.sessionId,
            WalletInteractionAction.selectCredentials(
                WalletCredentialSelection(
                    selectedCredentialIdsByRequirement =
                        mapOf(
                            "oid4vci-offer" to
                                engine
                                    .observe(session.sessionId)
                                    .value.credentialOffer!!
                                    .credentialConfigurationIds
                        ),
                ),
            ),
        )
        val completedState = engine.observe(session.sessionId).value
        assertEquals(WalletInteractionStatus.Completed, completedState.status, "Credential issuance state: $completedState")
        assertTrue(completedState.terminal, "Credential issuance session should be terminal")

        val metadataResult = credentialStore.listMetadata(SESSION_WALLET_UNIT_ID)
        assertTrue(
            metadataResult.isOk,
            "Issued credential metadata should be readable: ${if (metadataResult.isErr) metadataResult.error.message.defaultMessage else ""}",
        )
        val metadata =
            metadataResult.value.singleOrNull { it.credentialConfigurationId == SD_JWT_CONFIG_ID }
                ?: error("Expected one stored credential for '$SD_JWT_CONFIG_ID', found ${metadataResult.value.map { it.credentialConfigurationId }}")
        val recordResult = credentialStore.getCredential(SESSION_WALLET_UNIT_ID, metadata.credentialRecordId)
        assertTrue(
            recordResult.isOk,
            "Issued credential should be readable: ${if (recordResult.isErr) recordResult.error.message.defaultMessage else ""}",
        )
        val record = assertNotNull(recordResult.value)
        assertEquals(
            setOf(SD_JWT_VCT),
            record.credentialTypeRefs.map { it.value }.toSet(),
            "The RP DCQL query must use the VCT indexed by the wallet credential store",
        )
        return record
    }

    private fun createPromptlessWsca(): Wsca =
        LocalWsca(
            wscd = (ctx.session.graph as WalletInteractionOid4vpWscdTestGraph).wscd,
            dpopProofAssembly = DpopProofAssembly(defaultSecureRandom()),
            userAuthenticator =
                WalletUserAuthenticator { request ->
                    Ok(
                        ActivationProof(
                            kind = ActivationProofKind.LOCAL_USER_AUTH,
                            token = "oid4vp-integration-local-user-auth",
                            digestBinding = request.digestBinding,
                            nonce = request.nonce,
                            evidence = mapOf("factor" to "pin"),
                        ),
                    )
                },
            walletProviderAttestationSignerResolver = LocalWalletProviderAttestationSignerResolver(),
            secureRandom = defaultSecureRandom(),
        )

    private suspend fun createVerifierAuthorizationRequest(): VerifierRequest {
        val dcqlQuery =
            DcqlQuery(
                credentials =
                    listOf(
                        DcqlCredentialQuery(
                            id = SD_JWT_CONFIG_ID,
                            format = "dc+sd-jwt",
                            meta = sdJwtVcMeta(SD_JWT_VCT),
                            claims = listOf(DcqlClaimQuery(path = claimsPathPointer("degree"))),
                        ),
                    ),
            )
        val input =
            CreateAuthorizationRequestInput(
                dcqlQuery = dcqlQuery,
                clientId = verifierClientId,
                state = "wallet-interaction-e2e-state",
                responseUri = "$verifierClientId/oid4vp/auth/response",
                qrCodeOptions = QrCodeOptions(),
            )
        val response =
            ctx.dispatchInProcessHttp(
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path = "/oid4vp/backend/auth/requests",
                    headers = mapOf("Content-Type" to "application/json"),
                    body = json.encodeToString(CreateAuthorizationRequestInput.serializer(), input),
                ),
            )
        assertEquals(201, response.statusCode, "Verifier authorization request creation should return 201. Body: ${response.body}")
        val output = json.decodeFromString(CreateAuthorizationRequestOutput.serializer(), assertNotNull(response.body))
        return VerifierRequest(
            correlationId = assertNotNull(output.correlationId),
            requestUri = assertNotNull(output.requestUri),
        )
    }

    private suspend fun assertVerifierVerified(correlationId: String) {
        val response =
            ctx.dispatchInProcessHttp(
                GenericHttpRequest(
                    method = "GET",
                    path = "/oid4vp/backend/auth/requests/$correlationId",
                ),
            )
        assertEquals(200, response.statusCode, "Status check should return 200. Body: ${response.body}")
        val statusOutput = json.decodeFromString(GetAuthorizationRequestStatusOutput.serializer(), assertNotNull(response.body))
        assertEquals(correlationId, statusOutput.correlationId)
        assertEquals(
            AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED,
            statusOutput.status,
            "Verifier session should reach AUTHORIZATION_RESPONSE_VERIFIED after neutral wallet interaction presentation",
        )
    }

    private suspend fun ensureIssuerSigningKey(): Jwk {
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
        val signingConfig =
            (ctx.session.graph as WalletInteractionOid4vpIssuerConfigTestGraph)
                .oid4vciIssuerConfigProvider
                .credentialSigningConfigs()[SD_JWT_CONFIG_ID]
        assertEquals(
            ISSUER_SIGNING_KEY_ALIAS,
            signingConfig?.signingKeyAlias,
            "The SD-JWT fixture must resolve its issuer signing key through the test authority",
        )
        val publicKey =
            result.value.keyPair
                ?.joseToManagedKeyInfo(KeyVisibility.PUBLIC)
                ?.key
        return assertIs<Jwk>(publicKey)
    }

    private fun issuerJwtKid(jwt: String): String {
        val header = json.parseToJsonElement(jwt.substringBefore('.').decodeFromBase64Url().decodeToString()).jsonObject
        return assertNotNull(header["kid"]?.jsonPrimitive?.content)
    }

    private suspend fun ensureVerifierSigningKey() {
        val kms =
            ctx.session.graph
                .asKeyManagerServiceGraph()
                .keyManagerService
        val result =
            kms.generateKeyResult(
                alias = VERIFIER_SIGNING_KEY_ALIAS,
                use = JwkUse.sig,
                alg = SignatureAlgorithm.ECDSA_SHA256,
            )
        assertTrue(
            result.isOk,
            "Verifier JAR signing key generation should succeed: ${if (result.isErr) result.error.message.defaultMessage else ""}",
        )
    }

    private class RecordingSecurityGate : WalletSecurityGate {
        var lastRequest: WalletSecurityGateRequest? = null

        override suspend fun authorize(request: WalletSecurityGateRequest): WalletSecurityGateResult {
            lastRequest = request
            return WalletSecurityGateResult.Authorized(
                WalletSecurityGrant(
                    grantId = request.operationId,
                    assurance = request.requiredAssurance,
                    evidence =
                        mapOf(
                            "operation" to request.operation.name,
                            "keyRef" to request.keyRef.orEmpty(),
                            "walletUnitId" to request.walletUnitId.orEmpty(),
                            "operationHash" to request.operationHash.orEmpty(),
                            // The real protocol adapter keeps this one-use authorization
                            // binding in private session state and passes it to the existing
                            // IDK holder-binding signer.
                            "operation_binding" to HSM_OPERATION_BINDING,
                        ),
                ),
            )
        }
    }

    private data class VerifierRequest(
        val correlationId: String,
        val requestUri: String,
    )
}
