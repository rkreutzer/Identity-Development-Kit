/*
 * (c) 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.openid.oid4vci.integration

import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.dataintegrity.model.ProofPurpose
import com.sphereon.crypto.dataintegrity.resolution.TrustedVerificationMethod
import com.sphereon.crypto.dataintegrity.resolution.VerificationMethodResolutionPolicy
import com.sphereon.crypto.resolution.extern.ExternalIdentifierDidOpts
import com.sphereon.di.session.SessionScope
import com.sphereon.did.methods.jwk.JwkDidProviderImpl
import com.sphereon.jsonld.loader.LinkedDataDocumentLoader
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.oauth2.common.model.AuthorizationResponse
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vc.common.vcdm.VcdmProfiles
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialDefinition
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.issuer.format.CredentialFormatHandler
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.openid.oid4vp.common.ClientMetadata
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.common.VpFormatInfo
import com.sphereon.openid.oid4vp.common.VpToken
import com.sphereon.openid.oid4vp.common.vpToken
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.w3cVcMeta
import com.sphereon.openid.oid4vp.holder.CreateAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.SelectedCredential
import com.sphereon.openid.oid4vp.holder.VerifierInfo
import com.sphereon.openid.oid4vp.verifier.CreateAuthorizationRequestArgs
import com.sphereon.openid.oid4vp.verifier.ParseAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.verifier.ValidateAuthorizationResponseArgs
import com.sphereon.wallet.interaction.protocol.oid4vp.Oid4vpDataIntegrityHolderBindingRequest
import com.sphereon.wallet.interaction.protocol.oid4vp.SecureComponentOid4vpDataIntegrityHolderBindingProvider
import com.sphereon.wallet.unit.SecureComponentUsage
import dev.zacsweers.metro.ContributesTo
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

@ContributesTo(SessionScope::class)
interface VcdmDataIntegrityIssuerTestGraph {
    val credentialFormatHandlers: Set<CredentialFormatHandler>
    val ldpVcFormatHandler: CredentialFormatHandler
        get() = credentialFormatHandlers.single { it.supportedFormat == CredentialFormat.LDP_VC.value }
    val linkedDataDocumentLoader: LinkedDataDocumentLoader
}

/**
 * Real VCDM 2.0 Data Integrity issue -> holder VP -> verifier validation flow.
 *
 * The issuer uses the production ldp_vc format handler and `eddsa-jcs-2022`. The holder first
 * provisions and then signs through WSCA; no wallet caller obtains a KeyManagerService. The
 * verifier is given an exact DID/JWK trust policy for both proof relationships, so it exercises
 * the identifier-neutral resolver rather than trusting a key embedded in the presentation.
 */
class VcdmDataIntegrityIssuePresentVerifyE2ETest {
    private val ctx = Oid4vciTestContext(this)
    private val json = Json { ignoreUnknownKeys = true }
    private val verifier = "https://vcdm-di-verifier.example"
    private val issuerAlias = "vcdm-di-issuer-key"
    private val holderKeyAlias = "vcdm-di-holder-key"
    private val walletUnitId = "vcdm-di-wallet-unit"

    @Test
    fun vcdm20DataIntegrityIssuePresentAndVerifySecuresEachSelectedCredential() =
        runTest {
            val issuer = generateIssuer()
            val holder = provisionHolder()
            val query = query()
            val request = createRequest(query, nonce = "vcdm-di-valid-nonce", state = "vcdm-di-valid-state")
            val resolved = resolvedRequest(request.request, query)
            val credentials =
                listOf(
                    issue(issuer, holder.did, "Alice"),
                    issue(issuer, holder.did, "Engineering"),
                )

            val response = createResponse(resolved, credentials, holder)
            val token = assertNotNull(response.value.vpToken)
            assertEquals(2, token.presentationCount, "the aggregate VP is mapped to both selected credential queries")
            assertEquals(1, token.allPresentations.distinct().size, "compatible ldp_vc credentials share one aggregate VP artifact")
            assertVp(token, issuer, holder, request.request.nonce!!)
            assertEquals(
                token.getSinglePresentationElement(QUERY_A),
                token.getSinglePresentationElement(QUERY_B),
                "both query mappings must reference the same aggregate VP",
            )

            val validation = validate(request.request, query, response.value, request.request.nonce!!, issuer, holder)
            assertTrue(validation.isOk, "verifier should return a structured validation result")
            assertTrue(validation.value.valid, "issuer and holder Data Integrity proofs must verify: ${validation.value.errors}")
        }

    @Test
    fun tamperedCredentialFailsAfterHolderDataIntegrityPresentationIsSigned() =
        runTest {
            val issuer = generateIssuer()
            val holder = provisionHolder()
            val query = query()
            val request = createRequest(query, nonce = "vcdm-di-tamper-nonce", state = "vcdm-di-tamper-state")
            val response = createResponse(resolvedRequest(request.request, query), listOf(issue(issuer, holder.did, "Alice"), issue(issuer, holder.did, "Engineering")), holder)
            val tamperedToken = tamperFirstCredential(assertNotNull(response.value.vpToken))
            val tampered =
                response.value.copy(
                    additionalParameters = response.value.additionalParameters + ("vp_token" to VpToken.run { tamperedToken.toJson() }),
                )

            val validation = validate(request.request, query, tampered, request.request.nonce!!, issuer, holder)
            assertTrue(validation.isOk, "tampering should produce a structured invalid result")
            assertFalse(validation.value.valid, "a tampered VC must fail issuer or holder Data Integrity verification")
        }

    @Test
    fun wrongNonceOrDomainFailsHolderDataIntegrityBinding() =
        runTest {
            val issuer = generateIssuer()
            val holder = provisionHolder()
            val query = query()
            var request = createRequest(query, nonce = "vcdm-di-binding-nonce", state = "vcdm-di-binding-state")
            var resolved = resolvedRequest(request.request, query)
            val credentials = listOf(issue(issuer, holder.did, "Alice"), issue(issuer, holder.did, "Engineering"))

            val wrongNonceRequest = resolved.copy(request = resolved.request.copy(nonce = "wrong-vcdm-di-nonce"))
            val wrongNonceResponse = createResponse(wrongNonceRequest, credentials, holder)
            val wrongNonce = validate(request.request, query, wrongNonceResponse.value, request.request.nonce!!, issuer, holder)
            assertTrue(wrongNonce.isOk)
            assertFalse(wrongNonce.value.valid, "a holder proof with the wrong challenge must fail")

            request = createRequest(query, nonce = "vcdm-di-binding-nonce", state = "vcdm-di-binding-wrong-domain-state")
            resolved = resolvedRequest(request.request, query)
            val wrongDomainRequest = resolved.copy(verifierInfo = resolved.verifierInfo.copy(clientId = "https://wrong-vcdm-di-verifier.example"))
            val wrongDomainResponse = createResponse(wrongDomainRequest, credentials, holder)
            val wrongDomain = validate(request.request, query, wrongDomainResponse.value, request.request.nonce!!, issuer, holder)
            assertTrue(wrongDomain.isOk)
            assertFalse(wrongDomain.value.valid, "a holder proof with the wrong domain must fail")
        }

    private suspend fun generateIssuer(): IssuerMaterial {
        // This is issuer-side setup. Holder key provisioning/signing below is deliberately WSCA-only.
        val kms =
            ctx.session.graph
                .asKeyManagerServiceGraph()
                .keyManagerService
        val generated = kms.generateKeyResult(alias = issuerAlias, use = JwkUse.sig, alg = SignatureAlgorithm.ED25519)
        assertTrue(generated.isOk, "issuer Ed25519 key generation must succeed")
        val publicJwk =
            assertNotNull(
                generated.value.keyPair
                    ?.jose
                    ?.publicJwk
            )
        val did = JwkDidProviderImpl.didFromJwk(publicJwk)
        return IssuerMaterial(did, "$did#0")
    }

    private suspend fun provisionHolder(): HolderMaterial {
        val wsca = (ctx.session.graph as WalletInteractionOid4vciWscaTestGraph).wsca
        val key =
            wsca.ensureKey(
                walletUnitId = walletUnitId,
                usage = SecureComponentUsage.WALLET_CREDENTIAL_PROOF,
                algorithm = SignatureAlgorithm.ED25519,
                keyAlias = holderKeyAlias,
            )
        assertTrue(key.isOk, "holder key must be provisioned through WSCA")
        val publicJwk = Json.decodeFromString<Jwk>(assertNotNull(key.value.publicKeyJwk))
        val did = JwkDidProviderImpl.didFromJwk(publicJwk)
        return HolderMaterial(did, "$did#0", holderKeyAlias)
    }

    private suspend fun issue(
        issuer: IssuerMaterial,
        holderDid: String,
        name: String
    ): JsonObject {
        val configuration =
            CredentialConfigurationSupported(
                format = CredentialFormat.LDP_VC.value,
                credentialDefinition =
                    CredentialDefinition(
                        context = listOf(VcdmProfiles.V2_0_CONTEXT),
                        type = listOf("VerifiableCredential", "DataIntegrityVcdm2Credential"),
                    ),
            )
        val result =
            (ctx.session.graph as VcdmDataIntegrityIssuerTestGraph).ldpVcFormatHandler.issueCredential(
                CredentialRequest(format = CredentialFormat.LDP_VC.value),
                IssuanceContext(
                    subject = holderDid,
                    clientId = "https://vcdm-di-client.example",
                    issuerIdentifier = issuer.did,
                    credentialConfigurationId = "vcdm-di-v2",
                    credentialConfiguration = configuration,
                    holderBindingKey = null,
                    attributes = emptyMap(),
                    credentialSubjects =
                        listOf(
                            JsonObject(mapOf("id" to JsonPrimitive(holderDid), "name" to JsonPrimitive(name))),
                        ),
                    signingKeyAlias = issuerAlias,
                    signingKeyMode = SigningKeyMode.JwkThumbprint,
                    signingVerificationMethodId = issuer.verificationMethod,
                    dataIntegrityCryptosuite = "eddsa-jcs-2022",
                    issuanceClockSkewInSeconds = 0,
                    expirationInDays = 30,
                ),
            )
        assertTrue(result.isOk, "production ldp_vc issuer must issue VCDM 2.0 DI credentials: ${if (result.isErr) result.error else ""}")
        val credential = result.value.credential.jsonObject
        assertEquals(JsonPrimitive(holderDid), credential.getValue("credentialSubject").jsonObject["id"])
        return credential
    }

    private suspend fun createRequest(
        query: DcqlQuery,
        nonce: String,
        state: String
    ) = (ctx.session.graph as Oid4vpPresentationTestGraph)
        .oid4vpVerifierService
        .createAuthorizationRequest(
            CreateAuthorizationRequestArgs(
                instanceId = "vcdm-di-verifier",
                dcqlQuery = query,
                clientId = verifier,
                responseUri = "$verifier/response",
                responseMode = ResponseMode.DIRECT_POST,
                nonce = nonce,
                state = state,
                clientMetadata = dataIntegrityClientMetadata(),
            ),
        ).also { assertTrue(it.isOk, "production verifier request command must succeed") }
        .value

    private fun resolvedRequest(
        request: AuthorizationRequest,
        query: DcqlQuery
    ) = ResolvedOid4vpRequest(
        request = request,
        dcqlQuery = query,
        clientMetadata = dataIntegrityClientMetadata(),
        verifierInfo = VerifierInfo(clientId = verifier, clientIdScheme = com.sphereon.openid.oid4vp.common.ClientIdScheme.REDIRECT_URI),
    )

    private fun dataIntegrityClientMetadata() =
        ClientMetadata(
            vpFormatsSupported =
                mapOf(
                    CredentialFormat.LDP_VC.value to
                        VpFormatInfo(
                            proofTypeValues = listOf("DataIntegrityProof"),
                            cryptosuiteValues = listOf("eddsa-jcs-2022"),
                        ),
                ),
        )

    private suspend fun createResponse(
        request: ResolvedOid4vpRequest,
        credentials: List<JsonObject>,
        holder: HolderMaterial
    ) = (ctx.session.graph as Oid4vpPresentationTestGraph).let { graph ->
        val selected =
            credentials.mapIndexed { index, credential ->
                SelectedCredential(
                    credentialQueryId = if (index == 0) QUERY_A else QUERY_B,
                    credentialId = "vcdm-di-credential-$index",
                    presentation = credential,
                    credentialFormat = CredentialFormat.LDP_VC,
                    holderKeyRef = holder.keyAlias,
                    holderId = holder.did,
                    holderVerificationMethod = holder.verificationMethod,
                    holderSigningAlgorithm = SignatureAlgorithm.ED25519,
                    dataIntegrityCryptosuite = "eddsa-jcs-2022",
                )
            }
        val bound =
            SecureComponentOid4vpDataIntegrityHolderBindingProvider(
                (ctx.session.graph as WalletInteractionOid4vciWscaTestGraph).wsca,
                (ctx.session.graph as VcdmDataIntegrityIssuerTestGraph).linkedDataDocumentLoader,
                com.sphereon.wallet.interaction.protocol.oid4vp.Oid4vpDataIntegritySigningAlgorithmResolver.selectedCredentialMetadata,
            ).applyHolderBinding(
                Oid4vpDataIntegrityHolderBindingRequest(
                    walletUnitId = walletUnitId,
                    operationBinding = "vcdm-di-attended-operation",
                    request = request,
                    selectedCredentials = selected,
                ),
            )
        assertTrue(bound.isOk, "holder must bind each VP through WSCA: ${if (bound.isErr) bound.error else ""}")
        graph.oid4vpHolder.commands.createAuthorizationResponse
            .execute(
                CreateAuthorizationResponseArgs(
                    request = request,
                    selectedCredentials = bound.value.selectedCredentials,
                    preparedPresentations = bound.value.preparedPresentations,
                ),
            ).also { assertTrue(it.isOk, "production holder response command must serialize secured VPs") }
    }

    private suspend fun validate(
        request: AuthorizationRequest,
        query: DcqlQuery,
        response: AuthorizationResponse,
        expectedNonce: String,
        issuer: IssuerMaterial,
        holder: HolderMaterial,
    ) = (ctx.session.graph as Oid4vpPresentationTestGraph).oid4vpVerifierService.let { service ->
        val vpToken = assertNotNull(response.vpToken)
        val parsed =
            service.parseAuthorizationResponse(
                ParseAuthorizationResponseArgs(
                    responseParams =
                        mapOf(
                            "vp_token" to
                                json.encodeToString(
                                    kotlinx.serialization.json.JsonElement
                                        .serializer(),
                                    VpToken.run { vpToken.toJson() }
                                ),
                            "state" to assertNotNull(response.state),
                        ),
                    originalRequest = request,
                ),
            )
        assertTrue(parsed.isOk, "production response parser must accept the holder command output")
        service.validateAuthorizationResponse(
            ValidateAuthorizationResponseArgs(
                parsedResponse = parsed.value,
                originalRequest = request,
                dcqlQuery = query,
                expectedNonce = expectedNonce,
                verificationMethodResolutionPolicy =
                    VerificationMethodResolutionPolicy.of(
                        listOf(
                            TrustedVerificationMethod(
                                reference = issuer.verificationMethod,
                                identifierOpts = ExternalIdentifierDidOpts(issuer.did),
                                controller = issuer.did,
                                authorizedProofPurposes = setOf(ProofPurpose.ASSERTION_METHOD),
                            ),
                            TrustedVerificationMethod(
                                reference = holder.verificationMethod,
                                identifierOpts = ExternalIdentifierDidOpts(holder.did),
                                controller = holder.did,
                                authorizedProofPurposes = setOf(ProofPurpose.AUTHENTICATION),
                            ),
                        ),
                    ),
            ),
        )
    }

    private fun query() =
        DcqlQuery(
            credentials =
                listOf(
                    DcqlCredentialQuery(
                        id = QUERY_A,
                        format = CredentialFormat.LDP_VC.value,
                        meta = w3cVcMeta(listOf("VerifiableCredential", "DataIntegrityVcdm2Credential")),
                    ),
                    DcqlCredentialQuery(
                        id = QUERY_B,
                        format = CredentialFormat.LDP_VC.value,
                        meta = w3cVcMeta(listOf("VerifiableCredential", "DataIntegrityVcdm2Credential")),
                    ),
                ),
        )

    private fun assertVp(
        token: VpToken,
        issuer: IssuerMaterial,
        holder: HolderMaterial,
        nonce: String
    ) {
        val vp = assertIs<JsonObject>(token.getSinglePresentationElement(QUERY_A))
        assertEquals(holder.did, vp["holder"]?.toString()?.trim('"'))
        val vcs = assertIs<JsonArray>(vp["verifiableCredential"])
        assertEquals(2, vcs.size, "the compatible selected credentials must be enclosed in one aggregate VP")
        vcs.forEach { credential ->
            val issuerProof = assertIs<JsonObject>(assertIs<JsonObject>(credential)["proof"])
            assertEquals("DataIntegrityProof", issuerProof["type"]?.toString()?.trim('"'))
            assertEquals("eddsa-jcs-2022", issuerProof["cryptosuite"]?.toString()?.trim('"'))
            assertEquals(ProofPurpose.ASSERTION_METHOD.value, issuerProof["proofPurpose"]?.toString()?.trim('"'))
            assertEquals(issuer.verificationMethod, issuerProof["verificationMethod"]?.toString()?.trim('"'))
        }
        val proofs = assertIs<JsonArray>(vp["proof"])
        assertEquals(1, proofs.size, "same resolved holder binding key is represented by one aggregate proof")
        val proof = assertIs<JsonObject>(proofs.single())
        assertEquals("DataIntegrityProof", proof["type"]?.toString()?.trim('"'))
        assertEquals("eddsa-jcs-2022", proof["cryptosuite"]?.toString()?.trim('"'))
        assertEquals(ProofPurpose.AUTHENTICATION.value, proof["proofPurpose"]?.toString()?.trim('"'))
        assertEquals(holder.verificationMethod, proof["verificationMethod"]?.toString()?.trim('"'))
        assertEquals(verifier, proof["domain"]?.toString()?.trim('"'))
        assertEquals(nonce, proof["challenge"]?.toString()?.trim('"'))
    }

    private fun tamperFirstCredential(token: VpToken): VpToken {
        val vp = assertIs<JsonObject>(token.getSinglePresentationElement(QUERY_A))
        val vcs = assertIs<JsonArray>(vp["verifiableCredential"])
        val vc = assertIs<JsonObject>(vcs.first())
        val subject = assertIs<JsonObject>(vc["credentialSubject"])
        val tamperedSubject = JsonObject(subject + ("name" to JsonPrimitive("Mallory")))
        val tamperedVc = JsonObject(vc + ("credentialSubject" to tamperedSubject))
        val tamperedVp = JsonObject(vp + ("verifiableCredential" to JsonArray(listOf(tamperedVc) + vcs.drop(1))))
        return VpToken(token.presentationElements + (QUERY_A to listOf(tamperedVp)) + (QUERY_B to listOf(tamperedVp)))
    }

    private data class IssuerMaterial(
        val did: String,
        val verificationMethod: String
    )

    private data class HolderMaterial(
        val did: String,
        val verificationMethod: String,
        val keyAlias: String
    )

    private companion object {
        const val QUERY_A = "vcdm-di-a"
        const val QUERY_B = "vcdm-di-b"
    }
}
