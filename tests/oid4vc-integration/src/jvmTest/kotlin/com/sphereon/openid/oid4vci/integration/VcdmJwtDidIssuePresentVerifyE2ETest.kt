/*
 * (c) 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.sphereon.openid.oid4vci.integration

import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.resolution.extern.ExternalIdentifierDidOpts
import com.sphereon.did.capabilities.DidMethodCapabilities
import com.sphereon.did.methods.jwk.JwkDidProviderImpl
import com.sphereon.did.models.DidDocument
import com.sphereon.did.models.VerificationMethod
import com.sphereon.did.models.VerificationMethodOrReference
import com.sphereon.did.models.VerificationMethodType
import com.sphereon.did.resolver.DidDereferenceOptions
import com.sphereon.did.resolver.DidDereferenceResult
import com.sphereon.did.resolver.DidDocumentMetadata
import com.sphereon.did.resolver.DidResolutionMetadata
import com.sphereon.did.resolver.DidResolutionOptions
import com.sphereon.did.resolver.DidResolutionResult
import com.sphereon.did.resolver.DidResolver
import com.sphereon.did.resolver.DidResolverRegistry
import com.sphereon.did.resolver.impl.DidExternalIdentifierResolutionService
import com.sphereon.oauth2.common.model.AuthorizationResponse
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialDefinition
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.issuer.format.CredentialFormatHandler
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.common.ClientMetadata
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.common.VpToken
import com.sphereon.openid.oid4vp.common.jwtVcFormatInfo
import com.sphereon.openid.oid4vp.common.vpToken
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.w3cVcMeta
import com.sphereon.openid.oid4vp.holder.CreateAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.holder.HolderJwtVpSigningIdentifier
import com.sphereon.openid.oid4vp.holder.Oid4vpHolder
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.SelectedCredential
import com.sphereon.openid.oid4vp.holder.VerifierInfo
import com.sphereon.openid.oid4vp.verifier.CreateAuthorizationRequestArgs
import com.sphereon.openid.oid4vp.verifier.Oid4vpVerifierService
import com.sphereon.openid.oid4vp.verifier.ParseAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import com.sphereon.openid.oid4vp.verifier.ValidateAuthorizationResponseArgs
import com.sphereon.wallet.unit.SecureComponentUsage
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Production format handler, DID resolver, holder, and verifier services used by this E2E. */
@ContributesTo(com.sphereon.di.session.SessionScope::class)
interface VcdmJwtDidTestGraph {
    val credentialFormatHandlers: Set<CredentialFormatHandler>
    val jwtVcJsonFormatHandler: CredentialFormatHandler
        get() = credentialFormatHandlers.single { it.supportedFormat == CredentialFormat.JWT_VC_JSON.value }
    val vcLdJsonJwtFormatHandler: CredentialFormatHandler
        get() = credentialFormatHandlers.single { it.supportedFormat == CredentialFormat.JWT_VC_JSON_LD.value }
    val oid4vpHolder: Oid4vpHolder
    val oid4vpVerifierService: Oid4vpVerifierService
    val issuerKeyIdResolver: IssuerKeyIdResolver
    val didResolverRegistry: DidResolverRegistry
    val didExternalIdentifierResolutionService: DidExternalIdentifierResolutionService
    val deactivatedDidResolver: DeactivatedDidResolverRegistration
}

/**
 * A registry-backed DID method fixture for the mutable-document lifecycle boundary. The
 * presented key is the same JWK registered here, while resolution marks the document
 * deactivated. This keeps the negative vector on the production DID resolver and OID4VP
 * verifier paths instead of substituting a different key or bypassing resolution.
 */
interface DeactivatedDidResolverRegistration {
    fun register(
        did: String,
        publicJwk: Jwk
    )
}

@Inject
@SingleIn(com.sphereon.di.session.SessionScope::class)
@ContributesBinding(
    com.sphereon.di.session.SessionScope::class,
    binding = binding<DeactivatedDidResolverRegistration>(),
)
@ContributesIntoSet(
    com.sphereon.di.session.SessionScope::class,
    binding = binding<DidResolver>(),
)
class DeactivatedDidResolver :
    DidResolver,
    DeactivatedDidResolverRegistration {
    private val keys = mutableMapOf<String, Jwk>()

    override val supportedMethods: List<String> = listOf(METHOD)
    override val capabilities: DidMethodCapabilities = DidMethodCapabilities.WEB.copy(method = METHOD)

    override fun register(
        did: String,
        publicJwk: Jwk
    ) {
        check(did.startsWith("did:$METHOD:")) { "unexpected deactivated DID: $did" }
        keys[did] = publicJwk
    }

    override suspend fun resolve(
        did: String,
        options: DidResolutionOptions,
    ): com.sphereon.core.api.IdkResult<DidResolutionResult, com.sphereon.core.api.error.IdkError> {
        val jwk =
            keys[did]
                ?: return com.sphereon.core.api.Err(
                    com.sphereon.core.api.error.IdkError
                        .NOT_FOUND_ERROR(message = "No fixture key registered for $did"),
                )
        val vmId = "$did#0"
        val vm =
            VerificationMethod(
                id = vmId,
                type = VerificationMethodType.JSON_WEB_KEY_2020.value,
                controller = did,
                publicKeyJwk = jwk,
            )
        val document =
            DidDocument(
                id = did,
                verificationMethod = listOf(vm),
                authentication = listOf(VerificationMethodOrReference.fromReference(vmId)),
                assertionMethod = listOf(VerificationMethodOrReference.fromReference(vmId)),
                capabilityInvocation = listOf(VerificationMethodOrReference.fromReference(vmId)),
                capabilityDelegation = listOf(VerificationMethodOrReference.fromReference(vmId)),
            )
        return com.sphereon.core.api.Ok(
            DidResolutionResult(
                didDocument = document,
                didResolutionMetadata = DidResolutionMetadata.success(),
                didDocumentMetadata = DidDocumentMetadata(deactivated = true),
                verificationMethodsByPurpose = document.getVerificationMethodsByPurpose(),
            ),
        )
    }

    override suspend fun dereference(
        didUrl: String,
        options: DidDereferenceOptions,
    ): com.sphereon.core.api.IdkResult<DidDereferenceResult, com.sphereon.core.api.error.IdkError> =
        com.sphereon.core.api.Err(
            com.sphereon.core.api.error.IdkError
                .NOT_FOUND_ERROR(message = "Fixture does not dereference $didUrl"),
        )

    private companion object {
        const val METHOD = "deactivated"
    }
}

/**
 * VCDM 1.1 and 2.0 JWT VC issue -> JWT VP presentation -> verification using DID-bound keys.
 *
 * The issuer uses the in-process software KMS while holder signing is performed only through the
 * production WSCA. DID trust is resolved from the production provider/resolver registry using the
 * exact DID verification-method URL in each protected `kid`; no verifier-admitted JWKS is
 * constructed from the test key objects.
 */
class VcdmJwtDidIssuePresentVerifyE2ETest {
    private val ctx = Oid4vciTestContext(this)
    private val json = Json { ignoreUnknownKeys = true }
    private val verifier = "https://did-vcdm-verifier.example"

    @Test
    fun vcdm11AndVcdm20JwtIssuePresentAndVerifyUseProductionDidResolutionForIssuerAndHolder() =
        runTest {
            for (version in JwtVersion.entries) {
                val flow = createFlow("did-vcdm-valid-${version.name.lowercase()}", version)
                val graph = ctx.session.graph as VcdmJwtDidTestGraph

                assertTrue(graph.didResolverRegistry.getSupportedMethods().contains("jwk"), "did:jwk provider must be registered")
                assertDidResolution(graph, flow.issuerVerificationMethod)
                assertDidResolution(graph, flow.holderVerificationMethod)
                assertCredentialShape(flow.credential, flow.issuerVerificationMethod, version, flow.holderKey)

                val vp = assertNotNull(flow.response.vpToken).getSinglePresentation(QUERY_ID)
                assertNotNull(vp)
                val vpHeader = jwtObject(vp, 0)
                val vpPayload = jwtObject(vp, 1)
                if (version == JwtVersion.V11) {
                    assertEquals("JWT", vpHeader["typ"]?.jsonPrimitive?.content)
                    assertFalse(vpHeader.containsKey("cty"))
                } else {
                    assertEquals("vp+jwt", vpHeader["typ"]?.jsonPrimitive?.content)
                    assertEquals("vp", vpHeader["cty"]?.jsonPrimitive?.content)
                }
                assertEquals(flow.holderVerificationMethod, vpHeader["kid"]?.jsonPrimitive?.content)
                assertFalse(vpHeader.containsKey("jwk"), "holder output must not carry token-controlled JWK material")
                assertVpShape(vpPayload, version, "did-vcdm-nonce")

                val validation = validate(flow, trusted(flow))
                assertTrue(validation.isOk, "production verifier must return a structured result")
                assertTrue(validation.value.valid, "issuer and holder DID JWT signatures must verify: ${validation.value.errors}")
            }
        }

    @Test
    fun anonymousVcdm11BearerCredentialCannotAuthenticateThePresentationHolder() =
        runTest {
            val flow = createFlow("did-vcdm-anonymous-bearer", JwtVersion.V11, bindHolder = false)
            val payload = jwtObject(flow.credential, 1)
            val vc = assertNotNull(payload["vc"] as? JsonObject)
            assertAnonymousCredentialSubject(vc["credentialSubject"] as? JsonObject)
            assertFalse(payload.containsKey("cnf"))

            val validation = validate(flow, trusted(flow))

            assertTrue(validation.isOk, "anonymous credential rejection must return a structured result")
            assertFalse(validation.value.valid, "an anonymous bearer credential cannot establish holder binding")
            assertTrue(validation.value.errors.any { it.contains("not bound to the presentation holder") })
        }

    @Test
    fun wrongOrUnresolvedDidKeysAndWrongVpBindingAreRejected() =
        runTest {
            var flow = createFlow("did-vcdm-negative-wrong-issuer")
            val unrelatedKey = generateKey("did-vcdm-negative-unrelated")
            val unrelatedVm = didVerificationMethod(unrelatedKey.alias)

            val wrongIssuer =
                validate(
                    flow,
                    listOf(
                        TrustedAuthenticationResolution(
                            controller = flow.issuerDid,
                            identifier = ExternalIdentifierDidOpts(unrelatedVm),
                            purpose = TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                        ),
                        holderTrust(flow),
                    ),
                )
            assertTrue(wrongIssuer.isOk, "wrong issuer DID validation should return a result: ${if (wrongIssuer.isErr) wrongIssuer.error else ""}")
            assertFalse(wrongIssuer.value.valid, "an issuer DID resolving to an unrelated key must fail")

            flow = createFlow("did-vcdm-negative-unresolved-holder")
            val unresolvedHolder =
                validate(
                    flow,
                    listOf(
                        issuerTrust(flow),
                        TrustedAuthenticationResolution(
                            controller = flow.holderDid,
                            identifier = ExternalIdentifierDidOpts("did:unknown:unresolved-holder"),
                            purpose = TrustedAuthenticationPurpose.HOLDER,
                        ),
                    ),
                )
            assertTrue(unresolvedHolder.isOk, "unresolved holder DID validation should return a result: ${if (unresolvedHolder.isErr) unresolvedHolder.error else ""}")
            assertFalse(unresolvedHolder.value.valid, "an unresolved holder DID must fail closed")

            flow = createFlow("did-vcdm-negative-wrong-nonce")
            val wrongNonceRequest = flow.resolvedRequest.copy(request = flow.resolvedRequest.request.copy(nonce = "wrong-nonce"))
            val wrongNonceResponse = createResponse(wrongNonceRequest, flow.credential, flow.holderKey, flow.holderDid, flow.holderVerificationMethod)
            val wrongNonce = validate(flow, trusted(flow), wrongNonceResponse)
            assertTrue(wrongNonce.isOk, "wrong nonce validation should return a result: ${if (wrongNonce.isErr) wrongNonce.error else ""}")
            assertFalse(wrongNonce.value.valid, "a VP nonce not bound to the verifier request must fail")

            flow = createFlow("did-vcdm-negative-wrong-audience")
            val wrongAudienceRequest = flow.resolvedRequest.copy(verifierInfo = flow.resolvedRequest.verifierInfo.copy(clientId = "https://wrong-audience.example"))
            val wrongAudienceResponse = createResponse(wrongAudienceRequest, flow.credential, flow.holderKey, flow.holderDid, flow.holderVerificationMethod)
            val wrongAudience = validate(flow, trusted(flow), wrongAudienceResponse)
            assertTrue(wrongAudience.isOk, "wrong audience validation should return a result: ${if (wrongAudience.isErr) wrongAudience.error else ""}")
            assertFalse(wrongAudience.value.valid, "a VP audience not bound to the verifier must fail")
        }

    @Test
    fun nullDidDocumentCannotEstablishHolderTrust() =
        runTest {
            val flow = createFlow("did-vcdm-null-document")
            val graph = ctx.session.graph as VcdmJwtDidTestGraph

            // A resolver result without a DID document is never an admissible trust source. The
            // production external identifier adapter may surface that state as either a
            // structured resolution error or a result carrying a null document; both states
            // must remain fail-closed at the composed OID4VP verifier boundary.
            val nullDocumentIdentifier = ExternalIdentifierDidOpts("did:unknown:null-document")
            val nullDocumentResolution = graph.didExternalIdentifierResolutionService.resolve(nullDocumentIdentifier)
            assertTrue(
                nullDocumentResolution.isErr || nullDocumentResolution.value.didDocument == null,
                "a DID resolution without a document must not be promoted to a resolved identity: $nullDocumentResolution",
            )
            val nullDocumentHolder =
                validate(
                    flow,
                    listOf(
                        issuerTrust(flow),
                        TrustedAuthenticationResolution(
                            controller = flow.holderDid,
                            identifier = nullDocumentIdentifier,
                            purpose = TrustedAuthenticationPurpose.HOLDER,
                        ),
                    ),
                )
            assertTrue(nullDocumentHolder.isOk, "null-document DID validation should return a result: ${if (nullDocumentHolder.isErr) nullDocumentHolder.error else ""}")
            assertFalse(nullDocumentHolder.value.valid, "a DID with no resolved document must not authenticate the holder VP")
        }

    @Test
    fun didControllerMismatchedHolderMaterialIsRejectedByComposedVerifier() =
        runTest {
            val flow = createFlow("did-vcdm-controller-mismatch")

            // The source is admitted under the holder controller, but its DID verification
            // method belongs to the issuer. The composed verifier must bind the resolved key to
            // the authenticated controller and reject this cross-controller substitution.
            val mismatchedHolderSource =
                TrustedAuthenticationResolution(
                    controller = flow.holderDid,
                    identifier = ExternalIdentifierDidOpts(flow.issuerVerificationMethod),
                    purpose = TrustedAuthenticationPurpose.HOLDER,
                )
            val validation =
                validate(
                    flow,
                    listOf(issuerTrust(flow), mismatchedHolderSource),
                )
            assertTrue(
                validation.isOk,
                "controller-mismatched DID validation must return a structured result: ${if (validation.isErr) validation.error else ""}",
            )
            assertFalse(
                validation.value.valid,
                "a DID verification method controlled by another DID must not authenticate the holder VP: ${validation.value.errors}",
            )
        }

    @Test
    fun deactivatedDidDocumentCannotAuthenticateMatchingHolderMaterial() =
        runTest {
            val deactivatedDid = "did:deactivated:vcdm-holder"
            val flow = createFlow("did-vcdm-deactivated", holderDidOverride = deactivatedDid)
            val graph = ctx.session.graph as VcdmJwtDidTestGraph

            // The resolver returns the exact holder JWK used to sign this VP, while preserving
            // the DID Resolution document metadata that marks the DID as deactivated.
            val resolved =
                graph.didExternalIdentifierResolutionService.resolve(
                    ExternalIdentifierDidOpts(flow.holderVerificationMethod),
                )
            assertTrue(
                resolved.isOk,
                "deactivated DID must still resolve its presented key before policy rejection: ${if (resolved.isErr) resolved.error else ""}",
            )
            assertEquals(
                "true",
                resolved.value.didResolutionResult.didDocumentMetadata
                    ?.get("deactivated"),
                "the composed test must exercise deactivated DID document metadata",
            )

            val validation = validate(flow, trusted(flow))
            assertTrue(
                validation.isOk,
                "deactivated DID validation must return a structured result: ${if (validation.isErr) validation.error else ""}",
            )
            assertFalse(
                validation.value.valid,
                "a deactivated DID must not authenticate matching holder material: ${validation.value.errors}",
            )
        }

    private suspend fun createFlow(
        prefix: String,
        version: JwtVersion = JwtVersion.V20,
        holderDidOverride: String? = null,
        bindHolder: Boolean = true,
    ): Flow {
        val issuerKey = generateKey("$prefix-issuer")
        val provisionedHolder = provisionHolder("$prefix-holder")
        val holderKey =
            holderDidOverride?.let {
                val graph = ctx.session.graph as VcdmJwtDidTestGraph
                assertSame<Any>(graph.deactivatedDidResolver, assertNotNull(graph.didResolverRegistry.getResolver("deactivated")))
                graph.deactivatedDidResolver.register(it, provisionedHolder.publicJwk)
                provisionedHolder.copy(did = it, verificationMethod = "$it#0")
            } ?: provisionedHolder
        val issuerVm = didVerificationMethod(issuerKey.alias)
        val holderVm = holderKey.verificationMethod
        val issuerDid = issuerVm.substringBefore('#')
        val holderDid = holderKey.did
        val credential = issue(issuerKey.alias, issuerDid, issuerVm, holderDid, version, holderKey.takeIf { bindHolder })
        val query = DcqlQuery(credentials = listOf(query(version)))
        val request =
            verifierService()
                .createAuthorizationRequest(
                    CreateAuthorizationRequestArgs(
                        instanceId = "did-vcdm-verifier",
                        dcqlQuery = query,
                        clientId = verifier,
                        responseUri = "$verifier/response",
                        responseMode = ResponseMode.DIRECT_POST,
                        nonce = "did-vcdm-nonce",
                        state = "did-vcdm-state-$prefix-${version.name.lowercase()}",
                        clientMetadata = ClientMetadata(vpFormatsSupported = mapOf(version.format.value to jwtVcFormatInfo(listOf("ES256")))),
                    ),
                ).also {
                    assertTrue(it.isOk, "production verifier request command should succeed: ${if (it.isErr) it.error else ""}")
                }.value
        val resolved =
            ResolvedOid4vpRequest(
                request = request.request,
                dcqlQuery = query,
                clientMetadata = ClientMetadata(vpFormatsSupported = mapOf(version.format.value to jwtVcFormatInfo(listOf("ES256")))),
                verifierInfo = VerifierInfo(clientId = verifier, clientIdScheme = ClientIdScheme.REDIRECT_URI),
            )
        val response = createResponse(resolved, credential, holderKey, holderDid, holderVm, version)
        return Flow(version, issuerDid, issuerVm, holderDid, holderVm, holderKey, credential, query, resolved, response)
    }

    private suspend fun issue(
        alias: String,
        issuerDid: String,
        issuerVm: String,
        holderDid: String,
        version: JwtVersion,
        holderKey: HolderMaterial?,
    ): String {
        ctx.registerIssuerSigningKey(alias)
        val configuration =
            CredentialConfigurationSupported(
                format = version.format.value,
                credentialDefinition = CredentialDefinition(type = listOf("VerifiableCredential", version.credentialType)),
            )
        val graph = ctx.session.graph as VcdmJwtDidTestGraph
        val handler: CredentialFormatHandler = if (version == JwtVersion.V11) graph.jwtVcJsonFormatHandler else graph.vcLdJsonJwtFormatHandler
        val result =
            handler.issueCredential(
                CredentialRequest(format = version.format.value),
                IssuanceContext(
                    subject = holderDid,
                    clientId = "did-vcdm-client",
                    issuerIdentifier = issuerDid,
                    credentialConfigurationId = "did-vcdm-credential",
                    credentialConfiguration = configuration,
                    holderBindingKey = holderKey?.publicJwk?.let { json.encodeToJsonElement(Jwk.serializer(), it).jsonObject },
                    holderKeyId = holderKey?.verificationMethod,
                    attributes = mapOf("level" to JsonPrimitive("gold")),
                    signingKeyAlias = alias,
                    signingKeyMode = SigningKeyMode.Did("jwk"),
                    signingVerificationMethodId = issuerVm,
                    issuanceClockSkewInSeconds = 0,
                    expirationInDays = 30,
                ),
            )
        assertTrue(result.isOk, "production ${version.label} DID issuer must issue: ${if (result.isErr) result.error else ""}")
        return result.value.credential.jsonPrimitive.content
    }

    private suspend fun createResponse(
        request: ResolvedOid4vpRequest,
        credential: String,
        holderKey: HolderMaterial,
        holderDid: String,
        holderVm: String,
        version: JwtVersion = JwtVersion.V20,
    ): AuthorizationResponse {
        val result =
            (ctx.session.graph as VcdmJwtDidTestGraph).oid4vpHolder.commands.createAuthorizationResponse.execute(
                CreateAuthorizationResponseArgs(
                    request = request,
                    selectedCredentials =
                        listOf(
                            SelectedCredential(
                                credentialQueryId = QUERY_ID,
                                credentialId = "did-vcdm-credential",
                                presentation = JsonPrimitive(credential),
                                credentialFormat = version.format,
                                holderKeyRef = holderKey.keyRef,
                                holderId = holderDid,
                                holderVerificationMethod = holderVm,
                                holderJwtVpSigningIdentifier = HolderJwtVpSigningIdentifier.DidVerificationMethod(holderVm),
                                holderSigningAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                                holderJwtVpOperationBinding = HOLDER_OPERATION_BINDING,
                                holderJwtVpWalletUnitId = HOLDER_WALLET_UNIT_ID,
                            ),
                        ),
                ),
            )
        assertTrue(
            result.isOk,
            "production holder command must create a DID-bound VCDM VP: ${if (result.isErr) result.error else ""}",
        )
        return result.value
    }

    private suspend fun validate(
        flow: Flow,
        trusted: List<TrustedAuthenticationResolution>,
        response: AuthorizationResponse = flow.response,
    ) = verifierService().let { service ->
        val parsed =
            service
                .parseAuthorizationResponse(
                    ParseAuthorizationResponseArgs(
                        responseParams =
                            mapOf(
                                "vp_token" to json.encodeToString(JsonElement.serializer(), VpToken.run { response.vpToken!!.toJson() }),
                                "state" to assertNotNull(response.state),
                            ),
                        originalRequest = flow.resolvedRequest.request,
                    ),
                ).also {
                    assertTrue(it.isOk, "production response parser should accept command output: ${if (it.isErr) it.error else ""}")
                }
        service.validateAuthorizationResponse(
            ValidateAuthorizationResponseArgs(
                parsedResponse = parsed.value,
                originalRequest = flow.resolvedRequest.request,
                dcqlQuery = flow.query,
                expectedNonce = "did-vcdm-nonce",
                trustedAuthentications = trusted,
            ),
        )
    }

    private fun trusted(flow: Flow) = listOf(issuerTrust(flow), holderTrust(flow))

    private fun issuerTrust(flow: Flow) =
        TrustedAuthenticationResolution(
            controller = flow.issuerDid,
            identifier = ExternalIdentifierDidOpts(flow.issuerVerificationMethod),
        )

    private fun holderTrust(flow: Flow) =
        TrustedAuthenticationResolution(
            controller = flow.holderDid,
            identifier = ExternalIdentifierDidOpts(flow.holderVerificationMethod),
            purpose = TrustedAuthenticationPurpose.HOLDER,
        )

    private suspend fun assertDidResolution(
        graph: VcdmJwtDidTestGraph,
        verificationMethod: String
    ) {
        val resolved = graph.didExternalIdentifierResolutionService.resolve(ExternalIdentifierDidOpts(verificationMethod))
        assertTrue(
            resolved.isOk,
            "production DID resolver must resolve $verificationMethod: ${if (resolved.isErr) resolved.error else ""}",
        )
        assertEquals(verificationMethod, resolved.value.keyInfo.kid, "DID resolver must select the exact verification-method fragment")
    }

    private suspend fun didVerificationMethod(alias: String): String =
        (ctx.session.graph as VcdmJwtDidTestGraph)
            .issuerKeyIdResolver
            .resolveDidVerificationMethodId(alias, "jwk")
            .getOrThrow()

    private suspend fun generateKey(alias: String): ManagedKeyInfoType<*> {
        val result =
            ctx.session.graph.asKeyManagerServiceGraph().keyManagerService.generateKeyResult(
                alias = alias,
                use = JwkUse.sig,
                alg = SignatureAlgorithm.ECDSA_SHA256,
            )
        assertTrue(result.isOk, "software KMS key generation must succeed")
        return assertNotNull(result.value.keyPair?.joseToManagedKeyInfo(KeyVisibility.PRIVATE))
    }

    private suspend fun provisionHolder(alias: String): HolderMaterial {
        val result =
            (ctx.session.graph as WalletInteractionOid4vciWscaTestGraph).wsca.ensureKey(
                walletUnitId = HOLDER_WALLET_UNIT_ID,
                usage = SecureComponentUsage.WALLET_CREDENTIAL_PROOF,
                algorithm = SignatureAlgorithm.ECDSA_SHA256,
                keyAlias = alias,
            )
        assertTrue(result.isOk, "holder key must be provisioned through WSCA: ${if (result.isErr) result.error else ""}")
        val key = result.value
        val publicJwk = json.decodeFromString(Jwk.serializer(), assertNotNull(key.publicKeyJwk))
        val did = JwkDidProviderImpl.didFromJwk(publicJwk)
        return HolderMaterial(
            keyRef = assertNotNull(key.keyRef, "WSCA must return an opaque holder keyRef"),
            did = did,
            verificationMethod = "$did#0",
            publicJwk = publicJwk,
        )
    }

    private fun verifierService(): Oid4vpVerifierService = (ctx.session.graph as VcdmJwtDidTestGraph).oid4vpVerifierService

    private fun query(version: JwtVersion = JwtVersion.V20) =
        DcqlCredentialQuery(
            id = QUERY_ID,
            format = version.format.value,
            meta = w3cVcMeta(listOf("VerifiableCredential", version.credentialType)),
        )

    private fun jwtObject(
        jwt: String,
        part: Int
    ): JsonObject = json.parseToJsonElement(jwt.split('.')[part].decodeFromBase64Url().decodeToString()).jsonObject

    private fun contextValue(payload: JsonObject): String =
        ((payload["@context"] as? JsonArray)?.firstOrNull() as? JsonPrimitive)?.content
            ?: error("VCDM 2.0 JWT payload must contain the VCDM 2.0 context as its first context")

    private fun assertCredentialShape(
        jwt: String,
        issuerVerificationMethod: String,
        version: JwtVersion,
        holderKey: HolderMaterial,
    ) {
        val header = jwtObject(jwt, 0)
        val payload = jwtObject(jwt, 1)
        assertEquals(version.credentialTyp, header["typ"]?.jsonPrimitive?.content)
        assertEquals(issuerVerificationMethod, header["kid"]?.jsonPrimitive?.content)
        assertFalse(header.containsKey("jwk"), "issuer output must not carry token-controlled JWK material")
        assertFalse(header.containsKey("x5c"), "DID issuer output must not carry X.509 material")
        if (version == JwtVersion.V11) {
            assertFalse(header.containsKey("cty"))
            val vc = assertNotNull(payload["vc"] as? JsonObject)
            assertEquals(version.context, (vc["@context"] as JsonArray).first().jsonPrimitive.content)
            assertEquals(version.credentialType, (vc["type"] as JsonArray).last().jsonPrimitive.content)
            val subject = assertNotNull(vc["credentialSubject"] as? JsonObject)
            assertEquals("gold", subject["level"]?.jsonPrimitive?.content)
            assertEquals(holderKey.did, subject["id"]?.jsonPrimitive?.content)
            assertEquals(holderKey.did, payload["sub"]?.jsonPrimitive?.content)
            assertFalse(payload.containsKey("cnf"), "VCDM 1.1 maps holder binding through its subject identifier")
            assertFalse(payload.containsKey("@context"))
        } else {
            assertEquals("vc", header["cty"]?.jsonPrimitive?.content)
            assertEquals(version.context, contextValue(payload))
            assertEquals(version.credentialType, (payload["type"] as JsonArray).last().jsonPrimitive.content)
            assertAnonymousCredentialSubject(payload["credentialSubject"] as? JsonObject)
            assertEquals(
                holderKey.verificationMethod,
                payload
                    .getValue("cnf")
                    .jsonObject["kid"]
                    ?.jsonPrimitive
                    ?.content,
            )
            assertFalse(payload.getValue("cnf").jsonObject.containsKey("jwk"))
        }
    }

    private fun assertAnonymousCredentialSubject(subject: JsonObject?) {
        val anonymousSubject = assertNotNull(subject)
        assertEquals("gold", anonymousSubject["level"]?.jsonPrimitive?.content)
        assertFalse(anonymousSubject.containsKey("id"), "credential subject must remain anonymous")
    }

    private fun assertVpShape(
        payload: JsonObject,
        version: JwtVersion,
        nonce: String
    ) {
        if (version == JwtVersion.V11) {
            val vp = assertNotNull(payload["vp"] as? JsonObject)
            assertEquals(version.context, (vp["@context"] as JsonArray).first().jsonPrimitive.content)
            assertEquals("VerifiablePresentation", (vp["type"] as JsonArray).first().jsonPrimitive.content)
        } else {
            assertEquals(version.context, contextValue(payload))
        }
        assertEquals(nonce, payload["nonce"]?.jsonPrimitive?.content)
        assertEquals(verifier, payload["aud"]?.jsonPrimitive?.content)
    }

    private data class Flow(
        val version: JwtVersion,
        val issuerDid: String,
        val issuerVerificationMethod: String,
        val holderDid: String,
        val holderVerificationMethod: String,
        val holderKey: HolderMaterial,
        val credential: String,
        val query: DcqlQuery,
        val resolvedRequest: ResolvedOid4vpRequest,
        val response: AuthorizationResponse,
    )

    private enum class JwtVersion(
        val format: CredentialFormat,
        val label: String,
        val credentialType: String,
        val context: String,
        val credentialTyp: String,
    ) {
        V11(CredentialFormat.JWT_VC_JSON, "VCDM 1.1", "DidVcdm11Credential", "https://www.w3.org/2018/credentials/v1", "JWT"),
        V20(CredentialFormat.JWT_VC_JSON_LD, "VCDM 2.0", "DidVcdm2Credential", "https://www.w3.org/ns/credentials/v2", "vc+jwt"),
    }

    private data class HolderMaterial(
        val keyRef: String,
        val did: String,
        val verificationMethod: String,
        val publicJwk: Jwk,
    )

    private companion object {
        const val QUERY_ID = "did-vcdm-query"
        const val HOLDER_WALLET_UNIT_ID = "wallet-unit-did-vcdm-e2e"
        const val HOLDER_OPERATION_BINDING = "did-vcdm-attended-presentation"
    }
}
