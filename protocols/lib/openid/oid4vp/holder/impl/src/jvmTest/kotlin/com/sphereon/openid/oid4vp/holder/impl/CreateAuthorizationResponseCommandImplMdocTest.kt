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

package com.sphereon.openid.oid4vp.holder.impl

import com.sphereon.core.api.Ok
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.core.compat.DateTimeUtils
import com.sphereon.core.compat.Uuid
import com.sphereon.core.defaults.app.DefaultRootScopeProvider
import com.sphereon.crypto.core.CoseCryptoServiceImpl
import com.sphereon.crypto.core.DefaultCallbacks
import com.sphereon.crypto.core.KeyEncoding
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyInfo
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.cose.CoseCryptoProviderToCallbackAdapter
import com.sphereon.crypto.core.cose.CoseKey
import com.sphereon.crypto.core.cose.CoseKeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.generic.X509DistinguishedNameElements
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.JwaCurve
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkSet
import com.sphereon.crypto.jose.jws.JwtServiceImpl
import com.sphereon.crypto.core.jose.tryGenerateJwkThumbprint
import com.sphereon.crypto.kms.CertificateServiceImpl
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.crypto.dataintegrity.command.AddProofInput
import com.sphereon.crypto.dataintegrity.command.AddProofOutput
import com.sphereon.crypto.dataintegrity.command.AddProofServiceCommand
import com.sphereon.di.app.AbstractAppGraph
import com.sphereon.di.app.RootScopeProvider
import com.sphereon.mdoc.MdocSignService
import com.sphereon.mdoc.MdocSignServiceImpl
import com.sphereon.mdoc.SessionTranscriptCborCodecImpl
import com.sphereon.mdoc.data.DeviceAuthValidationImpl
import com.sphereon.mdoc.data.device.DataElementIdentifier
import com.sphereon.mdoc.data.device.DeviceResponseCborCodecImpl
import com.sphereon.mdoc.data.device.DocType
import com.sphereon.mdoc.data.device.IssuerSigned
import com.sphereon.mdoc.data.device.IssuerSignedCborCodecImpl
import com.sphereon.mdoc.data.device.IssuerSignedItem
import com.sphereon.mdoc.data.device.IssuerSignedItemCborCodecImpl
import com.sphereon.mdoc.data.device.NameSpace
import com.sphereon.mdoc.data.mso.DigestID
import com.sphereon.mdoc.data.mso.MobileSecurityObjectCborCodecImpl
import com.sphereon.mdoc.oid4vp.MdocOid4vpServiceImpl
import com.sphereon.mdoc.transfer.reader.SessionTranscript
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.common.ClientMetadata
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.common.responseUri
import com.sphereon.openid.oid4vp.common.vpToken
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vp.dcql.ClaimsPathPointer
import com.sphereon.openid.oid4vp.dcql.DcqlClaimQuery
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.holder.CreateAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.holder.MdocCredentialSigningSignature
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.SelectedCredential
import com.sphereon.openid.oid4vp.holder.VerifierInfo
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.DependencyGraph
import dev.zacsweers.metro.Named
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.createGraphFactory
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * End-to-end test for the `mso_mdoc` branch of [CreateAuthorizationResponseCommandImpl].
 *
 * Issues a REAL ISO 18013-5 mdoc bound to a holder-controlled device key, hands the stored
 * `IssuerSigned` to the command, and asserts the command produces a genuine ISO 18013-7
 * `DeviceResponse` (`{version, documents, status}` with a `DeviceAuth` COSE_Sign1) — NOT the
 * stored `IssuerSigned` passed through verbatim (the prior bug). The DeviceAuth is signed over the
 * OID4VP §B.2.6 OpenID4VPHandover SessionTranscript built from `client_id` + `nonce` +
 * `response_uri`, exactly as the verifier reconstructs it.
 */
class CreateAuthorizationResponseCommandImplMdocTest {
    private val docType = DocType("org.acme.businesscard.1")
    private val docTypeNamespace = NameSpace("org.acme.businesscard.1")

    @DependencyGraph(AppScope::class)
    abstract class TestHolderMdocAppGraph : AbstractAppGraph() {
        @DependencyGraph.Factory
        fun interface Factory {
            fun create(
                @Provides application: Any,
                @Provides @Named("appId") appId: String,
                @Provides @Named("profile") profile: String,
                @Provides @Named("version") version: String,
                @Provides rootScopeProvider: RootScopeProvider,
            ): TestHolderMdocAppGraph
        }
    }

    private class Setup(
        testInstance: Any
    ) {
        val app: AbstractAppGraph =
            createGraphFactory<TestHolderMdocAppGraph.Factory>()
                .create(
                    application = testInstance,
                    appId = "test-holder-mdoc",
                    profile = "test",
                    version = "1.0.0-test",
                    rootScopeProvider = DefaultRootScopeProvider(),
                ).also { it.initRootScopeProvider() }

        val userContext = app.userContextManager.getAnonymous()
        val sessionContext = userContext.sessionContextManager.createOrGetFromId("holder-mdoc-${Uuid.v4String()}", principalType = com.sphereon.di.context.PrincipalType.USER)
        val execution: SessionExecution = sessionContext.asCoreApiServiceGraph().serviceExecution
        val kms: KeyManagerService = sessionContext.graph.asKeyManagerServiceGraph().keyManagerService
        val certificateService: CertificateServiceImpl
        val mdocSignService: MdocSignService

        init {
            val factory = (app as SoftwareKmsProviderFactoryImpl.Graph).softwareKmsProvider
            val provider = factory.create(SoftwareKmsProviderConfig(id = "test-software"), sessionContext.sessionExecution)
            kms.registerProvider(provider, makeDefaultKms = true)
            DefaultCallbacks.setCoseCryptoDefault(
                CoseCryptoProviderToCallbackAdapter(keyManagerServiceProvider = { kms }),
            )
            certificateService = CertificateServiceImpl(keyManagerService = kms)
            mdocSignService =
                MdocSignServiceImpl(
                    coseCryptoService = CoseCryptoServiceImpl(),
                    execution = execution,
                    mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                    sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
                )
        }
    }

    private suspend fun issuerKeyWithCert(setup: Setup): ManagedKeyInfoType<CoseKeyType> {
        val issuerKeyPair =
            setup.kms.generateKeyAsync(
                alias = "test-mdoc-issuer-${Uuid.v4String()}",
                alg = SignatureAlgorithm.ECDSA_SHA256,
                keyVisibility = KeyVisibility.PRIVATE,
                providerId = null,
            )
        val issuerKeyInfo = issuerKeyPair.toManagedKeyInfo<CoseKey>(KeyVisibility.PRIVATE, KeyEncoding.COSE)
        val dn =
            X509DistinguishedNameElements(
                commonName = "Acme Business Card Issuer",
                organizationName = "Acme",
                country = "US",
            )
        val cert =
            setup.certificateService.createCertificate(
                issuerKeyInfo = issuerKeyInfo,
                issuer = dn,
                subjectKeyInfo = issuerKeyInfo,
                subject = dn,
                serialNumber = 1,
            )
        return ManagedKeyInfo(
            alias = issuerKeyInfo.alias,
            providerId = issuerKeyInfo.providerId,
            resolvedKeyInfo = cert.certificate.amendCoseKeyInfo(issuerKeyInfo),
        )
    }

    @Suppress("UNCHECKED_CAST")
    @Test
    fun `holder builds a real mdoc DeviceResponse with DeviceAuth`() =
        runTest {
            val setup = Setup(this)
            val command =
                CreateAuthorizationResponseCommandImpl(
                    execution = setup.execution,
                    holderJwtVpSigningProvider =
                        JwtServiceHolderJwtVpSigningProvider((setup.sessionContext.graph as JwtServiceImpl.Graph).jwtService),
                    addProofServiceCommand = UnusedAddProofCommand,
                    mdocOid4vpService =
                        MdocOid4vpServiceImpl(
                            signService = setup.mdocSignService,
                            logService = setup.execution.log,
                            mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                        ),
                    issuerSignedCborCodec = IssuerSignedCborCodecImpl(),
                    deviceResponseCborCodec = DeviceResponseCborCodecImpl(),
                    mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                )

            // 1. The holder generates a device key it controls (PRIVATE: it retains the private
            //    half so it can later sign DeviceAuth). The PUBLIC half is bound into the MSO.
            //    Faithful to the real wallet `createHolderKey()`: no explicit alias, so the KMS
            //    keys it under its kid (RFC 7638 thumbprint) and the holder references it by kid.
            val deviceKeyPair =
                setup.kms.generateKeyAsync(
                    alias = null,
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                    keyVisibility = KeyVisibility.PRIVATE,
                    providerId = null,
                )
            val deviceKeyInfo = deviceKeyPair.toManagedKeyInfo<CoseKey>(KeyVisibility.PUBLIC, KeyEncoding.COSE)

            // 2. The issuer signs an mdoc binding that device key into the MSO deviceKeyInfo.
            val issuerKeyInfo = issuerKeyWithCert(setup)
            val now = DateTimeUtils.DEFAULTS.dateTimeLocal()
            val item1 =
                IssuerSignedItem.create(
                    digestID = DigestID(1u),
                    elementIdentifier = DataElementIdentifier("given_name"),
                    elementValue = "Jane",
                )
            val item2 =
                IssuerSignedItem.create(
                    digestID = DigestID(2u),
                    elementIdentifier = DataElementIdentifier("family_name"),
                    elementValue = "Doe",
                )
            val issuerSigned =
                IssuerSigned
                    .MsoBuilder(issuerSignedItemCborCodec = IssuerSignedItemCborCodecImpl())
                    .withDocType(docType)
                    .withDeviceKeyInfo(deviceKeyInfo)
                    .withSigningKeyInfo(issuerKeyInfo)
                    .withSigned(now)
                    .withValidFrom(now)
                    .withValidUntil(now)
                    .also { it.addNameSpace(docTypeNamespace, item1 as IssuerSignedItem<Any>, item2 as IssuerSignedItem<Any>) }
                    .buildAndSign(mdocSignService = setup.mdocSignService, requireDeviceX5Chain = false)

            // OID4VCI mso_mdoc credential wire form: base64url(CBOR(IssuerSigned)).
            val storedCredential = IssuerSignedCborCodecImpl().encode(issuerSigned).getOrThrow().encodeToBase64Url()

            // 3. The verifier's request (the SAME client_id/nonce/response_uri the verifier will
            //    use to reconstruct the SessionTranscript).
            val resolvedRequest = resolvedRequest()
            val selected =
                listOf(
                    SelectedCredential(
                        credentialQueryId = "businesscard_mdoc",
                        credentialId = "mdoc-1",
                        presentation = JsonPrimitive(storedCredential),
                        credentialFormat = CredentialFormat.MSO_MDOC,
                        holderKeyRef = deviceKeyPair.kid ?: deviceKeyPair.alias,
                    ),
                )

            val result = command.execute(CreateAuthorizationResponseArgs(resolvedRequest, selected))
            if (result.isErr) error("command failed: ${result.error.message.defaultMessage}")
            assertIs<Ok<*>>(result)
            val response = result.getOrThrow()
            val vpToken = response.vpToken
            assertNotNull(vpToken)
            val wireVpToken = assertIs<JsonObject>(response.additionalParameters["vp_token"])
            assertEquals(1, assertIs<JsonArray>(wireVpToken["businesscard_mdoc"]).size)

            val presentation = vpToken.getSinglePresentation("businesscard_mdoc")
            assertNotNull(presentation)
            // The presentation must NOT be the stored IssuerSigned passed through verbatim.
            assertTrue(presentation != storedCredential, "holder must not pass the stored IssuerSigned through verbatim")

            // 4. Decode the produced vp_token entry and assert it is a real DeviceResponse with a
            //    DeviceAuth COSE_Sign1 over the device key (i.e. the holder built + signed it).
            val deviceResponseBytes = presentation.decodeFromBase64Url()
            val deviceResponse = DeviceResponseCborCodecImpl().decode(deviceResponseBytes).getOrThrow().value
            val documents = deviceResponse.documents
            assertNotNull(documents)
            assertEquals(1, documents.size)
            val doc = documents.first()
            assertEquals(docType, doc.docType)
            assertNotNull(doc.deviceSigned, "DeviceResponse document must carry deviceSigned (DeviceAuth)")
            assertNotNull(doc.deviceSigned!!.deviceAuth.deviceSignature, "DeviceAuth must carry a device signature")
            // The disclosed issuer-signed elements survive.
            assertNotNull(doc.issuerSigned.getIssuerSignedItem(docTypeNamespace, DataElementIdentifier("given_name")))

            val noClaimsRequest =
                resolvedRequest(
                    dcqlQuery =
                        DcqlQuery(
                            credentials =
                                listOf(
                                    DcqlCredentialQuery(
                                        id = "businesscard_mdoc",
                                        format = "mso_mdoc",
                                        meta = JsonObject(mapOf("doctype_value" to JsonPrimitive(docType.toString()))),
                                    ),
                                ),
                        ),
                )
            val noClaimsResult = command.execute(CreateAuthorizationResponseArgs(noClaimsRequest, selected))
            if (noClaimsResult.isErr) error("mdoc no-claims request failed: ${noClaimsResult.error.message.defaultMessage}")
            val noClaimsPresentation = noClaimsResult.getOrThrow().vpToken?.getSinglePresentation("businesscard_mdoc")
            assertNotNull(noClaimsPresentation)
            val noClaimsDocument =
                DeviceResponseCborCodecImpl()
                    .decode(noClaimsPresentation.decodeFromBase64Url())
                    .getOrThrow()
                    .value
                    .documents
                    ?.single()
            assertNotNull(noClaimsDocument)
            assertNotNull(noClaimsDocument.deviceSigned?.deviceAuth?.deviceSignature)
            assertTrue(
                noClaimsDocument.issuerSigned.nameSpaces.orEmpty().values.all { it.isEmpty() },
                "DCQL with claims absent must not disclose selectively-disclosable mdoc elements",
            )

            val unsatisfiableRequest =
                resolvedRequest(
                    dcqlQuery =
                        DcqlQuery(
                            credentials =
                                listOf(
                                    DcqlCredentialQuery(
                                        id = "businesscard_mdoc",
                                        format = "mso_mdoc",
                                        meta = JsonObject(mapOf("doctype_value" to JsonPrimitive(docType.toString()))),
                                        claims =
                                            listOf(
                                                DcqlClaimQuery(
                                                    path =
                                                        ClaimsPathPointer(
                                                            listOf(
                                                                JsonPrimitive(docTypeNamespace.toString()),
                                                                JsonPrimitive("not_in_credential"),
                                                            ),
                                                        ),
                                                ),
                                            ),
                                    ),
                                ),
                        ),
                )
            val unsatisfiableResult = command.execute(CreateAuthorizationResponseArgs(unsatisfiableRequest, selected))
            assertTrue(unsatisfiableResult.isErr, "a required mdoc claim absent from the credential must not produce a vp_token")

            // Prepare the same credential without signing, then compose using the exact raw
            // DeviceAuth signature from the independent legacy signer. The prepared path must
            // re-derive the transcript and verify the supplied signature before creating the wire
            // response; it must not fall back to another local signature.
            val preparedSignings = command.prepareMdocDeviceAuthenticationSignatures(resolvedRequest, selected)
            if (preparedSignings.isErr) error("mdoc signing preparation failed: ${preparedSignings.error.message.defaultMessage}")
            val prepared = preparedSignings.getOrThrow()
            assertEquals(1, prepared.size)
            assertEquals("mdoc-1", prepared.single().credentialId)
            assertEquals(docType.toString(), prepared.single().signing.docType)
            val detachedSignature = requireNotNull(doc.deviceSigned!!.deviceAuth.deviceSignature).signature.value
            val remotelyCompleted = command.createAuthorizationResponseWithPreparedSignatures(
                request = resolvedRequest,
                selectedCredentials = selected,
                preparedPresentations = emptyList(),
                preparedJwtVp = null,
                jwtSignatures = emptyList(),
                preparedMdocSignings = prepared,
                mdocSignatures = listOf(MdocCredentialSigningSignature("mdoc-1", detachedSignature)),
            )
            if (remotelyCompleted.isErr) error("prepared mdoc response failed: ${remotelyCompleted.error.message.defaultMessage}")
            val remotePresentation = remotelyCompleted.getOrThrow().vpToken?.getSinglePresentation("businesscard_mdoc")
            assertNotNull(remotePresentation)
            val remoteDocument = DeviceResponseCborCodecImpl().decode(remotePresentation.decodeFromBase64Url()).getOrThrow().value.documents!!.single()
            assertNotNull(remoteDocument.deviceSigned?.deviceAuth?.deviceSignature)

            // 5. For an encrypted response the holder must bind DeviceAuth to the exact
            // verifier JWK selected for the response JWE. This is the OpenID4VP 1.0 final
            // B.2.6 slot that used to be signed as null and caused verifier rejection.
            val verifierEncryptionJwk =
                Jwk(
                    kty = JwaKeyType.EC,
                    crv = JwaCurve.P_256,
                    x = "0_3S7HedSywaxlekdt6Or8pkcR13hQaCPMqt9cuZBVc",
                    y = "ZVXSCL3HlnMQWKrwMyIAe5wsAIWd3Eu1misKFr3POdA",
                    use = "enc",
                    alg = JwaAlgorithm.ECDH_ES,
                    kid = "verifier-encryption-key",
                )
            val encryptedRequest =
                resolvedRequest(
                    responseMode = ResponseMode.DIRECT_POST_JWT,
                    clientMetadata =
                        ClientMetadata(
                            jwks = JwkSet(arrayOf(verifierEncryptionJwk)),
                            encryptedResponseEncValuesSupported = listOf("A128GCM"),
                        ),
                )
            val encryptedResult = command.execute(CreateAuthorizationResponseArgs(encryptedRequest, selected))
            if (encryptedResult.isErr) error("encrypted command failed: ${encryptedResult.error.message.defaultMessage}")
            val encryptedPresentation =
                encryptedResult
                    .getOrThrow()
                    .vpToken
                    ?.getSinglePresentation("businesscard_mdoc")
            assertNotNull(encryptedPresentation)
            val encryptedDocument =
                DeviceResponseCborCodecImpl()
                    .decode(encryptedPresentation.decodeFromBase64Url())
                    .getOrThrow()
                    .value
                    .documents
                    ?.single()
            assertNotNull(encryptedDocument)

            val verifierThumbprint =
                tryGenerateJwkThumbprint(verifierEncryptionJwk)
                    .getOrThrow()
                    .decodeFromBase64Url()
            val expectedTranscript =
                SessionTranscript.fromOid4vpClientIdAndResponseUri(
                    clientId = encryptedRequest.request.clientId,
                    nonce = encryptedRequest.request.nonce!!,
                    jwkThumbprint = verifierThumbprint,
                    responseUri = encryptedRequest.request.responseUri!!,
                )
            val deviceAuthValidation =
                DeviceAuthValidationImpl(
                    coseCryptoService = CoseCryptoServiceImpl(),
                    sessionTranscriptCborCodec = SessionTranscriptCborCodecImpl(),
                    mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                )
            val correctBinding =
                deviceAuthValidation.verifyDeviceAuth(
                    document = encryptedDocument,
                    expectedSessionTranscript = expectedTranscript,
                )
            assertFalse(correctBinding.error, "encrypted DeviceAuth must verify with the verifier JWK thumbprint: ${correctBinding.message}")

            val oldNullBinding =
                deviceAuthValidation.verifyDeviceAuth(
                    document = encryptedDocument,
                    expectedSessionTranscript =
                        SessionTranscript.fromOid4vpClientIdAndResponseUri(
                            clientId = encryptedRequest.request.clientId,
                            nonce = encryptedRequest.request.nonce!!,
                            jwkThumbprint = null,
                            responseUri = encryptedRequest.request.responseUri!!,
                        ),
                )
            assertTrue(oldNullBinding.error, "encrypted DeviceAuth must reject the old null-thumbprint transcript")

            // Digital Credentials API mode has no response_uri/redirect_uri. Its transcript
            // uses the browser origin supplied by the validated transport parser, not the
            // `origin:` client_id value.
            val callerOrigin = "https://wallet.example.test"
            val dcApiRequest =
                resolvedRequest(
                    responseMode = ResponseMode.DC_API,
                    callerOrigin = callerOrigin,
                )
            assertEquals(null, dcApiRequest.request.responseUri)
            assertEquals(null, dcApiRequest.request.redirectUri)
            val dcApiResult = command.execute(CreateAuthorizationResponseArgs(dcApiRequest, selected))
            if (dcApiResult.isErr) error("dc_api command failed: ${dcApiResult.error.message.defaultMessage}")
            val dcApiPresentation =
                dcApiResult.getOrThrow().vpToken?.getSinglePresentation("businesscard_mdoc")
            assertNotNull(dcApiPresentation)
            val dcApiDocument =
                DeviceResponseCborCodecImpl()
                    .decode(dcApiPresentation.decodeFromBase64Url())
                    .getOrThrow()
                    .value.documents!!.single()
            val dcApiTranscript = SessionTranscript.fromOid4vpDigitalCredentialsApi(callerOrigin, "test-nonce", null)
            val dcApiBinding = deviceAuthValidation.verifyDeviceAuth(dcApiDocument, dcApiTranscript)
            assertFalse(dcApiBinding.error, "dc_api DeviceAuth must bind raw caller origin: ${dcApiBinding.message}")
            assertFailsWith<IllegalArgumentException>("DC API transcript factory must reject origin-prefixed client_id") {
                SessionTranscript.fromOid4vpDigitalCredentialsApi("origin:$callerOrigin", "test-nonce", null)
            }

            val missingOriginRequest = resolvedRequest(responseMode = ResponseMode.DC_API)
            val missingOriginResult = command.execute(CreateAuthorizationResponseArgs(missingOriginRequest, selected))
            assertTrue(missingOriginResult.isErr, "dc_api mdoc signing must fail closed without parser-provided origin")
        }

    private fun resolvedRequest(
        responseMode: ResponseMode = ResponseMode.DIRECT_POST,
        clientMetadata: ClientMetadata? = null,
        callerOrigin: String? = null,
        dcqlQuery: DcqlQuery? = null,
    ): ResolvedOid4vpRequest {
        val isDigitalCredentialsApi = responseMode == ResponseMode.DC_API || responseMode == ResponseMode.DC_API_JWT
        val isDirectPost = responseMode == ResponseMode.DIRECT_POST || responseMode == ResponseMode.DIRECT_POST_JWT
        val clientId = if (isDigitalCredentialsApi) "origin:${callerOrigin ?: "https://wallet.example.test"}" else "https://verifier.acme.example"
        val authRequest =
            AuthorizationRequest(
                clientId = clientId,
                redirectUri = if (isDigitalCredentialsApi || isDirectPost) null else "https://verifier.acme.example/callback",
                responseType = "vp_token",
                responseMode = responseMode.value,
                scope = null,
                state = "test-state",
                nonce = "test-nonce",
                additionalParameters =
                    buildMap {
                        if (isDirectPost) {
                            put("response_uri", JsonPrimitive("https://verifier.acme.example/oid4vp/auth/response"))
                        }
                        put("response_mode", JsonPrimitive(responseMode.value))
                        callerOrigin?.let { put(DIGITAL_CREDENTIAL_ORIGIN_PARAMETER, JsonPrimitive(it)) }
                    },
            )
        return ResolvedOid4vpRequest(
            request = authRequest,
            dcqlQuery = dcqlQuery,
            clientMetadata = clientMetadata,
            verifierInfo =
                VerifierInfo(
                    clientId = clientId,
                    clientIdScheme = ClientIdScheme.PRE_REGISTERED,
                    displayName = "Acme Verifier",
                ),
        )
    }

}

private object UnusedAddProofCommand : AddProofServiceCommand {
    override val inputTypeToken: TypeToken<AddProofInput> = typeToken<AddProofInput>()
    override val outputTypeToken: TypeToken<AddProofOutput> = typeToken<AddProofOutput>()
    override val isEnabled: Boolean = true
    override suspend fun execute(args: AddProofInput): IdkResult<AddProofOutput, IdkError> =
        error("Data Integrity proof creation is not used by the mdoc test")
}
