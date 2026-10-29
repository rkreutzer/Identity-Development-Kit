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

import com.sphereon.cbor.CborParserImpl
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
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
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.kms.CertificateServiceImpl
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.di.app.AbstractAppGraph
import com.sphereon.di.app.RootScopeProvider
import com.sphereon.mdoc.MdocSignService
import com.sphereon.mdoc.MdocSignServiceImpl
import com.sphereon.mdoc.SessionTranscriptCborCodecImpl
import com.sphereon.mdoc.data.device.DataElementIdentifier
import com.sphereon.mdoc.data.device.DeviceResponse
import com.sphereon.mdoc.data.device.DeviceResponseCborCodecImpl
import com.sphereon.mdoc.data.device.DocType
import com.sphereon.mdoc.data.device.Document
import com.sphereon.mdoc.data.device.IssuerSigned
import com.sphereon.mdoc.data.device.IssuerSignedItem
import com.sphereon.mdoc.data.device.IssuerSignedItemCborCodecImpl
import com.sphereon.mdoc.data.device.NameSpace
import com.sphereon.mdoc.data.mso.DigestID
import com.sphereon.mdoc.data.mso.MobileSecurityObjectCborCodecImpl
import com.sphereon.openid.oid4vp.common.CredentialFormat
import com.sphereon.openid.oid4vp.verifier.HolderBindingResult
import com.sphereon.openid.oid4vp.verifier.VerifyHolderBindingArgs
import com.sphereon.openid.oid4vp.verifier.VerifyHolderBindingCommand
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerificationArgs
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerificationResult
import com.sphereon.openid.oid4vp.verifier.VcdmDataIntegrityVerifier
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.DependencyGraph
import dev.zacsweers.metro.Named
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.createGraphFactory
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Verifies that the verifier's claim-extraction surfaces disclosed mso_mdoc data elements into
 * the normalized claims map, exactly as the SD-JWT path does for SD-JWT disclosures.
 *
 * A REAL ISO 18013-5 mdoc is issued (issuer-signed MSO over two namespaces), the produced
 * `IssuerSigned` is wrapped into a `DeviceResponse`, CBOR-encoded with the real
 * [DeviceResponseCborCodecImpl] and base64url-encoded into the OID4VP wire form. The verifier
 * then extracts the claims with the real codec wired in — no fakes.
 */
class ValidateAuthorizationResponseMdocClaimExtractionTest {
    private val mdlDocType = DocType("org.iso.18013.5.1.mDL")
    private val mdlNamespace = NameSpace("org.iso.18013.5.1")
    private val extraNamespace = NameSpace("org.iso.18013.5.1.aamva")

    @DependencyGraph(AppScope::class)
    abstract class TestVerifierMdocAppGraph : AbstractAppGraph() {
        @DependencyGraph.Factory
        fun interface Factory {
            fun create(
                @Provides application: Any,
                @Provides @Named("appId") appId: String,
                @Provides @Named("profile") profile: String,
                @Provides @Named("version") version: String,
                @Provides rootScopeProvider: RootScopeProvider,
            ): TestVerifierMdocAppGraph
        }
    }

    private class Setup(
        testInstance: Any
    ) {
        val app: AbstractAppGraph =
            createGraphFactory<TestVerifierMdocAppGraph.Factory>()
                .create(
                    application = testInstance,
                    appId = "test-verifier-mdoc",
                    profile = "test",
                    version = "1.0.0-test",
                    rootScopeProvider = DefaultRootScopeProvider(),
                ).also { it.initRootScopeProvider() }

        val userContext = app.userContextManager.getAnonymous()
        val sessionContext = userContext.sessionContextManager.createOrGetFromId("verifier-mdoc-${Uuid.v4String()}", principalType = com.sphereon.di.context.PrincipalType.USER)
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
                commonName = "Test mDL Issuer",
                organizationName = "Test",
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
    fun `extracts mso_mdoc claims as namespace-qualified entries with unwrapped values`() =
        runTest {
            val setup = Setup(this)

            // Holder device key bound into the MSO (PUBLIC half only).
            val deviceKeyPair =
                setup.kms.generateKeyAsync(
                    alias = null,
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                    keyVisibility = KeyVisibility.PRIVATE,
                    providerId = null,
                )
            val deviceKeyInfo = deviceKeyPair.toManagedKeyInfo<CoseKey>(KeyVisibility.PUBLIC, KeyEncoding.COSE)

            val issuerKeyInfo = issuerKeyWithCert(setup)
            val now = DateTimeUtils.DEFAULTS.dateTimeLocal()

            val givenName =
                IssuerSignedItem.create(
                    digestID = DigestID(1u),
                    elementIdentifier = DataElementIdentifier("given_name"),
                    elementValue = "Jane",
                )
            val familyName =
                IssuerSignedItem.create(
                    digestID = DigestID(2u),
                    elementIdentifier = DataElementIdentifier("family_name"),
                    elementValue = "Doe",
                )
            val ageOver18 =
                IssuerSignedItem.create(
                    digestID = DigestID(3u),
                    elementIdentifier = DataElementIdentifier("age_over_18"),
                    elementValue = true,
                )
            val aamvaName =
                IssuerSignedItem.create(
                    digestID = DigestID(4u),
                    elementIdentifier = DataElementIdentifier("organ_donor"),
                    elementValue = "yes",
                )

            // A real signed mdoc spanning two namespaces — verifies namespace qualification.
            val issuerSigned =
                IssuerSigned
                    .MsoBuilder(issuerSignedItemCborCodec = IssuerSignedItemCborCodecImpl())
                    .withDocType(mdlDocType)
                    .withDeviceKeyInfo(deviceKeyInfo)
                    .withSigningKeyInfo(issuerKeyInfo)
                    .withSigned(now)
                    .withValidFrom(now)
                    .withValidUntil(now)
                    .also {
                        it.addNameSpace(
                            mdlNamespace,
                            givenName as IssuerSignedItem<Any>,
                            familyName as IssuerSignedItem<Any>,
                            ageOver18 as IssuerSignedItem<Any>,
                        )
                        it.addNameSpace(extraNamespace, aamvaName as IssuerSignedItem<Any>)
                    }.buildAndSign(mdocSignService = setup.mdocSignService, requireDeviceX5Chain = false)

            val deviceResponse =
                DeviceResponse(
                    documents =
                        arrayOf(
                            Document(
                                docType = mdlDocType,
                                issuerSigned = issuerSigned,
                                deviceSigned = null,
                                original = null,
                            ),
                        ),
                    original = null,
                )

            // OID4VP wire form: base64url(CBOR(DeviceResponse)).
            val presentation = DeviceResponseCborCodecImpl().encode(deviceResponse).getOrThrow().encodeToBase64Url()

            val command =
                ValidateAuthorizationResponseCommandImpl(
                    execution = setup.execution,
                    authorizationSessionStore = TestAuthorizationSessionStore(),
                    verifyHolderBindingCommand = AlwaysValidHolderBindingCommandForMdoc,
                    verifyJwsCommand = RejectingVerifyJwsCommand,
                    jsonLdContextValidator =
                        com.sphereon.jsonld.command.JsonLdContextValidator(
                            com.sphereon.jsonld.loader.BuiltInContextLinkedDataDocumentLoader(
                                com.sphereon.jsonld.loader
                                    .DefaultBuiltInContextRegistry(),
                            ),
                        ),
                    jsonLdSchemaValidator =
                        com.sphereon.jsonld.command.JsonLdSchemaValidator(
                            com.sphereon.jsonld.command
                                .MapBackedJsonLdSchemaRegistry(emptyMap()),
                     ),
                     deviceResponseCborCodec = DeviceResponseCborCodecImpl(),
                     mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                     cborParser = CborParserImpl(),
                     vcdmDataIntegrityVerifier = RejectingVcdmDataIntegrityVerifierForMdoc,
                    credentialStatusVerifiers = emptySet(),
                    credentialTrustValidators = emptySet(),
                    businessAuthorizations = emptySet(),
                    credentialTypeMatcher = com.sphereon.openid.oid4vp.verifier.impl.testutil.testCredentialTypeMatcher(),
                )

            val projection = command.extractClaimProjections(presentation, CredentialFormat.MSO_MDOC).value.single()
            val claims = projection.claims

            // Keys are <namespace>.<elementIdentifier>, mirroring mdoc DCQL [namespace, element] paths.
            assertEquals(JsonPrimitive("Jane"), claims["org.iso.18013.5.1.given_name"])
            assertEquals(JsonPrimitive("Doe"), claims["org.iso.18013.5.1.family_name"])
            assertEquals(JsonPrimitive(true), claims["org.iso.18013.5.1.age_over_18"])
            assertEquals(JsonPrimitive("yes"), claims["org.iso.18013.5.1.aamva.organ_donor"])
            assertEquals(4, claims.size)
            // The query root nests the same values by namespace, the shape DCQL claim paths address.
            assertEquals(JsonPrimitive("yes"), (projection.queryRoot["org.iso.18013.5.1.aamva"] as JsonObject)["organ_donor"])
            assertEquals("org.iso.18013.5.1.mDL", projection.credentialType)
        }

    @Test
    fun shouldRefuseAnUndecodableMdocPresentationInsteadOfReportingNoClaims() =
        runTest {
            val setup = Setup(this)
            val command =
                ValidateAuthorizationResponseCommandImpl(
                    execution = setup.execution,
                    authorizationSessionStore = TestAuthorizationSessionStore(),
                    verifyHolderBindingCommand = AlwaysValidHolderBindingCommandForMdoc,
                    verifyJwsCommand = RejectingVerifyJwsCommand,
                    jsonLdContextValidator =
                        com.sphereon.jsonld.command.JsonLdContextValidator(
                            com.sphereon.jsonld.loader.BuiltInContextLinkedDataDocumentLoader(
                                com.sphereon.jsonld.loader
                                    .DefaultBuiltInContextRegistry(),
                            ),
                        ),
                    jsonLdSchemaValidator =
                        com.sphereon.jsonld.command.JsonLdSchemaValidator(
                            com.sphereon.jsonld.command
                                .MapBackedJsonLdSchemaRegistry(emptyMap()),
                     ),
                     deviceResponseCborCodec = DeviceResponseCborCodecImpl(),
                     mobileSecurityObjectCborCodec = MobileSecurityObjectCborCodecImpl(),
                     cborParser = CborParserImpl(),
                     vcdmDataIntegrityVerifier = RejectingVcdmDataIntegrityVerifierForMdoc,
                    credentialStatusVerifiers = emptySet(),
                    credentialTrustValidators = emptySet(),
                    businessAuthorizations = emptySet(),
                    credentialTypeMatcher = com.sphereon.openid.oid4vp.verifier.impl.testutil.testCredentialTypeMatcher(),
                )

            // Valid base64url ("notcbor") but not a CBOR DeviceResponse: refused, never an empty claims map.
            assertTrue(command.extractClaimProjections("bm90Y2Jvcg", CredentialFormat.MSO_MDOC).isErr)
            assertTrue(command.extractClaimProjections("!!", CredentialFormat.MSO_MDOC).isErr)
        }
}

private object RejectingVcdmDataIntegrityVerifierForMdoc : VcdmDataIntegrityVerifier {
    override suspend fun verify(args: VcdmDataIntegrityVerificationArgs): IdkResult<VcdmDataIntegrityVerificationResult, IdkError> =
        Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Data Integrity test stub was not configured"))
}

/**
 * Holder-binding stub. The claim-extraction tests call [ValidateAuthorizationResponseCommandImpl.extractDisclosedClaims]
 * directly, so the command never dispatches to this; it only satisfies the constructor dependency.
 */
private object AlwaysValidHolderBindingCommandForMdoc : VerifyHolderBindingCommand {
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

private object RejectingVerifyJwsCommand : VerifyJwsCommand {
    override val commandId: String = VerifyJwsCommand.COMMAND_ID
    override val inputTypeToken: TypeToken<VerifyJwsArgs> = typeToken<VerifyJwsArgs>()
    override val outputTypeToken: TypeToken<com.sphereon.crypto.jose.jws.JwsValidationResult> =
        typeToken<com.sphereon.crypto.jose.jws.JwsValidationResult>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is VerifyJwsArgs

    override suspend fun execute(args: VerifyJwsArgs): IdkResult<com.sphereon.crypto.jose.jws.JwsValidationResult, IdkError> =
        com.sphereon.core.api.Err(IdkError.fromString("not used by claim extraction tests"))
}
