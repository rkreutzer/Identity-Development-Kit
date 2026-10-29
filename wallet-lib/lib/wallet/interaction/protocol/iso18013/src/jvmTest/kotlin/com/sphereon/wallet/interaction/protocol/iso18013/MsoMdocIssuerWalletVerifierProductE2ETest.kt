/*
 * Copyright (c) 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0.
 */

package com.sphereon.wallet.interaction.protocol.iso18013

import com.sphereon.cbor.CborByteString
import com.sphereon.cbor.CborString
import com.sphereon.core.api.Encoding
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.conf.AppConfigService
import com.sphereon.core.api.conf.MapPropertySource
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFrom
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.events.EventTypes
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.core.api.http.command.HttpEndpointCommandRegistry
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteMatch
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.core.defaults.context.DefaultPrincipalInputString
import com.sphereon.core.defaults.context.DefaultTenantInputString
import com.sphereon.core.events.EventHub
import com.sphereon.crypto.core.CoseCryptoServiceImpl
import com.sphereon.crypto.core.CryptoServices
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyInfo
import com.sphereon.crypto.core.cose.CoseHeaderCbor
import com.sphereon.crypto.core.cose.CoseSign1CborCodecImpl
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.generic.X509DistinguishedNameElements
import com.sphereon.crypto.core.interop.getPublicKeyJwk
import com.sphereon.crypto.core.interop.x509CertificateFromDer
import com.sphereon.crypto.core.kms.CertificateService
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.X509CertificateExtensionSpec
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.core.x509.Certificate
import com.sphereon.crypto.core.x509.X509ExtensionOids
import com.sphereon.crypto.dataintegrity.command.AddProofInput
import com.sphereon.crypto.dataintegrity.command.AddProofOutput
import com.sphereon.crypto.dataintegrity.command.AddProofServiceCommand
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.data.store.blob.BlobService
import com.sphereon.data.store.blob.BlobStore
import com.sphereon.data.store.blob.BlobStoreConfigBase
import com.sphereon.data.store.blob.InMemoryBlobStoreConfig
import com.sphereon.data.store.blob.impl.BlobStoreService
import com.sphereon.data.store.blob.impl.DefaultBlobService
import com.sphereon.data.store.blob.impl.DefaultRetentionPolicyService
import com.sphereon.data.store.blob.impl.KvBlobMetadataIndex
import com.sphereon.data.store.blob.memory.InMemoryBlobBackingStorageImpl
import com.sphereon.data.store.blob.memory.InMemoryBlobStoreFactoryImpl
import com.sphereon.data.store.kv.InMemoryKvStoreConfig
import com.sphereon.data.store.kv.KvStoreScopeBinding
import com.sphereon.data.store.kv.impl.KvStoreService
import com.sphereon.data.store.kv.memory.InMemoryKvBackingStorageImpl
import com.sphereon.data.store.kv.memory.InMemoryKvStoreFactoryImpl
import com.sphereon.di.context.PrincipalType
import com.sphereon.di.session.SessionScope
import com.sphereon.mdoc.MdocSignServiceImpl
import com.sphereon.mdoc.SessionTranscriptCborCodecImpl
import com.sphereon.mdoc.data.device.DeviceResponseCborCodecImpl
import com.sphereon.mdoc.data.device.IssuerSignedCborCodecImpl
import com.sphereon.mdoc.data.device.IssuerSignedItemCborCodecImpl
import com.sphereon.mdoc.data.mso.MobileSecurityObjectCborCodecImpl
import com.sphereon.mdoc.oid4vp.MdocOid4vpServiceImpl
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import com.sphereon.openid.oid4vci.issuer.impl.format.MsoMdocFormatHandler
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.mdocMeta
import com.sphereon.openid.oid4vp.holder.CreateAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.holder.CreateAuthorizationResponseCommand
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.SelectedCredential
import com.sphereon.openid.oid4vp.holder.impl.CreateAuthorizationResponseCommandImpl
import com.sphereon.openid.oid4vp.holder.impl.JwtServiceHolderJwtVpSigningProvider
import com.sphereon.openid.oid4vp.verifier.CreateAuthorizationRequestArgs
import com.sphereon.openid.oid4vp.verifier.Oid4vpVerifierService
import com.sphereon.openid.oid4vp.verifier.ParseAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.verifier.ValidateAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.verifier.ValidationResult
import com.sphereon.openid.oid4vp.verifier.impl.Oid4VpVerifierServiceImpl
import com.sphereon.statuslist.AllocateEntryArgs
import com.sphereon.statuslist.CreateStatusListArgs
import com.sphereon.statuslist.CredentialStatusInput
import com.sphereon.statuslist.CredentialStatusReference
import com.sphereon.statuslist.EntryRef
import com.sphereon.statuslist.MdocCwtStatusListSigningArgs
import com.sphereon.statuslist.MdocStatusListPayload
import com.sphereon.statuslist.MdocStatusListProfile
import com.sphereon.statuslist.ResolvedStatus
import com.sphereon.statuslist.StatusListBinding
import com.sphereon.statuslist.StatusListContentTypes
import com.sphereon.statuslist.StatusListRef
import com.sphereon.statuslist.StatusListSpec
import com.sphereon.statuslist.StatusListToken
import com.sphereon.statuslist.StatusProofFormat
import com.sphereon.statuslist.StatusPurpose
import com.sphereon.statuslist.StatusValues
import com.sphereon.statuslist.UpdateEntryStatusArgs
import com.sphereon.statuslist.hosting.rest.StatusListHostingConfig
import com.sphereon.statuslist.hosting.rest.adapter.StatusListHostingHttpAdapter
import com.sphereon.statuslist.hosting.rest.command.GetStatusListTokenByCorrelationIdEndpointCommandImpl
import com.sphereon.statuslist.hosting.rest.http.GetStatusListTokenByCorrelationIdEndpointCommand
import com.sphereon.statuslist.impl.codec.MdocRevocationCwtClaimsCodecImpl
import com.sphereon.statuslist.impl.command.GetStatusListTokenCommandImpl
import com.sphereon.statuslist.impl.driver.InMemoryStatusListDriver
import com.sphereon.statuslist.impl.driver.InMemoryStatusListStore
import com.sphereon.statuslist.impl.enrich.CredentialStatusEnricherImpl
import com.sphereon.statuslist.impl.sign.MdocCwtStatusListSigner
import com.sphereon.statuslist.impl.verify.MdocCredentialStatusVerifier
import com.sphereon.statuslist.spi.CredentialStatusVerifier
import com.sphereon.statuslist.spi.StatusListResolver
import com.sphereon.statuslist.spi.StatusListSigner
import com.sphereon.wallet.credential.BodyStorageKind
import com.sphereon.wallet.credential.BodyStorageRef
import com.sphereon.wallet.credential.CredentialInstance
import com.sphereon.wallet.credential.CredentialLifecycleState
import com.sphereon.wallet.credential.CredentialMetadataFilter
import com.sphereon.wallet.credential.CredentialRecord
import com.sphereon.wallet.credential.CredentialTypeRef
import com.sphereon.wallet.credential.CredentialTypeRefKind
import com.sphereon.wallet.credential.CredentialTypeRefSource
import com.sphereon.wallet.credential.CredentialValidityWindow
import com.sphereon.wallet.credential.IdentifierRef
import com.sphereon.wallet.credential.KeyRef
import com.sphereon.wallet.credential.StoreRef
import com.sphereon.wallet.credential.store.BlobWalletCredentialStore
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Provider
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.get
import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.headersOf
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.TestResult
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.datetime.Clock
import kotlinx.datetime.DateTimeUnit
import kotlinx.datetime.plus
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import java.util.zip.Deflater
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import com.sphereon.wallet.credential.CredentialFormat as WalletCredentialFormat

/**
 * In-process transport for the graph-selected status-list resolver. The HTTP edge remains a
 * Ktor MockEngine, but every response is produced by the real status hosting adapter and endpoint
 * command over the real status-list driver.
 */
@Inject
@SingleIn(SessionScope::class)
class ProductStatusListTransport {
    private val adapters = mutableMapOf<String, StatusListHostingHttpAdapter>()
    private val requestCounts = mutableMapOf<String, Int>()
    private val explicitResponses = mutableMapOf<String, ProductHostedStatusResponse>()

    fun register(
        uri: String,
        adapter: StatusListHostingHttpAdapter
    ) {
        adapters[Url(uri).encodedPath] = adapter
    }

    fun requestCount(uri: String): Int = requestCounts[Url(uri).encodedPath] ?: 0

    fun host(
        uri: String,
        bytes: ByteArray,
        contentType: String,
        status: HttpStatusCode = HttpStatusCode.OK
    ) {
        explicitResponses[Url(uri).encodedPath] = ProductHostedStatusResponse(bytes, contentType, status)
    }

    fun unavailable(uri: String) {
        explicitResponses[Url(uri).encodedPath] =
            ProductHostedStatusResponse(
                bytes = "unavailable".encodeToByteArray(),
                contentType = "text/plain",
                status = HttpStatusCode.ServiceUnavailable,
            )
    }

    fun client(): HttpClient =
        HttpClient(
            MockEngine { request ->
                val path = request.url.encodedPath
                requestCounts[path] = (requestCounts[path] ?: 0) + 1
                explicitResponses[path]?.let { response ->
                    return@MockEngine respond(
                        response.bytes,
                        status = response.status,
                        headers = headersOf(HttpHeaders.ContentType, response.contentType),
                    )
                }
                val adapter = adapters[path]
                if (adapter == null) {
                    respond(ByteArray(0), status = HttpStatusCode.NotFound, headers = headersOf())
                } else {
                    val generic =
                        GenericHttpRequest.withTextBody(
                            method = "GET",
                            path = path,
                            body = null,
                            headers = mapOf("Host" to request.url.host),
                        )
                    val response =
                        adapter.handleResolvedRequest(
                            generic,
                            HttpAdapterRouteMatch(
                                adapterId = adapter.id,
                                method = generic.method,
                                originalPath = path,
                                normalizedPath = path,
                                matchedPathPattern = "/public/statuslists/{correlationId}",
                                handlerCommandId = GetStatusListTokenByCorrelationIdEndpointCommand.COMMAND_ID,
                                tenantIdFromPath = null,
                            ),
                        )
                    respond(
                        response.bodyBytes ?: ByteArray(0),
                        status = HttpStatusCode.fromValue(response.statusCode),
                        headers = response.toKtorHeaders(),
                    )
                }
            }
        )
}

private fun com.sphereon.core.api.http.GenericHttpResponse.toKtorHeaders(): Headers =
    Headers.build {
        val multiValueNames = multiValueHeaders.keys
        headers.forEach { (name, value) ->
            if (multiValueNames.none { it.equals(name, ignoreCase = true) }) {
                append(name, value)
            }
        }
        multiValueHeaders.forEach { (name, values) ->
            values.forEach { value -> append(name, value) }
        }
    }

private data class ProductHostedStatusResponse(
    val bytes: ByteArray,
    val contentType: String,
    val status: HttpStatusCode,
)

/**
 * Observes the real mdoc verifier without replacing any decision. These counters keep the product
 * failure boundary explicit: typed MSO dispatch, reference recognition, resolution, or transport.
 */
private class ProductStatusVerifierTrace(
    private val delegate: CredentialStatusVerifier,
) : CredentialStatusVerifier {
    override val mechanism: String = delegate.mechanism
    var typedReferenceCalls: Int = 0
        private set
    var recognizedReferenceCount: Int = 0
        private set
    var resolveCalls: Int = 0
        private set
    var lastResolutionError: IdkError? = null
        private set

    override fun references(credentialClaims: kotlinx.serialization.json.JsonObject): List<CredentialStatusReference> = delegate.references(credentialClaims)

    override fun references(input: CredentialStatusInput): List<CredentialStatusReference> {
        typedReferenceCalls += 1
        return delegate.references(input).also { recognizedReferenceCount += it.size }
    }

    override suspend fun resolve(reference: CredentialStatusReference): IdkResult<ResolvedStatus, IdkError> =
        delegate.resolve(reference).also { result ->
            resolveCalls += 1
            result.onFailure { error -> lastResolutionError = error }
        }
}

@ContributesTo(SessionScope::class)
interface ProductStatusListTransportGraph {
    val productStatusListTransport: ProductStatusListTransport
}

@ContributesTo(SessionScope::class)
interface ProductStatusListResolverGraph {
    val statusListResolver: StatusListResolver
}

/** Replace only the platform HTTP factory; resolver, CWT verification, and trust remain real. */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(
    SessionScope::class,
    binding = binding<com.sphereon.ktor.http.client.provider.HttpClientFactory>(),
    replaces = [com.sphereon.ktor.http.client.provider.HttpClientFactoryJvmImpl::class],
)
class ProductStatusListHttpClientFactory(
    private val transport: ProductStatusListTransport,
) : com.sphereon.ktor.http.client.provider.HttpClientFactory {
    override fun createClient(options: com.sphereon.ktor.http.client.provider.HttpClientOptions): HttpClient = transport.client()

    override fun isSupportedOptions(options: com.sphereon.ktor.http.client.provider.HttpClientOptions): Boolean = true

    override fun getEngineTypesSupported(): List<com.sphereon.ktor.http.client.provider.HttpClientEngineType> = listOf(com.sphereon.ktor.http.client.provider.HttpClientEngineType.CIO)

    override fun getEngineTypeDefault(): com.sphereon.ktor.http.client.provider.HttpClientEngineType = com.sphereon.ktor.http.client.provider.HttpClientEngineType.CIO
}

private class ProductBlobStoreService(
    private val store: BlobStore
) : BlobStoreService {
    override fun getStoreIds(): Array<String> = arrayOf("memory")

    override fun getStoreConfig(storeId: String): BlobStoreConfigBase = InMemoryBlobStoreConfig(id = storeId)

    override fun getStore(storeId: String): BlobStore = store
}

private object UnusedAddProofCommand : AddProofServiceCommand {
    override val inputTypeToken: TypeToken<AddProofInput> = typeToken<AddProofInput>()
    override val outputTypeToken: TypeToken<AddProofOutput> = typeToken<AddProofOutput>()
    override val isEnabled: Boolean = true

    override suspend fun execute(args: AddProofInput): IdkResult<AddProofOutput, IdkError> = error("Data Integrity proof creation is not used by the mdoc product command test")
}

private class ProductKvStoreService(
    private val store: com.sphereon.data.store.kv.KvStore
) : KvStoreService {
    override fun getStoreIds(): Array<String> = arrayOf(KvBlobMetadataIndex.STORE_ID)

    override fun getStoreConfig(storeId: String): com.sphereon.data.store.kv.KvStoreConfigBase = InMemoryKvStoreConfig(id = storeId, scopeBinding = KvStoreScopeBinding.APP)

    override fun getStore(storeId: String) = store
}

private class ProductEventService : com.sphereon.core.events.SessionEventService {
    private val hub =
        com.sphereon.core.events.impl
            .EventHubImpl()
    override val scope = com.sphereon.core.api.context.IdkScope.SESSION
    override val eventHub = hub
    override val parent get() = throw NotImplementedError("product test does not use parent events")
    override val sessionContext = com.sphereon.di.context.NoOpSessionContext

    override suspend fun emit(event: com.sphereon.core.events.Event) {
        hub.publish(event)
    }

    override suspend fun emit(
        event: com.sphereon.core.events.Event,
        sign: Boolean,
        encrypt: Boolean,
        keyAlias: String?,
        encryptionKeyAlias: String?,
        encryptParts: Set<com.sphereon.core.events.EncryptedPart>
    ) {
        hub.publish(event)
    }

    override fun eventBuilder() =
        com.sphereon.core.events.impl
            .DefaultEventBuilder(scope)
}

private class ProductSessionExecution : SessionExecution {
    override val sessionContext = com.sphereon.di.context.NoOpSessionContext
    override val sessionContextManager get() = throw NotImplementedError("product test does not use session manager")
    override val log =
        object : com.sphereon.core.api.log.SessionLogService {
            override val id = "product-mdoc-log"
            override val isEnabled = false
            override val scope = com.sphereon.core.api.context.IdkScope.SESSION
            override val sessionContext = com.sphereon.di.context.NoOpSessionContext
            override val logManager get() = throw NotImplementedError("product test does not log")

            override suspend fun setConfig(config: com.sphereon.core.api.log.LoggerConfig) = this

            override fun executeAsync(message: com.sphereon.core.api.log.LogMessage) =
                com.sphereon.core.api
                    .Ok(Unit)

            override fun toAsync() = throw NotImplementedError("product test does not log")
        }
    override val conf get() = throw NotImplementedError("product test does not use config")
}

private object TestCredentialBodyProtector : com.sphereon.wallet.credential.store.WalletCredentialBodyProtector {
    override suspend fun protect(
        walletUnitId: String,
        credentialRecordId: String,
        credentialInstanceId: String,
        plaintext: ByteArray,
        documentRole: com.sphereon.wallet.credential.store.WalletCredentialProtectedDocumentRole
    ) = com.sphereon.core.api
        .Ok(plaintext.reversedArray())

    override suspend fun open(
        walletUnitId: String,
        credentialRecordId: String,
        credentialInstanceId: String,
        protectedBody: ByteArray,
        documentRole: com.sphereon.wallet.credential.store.WalletCredentialProtectedDocumentRole
    ) = com.sphereon.core.api
        .Ok(protectedBody.reversedArray())
}

private fun createTestBlobService(): DefaultBlobService {
    val blobStore = InMemoryBlobStoreFactoryImpl(InMemoryBlobBackingStorageImpl()).create(InMemoryBlobStoreConfig(id = "memory"))
    val kvStore = InMemoryKvStoreFactoryImpl(InMemoryKvBackingStorageImpl()).create(InMemoryKvStoreConfig(id = KvBlobMetadataIndex.STORE_ID, scopeBinding = KvStoreScopeBinding.APP))
    return DefaultBlobService(
        blobStoreService = ProductBlobStoreService(blobStore),
        metadataIndex = KvBlobMetadataIndex(ProductKvStoreService(kvStore)),
        retentionPolicyService = DefaultRetentionPolicyService(),
        tempUrlPolicy =
            com.sphereon.data.store.blob
                .DefaultTempUrlPolicy(),
        eventService = ProductEventService(),
        execution = ProductSessionExecution(),
    )
}

/**
 * Production product journey: OID4VCI mso_mdoc format handler -> BlobWalletCredentialStore ->
 * ISO wallet document provider -> real status verifier/resolver. Only the fetched status HTTP
 * edge is mocked; credential codecs, KMS signatures, and the wallet store/read adapters are
 * production implementations, while this test's blob/KV backing and body protector are in-memory
 * test implementations.
 */
private object EmptyTrustAnchorLoader : com.sphereon.trust.x509.X509TrustAnchorLoader {
    override suspend fun loadTrustedCerts(): List<String> = emptyList()
}

class MsoMdocIssuerWalletVerifierProductE2ETest {
    @Test
    fun productTransportPreservesProductionHostingStatusContentTypeAndCacheControl() =
        runProductTest {
            val setup = ProductSetup(this@MsoMdocIssuerWalletVerifierProductE2ETest)
            listOf(
                Triple("hosting-token", MdocStatusListProfile.STATUS_LIST, StatusListContentTypes.STATUSLIST_CWT),
                Triple("hosting-identifiers", MdocStatusListProfile.IDENTIFIER_LIST, StatusListContentTypes.IDENTIFIERLIST_CWT),
            ).forEach { (id, profile, contentType) ->
                val uri = "https://issuer.example/public/statuslists/$id"
                val driver = setup.newDriver()
                setup.createCertificateBearingKey(id)
                setup.createStatusList(driver, id, uri, profile)
                setup.graphStatusResolver(driver, uri)

                val response = setup.fetchHostedStatus(uri)

                assertEquals(HttpStatusCode.OK, response.status)
                assertEquals(contentType, response.headers[HttpHeaders.ContentType])
                assertEquals("public, max-age=0", response.headers[HttpHeaders.CacheControl])
            }
        }

    @Test
    fun tokenStatusIsAuthenticatedInMsoPersistedAndRejectedAfterPublicationChange() =
        runProductTest {
            val setup = ProductSetup(this@MsoMdocIssuerWalletVerifierProductE2ETest)
            val statusListId = "product-token"
            val uri = "https://issuer.example/public/statuslists/product-token"
            val firstSubject = "product-token-subject-1"
            val firstCredentialId = "urn:vdx:credential:product-token:1"
            val secondSubject = "product-token-subject-2"
            val secondCredentialId = "urn:vdx:credential:product-token:2"
            val driver = setup.newDriver()
            val alias = setup.createCertificateBearingKey(statusListId)
            setup.createStatusList(driver, statusListId, uri, MdocStatusListProfile.STATUS_LIST)
            assertNull(
                driver
                    .getEntry(EntryRef(correlationId = statusListId, entryCorrelationId = firstSubject))
                    .getOrElse { fail("read token status entry before issuance: $it") },
                "the issuer must not reuse a pre-existing status-list allocation",
            )
            val handler = setup.handler(driver)
            val envelope =
                setup.issue(
                    handler = handler,
                    statusListId = statusListId,
                    subject = firstSubject,
                    credentialId = firstCredentialId,
                    profile = MdocStatusListProfile.STATUS_LIST,
                    alias = alias,
                )
            assertNull(
                driver
                    .getEntry(EntryRef(correlationId = statusListId, entryCorrelationId = secondSubject))
                    .getOrElse { fail("read second token status entry before issuance: $it") },
                "the second credential must not have an allocation before its issuance begins",
            )
            val secondEnvelope =
                setup.issue(
                    handler = handler,
                    statusListId = statusListId,
                    subject = secondSubject,
                    credentialId = secondCredentialId,
                    profile = MdocStatusListProfile.STATUS_LIST,
                    alias = alias,
                )
            val issuerSignedBytes =
                envelope.credential.jsonPrimitive.content
                    .decodeFromBase64Url()
            val issuerSigned =
                setup.issuerSignedCodec
                    .decode(issuerSignedBytes)
                    .getOrElse { fail("decode IssuerSigned: $it") }
                    .value
            val mso =
                setup.msoCodec
                    .decode(issuerSigned.issuerAuth.payload?.value ?: fail("missing MSO payload"))
                    .getOrElse { fail("decode MSO: $it") }
                    .value
            val statusReference = assertNotNull(mso.status?.statusList, "status must be authenticated MSO metadata")
            val allocatedEntry =
                assertNotNull(
                    driver
                        .getEntry(EntryRef(correlationId = statusListId, entryCorrelationId = firstSubject))
                        .getOrElse { fail("read token status entry after issuance: $it") },
                    "issuance must reserve and bind one status-list entry before returning the signed MSO",
                )
            val secondIssuerSigned =
                setup.issuerSignedCodec
                    .decode(
                        secondEnvelope.credential.jsonPrimitive.content
                            .decodeFromBase64Url()
                    ).getOrElse { fail("decode second IssuerSigned: $it") }
                    .value
            val secondMso =
                setup.msoCodec
                    .decode(secondIssuerSigned.issuerAuth.payload?.value ?: fail("missing second MSO payload"))
                    .getOrElse { fail("decode second MSO: $it") }
                    .value
            val secondStatusReference = assertNotNull(secondMso.status?.statusList, "second status must be authenticated MSO metadata")
            val secondAllocatedEntry =
                assertNotNull(
                    driver
                        .getEntry(EntryRef(correlationId = statusListId, entryCorrelationId = secondSubject))
                        .getOrElse { fail("read second token status entry after issuance: $it") },
                    "the second issuance must reserve and bind its own status-list entry",
                )
            assertEquals(firstSubject, allocatedEntry.entryCorrelationId)
            assertEquals(firstCredentialId, allocatedEntry.credentialId, "the first allocation must bind the issued credential id")
            assertEquals(secondSubject, secondAllocatedEntry.entryCorrelationId)
            assertEquals(secondCredentialId, secondAllocatedEntry.credentialId, "the second allocation must bind the issued credential id")
            assertEquals(
                allocatedEntry.statusListIndex,
                driver
                    .getEntry(EntryRef(correlationId = statusListId, credentialId = firstCredentialId))
                    .getOrElse { fail("resolve first token allocation by credential id: $it") }
                    ?.statusListIndex,
            )
            assertEquals(
                secondAllocatedEntry.statusListIndex,
                driver
                    .getEntry(EntryRef(correlationId = statusListId, credentialId = secondCredentialId))
                    .getOrElse { fail("resolve second token allocation by credential id: $it") }
                    ?.statusListIndex,
            )
            assertNotEquals(allocatedEntry.statusListIndex, secondAllocatedEntry.statusListIndex, "two issuances on one list must allocate unique indices")
            assertEquals(allocatedEntry.statusListIndex.toUInt(), statusReference.idx, "the signed MSO must embed the allocated index")
            assertEquals(secondAllocatedEntry.statusListIndex.toUInt(), secondStatusReference.idx, "the second signed MSO must embed its own allocated index")
            assertEquals(uri, statusReference.uri)
            assertEquals(uri, secondStatusReference.uri)
            assertNull(allocatedEntry.identifier, "the one-bit Token Status List profile must use an index, not an identifier")
            assertNull(secondAllocatedEntry.identifier, "the one-bit Token Status List profile must not allocate identifiers")
            assertEquals(setup.holderCoseKey, mso.deviceKeyInfo.deviceKey.toPublicKey(), "MSO must bind the independent holder device key")
            assertTrue(
                issuerSigned.nameSpaces
                    ?.values
                    .orEmpty()
                    .flatMap { it.asList() }
                    .none { it.data().elementIdentifier.toString() == "status" }
            )

            val store = setup.walletStore()
            assertEquals(
                "product-token-holder",
                setup
                    .record(envelope.credential.jsonPrimitive.content, "product-token")
                    .instances
                    .single()
                    .holderKeyRef
                    ?.alias
            )
            store
                .putCredential("wallet-product", setup.record(envelope.credential.jsonPrimitive.content, "product-token"))
                .getOrElse { fail("persist mdoc: $it") }
            setup.assertPersistedStatusCredentialBoundary(
                store = store,
                recordId = "product-token",
                expectedRaw = envelope.credential.jsonPrimitive.content,
                expectedProfile = MdocStatusListProfile.STATUS_LIST,
                expectedUri = uri,
            )
            val resolver = setup.graphStatusResolver(driver, uri)
            val verifier = ProductStatusVerifierTrace(MdocCredentialStatusVerifier(resolver, setup.x509, EmptyTrustAnchorLoader))
            val provider =
                WalletStoreIso18013DocumentProvider(
                    credentialStore = store,
                    walletUnitId = "wallet-product",
                    issuerSignedCborCodec = setup.issuerSignedCodec,
                    mobileSecurityObjectCborCodec = setup.msoCodec,
                    credentialStatusVerifiers = setOf(verifier),
                )
            assertEquals(0, setup.statusRequestCount(uri), "status must not be fetched before presentation policy runs")
            val documents = provider.getDocuments()
            assertEquals(1, verifier.typedReferenceCalls, "provider must dispatch authenticated MSO status as typed metadata")
            assertEquals(1, verifier.recognizedReferenceCount, "real mdoc verifier must recognize the authenticated Token Status List reference")
            assertEquals(1, verifier.resolveCalls, "recognized Token Status List reference must reach real resolution exactly once")
            assertNull(verifier.lastResolutionError, "valid Token Status List resolution must not fail before presentation")
            assertEquals(1, documents.size, "valid signed status must be presentable")
            assertEquals(1, setup.statusRequestCount(uri), "one presentation decision must resolve authenticated status exactly once")

            driver
                .updateEntryStatus(
                    UpdateEntryStatusArgs(EntryRef(correlationId = statusListId, entryCorrelationId = firstSubject), StatusValues.INVALID),
                ).getOrElse { fail("revoke status: $it") }
            setup.publish(driver, uri)
            assertTrue(provider.getDocuments().isEmpty(), "verifier must reject after signed publication changes")
            assertEquals(2, setup.statusRequestCount(uri), "the post-change presentation decision must perform one fresh resolution")
        }

    @Test
    fun identifierListStatusIsAuthenticatedInMsoPersistedAndRejectedAfterPublicationChange() =
        runProductTest {
            val setup = ProductSetup(this@MsoMdocIssuerWalletVerifierProductE2ETest)
            val statusListId = "product-identifiers"
            val uri = "https://issuer.example/public/statuslists/product-identifiers"
            val firstSubject = "product-identifiers-subject-1"
            val firstCredentialId = "urn:vdx:credential:product-identifiers:1"
            val secondSubject = "product-identifiers-subject-2"
            val secondCredentialId = "urn:vdx:credential:product-identifiers:2"
            val driver = setup.newDriver()
            val alias = setup.createCertificateBearingKey(statusListId)
            setup.createStatusList(driver, statusListId, uri, MdocStatusListProfile.IDENTIFIER_LIST)
            assertNull(
                driver
                    .getEntry(EntryRef(correlationId = statusListId, entryCorrelationId = firstSubject))
                    .getOrElse { fail("read identifier status entry before issuance: $it") },
                "the issuer must not reuse a pre-existing identifier allocation",
            )
            val handler = setup.handler(driver)
            val envelope =
                setup.issue(
                    handler = handler,
                    statusListId = statusListId,
                    subject = firstSubject,
                    credentialId = firstCredentialId,
                    profile = MdocStatusListProfile.IDENTIFIER_LIST,
                    alias = alias,
                )
            assertNull(
                driver
                    .getEntry(EntryRef(correlationId = statusListId, entryCorrelationId = secondSubject))
                    .getOrElse { fail("read second identifier status entry before issuance: $it") },
                "the second credential must not have an identifier before its issuance begins",
            )
            val secondEnvelope =
                setup.issue(
                    handler = handler,
                    statusListId = statusListId,
                    subject = secondSubject,
                    credentialId = secondCredentialId,
                    profile = MdocStatusListProfile.IDENTIFIER_LIST,
                    alias = alias,
                )
            val issuerSignedBytes =
                envelope.credential.jsonPrimitive.content
                    .decodeFromBase64Url()
            val issuerSigned =
                setup.issuerSignedCodec
                    .decode(issuerSignedBytes)
                    .getOrElse { fail("decode IssuerSigned: $it") }
                    .value
            val mso =
                setup.msoCodec
                    .decode(issuerSigned.issuerAuth.payload?.value ?: fail("missing MSO payload"))
                    .getOrElse { fail("decode MSO: $it") }
                    .value
            val statusReference = assertNotNull(mso.status?.identifierList, "identifier reference must be authenticated MSO metadata")
            val allocatedEntry =
                assertNotNull(
                    driver
                        .getEntry(EntryRef(correlationId = statusListId, entryCorrelationId = firstSubject))
                        .getOrElse { fail("read identifier status entry after issuance: $it") },
                    "issuance must reserve and bind one identifier before returning the signed MSO",
                )
            val secondIssuerSigned =
                setup.issuerSignedCodec
                    .decode(
                        secondEnvelope.credential.jsonPrimitive.content
                            .decodeFromBase64Url()
                    ).getOrElse { fail("decode second identifier IssuerSigned: $it") }
                    .value
            val secondMso =
                setup.msoCodec
                    .decode(secondIssuerSigned.issuerAuth.payload?.value ?: fail("missing second identifier MSO payload"))
                    .getOrElse { fail("decode second identifier MSO: $it") }
                    .value
            val secondStatusReference = assertNotNull(secondMso.status?.identifierList, "second identifier reference must be authenticated MSO metadata")
            val secondAllocatedEntry =
                assertNotNull(
                    driver
                        .getEntry(EntryRef(correlationId = statusListId, entryCorrelationId = secondSubject))
                        .getOrElse { fail("read second identifier status entry after issuance: $it") },
                    "the second issuance must reserve and bind its own identifier",
                )
            assertEquals(firstSubject, allocatedEntry.entryCorrelationId)
            assertEquals(firstCredentialId, allocatedEntry.credentialId, "the first identifier allocation must bind the issued credential id")
            assertEquals(secondSubject, secondAllocatedEntry.entryCorrelationId)
            assertEquals(secondCredentialId, secondAllocatedEntry.credentialId, "the second identifier allocation must bind the issued credential id")
            val allocatedIdentifier = assertNotNull(allocatedEntry.identifier, "identifier profile allocation must persist an identifier")
            val secondAllocatedIdentifier = assertNotNull(secondAllocatedEntry.identifier, "second identifier profile allocation must persist an identifier")
            assertFalse(allocatedIdentifier.contentEquals(secondAllocatedIdentifier), "two issuances on one identifier list must allocate distinct identifiers")
            assertNotEquals(allocatedEntry.statusListIndex, secondAllocatedEntry.statusListIndex, "two identifier-list issuances must also reserve distinct entries")
            assertContentEquals(allocatedIdentifier, statusReference.id, "the signed MSO must embed the allocated identifier")
            assertContentEquals(secondAllocatedIdentifier, secondStatusReference.id, "the second signed MSO must embed its own allocated identifier")
            assertEquals(uri, statusReference.uri)
            assertEquals(uri, secondStatusReference.uri)
            assertEquals(setup.holderCoseKey, mso.deviceKeyInfo.deviceKey.toPublicKey(), "MSO must bind the independent holder device key")
            assertFalse(
                issuerSigned.nameSpaces
                    ?.values
                    .orEmpty()
                    .flatMap { it.asList() }
                    .any { it.data().elementIdentifier.toString() == "status" }
            )

            val store = setup.walletStore()
            assertEquals(
                "product-identifiers-holder",
                setup
                    .record(envelope.credential.jsonPrimitive.content, "product-identifiers")
                    .instances
                    .single()
                    .holderKeyRef
                    ?.alias
            )
            store
                .putCredential("wallet-product", setup.record(envelope.credential.jsonPrimitive.content, "product-identifiers"))
                .getOrElse { fail("persist identifier mdoc: $it") }
            setup.assertPersistedStatusCredentialBoundary(
                store = store,
                recordId = "product-identifiers",
                expectedRaw = envelope.credential.jsonPrimitive.content,
                expectedProfile = MdocStatusListProfile.IDENTIFIER_LIST,
                expectedUri = uri,
            )
            val verifier = ProductStatusVerifierTrace(MdocCredentialStatusVerifier(setup.graphStatusResolver(driver, uri), setup.x509, EmptyTrustAnchorLoader))
            val provider =
                WalletStoreIso18013DocumentProvider(
                    credentialStore = store,
                    walletUnitId = "wallet-product",
                    issuerSignedCborCodec = setup.issuerSignedCodec,
                    mobileSecurityObjectCborCodec = setup.msoCodec,
                    credentialStatusVerifiers = setOf(verifier),
                )
            assertEquals(0, setup.statusRequestCount(uri), "identifier status must not be fetched before presentation policy runs")
            val documents = provider.getDocuments()
            assertEquals(1, verifier.typedReferenceCalls, "provider must dispatch authenticated Identifier List status as typed metadata")
            assertEquals(1, verifier.recognizedReferenceCount, "real mdoc verifier must recognize the authenticated Identifier List reference")
            assertEquals(1, verifier.resolveCalls, "recognized Identifier List reference must reach real resolution exactly once")
            assertNull(verifier.lastResolutionError, "valid Identifier List resolution must not fail before presentation")
            assertEquals(1, documents.size, "valid signed Identifier List status must be presentable")
            assertEquals(1, setup.statusRequestCount(uri), "one identifier-list presentation decision must resolve exactly once")
            driver
                .updateEntryStatus(
                    UpdateEntryStatusArgs(EntryRef(correlationId = statusListId, entryCorrelationId = firstSubject), StatusValues.INVALID),
                ).getOrElse { fail("revoke identifier status: $it") }
            setup.publish(driver, uri)
            assertTrue(provider.getDocuments().isEmpty())
            assertEquals(2, setup.statusRequestCount(uri), "the post-change identifier decision must perform one fresh resolution")
        }

    /**
     * Command-level OID4VP journey: the verifier creates and persists the request, the wallet
     * reads the persisted mdoc and uses the holder key reference to build DeviceAuth, then the
     * production verifier parses and validates the response against the persisted session.
     */
    @Test
    fun productionOid4vpCommandAcceptsAndThenRejectsBothMdocStatusProfiles() =
        runProductTest {
            val setup = ProductSetup(this@MsoMdocIssuerWalletVerifierProductE2ETest)
            val verifier = setup.oid4vpVerifierService()
            listOf(
                "command-token" to MdocStatusListProfile.STATUS_LIST,
                "command-identifiers" to MdocStatusListProfile.IDENTIFIER_LIST,
            ).forEach { (id, profile) ->
                val uri = "https://issuer.example/public/statuslists/$id"
                val subject = "$id-subject"
                val credentialId = "urn:vdx:credential:$id"
                val driver = setup.newDriver()
                val alias = setup.createCertificateBearingKey(id)
                setup.createStatusList(driver, id, uri, profile)
                val handler = setup.handler(driver)
                val envelope =
                    setup.issue(
                        handler = handler,
                        statusListId = id,
                        subject = subject,
                        credentialId = credentialId,
                        profile = profile,
                        alias = alias,
                    )
                val store = setup.walletStore()
                val record = setup.record(envelope.credential.jsonPrimitive.content, id)
                assertEquals(
                    "$id-holder",
                    record.instances
                        .single()
                        .holderKeyRef
                        ?.alias
                )
                store.putCredential("wallet-product", record).getOrElse { fail("persist command mdoc: $it") }
                val statusVerifier = MdocCredentialStatusVerifier(setup.graphStatusResolver(driver, uri), setup.x509, EmptyTrustAnchorLoader)
                val documentProvider =
                    WalletStoreIso18013DocumentProvider(
                        credentialStore = store,
                        walletUnitId = "wallet-product",
                        issuerSignedCborCodec = setup.issuerSignedCodec,
                        mobileSecurityObjectCborCodec = setup.msoCodec,
                        credentialStatusVerifiers = setOf(statusVerifier),
                    )
                val walletDocument = documentProvider.getDocuments(Iso18013DocumentSelectorData(setOf("org.iso.18013.5.1.mDL"))).single()
                assertEquals(1, setup.statusRequestCount(uri), "wallet selection must perform the first valid $profile status fetch")
                assertEquals("$id-holder", walletDocument.keyAlias, "wallet must resolve the persisted holder key reference")
                assertFalse(walletDocument.keyAlias == alias, "issuer and holder key references must remain distinct")
                val storedCredential =
                    setup.issuerSignedCodec
                        .encode(walletDocument.document.issuerSigned)
                        .getOrElse { fail("encode wallet mdoc: $it") }
                        .encodeToBase64Url()
                val query =
                    DcqlQuery(
                        credentials = listOf(DcqlCredentialQuery(id = "mdoc", format = CredentialFormat.MSO_MDOC.value, meta = mdocMeta("org.iso.18013.5.1.mDL"))),
                    )

                suspend fun createValidationArgs(suffix: String): ValidateAuthorizationResponseArgs {
                    val request =
                        verifier
                            .createAuthorizationRequest(
                                CreateAuthorizationRequestArgs(
                                    instanceId = "product-verifier-$id",
                                    dcqlQuery = query,
                                    clientId = "https://verifier.example",
                                    responseUri = "https://verifier.example/oid4vp/response",
                                    responseMode = com.sphereon.openid.oid4vp.common.ResponseMode.DIRECT_POST,
                                    nonce = "nonce-$id$suffix",
                                    state = "state-$id$suffix",
                                    credentialStatusPolicies = mapOf("mdoc" to com.sphereon.statuslist.CredentialStatusPolicy(requireStatus = true)),
                                ),
                            ).getOrElse { fail("create persisted authorization request: $it") }
                    val holderResponse =
                        setup
                            .holderCommand()
                            .execute(
                                CreateAuthorizationResponseArgs(
                                    request =
                                        ResolvedOid4vpRequest(
                                            request = request.request,
                                            dcqlQuery = query,
                                            verifierInfo =
                                                com.sphereon.openid.oid4vp.holder.VerifierInfo(
                                                    clientId = request.request.clientId,
                                                    clientIdScheme = com.sphereon.openid.oid4vp.common.ClientIdScheme.PRE_REGISTERED,
                                                ),
                                        ),
                                    selectedCredentials =
                                        listOf(
                                            SelectedCredential(
                                                credentialQueryId = "mdoc",
                                                credentialId = id,
                                                presentation = JsonPrimitive(storedCredential),
                                                credentialFormat = CredentialFormat.MSO_MDOC,
                                                holderKeyRef = walletDocument.keyAlias,
                                            ),
                                        ),
                                ),
                            ).getOrElse { fail("create persisted DeviceResponse: $it") }
                    val wireVpToken = holderResponse.additionalParameters["vp_token"] ?: fail("missing vp_token")
                    val parsed =
                        verifier
                            .parseAuthorizationResponse(
                                ParseAuthorizationResponseArgs(
                                    responseParams =
                                        mapOf(
                                            "vp_token" to
                                                Json.encodeToString(
                                                    kotlinx.serialization.json.JsonElement
                                                        .serializer(),
                                                    wireVpToken
                                                ),
                                            "state" to request.request.state.orEmpty(),
                                        ),
                                    originalRequest = request.request,
                                ),
                            ).getOrElse { fail("parse persisted DeviceResponse: $it") }
                    return ValidateAuthorizationResponseArgs(
                        parsedResponse = parsed,
                        originalRequest = request.request,
                        dcqlQuery = query,
                        expectedNonce = request.request.nonce.orEmpty(),
                    )
                }

                val valid =
                    verifier
                        .validateAuthorizationResponse(createValidationArgs(""))
                        .getOrElse { fail("validate command before revocation: $it") }
                assertTrue(valid.valid, "production command must accept a valid $profile response: ${valid.errors}")
                assertEquals(2, setup.statusRequestCount(uri), "zero-age production hosting must re-fetch valid $profile status")
                driver
                    .updateEntryStatus(
                        UpdateEntryStatusArgs(EntryRef(correlationId = id, entryCorrelationId = subject), StatusValues.INVALID),
                    ).getOrElse { fail("revoke command status: $it") }
                setup.publish(driver, uri)
                val revoked =
                    verifier
                        .validateAuthorizationResponse(createValidationArgs("-revoked"))
                        .getOrElse { fail("validate command after revocation: $it") }
                assertFalse(revoked.valid, "production command must reject revoked $profile response")
                assertTrue(revoked.errors.any { it.contains("mdoc", ignoreCase = true) || it.contains("invalid", ignoreCase = true) })
                assertEquals(3, setup.statusRequestCount(uri), "post-publication $profile validation must perform a fresh network fetch")
            }
        }

    @Test
    fun issuerAuthOmitsStoredIacaRootAndVerifierAcceptsWithOnlyIacaTrusted() =
        runProductTest {
            val fixture =
                ProductSetup(this@MsoMdocIssuerWalletVerifierProductE2ETest).commandFixture(
                    id = "issuerauth-iaca-chain",
                    useIacaCertificateChain = true,
                )
            val issuerSigned =
                fixture.setup.issuerSignedCodec
                    .decode(fixture.issuedCredential.decodeFromBase64Url())
                    .getOrElse { fail("decode IACA-backed IssuerSigned: $it") }
                    .value
            assertNull(issuerSigned.issuerAuth.protectedHeader.x5chain, "IssuerAuth x5chain must not be protected")
            val emittedChain =
                (
                    issuerSigned.issuerAuth.unprotectedHeader?.x5chain
                        ?: fail("IssuerAuth has no unprotected x5chain")
                ).value.map { it.value }

            assertEquals(1, emittedChain.size, "IssuerAuth must omit the terminal self-signed IACA root")
            assertContentEquals(fixture.documentSignerCertificateDer, emittedChain.single())
            assertFalse(emittedChain.single().contentEquals(fixture.iacaCertificateDer))

            val result =
                fixture.verifier
                    .validateAuthorizationResponse(fixture.validationArgs)
                    .getOrElse { fail("validate IACA-backed production DeviceResponse: $it") }
            assertTrue(result.valid, "production verifier must accept the DSC using only the IACA trust anchor: ${result.errors}")
            assertEquals(1, result.matchedCredentials.size)
        }

    @Test
    fun productionOid4vpCommandRejectsAdversarialStatusPublicationsWithCanonicalFailureEvidence() =
        runProductTest {
            suspend fun fixture(
                id: String,
                profile: MdocStatusListProfile = MdocStatusListProfile.STATUS_LIST,
                reserveLow: Boolean = false
            ) = ProductSetup(this@MsoMdocIssuerWalletVerifierProductE2ETest).commandFixture(id, profile, reserveLow)

            fixture("matrix-bad-signature").let { case ->
                val token = case.setup.publish(case.driver, case.uri)
                case.setup.host(case.uri, case.setup.tamperStatusSignature(token), token.contentType)
                assertCommandRejected(case, "signature")
            }

            fixture("matrix-expired-exp").let { case ->
                val source = case.setup.publish(case.driver, case.uri)
                val payload = case.setup.decodeStatusClaims(source).payload
                val now = Clock.System.now().epochSeconds
                case.setup.host(
                    case.uri,
                    case.setup.signStatus(case.statusSigningAlias, case.uri, payload, now - 120, now - 1, 60),
                )
                assertCommandRejected(case, "expired")
            }

            fixture("matrix-expired-next-update").let { case ->
                val source = case.setup.publish(case.driver, case.uri)
                val payload = case.setup.decodeStatusClaims(source).payload
                val now = Clock.System.now().epochSeconds
                // ISO status CWT freshness uses nextUpdate = iat + ttl; no alias wire claim exists.
                case.setup.host(
                    case.uri,
                    case.setup.signStatus(case.statusSigningAlias, case.uri, payload, now - 120, now + 3_600, 60),
                )
                assertCommandRejected(case, "publication freshness is expired")
            }

            fixture("matrix-invalid-next-update").let { case ->
                val source = case.setup.publish(case.driver, case.uri)
                val payload = case.setup.decodeStatusClaims(source).payload
                val now = Clock.System.now().epochSeconds
                case.setup.host(
                    case.uri,
                    case.setup.signStatus(case.statusSigningAlias, case.uri, payload, null, now + 3_600, 60),
                )
                assertCommandRejected(case, "ttl requires iat")
            }

            fixture("matrix-overflowing-next-update").let { case ->
                val source = case.setup.publish(case.driver, case.uri)
                val payload = case.setup.decodeStatusClaims(source).payload
                val now = Clock.System.now().epochSeconds
                case.setup.host(
                    case.uri,
                    case.setup.signStatus(case.statusSigningAlias, case.uri, payload, now, now + 3_600, Long.MAX_VALUE),
                )
                assertCommandRejected(case, "iat plus ttl overflows")
            }

            fixture("matrix-wrong-certificate").let { case ->
                val source = case.setup.publish(case.driver, case.uri)
                val payload = case.setup.decodeStatusClaims(source).payload
                val now = Clock.System.now().epochSeconds
                val untrustedAlias = case.setup.createUntrustedStatusKey("${case.statusListId}-untrusted")
                case.setup.host(
                    case.uri,
                    case.setup.signStatus(untrustedAlias, case.uri, payload, now, now + 3_600, 300),
                )
                assertCommandRejected(case, "not trusted")
            }

            fixture("matrix-bad-content-type").let { case ->
                val token = case.setup.publish(case.driver, case.uri)
                val malformed = case.setup.mutateStatusHeader(token) { it.copy(typ = CborString("application/cwt")) }
                case.setup.host(case.uri, malformed, token.contentType)
                assertCommandRejected(case, "unsupported protected typ")
            }

            fixture("matrix-missing-protected-alg").let { case ->
                val token = case.setup.publish(case.driver, case.uri)
                val malformed = case.setup.mutateStatusHeader(token) { it.copy(alg = null) }
                case.setup.host(case.uri, malformed, token.contentType)
                assertCommandRejected(case, "requires protected alg")
            }

            fixture("matrix-missing-x5chain").let { case ->
                val token = case.setup.publish(case.driver, case.uri)
                val malformed = case.setup.mutateStatusHeader(token) { it.copy(x5chain = null) }
                case.setup.host(case.uri, malformed, token.contentType)
                assertCommandRejected(case, "requires protected x5chain")
            }

            fixture("matrix-unavailable-source").let { case ->
                case.setup.unavailable(case.uri)
                assertCommandRejected(case, "503")
            }

            fixture("matrix-wrong-token-index", reserveLow = true).let { case ->
                val source = case.setup.publish(case.driver, case.uri)
                val now = Clock.System.now().epochSeconds
                case.setup.host(
                    case.uri,
                    case.setup.signStatus(
                        case.statusSigningAlias,
                        case.uri,
                        MdocStatusListPayload.Token(bits = 1, list = zlib(byteArrayOf(0))),
                        now,
                        now + 3_600,
                        300,
                    ),
                )
                assertCommandRejected(case, "outside the mdoc status list")
            }

            fixture("matrix-identifier-reference-token-profile", MdocStatusListProfile.IDENTIFIER_LIST).let { case ->
                val now = Clock.System.now().epochSeconds
                case.setup.host(
                    case.uri,
                    case.setup.signStatus(
                        case.statusSigningAlias,
                        case.uri,
                        MdocStatusListPayload.Token(bits = 1, list = zlib(byteArrayOf(0))),
                        now,
                        now + 3_600,
                        300,
                    ),
                )
                assertCommandRejected(case, "identifier was supplied")
            }
        }

    @Test
    fun productionOid4vpCommandRejectsDocumentIssuerAndHolderBindingFailures() =
        runProductTest {
            ProductSetup(this@MsoMdocIssuerWalletVerifierProductE2ETest)
                .commandFixture(
                    id = "matrix-document-type",
                    issuedDocumentType = "org.iso.18013.5.1.wrong",
                    requestedDocumentType = "org.iso.18013.5.1.mDL",
                ).let { case ->
                    assertGeneralCommandRejected(case, "document type", case.validationArgs)
                }

            ProductSetup(this@MsoMdocIssuerWalletVerifierProductE2ETest).commandFixture("matrix-issuer-binding").let { case ->
                assertGeneralCommandRejected(case, "signature", case.setup.tamperMdocAuthentication(case.validationArgs, issuer = true))
            }

            ProductSetup(this@MsoMdocIssuerWalletVerifierProductE2ETest).commandFixture("matrix-holder-binding").let { case ->
                assertGeneralCommandRejected(case, "signature", case.setup.tamperMdocAuthentication(case.validationArgs, issuer = false))
            }
        }

    @Test
    fun productionOid4vpCommandCannotReadAnotherTenantSessionInTheSameApplicationGraph() =
        runProductTest {
            val sharedApp = createIso18013MdocIntegrationTestAppGraph(this@MsoMdocIssuerWalletVerifierProductE2ETest)
            val tenantA =
                ProductSetup(
                    testInstance = this@MsoMdocIssuerWalletVerifierProductE2ETest,
                    app = sharedApp,
                    tenantId = "phase2-tenant-a",
                )
            val tenantFixture = tenantA.commandFixture("matrix-tenant-crossing")
            val tenantBVerifier =
                ProductSetup(
                    testInstance = this@MsoMdocIssuerWalletVerifierProductE2ETest,
                    app = sharedApp,
                    tenantId = "phase2-tenant-b",
                ).oid4vpVerifierService()
            val crossing = tenantBVerifier.validateAuthorizationResponse(tenantFixture.validationArgs)
            assertTrue(crossing.isErr, "tenant B must not read tenant A's authorization session")
            val crossingError = (crossing as? Err)?.error ?: fail("tenant crossing did not return an IdkError")
            assertEquals("NOT_FOUND_ERROR", crossingError.code)
            assertEquals(com.sphereon.core.api.error.ErrorCategory.NOT_FOUND, crossingError.category)
            assertTrue(crossingError.message.defaultMessage.contains("authorization session not found", ignoreCase = true))

            val tenantAResult =
                tenantFixture.verifier
                    .validateAuthorizationResponse(tenantFixture.validationArgs)
                    .getOrElse { fail("tenant A could not validate its own authorization session: $it") }
            assertTrue(tenantAResult.valid, "tenant A must validate the same response that tenant B cannot access")
            assertEquals(1, tenantAResult.matchedCredentials.size)
        }

    private data class CommandFixture(
        val setup: ProductSetup,
        val verifier: Oid4vpVerifierService,
        val driver: InMemoryStatusListDriver,
        val statusListId: String,
        val uri: String,
        val statusSigningAlias: String,
        val validationArgs: ValidateAuthorizationResponseArgs,
        val issuedCredential: String,
        val documentSignerCertificateDer: ByteArray = byteArrayOf(),
        val iacaCertificateDer: ByteArray = byteArrayOf(),
    )

    private suspend fun assertCommandRejected(
        fixture: CommandFixture,
        expectedCause: String,
        args: ValidateAuthorizationResponseArgs = fixture.validationArgs,
    ): ValidationResult {
        val result =
            fixture.verifier
                .validateAuthorizationResponse(args)
                .getOrElse { fail("command returned an IdkError instead of a validation result for '$expectedCause': $it") }
        assertFalse(result.valid, "production command must reject '$expectedCause'")
        assertTrue(result.matchedCredentials.isEmpty(), "a rejected mdoc must not remain in matched credentials")
        assertTrue(result.errors.any { it.contains("could not be validated", ignoreCase = true) }, "canonical user-facing rejection is missing: ${result.errors}")
        val state = args.originalRequest.state ?: fail("negative command fixture has no persisted state")
        val persisted =
            fixture.verifier.authorizationSessionStore
                .getByCorrelationId(state)
                .getOrElse { fail("read persisted negative result: $it") }
                ?: fail("persisted negative authorization session is missing")
        assertEquals("validation_failed", persisted.error?.code, "the persisted command failure category must remain canonical")
        assertTrue(persisted.error?.message?.contains("could not be validated", ignoreCase = true) == true)
        val technicalDetail = fixture.setup.lastStatusRejectionDetail()
        assertTrue(
            technicalDetail?.contains(expectedCause, ignoreCase = true) == true,
            "status-rejection security event must retain precise '$expectedCause' cause, got '$technicalDetail'",
        )
        return result
    }

    private suspend fun assertGeneralCommandRejected(
        fixture: CommandFixture,
        expectedCause: String,
        args: ValidateAuthorizationResponseArgs,
    ): ValidationResult {
        val result =
            fixture.verifier
                .validateAuthorizationResponse(args)
                .getOrElse { fail("command returned an IdkError instead of a validation result for '$expectedCause': $it") }
        assertFalse(result.valid, "production command must reject '$expectedCause'")
        assertTrue(result.matchedCredentials.isEmpty(), "a rejected mdoc must not remain in matched credentials")
        assertTrue(result.errors.any { it.contains(expectedCause, ignoreCase = true) }, "expected '$expectedCause', got ${result.errors}")
        val state = args.originalRequest.state ?: fail("negative command fixture has no persisted state")
        val persisted =
            fixture.verifier.authorizationSessionStore
                .getByCorrelationId(state)
                .getOrElse {
                    fail("read persisted negative result: $it")
                } ?: fail("persisted negative authorization session is missing")
        assertEquals("validation_failed", persisted.error?.code)
        assertTrue(persisted.error?.message?.contains(expectedCause, ignoreCase = true) == true)
        return result
    }

    private class ProductSetup(
        testInstance: Any,
        private val app: Iso18013MdocIntegrationTestAppGraph = createIso18013MdocIntegrationTestAppGraph(testInstance),
        tenantId: String? = null,
    ) {
        private val userContext =
            if (tenantId == null) {
                app.userContextManager.getAnonymous()
            } else {
                app.userContextManager.createOrGetFromInputs(
                    DefaultTenantInputString(tenantId),
                    DefaultPrincipalInputString("phase2-verifier"),
                )
            }
        private val session =
            userContext.sessionContextManager
                .createOrGetFromId("product-mdoc", principalType = PrincipalType.USER)
        val execution: SessionExecution = session.asCoreApiServiceGraph().serviceExecution
        val kms: KeyManagerService = session.graph.asKeyManagerServiceGraph().keyManagerService
        private val certificateService: CertificateService = (session.graph as CertificateService.Graph).certificateService
        private val productStatusListTransport =
            (session.graph as ProductStatusListTransportGraph).productStatusListTransport
        private val appConfig = (app as AppConfigService.Graph).appConfigService
        private val statusListHostingConfig = StatusListHostingConfig(Provider { appConfig })
        val issuerSignedCodec = IssuerSignedCborCodecImpl()
        val msoCodec = MobileSecurityObjectCborCodecImpl()

        /**
         * Use the X509 service selected by the application graph.  The production
         * OID4VP verifier and its mdoc status verifier receive this same service;
         * configuring a separately constructed verifier would only prove the
         * hand-written test path.
         */
        val x509 = (session.graph as CryptoServices.Graph).cryptoServices.x509
        private val jwtService = (session.graph as com.sphereon.crypto.jose.jws.JwtServiceImpl.Graph).jwtService
        private val coseCrypto = CoseCryptoServiceImpl()
        private lateinit var certificateDer: ByteArray
        private var iacaCertificateDer: ByteArray = byteArrayOf()
        private lateinit var holderBindingKey: kotlinx.serialization.json.JsonElement
        lateinit var holderCoseKey: com.sphereon.crypto.core.cose.CoseKeyType

        init {
            appConfig.addPropertySource(
                MapPropertySource(
                    "product-status-hosting-freshness",
                    mapOf(StatusListHostingConfig.CACHE_MAX_AGE_SECONDS_KEY to "0"),
                ),
            )
            val factory = (app as SoftwareKmsProviderFactoryImpl.Graph).softwareKmsProvider
            kms.registerProvider(
                factory.create(
                    SoftwareKmsProviderConfig(id = "product-software-kms", autoCreateCertificate = true),
                    session.asCoreApiServiceGraph().serviceExecution,
                ),
                makeDefaultKms = true,
            )
        }

        suspend fun createCertificateBearingKey(alias: String): String {
            val generated = kms.generateKey(providerId = "product-software-kms", alias = "$alias-source", alg = SignatureAlgorithm.ECDSA_SHA256, keyVisibility = KeyVisibility.PRIVATE)
            val cert =
                generated.jose.publicJwk.x5c
                    ?.firstOrNull() ?: fail("generated issuer key lacks certificate")
            val privateKeyInfo = ManagedKeyInfo.build(generated.joseToManagedKeyInfo(KeyVisibility.PRIVATE), alias = alias, providerId = generated.providerId)
            kms
                .storeKeyResult(
                    keyInfo = privateKeyInfo,
                    providerId = generated.providerId,
                    alias = alias,
                    certChain = arrayOf(Certificate.fromDer(cert.decodeFrom(Encoding.BASE64))),
                ).getOrElse { fail("store certificate-bearing issuer key: $it") }
            val key =
                kms.getKeyResult(KeyInfo<Nothing>(alias = alias)).getOrElse { fail("get key: $it") }.key
                    ?: fail("missing issuer key")
            val jwk = key.key as? com.sphereon.crypto.core.jose.Jwk ?: fail("issuer key is not JWK")
            val issuerCert = jwk.x5c?.firstOrNull() ?: cert
            certificateDer = issuerCert.decodeFrom(Encoding.BASE64)
            x509.setTrustedCerts(arrayOf(issuerCert))
            val holder =
                kms.generateKey(
                    providerId = "product-software-kms",
                    alias = "$alias-holder",
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                    keyVisibility = KeyVisibility.PRIVATE,
                )
            val holderJwk = holder.jose.publicJwk
            holderCoseKey = holderJwk.jwkToCoseKey().toPublicKey()
            holderBindingKey =
                Json.encodeToJsonElement(
                    com.sphereon.crypto.core.jose.Jwk
                        .serializer(),
                    holderJwk.toPublicKey()
                )
            assertFalse(
                jwk.toPublicKey().jwkToCoseKey() == holderCoseKey,
                "issuer signing key and holder device key must be independent",
            )
            return alias
        }

        suspend fun createIacaBackedCertificateBearingKey(alias: String): String {
            val iacaGenerated =
                kms.generateKey(
                    providerId = "product-software-kms",
                    alias = "$alias-iaca-source",
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                    keyVisibility = KeyVisibility.PRIVATE,
                )
            val iacaKeyInfo = iacaGenerated.joseToManagedKeyInfo(KeyVisibility.PRIVATE)
            val iacaDn = X509DistinguishedNameElements(commonName = "Product test IACA", country = "NL")
            val iacaCertificate =
                certificateService
                    .createCertificate(
                        issuerKeyInfo = iacaKeyInfo,
                        issuer = iacaDn,
                        subjectKeyInfo = iacaKeyInfo,
                        subject = iacaDn,
                        serialNumber = 1,
                        extensions =
                            listOf(
                                X509CertificateExtensionSpec(X509ExtensionOids.BASIC_CONSTRAINTS, critical = true, valueDer = byteArrayOf(0x30, 0x06, 0x01, 0x01, 0xff.toByte(), 0x02, 0x01, 0x00)),
                                X509CertificateExtensionSpec(X509ExtensionOids.KEY_USAGE, critical = true, valueDer = byteArrayOf(0x03, 0x02, 0x01, 0x06)),
                            ),
                    ).certificate
            val iacaSkiExtension =
                x509CertificateFromDer(iacaCertificate.der)
                    .tbsCertificate.extensions
                    ?.firstOrNull { it.oid.toString() == X509ExtensionOids.SUBJECT_KEY_IDENTIFIER }
                    ?: fail("generated IACA certificate has no subject key identifier")
            require(
                iacaSkiExtension.value.size == 22 &&
                    iacaSkiExtension.value[0] == 0x04.toByte() &&
                    iacaSkiExtension.value[1] == 0x14.toByte()
            ) { "generated IACA subject key identifier must be a DER OCTET STRING containing exactly 20 bytes" }
            val iacaSki = iacaSkiExtension.value.copyOfRange(2, 22)

            val dscGenerated =
                kms.generateKey(
                    providerId = "product-software-kms",
                    alias = "$alias-dsc-source",
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                    keyVisibility = KeyVisibility.PRIVATE,
                )
            val dscKeyInfo = dscGenerated.joseToManagedKeyInfo(KeyVisibility.PRIVATE)
            val dscCertificate =
                certificateService
                    .createCertificate(
                        issuerKeyInfo = iacaKeyInfo,
                        issuer = iacaDn,
                        subjectKeyInfo = dscKeyInfo,
                        subject = X509DistinguishedNameElements(commonName = "Product test DSC", country = "NL"),
                        serialNumber = 2,
                        extensions =
                            listOf(
                                X509CertificateExtensionSpec(X509ExtensionOids.BASIC_CONSTRAINTS, critical = true, valueDer = byteArrayOf(0x30, 0x00)),
                                X509CertificateExtensionSpec(X509ExtensionOids.KEY_USAGE, critical = true, valueDer = byteArrayOf(0x03, 0x02, 0x07, 0x80.toByte())),
                                X509CertificateExtensionSpec(
                                    X509ExtensionOids.EXTENDED_KEY_USAGE,
                                    valueDer = byteArrayOf(0x30, 0x09, 0x06, 0x07, 0x28, 0x81.toByte(), 0x8c.toByte(), 0x5d, 0x05, 0x01, 0x02)
                                ),
                                X509CertificateExtensionSpec(X509ExtensionOids.AUTHORITY_KEY_IDENTIFIER, valueDer = byteArrayOf(0x30, 0x16, 0x80.toByte(), 0x14) + iacaSki),
                            ),
                    ).certificate
            kms
                .storeKeyResult(
                    keyInfo = ManagedKeyInfo.build(dscKeyInfo, alias = alias, providerId = dscGenerated.providerId),
                    providerId = dscGenerated.providerId,
                    alias = alias,
                    certChain = arrayOf(dscCertificate, iacaCertificate),
                ).getOrElse { fail("store IACA-backed document signer key: $it") }
            val stored =
                kms.getKeyResult(KeyInfo<Nothing>(alias = alias)).getOrElse { fail("read IACA-backed document signer key: $it") }.key
                    ?: fail("missing IACA-backed document signer key")
            val storedJwk = stored.key as? com.sphereon.crypto.core.jose.Jwk ?: fail("document signer key is not JWK")
            val storedChain = storedJwk.x5c ?: fail("stored document signer key has no x5c")
            assertEquals(2, storedChain.size, "KMS storage must retain the complete DSC and IACA chain")
            assertContentEquals(dscCertificate.der, storedChain[0].decodeFrom(Encoding.BASE64))
            assertContentEquals(iacaCertificate.der, storedChain[1].decodeFrom(Encoding.BASE64))
            val certificatePublicKey = ecPublicPoint(dscCertificate.getPublicKeyJwk())
            assertEquals(
                certificatePublicKey,
                ecPublicPoint(dscGenerated.jose.publicJwk),
                "DSC certificate public key must match the generated signing key",
            )
            assertEquals(
                certificatePublicKey,
                ecPublicPoint(storedJwk),
                "DSC certificate public key must match the stored signing key",
            )

            certificateDer = dscCertificate.der
            iacaCertificateDer = iacaCertificate.der
            x509.setTrustedCerts(arrayOf(iacaCertificate.derToBase64()))
            val holder =
                kms.generateKey(
                    providerId = "product-software-kms",
                    alias = "$alias-holder",
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                    keyVisibility = KeyVisibility.PRIVATE,
                )
            val holderJwk = holder.jose.publicJwk
            holderCoseKey = holderJwk.jwkToCoseKey().toPublicKey()
            holderBindingKey =
                Json.encodeToJsonElement(
                    com.sphereon.crypto.core.jose.Jwk
                        .serializer(),
                    holderJwk.toPublicKey()
                )
            assertFalse(storedJwk.toPublicKey().jwkToCoseKey() == holderCoseKey, "DSC and holder device keys must be independent")
            return alias
        }

        fun newDriver(): InMemoryStatusListDriver {
            val mdocSigner = MdocCwtStatusListSigner(coseCrypto, CoseSign1CborCodecImpl(), kms)
            val signer: StatusListSigner =
                object : StatusListSigner {
                    override suspend fun signStatusListToken(args: com.sphereon.statuslist.spi.SignStatusListTokenArgs) = mdocSigner.sign(args)
                }
            return InMemoryStatusListDriver(InMemoryStatusListStore(), signer, execution)
        }

        suspend fun createStatusList(
            driver: InMemoryStatusListDriver,
            id: String,
            uri: String,
            profile: MdocStatusListProfile
        ) {
            driver
                .createStatusList(
                    CreateStatusListArgs(
                        correlationId = id,
                        spec = StatusListSpec.TOKEN_STATUS_LIST,
                        purposes = listOf(StatusPurpose.REVOCATION),
                        proofFormat = StatusProofFormat.CWT,
                        issuer = "https://issuer.example",
                        statusListUri = uri,
                        length = 256,
                        bitsPerStatus = 1,
                        signingKeyAlias = id,
                        validUntil = Clock.System.now().plus(24, DateTimeUnit.HOUR),
                        mdocProfile = profile,
                    )
                ).getOrElse { fail("create status list: $it") }
        }

        fun handler(driver: InMemoryStatusListDriver) =
            MsoMdocFormatHandler(
                mdocSignService = MdocSignServiceImpl(CoseCryptoServiceImpl(), execution, msoCodec, SessionTranscriptCborCodecImpl()),
                kms = kms,
                issuerSignedCborCodec = issuerSignedCodec,
                issuerSignedItemCborCodec = IssuerSignedItemCborCodecImpl(),
                statusEnricherProvider = Provider { CredentialStatusEnricherImpl(driver) },
            )

        fun holderCommand() =
            CreateAuthorizationResponseCommandImpl(
                execution = execution,
                holderJwtVpSigningProvider = JwtServiceHolderJwtVpSigningProvider(jwtService),
                addProofServiceCommand = UnusedAddProofCommand,
                mdocOid4vpService =
                    MdocOid4vpServiceImpl(
                        signService = MdocSignServiceImpl(CoseCryptoServiceImpl(), execution, msoCodec, SessionTranscriptCborCodecImpl()),
                        logService = execution.log,
                        mobileSecurityObjectCborCodec = msoCodec,
                    ),
                issuerSignedCborCodec = issuerSignedCodec,
                deviceResponseCborCodec = DeviceResponseCborCodecImpl(),
                mobileSecurityObjectCborCodec = msoCodec,
            )

        fun oid4vpVerifierService(): Oid4vpVerifierService = (session.graph as Oid4VpVerifierServiceImpl.Graph).oid4vpVerifierService

        suspend fun commandFixture(
            id: String,
            profile: MdocStatusListProfile = MdocStatusListProfile.STATUS_LIST,
            reserveLowTokenIndices: Boolean = false,
            issuedDocumentType: String = "org.iso.18013.5.1.mDL",
            requestedDocumentType: String = issuedDocumentType,
            useIacaCertificateChain: Boolean = false,
        ): CommandFixture {
            val verifier = oid4vpVerifierService()
            val uri = "https://issuer.example/public/statuslists/$id"
            val subject = "$id-subject"
            val alias = if (useIacaCertificateChain) createIacaBackedCertificateBearingKey(id) else createCertificateBearingKey(id)
            val driver = newDriver()
            createStatusList(driver, id, uri, profile)
            if (reserveLowTokenIndices) {
                repeat(8) { index ->
                    driver
                        .allocateEntry(
                            AllocateEntryArgs(
                                statusList = StatusListRef(correlationId = id),
                                explicitIndex = index,
                                credentialId = "$id-reserved-$index",
                            ),
                        ).getOrElse { fail("reserve low status index $index: $it") }
                }
            }
            val envelope =
                issue(
                    handler = handler(driver),
                    statusListId = id,
                    subject = subject,
                    credentialId = "urn:vdx:credential:$id",
                    profile = profile,
                    alias = alias,
                    documentType = issuedDocumentType,
                )
            val store = walletStore()
            val record = record(envelope.credential.jsonPrimitive.content, id, issuedDocumentType)
            store.putCredential("wallet-product", record).getOrElse { fail("persist command mdoc: $it") }
            graphStatusResolver(driver, uri)
            val query =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "mdoc",
                                format = CredentialFormat.MSO_MDOC.value,
                                meta = mdocMeta(requestedDocumentType),
                            ),
                        ),
                )
            val request =
                verifier
                    .createAuthorizationRequest(
                        CreateAuthorizationRequestArgs(
                            instanceId = "product-verifier-$id",
                            dcqlQuery = query,
                            clientId = "https://verifier.example",
                            responseUri = "https://verifier.example/oid4vp/response",
                            responseMode = com.sphereon.openid.oid4vp.common.ResponseMode.DIRECT_POST,
                            nonce = "nonce-$id",
                            state = "state-$id",
                            credentialStatusPolicies = mapOf("mdoc" to com.sphereon.statuslist.CredentialStatusPolicy(requireStatus = true)),
                        ),
                    ).getOrElse { fail("create persisted authorization request: $it") }
            val holderResponse =
                holderCommand()
                    .execute(
                        CreateAuthorizationResponseArgs(
                            request =
                                ResolvedOid4vpRequest(
                                    request = request.request,
                                    dcqlQuery = query,
                                    verifierInfo =
                                        com.sphereon.openid.oid4vp.holder.VerifierInfo(
                                            clientId = request.request.clientId,
                                            clientIdScheme = com.sphereon.openid.oid4vp.common.ClientIdScheme.PRE_REGISTERED,
                                        ),
                                ),
                            selectedCredentials =
                                listOf(
                                    SelectedCredential(
                                        credentialQueryId = "mdoc",
                                        credentialId = id,
                                        presentation = envelope.credential,
                                        credentialFormat = CredentialFormat.MSO_MDOC,
                                        holderKeyRef = "$id-holder",
                                    ),
                                ),
                        ),
                    ).getOrElse { fail("create signed DeviceResponse: $it") }
            val wireVpToken = holderResponse.additionalParameters["vp_token"] ?: fail("missing vp_token")
            val parsed =
                verifier
                    .parseAuthorizationResponse(
                        ParseAuthorizationResponseArgs(
                            responseParams =
                                mapOf(
                                    "vp_token" to
                                        Json.encodeToString(
                                            kotlinx.serialization.json.JsonElement
                                                .serializer(),
                                            wireVpToken
                                        ),
                                    "state" to request.request.state.orEmpty(),
                                ),
                            originalRequest = request.request,
                        ),
                    ).getOrElse { fail("parse signed DeviceResponse: $it") }
            return CommandFixture(
                setup = this,
                verifier = verifier,
                driver = driver,
                statusListId = id,
                uri = uri,
                statusSigningAlias = alias,
                issuedCredential = envelope.credential.jsonPrimitive.content,
                documentSignerCertificateDer = certificateDer,
                iacaCertificateDer = iacaCertificateDer,
                validationArgs =
                    ValidateAuthorizationResponseArgs(
                        parsedResponse = parsed,
                        originalRequest = request.request,
                        dcqlQuery = query,
                        expectedNonce = request.request.nonce.orEmpty(),
                    ),
            )
        }

        suspend fun issue(
            handler: MsoMdocFormatHandler,
            statusListId: String,
            subject: String,
            credentialId: String,
            profile: MdocStatusListProfile,
            alias: String,
            documentType: String = "org.iso.18013.5.1.mDL",
        ) = handler
            .issueCredential(
                CredentialRequest(credentialConfigurationId = statusListId),
                IssuanceContext(
                    subject = subject,
                    clientId = "wallet-product-client",
                    issuerIdentifier = "https://issuer.example",
                    credentialConfigurationId = statusListId,
                    credentialConfiguration =
                        CredentialConfigurationSupported(
                            format = CredentialFormat.MSO_MDOC.value,
                            doctype = documentType,
                        ),
                    holderBindingKey = holderBindingKey,
                    attributes = mapOf("org.iso.18013.5.1.given_name" to JsonPrimitive("Ada")),
                    signingKeyAlias = alias,
                    statusListBinding =
                        StatusListBinding(
                            statusListCorrelationId = statusListId,
                            spec = StatusListSpec.TOKEN_STATUS_LIST,
                            mdocProfile = profile,
                            proofFormat = StatusProofFormat.CWT,
                        ),
                    credentialId = credentialId,
                ),
            ).getOrElse { fail("issue mso_mdoc: $it") }

        suspend fun publish(
            driver: InMemoryStatusListDriver,
            uri: String
        ): StatusListToken =
            driver.getStatusListToken(StatusListRef(statusListUri = uri)).getOrElse { fail("publish: $it") }
                ?: fail("missing token")

        fun host(
            uri: String,
            token: StatusListToken
        ) {
            productStatusListTransport.host(uri, token.rawBytes(), token.contentType)
        }

        fun host(
            uri: String,
            bytes: ByteArray,
            contentType: String
        ) {
            productStatusListTransport.host(uri, bytes, contentType)
        }

        fun unavailable(uri: String) {
            productStatusListTransport.unavailable(uri)
        }

        fun decodeStatusClaims(token: StatusListToken) =
            MdocRevocationCwtClaimsCodecImpl.decode(
                CoseSign1CborCodecImpl()
                    .decode(untagCoseSign1(token.rawBytes()))
                    .getOrElse { fail("decode status COSE: $it") }
                    .value.payload
                    ?.value
                    ?: fail("status COSE payload is detached"),
            )

        suspend fun signStatus(
            alias: String,
            uri: String,
            payload: MdocStatusListPayload,
            issuedAtEpochSeconds: Long?,
            expiresAtEpochSeconds: Long,
            ttlSeconds: Long? = null,
        ): StatusListToken =
            MdocCwtStatusListSigner(coseCrypto, CoseSign1CborCodecImpl(), kms)
                .sign(
                    MdocCwtStatusListSigningArgs(
                        issuer = "https://issuer.example",
                        statusListUri = uri,
                        signingKeyName = alias,
                        expiresAtEpochSeconds = expiresAtEpochSeconds,
                        payload = payload,
                        issuedAtEpochSeconds = issuedAtEpochSeconds,
                        ttlSeconds = ttlSeconds,
                    ),
                ).getOrElse { fail("sign adversarial status CWT: $it") }

        suspend fun createUntrustedStatusKey(alias: String): String {
            val generated =
                kms.generateKey(
                    providerId = "product-software-kms",
                    alias = "$alias-source",
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                    keyVisibility = KeyVisibility.PRIVATE,
                )
            val cert =
                generated.jose.publicJwk.x5c
                    ?.firstOrNull() ?: fail("generated adversarial status key lacks certificate")
            kms
                .storeKeyResult(
                    keyInfo = ManagedKeyInfo.build(generated.joseToManagedKeyInfo(KeyVisibility.PRIVATE), alias = alias, providerId = generated.providerId),
                    providerId = generated.providerId,
                    alias = alias,
                    certChain = arrayOf(Certificate.fromDer(cert.decodeFrom(Encoding.BASE64))),
                ).getOrElse { fail("store adversarial status signing key: $it") }
            return alias
        }

        fun tamperStatusSignature(token: StatusListToken): ByteArray {
            val codec = CoseSign1CborCodecImpl()
            val cose = codec.decode(untagCoseSign1(token.rawBytes())).getOrElse { fail("decode status COSE for signature mutation: $it") }.value
            val signature = cose.signature.value.copyOf()
            signature[signature.lastIndex] = (signature.last().toInt() xor 0x01).toByte()
            return tagCoseSign1(codec.encode(cose.copy(signature = CborByteString(signature))).getOrElse { fail("encode tampered status COSE: $it") })
        }

        fun mutateStatusHeader(
            token: StatusListToken,
            header: (CoseHeaderCbor) -> CoseHeaderCbor
        ): ByteArray {
            val codec = CoseSign1CborCodecImpl()
            val cose = codec.decode(untagCoseSign1(token.rawBytes())).getOrElse { fail("decode status COSE for header mutation: $it") }.value
            return tagCoseSign1(
                codec
                    .encode(cose.copy(protectedHeader = header(cose.protectedHeader)))
                    .getOrElse { fail("encode status COSE with malformed protected header: $it") },
            )
        }

        fun tamperMdocAuthentication(
            args: ValidateAuthorizationResponseArgs,
            issuer: Boolean,
        ): ValidateAuthorizationResponseArgs {
            val presentation =
                args.parsedResponse.vpToken.presentationElements
                    .getValue("mdoc")
                    .single()
                    .jsonPrimitive.content
            val codec = DeviceResponseCborCodecImpl()
            val response =
                codec
                    .decode(presentation.decodeFromBase64Url())
                    .getOrElse { fail("decode DeviceResponse for authentication mutation: $it") }
                    .value
            val document = response.documents?.singleOrNull() ?: fail("authentication fixture must contain one clear mdoc")
            val mutatedDocument =
                if (issuer) {
                    val issuerAuth = document.issuerSigned.issuerAuth
                    val signature = issuerAuth.signature.value.copyOf()
                    signature[signature.lastIndex] = (signature.last().toInt() xor 0x01).toByte()
                    document.copy(
                        issuerSigned =
                            document.issuerSigned.copy(
                                issuerAuth = issuerAuth.copy(signature = CborByteString(signature)),
                                original = null,
                            ),
                        original = null,
                    )
                } else {
                    val deviceSigned = document.deviceSigned ?: fail("holder fixture is missing DeviceSigned")
                    val deviceSignature = deviceSigned.deviceAuth.deviceSignature ?: fail("holder fixture is missing DeviceSignature")
                    val signature = deviceSignature.signature.value.copyOf()
                    signature[signature.lastIndex] = (signature.last().toInt() xor 0x01).toByte()
                    document.copy(
                        deviceSigned =
                            deviceSigned.copy(
                                deviceAuth =
                                    deviceSigned.deviceAuth.copy(
                                        deviceSignature = deviceSignature.copy(signature = CborByteString(signature)),
                                        original = null,
                                    ),
                                original = null,
                            ),
                        original = null,
                    )
                }
            val encoded =
                codec
                    .encode(response.copy(documents = arrayOf(mutatedDocument), original = null))
                    .getOrElse { fail("encode DeviceResponse after authentication mutation: $it") }
                    .encodeToBase64Url()
            val parsed =
                args.parsedResponse.copy(
                    vpToken =
                        args.parsedResponse.vpToken.copy(
                            presentationElements = mapOf("mdoc" to listOf(JsonPrimitive(encoded))),
                        ),
                    rawVpToken = encoded,
                )
            return args.copy(parsedResponse = parsed)
        }

        suspend fun graphStatusResolver(
            driver: InMemoryStatusListDriver,
            uri: String
        ): StatusListResolver {
            publish(driver, uri)
            productStatusListTransport.register(uri, hostingAdapter(driver))
            return (session.graph as ProductStatusListResolverGraph).statusListResolver
        }

        fun statusRequestCount(uri: String): Int = productStatusListTransport.requestCount(uri)

        suspend fun fetchHostedStatus(uri: String) = productStatusListTransport.client().get(uri)

        fun lastStatusRejectionDetail(): String? =
            (app as EventHub.Graph)
                .eventHub.events.replayCache
                .lastOrNull { it.type == EventTypes.OID4VP_CREDENTIAL_STATUS_REJECTED }
                ?.payload
                ?.get("detail")
                ?.jsonPrimitive
                ?.content

        private fun hostingAdapter(driver: InMemoryStatusListDriver): StatusListHostingHttpAdapter {
            val execution = this.execution
            val endpoint =
                GetStatusListTokenByCorrelationIdEndpointCommandImpl(
                    execution,
                    GetStatusListTokenCommandImpl(execution, driver),
                    statusListHostingConfig,
                )
            val registry =
                object : HttpEndpointCommandRegistry {
                    private val commands = mapOf<String, HttpEndpointCommand>(endpoint.id to endpoint)

                    override fun get(handlerCommandId: String): HttpEndpointCommand? = commands[handlerCommandId]

                    override fun listHandlerCommandIds(): Set<String> = commands.keys
                }
            return StatusListHostingHttpAdapter(execution, registry, statusListHostingConfig)
        }

        fun walletStore() = BlobWalletCredentialStore(createTestBlobService(), TestCredentialBodyProtector)

        suspend fun assertPersistedStatusCredentialBoundary(
            store: BlobWalletCredentialStore,
            recordId: String,
            expectedRaw: String,
            expectedProfile: MdocStatusListProfile,
            expectedUri: String,
        ) {
            val selected =
                store
                    .listMetadata(
                        walletUnitId = "wallet-product",
                        filter =
                            CredentialMetadataFilter(
                                formats = setOf(WalletCredentialFormat.MSO_MDOC),
                                lifecycleStates = setOf(CredentialLifecycleState.ACTIVE),
                            ),
                    ).getOrElse { fail("select persisted wallet mdoc metadata: $it") }
            assertEquals(
                listOf(recordId),
                selected.map { it.credentialRecordId },
                "wallet metadata selection must return the one persisted active mdoc",
            )

            val hydrated =
                assertNotNull(
                    store
                        .getCredential("wallet-product", recordId)
                        .getOrElse { fail("hydrate persisted wallet mdoc '$recordId': $it") },
                    "selected wallet metadata must hydrate its credential record",
                )
            assertEquals(1, hydrated.instances.size, "hydrated wallet mdoc must retain one credential instance")
            val hydratedRaw = assertNotNull(hydrated.instances.single().raw, "hydrated wallet mdoc instance must retain its protected body")
            assertEquals(expectedRaw, hydratedRaw, "wallet body protection round-trip must preserve the IssuerSigned bytes")

            val persistedIssuerSigned =
                issuerSignedCodec
                    .decode(hydratedRaw.decodeFromBase64Url())
                    .getOrElse { fail("decode hydrated IssuerSigned '$recordId': $it") }
                    .value
            val persistedMso =
                msoCodec
                    .decode(persistedIssuerSigned.issuerAuth.payload?.value ?: fail("hydrated IssuerSigned '$recordId' has no MSO payload"))
                    .getOrElse { fail("decode hydrated MSO '$recordId': $it") }
                    .value
            when (expectedProfile) {
                MdocStatusListProfile.STATUS_LIST -> {
                    assertEquals(
                        expectedUri,
                        assertNotNull(persistedMso.status?.statusList, "hydrated MSO must retain its Token Status List reference").uri,
                    )
                }

                MdocStatusListProfile.IDENTIFIER_LIST -> {
                    assertEquals(
                        expectedUri,
                        assertNotNull(persistedMso.status?.identifierList, "hydrated MSO must retain its Identifier List reference").uri,
                    )
                }
            }
        }

        fun record(
            raw: String,
            id: String,
            documentType: String = "org.iso.18013.5.1.mDL",
        ) = CredentialRecord(
            id = id,
            walletUnitId = "wallet-product",
            issuerRef = IdentifierRef(com.sphereon.data.store.party.model.IdentifierType.URL, "https://issuer.example"),
            format = WalletCredentialFormat.MSO_MDOC,
            credentialTypeRefs =
                setOf(
                    CredentialTypeRef(WalletCredentialFormat.MSO_MDOC, CredentialTypeRefKind.MDOC_DOCTYPE, documentType, CredentialTypeRefSource.CREDENTIAL_PAYLOAD, primary = true)
                ),
            instances =
                listOf(
                    CredentialInstance(
                        id = "$id-instance",
                        walletUnitId = "wallet-product",
                        credentialRecordId = id,
                        format = WalletCredentialFormat.MSO_MDOC,
                        raw = raw,
                        bodyStorageRef = BodyStorageRef(BodyStorageKind.BLOB, "unused", StoreRef("memory", "blob")),
                        holderKeyRef = KeyRef("$id-holder"),
                        lifecycleState = CredentialLifecycleState.ACTIVE,
                        validity = CredentialValidityWindow(),
                        storedAt =
                            kotlin.time.Clock.System
                                .now(),
                        updatedAt =
                            kotlin.time.Clock.System
                                .now(),
                    )
                ),
            createdAt =
                kotlin.time.Clock.System
                    .now(),
            updatedAt =
                kotlin.time.Clock.System
                    .now(),
        )
    }
}

private const val COSE_SIGN1_TAG: Int = 0xd2

private fun untagCoseSign1(bytes: ByteArray): ByteArray {
    assertEquals(COSE_SIGN1_TAG, bytes.first().toInt() and 0xff, "status-list CWT must carry COSE_Sign1 tag 18")
    return bytes.copyOfRange(1, bytes.size)
}

private fun tagCoseSign1(bytes: ByteArray): ByteArray = byteArrayOf(COSE_SIGN1_TAG.toByte()) + bytes

/** The EC public point only: a certificate-derived key carries no kid or x5c, while a KMS key may. */
private fun ecPublicPoint(key: com.sphereon.crypto.core.jose.JwkType): List<Any?> =
    com.sphereon.crypto.core.jose.Jwk
        .from(key)
        .let { listOf(it.kty, it.crv, it.x, it.y) }

/**
 * Runs a product test body on real time. The status-list resolver bounds its HTTP fetch with
 * withTimeout, and the Ktor mock engine completes off the test dispatcher, so under virtual time
 * the idle scheduler would jump straight past that timeout.
 */
private fun runProductTest(block: suspend CoroutineScope.() -> Unit): TestResult = runTest { withContext(Dispatchers.Default) { block() } }

private fun zlib(bytes: ByteArray): ByteArray {
    val deflater = Deflater()
    try {
        deflater.setInput(bytes)
        deflater.finish()
        val output = ByteArray(bytes.size + 64)
        return output.copyOf(deflater.deflate(output))
    } finally {
        deflater.end()
    }
}
