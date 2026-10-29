package com.sphereon.openid.oid4vci.issuer.impl.http

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.HttpAdapter
import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.core.api.http.command.HttpEndpointCommandRegistry
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteMatch
import com.sphereon.core.defaults.http.NoOpRoutableSlugLookup
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialIssuerMetadata
import com.sphereon.openid.oid4vci.common.model.CredentialNotificationEvent
import com.sphereon.openid.oid4vci.common.model.CredentialOffer
import com.sphereon.openid.oid4vci.common.model.CredentialResponse
import com.sphereon.openid.oid4vci.common.model.CredentialResponseItem
import com.sphereon.openid.oid4vci.common.model.NonceResponse
import com.sphereon.openid.oid4vci.common.model.Oid4vciErrors
import com.sphereon.openid.oid4vci.issuer.config.MutableOid4vciIssuerInstanceIdProvider
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerInstanceResolver
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerSpecProfile
import com.sphereon.openid.oid4vci.issuer.config.CredentialSigningConfig
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationGrant
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationPolicySnapshot
import com.sphereon.openid.oid4vci.issuer.impl.http.command.DefaultOid4vciIssuerPublicUrlResolver
import com.sphereon.openid.oid4vci.issuer.impl.http.command.GetCredentialOfferEndpointCommandImpl
import com.sphereon.openid.oid4vci.issuer.impl.http.command.GetIssuerMetadataEndpointCommandImpl
import com.sphereon.openid.oid4vci.issuer.impl.http.command.HandleCredentialEndpointCommandImpl
import com.sphereon.openid.oid4vci.issuer.impl.http.command.HandleDeferredCredentialEndpointCommandImpl
import com.sphereon.openid.oid4vci.issuer.impl.http.command.HandleNotificationEndpointCommandImpl
import com.sphereon.openid.oid4vci.issuer.impl.http.command.IssueNonceEndpointCommandImpl
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

class Oid4vciIssuerProtocolHttpAdapterTest {
    @Test
    fun servedIssuerMetadataPublishesTheConfiguredCredentialThumbprintKey() = runTest {
        val publicKey = Json.parseToJsonElement("""{"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}""").jsonObject
        val provider = object : com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider by fakeConfigProvider {
            override val credentialConfigurations = mapOf("selected" to CredentialConfigurationSupported(format = "dc+sd-jwt"))
            override suspend fun credentialSigningConfigs() = mapOf("selected" to CredentialSigningConfig("server-owned-key", SigningKeyMode.JwkThumbprint))
        }
        fakeBuildMetadata.result = Ok(CredentialIssuerMetadata(
            credentialIssuer = "https://issuer.example.com",
            credentialEndpoint = "https://issuer.example.com/oid4vci/credential",
            credentialConfigurationsSupported = provider.credentialConfigurations,
        ))
        val resolver = object : IssuerKeyIdResolver {
            override suspend fun resolveDidVerificationMethodId(keyAlias: String, didMethod: String): IdkResult<String, IdkError> = error("No DID lookup")
            override suspend fun resolvePublicJwk(keyAlias: String): IdkResult<JsonObject, IdkError> {
                assertEquals("server-owned-key", keyAlias)
                return Ok(publicKey)
            }
        }
        val command = GetIssuerMetadataEndpointCommandImpl(execution, fakeBuildMetadata, fakeBuildSignedMetadata,
            provider, fakeRestConfigProvider, FakeMultiManagedIdentifierService,
            DefaultOid4vciIssuerPublicUrlResolver(NoOpAppConfigService), resolver)
        val response = command.execute(GenericHttpRequest(method = "GET", path = "/.well-known/openid-credential-issuer")).getOrThrow()
        assertEquals(200, response.statusCode)
        val body = Json.parseToJsonElement(response.body!!).jsonObject
        val published = body.getValue("jwks").jsonObject.getValue("keys").jsonArray.single().jsonObject
        assertEquals(publicKey, JsonObject(published - "kid" - "use"))
        assertTrue(published.getValue("kid").jsonPrimitive.content.startsWith("urn:ietf:params:oauth:jwk-thumbprint:sha-256:"))
        assertEquals(JsonPrimitive("sig"), published["use"])
    }

    private val routedIssuerId = "8b1c1e72-3677-4d46-8491-7bfcc7ed3f5e"
    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = false
        }
    private val execution = TestSessionExecution()
    private val fakeConfigProvider = FakeOid4vciIssuerConfigProvider()
    private val fakeOfferStore = FakeCredentialOfferStore()
    private val fakeOfferSessionStore = FakeCredentialOfferSessionStore()
    private val rateLimiterClock =
        object : kotlin.time.Clock {
            override fun now(): kotlin.time.Instant = kotlin.time.Instant.parse("2026-05-15T12:00:00Z")
        }
    private val offerRateLimiter =
        com.sphereon.openid.oid4vci.issuer.impl.command
            .InMemoryOfferRateLimiter(rateLimiterClock)
    private val fakeDecryptJweCommand = FakeDecryptJweCommand()
    private val fakeCreateCredentialOffer = FakeCreateCredentialOfferCommand()

    // Fake service commands
    private val fakeBuildMetadata = FakeBuildIssuerMetadataCommand()
    private val fakeBuildSignedMetadata = FakeBuildSignedIssuerMetadataCommand()
    private val fakeIssueNonce = FakeIssueNonceCommand()
    private val fakeHandleCredential = FakeHandleCredentialRequestCommand()
    private val fakeHandleDeferred = FakeHandleDeferredCredentialRequestCommand()
    private val fakeHandleNotification = FakeHandleNotificationCommand()

    @Test
    fun metadataCommandConstructionDoesNotRequireDefaultIssuerIdentifier() {
        val unconfiguredProvider =
            object : com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider by fakeConfigProvider {
                override val issuerIdentifier: String
                    get() = throw IllegalArgumentException("oid4vci.issuer.identifier is required")
            }

        val command =
            GetIssuerMetadataEndpointCommandImpl(
                execution,
                fakeBuildMetadata,
                fakeBuildSignedMetadata,
                unconfiguredProvider,
                fakeRestConfigProvider,
                FakeMultiManagedIdentifierService,
                DefaultOid4vciIssuerPublicUrlResolver(NoOpAppConfigService),
            )

        assertEquals(
            com.sphereon.openid.oid4vci.issuer.impl.http.command.GetIssuerMetadataEndpointCommand.COMMAND_ID,
            command.id,
        )
    }

    // Real endpoint commands with fake dependencies
    private val fakeRestConfigProvider =
        object : com.sphereon.openid.oid4vci.rest.Oid4vciRestConfigProvider {
            override fun getConfig() =
                com.sphereon.openid.oid4vci.rest
                    .Oid4vciRestConfig(externalBaseUrl = null)
        }
    private val metadataCommand =
        GetIssuerMetadataEndpointCommandImpl(
            execution,
            fakeBuildMetadata,
            fakeBuildSignedMetadata,
            fakeConfigProvider,
            fakeRestConfigProvider,
            FakeMultiManagedIdentifierService,
            DefaultOid4vciIssuerPublicUrlResolver(NoOpAppConfigService),
        )
    private val credentialOfferCommand =
        GetCredentialOfferEndpointCommandImpl(
            execution,
            fakeOfferStore,
            FakeCredentialIssuanceSessionStore(),
            fakeOfferSessionStore,
            offerRateLimiter,
            fakeCreateCredentialOffer,
        )
    private val nonceCommand = IssueNonceEndpointCommandImpl(execution, fakeIssueNonce)

    // Real CredentialResponseEncryptor wired with a JweService that throws — none of the
    // happy-path tests in this file exercise credential_response_encryption, so the encryptor
    // stays on its `Plain` short-circuit and never reaches JweService. Tests that DO exercise
    // encryption (e.g. encryption_required violation) use the credentialCommand fixture
    // unchanged because the violation rejection happens before the encryptor is invoked.
    private val credentialResponseEncryptor =
        com.sphereon.openid.oid4vci.issuer.impl.encryption
            .CredentialResponseEncryptor(
                jweService = ThrowingJweService,
                configProvider = fakeConfigProvider,
            )
    private val credentialCommand =
        HandleCredentialEndpointCommandImpl(
            execution,
            fakeHandleCredential,
            fakeDecryptJweCommand,
            fakeConfigProvider,
            fakeRestConfigProvider,
            DefaultOid4vciIssuerPublicUrlResolver(NoOpAppConfigService),
            credentialResponseEncryptor,
        )
    private val deferredCommand =
        HandleDeferredCredentialEndpointCommandImpl(
            execution,
            fakeHandleDeferred,
            fakeDecryptJweCommand,
            credentialResponseEncryptor,
            fakeConfigProvider,
        )
    private val notificationCommand = HandleNotificationEndpointCommandImpl(execution, fakeHandleNotification, fakeConfigProvider)
    private val metadataRegistry = TestHttpEndpointCommandRegistry(metadataCommand)
    private val protocolRegistry =
        TestHttpEndpointCommandRegistry(
            credentialOfferCommand,
            nonceCommand,
            credentialCommand,
            deferredCommand,
            notificationCommand,
        )

    // Adapters
    private val metadataAdapter =
        Oid4vciIssuerMetadataHttpAdapter(
            execution,
            metadataRegistry,
            NoOpRoutableSlugLookup(),
            testTenantIdProvider(),
            FixedIssuerInstanceResolver(Ok(routedIssuerId)),
            com.sphereon.openid.oid4vci.issuer.impl.config.DefaultOid4vciIssuerInstanceIdProvider(),
        )
    private val protocolAdapter =
        Oid4vciIssuerProtocolHttpAdapter(
            execution,
            protocolRegistry,
            NoOpRoutableSlugLookup(),
            testTenantIdProvider(),
            NoOpAppConfigService,
            FixedIssuerInstanceResolver(Ok(routedIssuerId)),
            com.sphereon.openid.oid4vci.issuer.impl.config.DefaultOid4vciIssuerInstanceIdProvider(),
        )

    // ========================================================================
    // 1. Metadata endpoint
    // ========================================================================

    @Test
    fun metadataEndpointRejectsMissingIssuerUuidSelector() =
        runTest {
            configureMetadataSuccess()
            val adapter = metadataAdapterWith(FixedIssuerInstanceResolver(Ok(null)))

            val response =
                adapter.dispatchForTest(
                    GenericHttpRequest(
                        method = "GET",
                        path = "/.well-known/openid-credential-issuer",
                        headers = mapOf("host" to "issuer.example.com"),
                    ),
                    metadataRegistry,
                )

            assertEquals(400, response.statusCode)
        }

    @Test
    fun metadataEndpointRejectsNonUuidIssuerSelector() =
        runTest {
            configureMetadataSuccess()
            val adapter = metadataAdapterWith(FixedIssuerInstanceResolver(Ok("default")))

            val response =
                adapter.dispatchForTest(
                    GenericHttpRequest(
                        method = "GET",
                        path = "/.well-known/openid-credential-issuer",
                        headers = mapOf("host" to "issuer.example.com"),
                    ),
                    metadataRegistry,
                )

            assertEquals(400, response.statusCode)
        }

    @Test
    fun metadataEndpointRejectsNonCanonicalUuidSelector() =
        runTest {
            configureMetadataSuccess()
            val adapter = metadataAdapterWith(FixedIssuerInstanceResolver(Ok(" $routedIssuerId ")))

            val response =
                adapter.dispatchForTest(
                    GenericHttpRequest(
                        method = "GET",
                        path = "/.well-known/openid-credential-issuer",
                        headers = mapOf("host" to "issuer.example.com"),
                    ),
                    metadataRegistry,
                )

            assertEquals(400, response.statusCode)
        }

    @Test
    fun metadataEndpointPublishesExactIssuerUuidOnlyDuringDispatch() =
        runTest {
            configureMetadataSuccess()
            val holder = RecordingIssuerInstanceIdProvider()
            val adapter = metadataAdapterWith(FixedIssuerInstanceResolver(Ok(routedIssuerId)), holder)

            val response =
                adapter.dispatchForTest(
                    GenericHttpRequest(
                        method = "GET",
                        path = "/.well-known/openid-credential-issuer",
                        headers = mapOf("host" to "issuer.example.com"),
                    ),
                    metadataRegistry,
                )

            assertEquals(200, response.statusCode)
            assertEquals(listOf(routedIssuerId), holder.assignedInstanceIds)
            assertNull(holder.currentInstanceId())
        }

    private fun metadataAdapterWith(
        resolver: Oid4vciIssuerInstanceResolver,
        holder: MutableOid4vciIssuerInstanceIdProvider = RecordingIssuerInstanceIdProvider(),
    ) =
        Oid4vciIssuerMetadataHttpAdapter(
            execution,
            metadataRegistry,
            NoOpRoutableSlugLookup(),
            testTenantIdProvider(),
            resolver,
            holder,
        )

    private fun configureMetadataSuccess() {
        fakeBuildMetadata.result =
            Ok(
                CredentialIssuerMetadata(
                    credentialIssuer = "https://issuer.example.com",
                    credentialEndpoint = "https://issuer.example.com/oid4vci/credential",
                    credentialConfigurationsSupported =
                        mapOf("TestCred" to CredentialConfigurationSupported(format = "jwt_vc_json")),
                ),
            )
    }

    @Test
    fun metadataEndpointReturns200WithMetadata() =
        runTest {
            val metadata =
                CredentialIssuerMetadata(
                    credentialIssuer = "https://issuer.example.com",
                    credentialEndpoint = "https://issuer.example.com/oid4vci/credential",
                    credentialConfigurationsSupported =
                        mapOf(
                            "TestCred" to CredentialConfigurationSupported(format = "jwt_vc_json"),
                        ),
                )
            fakeBuildMetadata.result = Ok(metadata)

            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/.well-known/openid-credential-issuer",
                    headers = mapOf("host" to "issuer.example.com"),
                )

            val response = metadataAdapter.dispatchForTest(request, metadataRegistry)

            assertEquals(200, response.statusCode)
            assertNotNull(response.body)
            val body = json.parseToJsonElement(response.body!!)
            assertEquals(
                "https://issuer.example.com",
                body.jsonObject["credential_issuer"]?.jsonPrimitive?.content,
            )
        }

    @Test
    fun metadataEndpointFallsBackToJsonWhenSignedMetadataIsRequestedWithoutSigningKey() =
        runTest {
            configureMetadataSuccess()

            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/.well-known/openid-credential-issuer",
                    headers = mapOf("host" to "issuer.example.com", "Accept" to "application/jwt"),
                )

            val response = metadataAdapter.dispatchForTest(request, metadataRegistry)

            assertEquals(200, response.statusCode)
            assertEquals("application/json", response.headers["Content-Type"])
            val body = json.parseToJsonElement(assertNotNull(response.body)).jsonObject
            assertEquals("https://issuer.example.com", body["credential_issuer"]?.jsonPrimitive?.content)
            assertNull(body["signed_metadata"])
            assertNull(fakeBuildSignedMetadata.lastArgs)
        }

    @Test
    fun pathBearingMetadataEndpointReturns200WithoutTenantResolution() =
        runTest {
            val pathConfigProvider =
                FakeOid4vciIssuerConfigProvider(
                    issuerIdentifier = "http://localhost:18084/oid4vci",
                )
            val buildMetadata = FakeBuildIssuerMetadataCommand()
            val buildSignedMetadata = FakeBuildSignedIssuerMetadataCommand()
            buildMetadata.result =
                Ok(
                    CredentialIssuerMetadata(
                        credentialIssuer = "http://localhost:18084/oid4vci",
                        credentialEndpoint = "http://localhost:18084/oid4vci/credential",
                        credentialConfigurationsSupported =
                            mapOf(
                                "TestCred" to CredentialConfigurationSupported(format = "jwt_vc_json"),
                            ),
                    ),
                )
            val command =
                GetIssuerMetadataEndpointCommandImpl(
                    execution,
                    buildMetadata,
                    buildSignedMetadata,
                    pathConfigProvider,
                    fakeRestConfigProvider,
                    FakeMultiManagedIdentifierService,
                    DefaultOid4vciIssuerPublicUrlResolver(NoOpAppConfigService),
                )
            val adapter =
                Oid4vciIssuerMetadataHttpAdapter(
                    execution,
                    TestHttpEndpointCommandRegistry(command),
                    NoOpRoutableSlugLookup(),
                    testTenantIdProvider(),
                    FixedIssuerInstanceResolver(Ok(routedIssuerId)),
                    com.sphereon.openid.oid4vci.issuer.impl.config.DefaultOid4vciIssuerInstanceIdProvider(),
                )
            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/.well-known/openid-credential-issuer/oid4vci",
                    headers = mapOf("host" to "localhost:18084"),
                )

            val response = adapter.dispatchForTest(request, TestHttpEndpointCommandRegistry(command))

            assertEquals(200, response.statusCode)
            assertEquals("http://localhost:18084/oid4vci", buildMetadata.lastArgs?.issuerIdentifier)
            assertEquals("http://localhost:18084/oid4vci", buildMetadata.lastArgs?.baseUrl)
        }

    /**
     * A tenant host carries several issuers under `/oid4vci/<instance>`. A request for an issuer
     * path that names none of them must not be answered with another issuer's metadata, even when
     * the URL resolver lands on a sibling (host-level or tenant-default binding).
     */
    @Test
    fun metadataEndpointRefusesUnknownIssuerPathInsteadOfServingAnotherIssuer() =
        runTest {
            val known = metadataFixtureFor("https://operator.example/oid4vci/msfm-r9")

            val response =
                known.adapter.dispatchForTest(
                    GenericHttpRequest(
                        method = "GET",
                        path = "/.well-known/openid-credential-issuer/oid4vci/does-not-exist",
                        headers = mapOf("host" to "operator.example"),
                    ),
                    known.registry,
                )

            assertEquals(404, response.statusCode, "unknown issuer path must be 404, got ${response.body}")
            val body = json.parseToJsonElement(assertNotNull(response.body)).jsonObject
            assertEquals("not_found", body["error"]?.jsonPrimitive?.content)
            assertNull(body["credential_issuer"], "no issuer metadata may be disclosed for an unknown issuer path")
            assertNull(known.buildMetadata.lastArgs, "metadata must not be built for an unknown issuer path")
        }

    @Test
    fun metadataEndpointServesKnownIssuerPathWithItsOwnIdentifier() =
        runTest {
            val known = metadataFixtureFor("https://operator.example/oid4vci/msfm-r9")

            val response =
                known.adapter.dispatchForTest(
                    GenericHttpRequest(
                        method = "GET",
                        path = "/.well-known/openid-credential-issuer/oid4vci/msfm-r9",
                        headers = mapOf("host" to "operator.example"),
                    ),
                    known.registry,
                )

            assertEquals(200, response.statusCode, "known issuer path must be served, got ${response.body}")
            val body = json.parseToJsonElement(assertNotNull(response.body)).jsonObject
            assertEquals(
                "https://operator.example/oid4vci/msfm-r9",
                body["credential_issuer"]?.jsonPrimitive?.content,
            )
        }

    @Test
    fun bareOriginIssuerIsServedOnlyAtTheBareWellKnownPath() =
        runTest {
            val bare = metadataFixtureFor("https://issuer.example.com")

            val bareResponse =
                bare.adapter.dispatchForTest(
                    GenericHttpRequest(
                        method = "GET",
                        path = "/.well-known/openid-credential-issuer",
                        headers = mapOf("host" to "issuer.example.com"),
                    ),
                    bare.registry,
                )
            assertEquals(200, bareResponse.statusCode)
            assertEquals(
                "https://issuer.example.com",
                json.parseToJsonElement(assertNotNull(bareResponse.body)).jsonObject["credential_issuer"]?.jsonPrimitive?.content,
            )

            val suffixed =
                metadataFixtureFor("https://issuer.example.com")
            val suffixedResponse =
                suffixed.adapter.dispatchForTest(
                    GenericHttpRequest(
                        method = "GET",
                        path = "/.well-known/openid-credential-issuer/anything",
                        headers = mapOf("host" to "issuer.example.com"),
                    ),
                    suffixed.registry,
                )
            assertEquals(404, suffixedResponse.statusCode, "a bare-origin issuer has no path-bearing alias")
            assertNull(suffixed.buildMetadata.lastArgs)
        }

    @Test
    fun legacyPrefixMetadataRequestForUnknownIssuerPathIsNotFound() =
        runTest {
            val known = metadataFixtureFor("https://operator.example/oid4vci/msfm-r9")

            val unknown =
                known.command.execute(
                    GenericHttpRequest(
                        method = "GET",
                        path = "/.well-known/openid-credential-issuer",
                        headers = mapOf("host" to "operator.example"),
                        originalPath = "/oid4vci/does-not-exist/.well-known/openid-credential-issuer",
                    ),
                )
            assertEquals(404, unknown.value.statusCode)
            assertNull(known.buildMetadata.lastArgs)

            val own =
                known.command.execute(
                    GenericHttpRequest(
                        method = "GET",
                        path = "/.well-known/openid-credential-issuer",
                        headers = mapOf("host" to "operator.example"),
                        originalPath = "/oid4vci/msfm-r9/.well-known/openid-credential-issuer",
                    ),
                )
            assertEquals(200, own.value.statusCode)
        }

    @Test
    fun endedIssuerSelectionAnswersNotFoundWithMetadataErrorShape() =
        runTest {
            val ended =
                metadataFixtureFor(
                    issuerIdentifier = "https://operator.example/oid4vci/ended",
                    resolvedUrls = Err(IdkError.NOT_FOUND_ERROR(message = "No active public endpoint for the selected OID4VCI issuer instance")),
                )

            val response =
                ended.adapter.dispatchForTest(
                    GenericHttpRequest(
                        method = "GET",
                        path = "/.well-known/openid-credential-issuer/oid4vci/ended",
                        headers = mapOf("host" to "operator.example"),
                    ),
                    ended.registry,
                )

            assertEquals(404, response.statusCode, "an ended issuer must be 404, got ${response.body}")
            assertEquals(
                "not_found",
                json.parseToJsonElement(assertNotNull(response.body)).jsonObject["error"]?.jsonPrimitive?.content,
            )
        }

    private class MetadataFixture(
        val command: GetIssuerMetadataEndpointCommandImpl,
        val registry: TestHttpEndpointCommandRegistry,
        val adapter: Oid4vciIssuerMetadataHttpAdapter,
        val buildMetadata: FakeBuildIssuerMetadataCommand,
    )

    /**
     * Metadata command whose URL resolver always answers [issuerIdentifier], regardless of the
     * requested path. This models a resolver that fell back to a host-level or tenant-default
     * binding: the command itself must still refuse a request for a different issuer path.
     */
    private fun metadataFixtureFor(
        issuerIdentifier: String,
        resolvedUrls: IdkResult<com.sphereon.openid.oid4vci.issuer.impl.http.command.Oid4vciIssuerPublicUrls, IdkError> =
            Ok(
                com.sphereon.openid.oid4vci.issuer.impl.http.command.Oid4vciIssuerPublicUrls(
                    issuerIdentifier = issuerIdentifier,
                    endpointBaseUrl = issuerIdentifier,
                ),
            ),
    ): MetadataFixture {
        val buildMetadata = FakeBuildIssuerMetadataCommand()
        buildMetadata.result =
            Ok(
                CredentialIssuerMetadata(
                    credentialIssuer = issuerIdentifier,
                    credentialEndpoint = "$issuerIdentifier/credential",
                    credentialConfigurationsSupported =
                        mapOf("TestCred" to CredentialConfigurationSupported(format = "jwt_vc_json")),
                ),
            )
        val resolver =
            object : com.sphereon.openid.oid4vci.issuer.impl.http.command.Oid4vciIssuerPublicUrlResolver {
                override suspend fun resolve(
                    request: GenericHttpRequest,
                    issuerConfigProvider: com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider,
                    restConfigProvider: com.sphereon.openid.oid4vci.rest.Oid4vciRestConfigProvider,
                ) = resolvedUrls
            }
        val command =
            GetIssuerMetadataEndpointCommandImpl(
                execution,
                buildMetadata,
                FakeBuildSignedIssuerMetadataCommand(),
                FakeOid4vciIssuerConfigProvider(issuerIdentifier = issuerIdentifier),
                fakeRestConfigProvider,
                FakeMultiManagedIdentifierService,
                resolver,
            )
        val registry = TestHttpEndpointCommandRegistry(command)
        val adapter =
            Oid4vciIssuerMetadataHttpAdapter(
                execution,
                registry,
                NoOpRoutableSlugLookup(),
                testTenantIdProvider(),
                FixedIssuerInstanceResolver(Ok(routedIssuerId)),
                com.sphereon.openid.oid4vci.issuer.impl.config.DefaultOid4vciIssuerInstanceIdProvider(),
            )
        return MetadataFixture(command, registry, adapter, buildMetadata)
    }

    // ========================================================================
    // 2. Credential offer endpoint
    // ========================================================================

    @Test
    fun credentialOfferReturns200WhenFound() =
        runTest {
            val offer =
                CredentialOffer(
                    credentialIssuer = "https://issuer.example.com",
                    credentialConfigurationIds = listOf("TestCred"),
                )
            fakeOfferStore.putOffer("offer-123", offer)

            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/oid4vci/credentials/offers/offer-123",
                )

            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(200, response.statusCode)
            assertNotNull(response.body)
            val body = json.parseToJsonElement(response.body!!)
            assertEquals(
                "https://issuer.example.com",
                body.jsonObject["credential_issuer"]?.jsonPrimitive?.content,
            )
        }

    @Test
    fun credentialOfferReturns404WhenNotFound() =
        runTest {
            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/oid4vci/credentials/offers/nonexistent",
                )

            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(404, response.statusCode)
        }

    @Test
    fun singleUseOfferReturns200WithoutNoStoreCacheControl() =
        runTest {
            val offer =
                CredentialOffer(
                    credentialIssuer = "https://issuer.example.com",
                    credentialConfigurationIds = listOf("TestCred"),
                )
            fakeOfferStore.putOffer("single-use-offer", offer)
            fakeOfferSessionStore.putSession(
                singleUseSession(offerId = "single-use-offer"),
            )

            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/oid4vci/credentials/offers/single-use-offer",
                )

            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(200, response.statusCode)
            assertNotNull(response.body)
            // SINGLE_USE keeps the pre-Task-4.3 behaviour: no reusable no-store cache directive.
            assertEquals("application/json", response.headers["Content-Type"])
            assertTrue(response.headers["Cache-Control"] != "no-store, no-cache, must-revalidate")
        }

    @Test
    fun reusableOfferOverRateLimitReturns429() =
        runTest {
            val offer =
                CredentialOffer(
                    credentialIssuer = "https://issuer.example.com",
                    credentialConfigurationIds = listOf("TestCred"),
                )
            fakeOfferStore.putOffer("reusable-offer", offer)
            fakeOfferSessionStore.putSession(
                reusableSession(
                    offerId = "reusable-offer",
                    rateLimit =
                        com.sphereon.openid.oid4vci.issuer.command
                            .OfferRateLimit(maxPerWindow = 1, windowSeconds = 60),
                ),
            )

            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/oid4vci/credentials/offers/reusable-offer",
                )

            // First fetch consumes the only slot in the window.
            protocolAdapter.dispatchForTest(request, protocolRegistry)
            // Second fetch is over the limit.
            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(429, response.statusCode)
            assertEquals("no-store, no-cache, must-revalidate", response.headers["Cache-Control"])
        }

    @Test
    fun reusableOfferWithinRateLimitMintsFreshOfferPerFetch() =
        runTest {
            val seenArgsBeforeFetch = fakeCreateCredentialOffer.seenArgs.size
            val offer =
                CredentialOffer(
                    credentialIssuer = "https://issuer.example.com",
                    credentialConfigurationIds = listOf("TestCred"),
                )
            fakeOfferStore.putOffer("reusable-offer-2", offer)
            fakeOfferSessionStore.putSession(
                reusableSession(
                    offerId = "reusable-offer-2",
                    rateLimit =
                        com.sphereon.openid.oid4vci.issuer.command
                            .OfferRateLimit(maxPerWindow = 5, windowSeconds = 60),
                ),
            )

            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/oid4vci/credentials/offers/reusable-offer-2",
                )

            val first = protocolAdapter.dispatchForTest(request, protocolRegistry)
            val second = protocolAdapter.dispatchForTest(request, protocolRegistry)

            // Both fetches succeed with the reusable no-store cache directive.
            assertEquals(200, first.statusCode)
            assertEquals(200, second.statusCode)
            assertEquals("no-store, no-cache, must-revalidate", first.headers["Cache-Control"])
            assertEquals("no-store, no-cache, must-revalidate", second.headers["Cache-Control"])

            // The fresh-per-fetch property: each GET mints a brand-new inner offer. The protocol
            // CredentialOffer wire object carries no correlation_id, so the per-mint distinguishing
            // value is the freshly registered pre-authorized code inside `grants`.
            assertNotNull(first.body)
            assertNotNull(second.body)
            val firstCode = preAuthorizedCodeOf(first.body!!)
            val secondCode = preAuthorizedCodeOf(second.body!!)
            assertNotNull(firstCode)
            assertNotNull(secondCode)
            assertTrue(firstCode != secondCode, "two GETs on the same reusable URI must mint distinct inner offers")
            val fetchArgs = fakeCreateCredentialOffer.seenArgs.drop(seenArgsBeforeFetch)
            assertEquals(2, fetchArgs.size)
            assertTrue(fetchArgs.all { it.instanceId == routedIssuerId })
        }

    private fun preAuthorizedCodeOf(body: String): String? =
        json
            .parseToJsonElement(body)
            .jsonObject["grants"]
            ?.jsonObject
            ?.get("urn:ietf:params:oauth:grant-type:pre-authorized_code")
            ?.jsonObject
            ?.get("pre-authorized_code")
            ?.jsonPrimitive
            ?.content

    private fun singleUseSession(offerId: String) =
        com.sphereon.openid.oid4vci.rest.CredentialOfferSession(
            correlationId = "corr-$offerId",
            instanceId = routedIssuerId,
            offerId = offerId,
            issuanceSessionId = "issuance-session-$offerId",
            status = com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED,
            createdAt = 0L,
            lastUpdatedAt = 0L,
            uriLifecycle = com.sphereon.openid.oid4vci.issuer.command.OfferUriLifecycle.SINGLE_USE,
        )

    private fun reusableSession(
        offerId: String,
        rateLimit: com.sphereon.openid.oid4vci.issuer.command.OfferRateLimit,
    ) = com.sphereon.openid.oid4vci.rest.CredentialOfferSession(
        correlationId = "corr-$offerId",
        instanceId = routedIssuerId,
        offerId = offerId,
        issuanceSessionId = "issuance-session-$offerId",
        status = com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED,
        createdAt = 0L,
        lastUpdatedAt = 0L,
        uriLifecycle = com.sphereon.openid.oid4vci.issuer.command.OfferUriLifecycle.REUSABLE_FRESH_PER_FETCH,
        rateLimit = rateLimit,
        authorizationPolicySnapshot = reusableAuthorizationSnapshot(),
        offerTemplate =
            com.sphereon.openid.oid4vci.rest.CredentialOfferTemplate(
                issuerId = "https://issuer.example.com",
                credentialConfigurationIds = listOf("TestCred"),
                preAuthorizedCodeGrant = true,
            ),
    )

    @OptIn(ExperimentalUuidApi::class)
    private fun reusableAuthorizationSnapshot() = Oid4vciAuthorizationPolicySnapshot(
        issuerId = Uuid.parse(routedIssuerId),
        authorizationServerId = Uuid.parse("00000000-0000-4000-8000-000000000051"),
        authorizationServerIssuer = "https://as.example.com",
        applicableGrants = setOf(Oid4vciAuthorizationGrant.PRE_AUTHORIZED_CODE),
        profile = Oid4vciIssuerSpecProfile.OID4VCI_1_0_FINAL,
        profileRevision = 3,
        authorizationServerRevision = 5,
        bindingRevision = 7,
    )

    // ========================================================================
    // 3. Nonce endpoint
    // ========================================================================

    @Test
    fun nonceEndpointReturns200() =
        runTest {
            fakeIssueNonce.result =
                Ok(
                    NonceResponse(cNonce = "test-nonce-value", cNonceExpiresIn = 300),
                )

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/oid4vci/nonce",
                )

            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(200, response.statusCode)
            assertNotNull(response.body)
            val body = json.parseToJsonElement(response.body!!)
            assertEquals("test-nonce-value", body.jsonObject["c_nonce"]?.jsonPrimitive?.content)
        }

    @Test
    fun nonceEndpointIncludesCacheControlNoStore() =
        runTest {
            fakeIssueNonce.result =
                Ok(
                    NonceResponse(cNonce = "cache-test-nonce", cNonceExpiresIn = 300),
                )

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/oid4vci/nonce",
                )

            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(200, response.statusCode)
            assertEquals("no-store", response.headers["Cache-Control"])
        }

    // ========================================================================
    // 4. Credential endpoint - success
    // ========================================================================

    @Test
    fun credentialEndpointReturns200OnSuccess() =
        runTest {
            fakeHandleCredential.result =
                Ok(
                    CredentialResponse(
                        credentials = listOf(CredentialResponseItem(credential = JsonPrimitive("eyJ.test.credential"))),
                    ),
                )

            val requestBody = """{"credential_configuration_id": "TestCred", "proofs": {"jwt": ["eyJ..."]}}"""

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/oid4vci/credential",
                    headers = mapOf("Authorization" to "Bearer test-token"),
                    bodySupplier = { requestBody },
                )

            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(200, response.statusCode)
            assertNotNull(response.body)
            val body = json.parseToJsonElement(response.body!!)
            assertNotNull(body.jsonObject["credentials"])

            assertNotNull(fakeHandleCredential.lastArgs)
            assertEquals("test-token", fakeHandleCredential.lastArgs!!.accessToken)
        }

    @Test
    fun credentialEndpointUsesResolvedPublicIssuerIdentifierForProofAudience() =
        runTest {
            val publicIssuerIdentifier = "https://tenant.example/oid4vci/issuer-instance"
            val handleCredential = FakeHandleCredentialRequestCommand()
            handleCredential.result =
                Ok(
                    CredentialResponse(
                        credentials = listOf(CredentialResponseItem(credential = JsonPrimitive("eyJ.test.credential"))),
                    ),
                )
            val publicUrlResolver =
                object : com.sphereon.openid.oid4vci.issuer.impl.http.command.Oid4vciIssuerPublicUrlResolver {
                    override suspend fun resolve(
                        request: GenericHttpRequest,
                        issuerConfigProvider: com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider,
                        restConfigProvider: com.sphereon.openid.oid4vci.rest.Oid4vciRestConfigProvider,
                    ) =
                        Ok(
                            com.sphereon.openid.oid4vci.issuer.impl.http.command.Oid4vciIssuerPublicUrls(
                                issuerIdentifier = publicIssuerIdentifier,
                                endpointBaseUrl = publicIssuerIdentifier,
                            ),
                        )
                }
            val command =
                HandleCredentialEndpointCommandImpl(
                    execution,
                    handleCredential,
                    fakeDecryptJweCommand,
                    fakeConfigProvider,
                    fakeRestConfigProvider,
                    publicUrlResolver,
                    credentialResponseEncryptor,
                )

            val result =
                command.execute(
                    GenericHttpRequest(
                        method = "POST",
                        path = "/credential",
                        headers = mapOf("Authorization" to "Bearer test-token"),
                        bodySupplier = {
                            """{"credential_configuration_id": "TestCred", "proofs": {"jwt": ["eyJ..."]}}"""
                        },
                    ),
                )

            assertTrue(result.isOk, "credential endpoint should succeed: ${result.errorOrNull()}")
            assertEquals(
                publicIssuerIdentifier,
                handleCredential.lastArgs?.issuerIdentifier,
                "proof verification audience must equal the credential_issuer value advertised by metadata",
            )
        }

    @Test
    fun credentialEndpointPreparesConfigProviderBeforeReadingCredentialConfigurations() =
        runTest {
            val preparedConfigId = "PreparedCred"
            val preparingConfigProvider =
                FakeOid4vciIssuerConfigProvider(
                    initialCredentialConfigurations = emptyMap(),
                    preparedCredentialConfigurations =
                        mapOf(
                            preparedConfigId to CredentialConfigurationSupported(format = "jwt_vc_json"),
                        ),
                )
            val handleCredential = FakeHandleCredentialRequestCommand()
            handleCredential.result =
                Ok(
                    CredentialResponse(
                        credentials = listOf(CredentialResponseItem(credential = JsonPrimitive("eyJ.prepared.credential"))),
                    ),
                )
            val encryptor =
                com.sphereon.openid.oid4vci.issuer.impl.encryption.CredentialResponseEncryptor(
                    jweService = ThrowingJweService,
                    configProvider = preparingConfigProvider,
                )
            val command =
                HandleCredentialEndpointCommandImpl(
                    execution,
                    handleCredential,
                    fakeDecryptJweCommand,
                    preparingConfigProvider,
                    fakeRestConfigProvider,
                    DefaultOid4vciIssuerPublicUrlResolver(NoOpAppConfigService),
                    encryptor,
                )

            val result =
                command.execute(
                    GenericHttpRequest(
                        method = "POST",
                        path = "/credential",
                        headers = mapOf("Authorization" to "Bearer test-token"),
                        bodySupplier = {
                            """{"credential_configuration_id": "$preparedConfigId", "proofs": {"jwt": ["eyJ..."]}}"""
                        },
                    ),
                )

            assertTrue(result.isOk, "credential endpoint should succeed with prepared provider: ${result.errorOrNull()}")
            assertEquals(200, result.value.statusCode)
            assertEquals(1, preparingConfigProvider.prepareCount)
            assertTrue(
                handleCredential.lastArgs?.credentialConfigurations?.containsKey(preparedConfigId) == true,
                "credential endpoint must pass the prepared configuration snapshot",
            )
        }

    // ========================================================================
    // 5. Credential endpoint - missing bearer token
    // ========================================================================

    @Test
    fun credentialEndpointReturns401WithoutBearerToken() =
        runTest {
            val requestBody = """{"credential_configuration_id": "TestCred"}"""

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/oid4vci/credential",
                    headers = emptyMap(),
                    bodySupplier = { requestBody },
                )

            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(401, response.statusCode)
            assertNotNull(response.body)
            val body = json.parseToJsonElement(response.body!!)
            assertEquals(Oid4vciErrors.INVALID_TOKEN, body.jsonObject["error"]?.jsonPrimitive?.content)
        }

    // ========================================================================
    // 6. Deferred credential endpoint - success (credential ready)
    // ========================================================================

    @Test
    fun deferredCredentialEndpointReturns200WhenReady() =
        runTest {
            fakeHandleDeferred.result =
                Ok(
                    CredentialResponse(
                        credentials = listOf(CredentialResponseItem(credential = JsonPrimitive("eyJ.deferred.credential"))),
                    ),
                )

            val requestBody = """{"transaction_id": "txn-123"}"""

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/oid4vci/deferredCredential",
                    headers = mapOf("Authorization" to "Bearer test-token"),
                    bodySupplier = { requestBody },
                )

            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(200, response.statusCode)
            assertNotNull(response.body)
            val body = json.parseToJsonElement(response.body!!)
            assertNotNull(body.jsonObject["credentials"])

            assertNotNull(fakeHandleDeferred.lastArgs)
            assertEquals("test-token", fakeHandleDeferred.lastArgs!!.accessToken)
            assertEquals("txn-123", fakeHandleDeferred.lastArgs!!.deferredRequest.transactionId)
        }

    // ========================================================================
    // 7. Deferred credential endpoint - issuance pending
    // ========================================================================

    @Test
    fun deferredCredentialEndpointReturns202WhenPending() =
        runTest {
            fakeHandleDeferred.result =
                Ok(
                    CredentialResponse(
                        transactionId = "txn-456",
                        interval = 5,
                    ),
                )

            val requestBody = """{"transaction_id": "txn-456"}"""

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/oid4vci/deferredCredential",
                    headers = mapOf("Authorization" to "Bearer test-token"),
                    bodySupplier = { requestBody },
                )

            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(202, response.statusCode)
            assertNotNull(response.body)
            val body = json.parseToJsonElement(response.body!!)
            assertEquals("txn-456", body.jsonObject["transaction_id"]?.jsonPrimitive?.content)
            assertNotNull(body.jsonObject["interval"])
            assertNull(body.jsonObject["error"])
        }

    // ========================================================================
    // 8. Notification endpoint - success
    // ========================================================================

    @Test
    fun notificationEndpointReturns204OnSuccess() =
        runTest {
            fakeHandleNotification.result = Ok(Unit)

            val requestBody = """{"notification_id": "notif-1", "event": "credential_accepted"}"""

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/oid4vci/notification",
                    headers = mapOf("Authorization" to "Bearer test-token"),
                    bodySupplier = { requestBody },
                )

            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(204, response.statusCode)
            assertNull(response.body)

            assertNotNull(fakeHandleNotification.lastArgs)
            assertEquals("test-token", fakeHandleNotification.lastArgs!!.accessToken)
            assertEquals("notif-1", fakeHandleNotification.lastArgs!!.notification.notificationId)
            assertEquals(CredentialNotificationEvent.CREDENTIAL_ACCEPTED, fakeHandleNotification.lastArgs!!.notification.event)
        }

    // ========================================================================
    // 9. Notification endpoint - missing bearer token
    // ========================================================================

    @Test
    fun notificationEndpointReturns401WithoutBearerToken() =
        runTest {
            val requestBody = """{"notification_id": "notif-1", "event": "credential_accepted"}"""

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/oid4vci/notification",
                    headers = emptyMap(),
                    bodySupplier = { requestBody },
                )

            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(401, response.statusCode)
            assertNotNull(response.body)
            val body = json.parseToJsonElement(response.body!!)
            assertEquals(Oid4vciErrors.INVALID_TOKEN, body.jsonObject["error"]?.jsonPrimitive?.content)
        }

    // ========================================================================
    // 10. Credential endpoint - service error
    // ========================================================================

    @Test
    fun credentialEndpointReturns400OnServiceError() =
        runTest {
            fakeHandleCredential.result =
                Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Invalid credential request"),
                )

            val requestBody = """{"credential_configuration_id": "TestCred"}"""

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/oid4vci/credential",
                    headers = mapOf("Authorization" to "Bearer test-token"),
                    bodySupplier = { requestBody },
                )

            val response = protocolAdapter.dispatchForTest(request, protocolRegistry)

            assertEquals(400, response.statusCode)
            assertNotNull(response.body)
            val body = json.parseToJsonElement(response.body!!)
            assertEquals(
                Oid4vciErrors.INVALID_CREDENTIAL_REQUEST,
                body.jsonObject["error"]?.jsonPrimitive?.content,
            )
            assertTrue(
                body.jsonObject["error_description"]
                    ?.jsonPrimitive
                    ?.content
                    ?.contains("Invalid credential request") == true,
            )
        }

    /**
     * JweService stand-in that throws on every method. None of the happy-path tests in this file
     * exercise credential_response_encryption, so the encryptor's `Plain` short-circuit always
     * fires and the JWE pipeline is never reached. Throwing makes any accidental test that DOES
     * trigger the encrypt path loud rather than silently producing fake JWE bytes.
     */
    private object ThrowingJweService : com.sphereon.crypto.jose.jwe.JweService {
        override val commands: com.sphereon.crypto.jose.jwe.JweService.Commands
            get() = throw UnsupportedOperationException("not used in HTTP-adapter tests")

        override suspend fun prepareJwe(args: com.sphereon.crypto.jose.jwe.PrepareJweArgs) = throw UnsupportedOperationException("ThrowingJweService.prepareJwe")

        override suspend fun createJweCompact(args: com.sphereon.crypto.jose.jwe.CreateJweCompactArgs) = throw UnsupportedOperationException("ThrowingJweService.createJweCompact")

        override suspend fun createJweJsonFlattened(args: com.sphereon.crypto.jose.jwe.CreateJweJsonArgs) = throw UnsupportedOperationException("ThrowingJweService.createJweJsonFlattened")

        override suspend fun createJweJsonGeneral(args: com.sphereon.crypto.jose.jwe.CreateJweJsonGeneralArgs) = throw UnsupportedOperationException("ThrowingJweService.createJweJsonGeneral")

        override suspend fun decryptJwe(args: com.sphereon.crypto.jose.jwe.DecryptJweArgs) = throw UnsupportedOperationException("ThrowingJweService.decryptJwe")
    }
}

private class FixedIssuerInstanceResolver(
    private val result: IdkResult<String?, IdkError>,
) : Oid4vciIssuerInstanceResolver {
    override suspend fun resolve(request: GenericHttpRequest): IdkResult<String?, IdkError> = result
}

private class RecordingIssuerInstanceIdProvider : MutableOid4vciIssuerInstanceIdProvider {
    val assignedInstanceIds = mutableListOf<String>()
    private var current: String? = null

    override fun currentInstanceId(): String? = current

    override fun setCurrentInstanceId(instanceId: String) {
        assignedInstanceIds += instanceId
        current = instanceId
    }

    override fun clearCurrentInstanceId() {
        current = null
    }
}

private class TestHttpEndpointCommandRegistry(
    vararg commands: HttpEndpointCommand,
) : HttpEndpointCommandRegistry {
    private val commandsById = commands.associateBy { it.id }

    override fun get(handlerCommandId: String): HttpEndpointCommand? = commandsById[handlerCommandId]

    override fun listHandlerCommandIds(): Set<String> = commandsById.keys

    fun resolve(
        request: GenericHttpRequest,
        adapter: HttpAdapter,
    ): ResolvedTestEndpoint {
        val mount = adapter.describe().mount
        val pathSegments = request.path.trim('/').split('/').filter { it.isNotEmpty() }
        val candidates =
            buildList {
                add(request.path)
                for (dropCount in 1 until pathSegments.size) {
                    add("/" + pathSegments.drop(dropCount).joinToString("/"))
                }
            }.distinct()
        for (normalizedPath in candidates) {
            val relativePath =
                when {
                    mount.adapterBasePath.isEmpty() || mount.adapterBasePath == "/" -> normalizedPath
                    normalizedPath == mount.adapterBasePath -> "/"
                    normalizedPath.startsWith(mount.adapterBasePath.trimEnd('/') + "/") ->
                        normalizedPath.removePrefix(mount.adapterBasePath).ifEmpty { "/" }
                    else -> continue
                }
            val relativeRequest = request.copy(path = relativePath)
            for (command in commandsById.values) {
                val endpointPattern =
                    command.endpoint.pathPatterns.firstOrNull {
                        relativeRequest.matches(command.endpoint.method.name, it)
                    } ?: continue
                val catalogPattern =
                    when {
                        mount.adapterBasePath.isEmpty() || mount.adapterBasePath == "/" -> endpointPattern
                        endpointPattern == "/" -> mount.adapterBasePath
                        else -> mount.adapterBasePath.trimEnd('/') + "/" + endpointPattern.trimStart('/')
                    }
                return ResolvedTestEndpoint(command.id, normalizedPath, catalogPattern)
            }
        }
        error("No test endpoint for ${request.method} ${request.path}; handlers=${commandsById.keys}")
    }
}

private data class ResolvedTestEndpoint(
    val handlerCommandId: String,
    val normalizedPath: String,
    val matchedPathPattern: String,
)

private suspend fun HttpAdapter.dispatchForTest(
    request: GenericHttpRequest,
    registry: TestHttpEndpointCommandRegistry,
): GenericHttpResponse {
    val resolved = registry.resolve(request, this)
    val route =
        HttpAdapterRouteMatch(
            adapterId = id,
            method = request.method,
            originalPath = request.path,
            normalizedPath = resolved.normalizedPath,
            matchedPathPattern = resolved.matchedPathPattern,
            handlerCommandId = resolved.handlerCommandId,
            tenantIdFromPath = null,
        )
    return handleResolvedRequest(route.applyTo(request), route)
}
