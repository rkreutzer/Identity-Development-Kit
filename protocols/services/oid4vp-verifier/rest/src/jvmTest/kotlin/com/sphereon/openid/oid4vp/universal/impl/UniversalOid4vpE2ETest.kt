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

package com.sphereon.openid.oid4vp.universal.impl

import com.sphereon.core.api.conf.DefaultPrincipalMapPropertySource
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.dispatch.HttpAdapterDispatcher
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteSelection
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteSelector
import com.sphereon.core.api.service.SessionScopedCommandRegistry
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.generic.KeyOperations
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.jose.jwe.DecryptJweArgs
import com.sphereon.crypto.jose.jwe.JweCompact
import com.sphereon.crypto.jose.jwe.JweServiceImpl
import com.sphereon.crypto.resolution.extern.ExternalIdentifierJwkOpts
import com.sphereon.crypto.resolution.IdentifierContext
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.oauth2.common.jarm.CreateJarmResponseArgs
import com.sphereon.oauth2.common.jarm.CreateJarmResponseCommand
import com.sphereon.oauth2.common.jarm.JarmConfig
import com.sphereon.oauth2.common.jarm.JarmMode
import com.sphereon.openid.oid4vc.common.QrCodeOptions
import com.sphereon.openid.oid4vp.common.VpToken.Companion.toJson
import com.sphereon.openid.oid4vp.common.vpTokenOf
import com.sphereon.openid.oid4vp.dcql.DcqlClaimQuery
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.dcql.claimsPathPointer
import com.sphereon.openid.oid4vp.universal.CreateAuthorizationRequestInput
import com.sphereon.openid.oid4vp.universal.CreateAuthorizationRequestOutput
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.universal.impl.createUniversalOid4vpTestAppGraph
import com.sphereon.openid.oid4vp.verifier.HandleDirectPostResponseArgs
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationPurpose
import com.sphereon.openid.oid4vp.verifier.TrustedAuthenticationResolution
import com.sphereon.openid.oid4vp.verifier.Oid4vpVerifierService
import com.sphereon.openid.oid4vp.verifier.ParseAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.verifier.impl.Oid4VpVerifierServiceImpl
import com.sphereon.openid.oid4vp.verifier.impl.TestRequestObjectSigningConfig
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.sdjwt.IssueSdJwtArgs
import com.sphereon.sdjwt.PresentSdJwtArgs
import com.sphereon.sdjwt.SdField
import com.sphereon.sdjwt.SdJwtService
import com.sphereon.sdjwt.SdJwtServiceImpl
import com.sphereon.sdjwt.SdMap
import com.sphereon.sdjwt.dsl.sdJwtPayload
import io.ktor.http.Url
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import kotlin.test.assertIs

private suspend fun HttpAdapterDispatcher.dispatchSelected(
    appGraph: Any,
    request: GenericHttpRequest,
): GenericHttpResponse {
    val selector = (appGraph as HttpAdapterRouteSelector.Graph).httpAdapterRouteSelector
    return when (val selection = selector.select(request.method, request.path)) {
        is HttpAdapterRouteSelection.Selected -> dispatch(request, selection.match)
        is HttpAdapterRouteSelection.NotFound -> GenericHttpResponse(404, emptyMap(), "Not found")
        is HttpAdapterRouteSelection.Ambiguous -> GenericHttpResponse(500, emptyMap(), "Ambiguous route")
        is HttpAdapterRouteSelection.Misconfigured -> GenericHttpResponse(500, emptyMap(), selection.message)
    }
}

/**
 * End-to-end integration tests for the Universal OID4VP REST API.
 *
 * These tests use:
 * - Full DI hierarchy (AppScope -> UserScope -> SessionScope)
 * - Real software KMS with memory keystore
 * - Real DCQL queries
 * - Real HTTP adapter dispatching
 *
 * No mocks except for HTTP transport (Ktor MockEngine when needed).
 */
class UniversalOid4vpE2ETest {
    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }

    @BeforeEach
    fun setup() {
        // Clear any previous test properties
        DefaultPrincipalMapPropertySource.getSource().clear()
        // Reset the global JAR signing flag — the [TestRequestObjectSigningConfig] holds it in
        // a `@Volatile var` so a previous test in another class that called `enableDidJwkSigning()`
        // would otherwise leave it on, which makes the verifier try to load a key alias these
        // tests don't generate and produces a 500 on the very first request.
        TestRequestObjectSigningConfig.disable()
    }

    @Test
    fun `create session with inline DCQL query and get status`() =
        runTest {
            // 1. Create full DI hierarchy with static app ID
            val testScope = TestScope()
            val app = createUniversalOid4vpTestAppGraph(testScope)

            // 2. Configure real software KMS
            DefaultPrincipalMapPropertySource.addProperties(
                mapOf(
                    "kms.providers.test-software.type" to "software",
                    "kms.providers.test-software.id" to "test-software",
                    "kms.providers.test-software.keystore.type" to "memory",
                    "kms.providers.test-software.keystore.id" to "test-memory-keystore",
                    "kms.providers.test-software.keystore.keyVisibility" to "private",
                    "kms.providers.test-software.keystore.overwriteAlias" to "true",
                ),
            )

            // 3. Apply new properties by destroying cached contexts
            app.userContextManager.destroyAll()

            // 4. Create session
            val context = app.userContextManager.getAnonymous()
            val session = context.sessionContextManager.createOrGetFromId("verifier-session", principalType = com.sphereon.di.context.PrincipalType.USER)
            val sessionGraph = session.graph

            // 5. Get the HTTP adapter dispatcher from DI (includes all contributed adapters)
            val dispatcher = (sessionGraph as HttpAdapterDispatcher.Graph).httpAdapterDispatcher

            // 6. Create authorization request with inline DCQL query
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "pid_credential",
                                format = "dc+sd-jwt",
                                meta = sdJwtVcMeta("urn:test:pid"),
                                claims =
                                    listOf(
                                        DcqlClaimQuery(path = claimsPathPointer("given_name")),
                                        DcqlClaimQuery(path = claimsPathPointer("family_name")),
                                        DcqlClaimQuery(path = claimsPathPointer("birthdate")),
                                    ),
                            ),
                        ),
                )

            val input =
                CreateAuthorizationRequestInput(
                    dcqlQuery = dcqlQuery,
                    clientId = "https://verifier.example.com",
                    state = "test-state-123",
                    qrCodeOptions = QrCodeOptions(),
                )

            val createRequest =
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path = "/oid4vp/backend/auth/requests",
                    headers = mapOf("Content-Type" to "application/json"),
                    body = json.encodeToString(CreateAuthorizationRequestInput.serializer(), input),
                )

            val createResponse = dispatcher.dispatchSelected(app, createRequest)
            assertEquals(201, createResponse.statusCode, "Expected 201 Created")

            val output = json.decodeFromString(CreateAuthorizationRequestOutput.serializer(), createResponse.body!!)
            assertNotNull(output.correlationId)
            assertNotNull(output.requestUri)
            assertNotNull(output.requestUri)
            assertNotNull(output.qrUri)
            assertTrue(output.qrUri!!.startsWith("data:image/png;base64,"))

            // 7. Get status
            val statusRequest =
                GenericHttpRequest(
                    method = "GET",
                    path = "/oid4vp/backend/auth/requests/${output.correlationId}",
                )

            val statusResponse = dispatcher.dispatchSelected(app, statusRequest)
            assertEquals(200, statusResponse.statusCode)

            val statusOutput = json.decodeFromString(GetAuthorizationRequestStatusOutput.serializer(), statusResponse.body!!)
            assertEquals(output.correlationId, statusOutput.correlationId)
            assertEquals(AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED, statusOutput.status)

            // 8. Delete session
            val deleteRequest =
                GenericHttpRequest(
                    method = "DELETE",
                    path = "/oid4vp/backend/auth/requests/${output.correlationId}",
                )

            val deleteResponse = dispatcher.dispatchSelected(app, deleteRequest)
            assertEquals(204, deleteResponse.statusCode)

            // 9. Verify session is deleted
            val statusAfterDelete = dispatcher.dispatchSelected(app, statusRequest)
            assertEquals(404, statusAfterDelete.statusCode)
        }

    @Test
    fun `create session and verify QR code data URI format`() =
        runTest {
            val testScope = TestScope()
            val app = createUniversalOid4vpTestAppGraph(testScope)

            DefaultPrincipalMapPropertySource.addProperties(
                mapOf(
                    "kms.providers.test-software.type" to "software",
                    "kms.providers.test-software.id" to "test-software",
                    "kms.providers.test-software.keystore.type" to "memory",
                    "kms.providers.test-software.keystore.id" to "test-memory-keystore",
                    // Tests don't drive the JAR signing path; keep request-object signing off.
                    "oid4vp.verifier.request-object.signing.enabled" to "false",
                ),
            )
            app.userContextManager.destroyAll()

            val context = app.userContextManager.getAnonymous()
            val session = context.sessionContextManager.createOrGetFromId("verifier-session", principalType = com.sphereon.di.context.PrincipalType.USER)
            val sessionGraph = session.graph

            val dispatcher = (sessionGraph as HttpAdapterDispatcher.Graph).httpAdapterDispatcher

            val input =
                CreateAuthorizationRequestInput(
                    dcqlQuery =
                        DcqlQuery(
                            credentials =
                                listOf(
                                    DcqlCredentialQuery(id = "test_cred", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential")),
                                ),
                        ),
                    clientId = "https://test.example.com",
                    qrCodeOptions = QrCodeOptions(),
                )

            val createResponse =
                dispatcher.dispatchSelected(
                    app,
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = "/oid4vp/backend/auth/requests",
                        headers = mapOf("Content-Type" to "application/json"),
                        body = json.encodeToString(CreateAuthorizationRequestInput.serializer(), input),
                    ),
                )

            assertEquals(201, createResponse.statusCode, "expected 201, got ${createResponse.statusCode}: ${createResponse.body}")
            val output = json.decodeFromString(CreateAuthorizationRequestOutput.serializer(), createResponse.body!!)

            // Verify QR code data URI format per Universal OID4VP spec
            assertTrue(
                output.qrUri!!.startsWith("data:image/png;base64,"),
                "QR code must be a data URI with base64-encoded PNG",
            )
            assertTrue(output.requestUri!!.isNotEmpty(), "Request URI must not be empty")
        }

    @Test
    fun `error handling - missing query parameters`() =
        runTest {
            val testScope = TestScope()
            val app = createUniversalOid4vpTestAppGraph(testScope)

            DefaultPrincipalMapPropertySource.addProperties(
                mapOf(
                    "kms.providers.test-software.type" to "software",
                    "kms.providers.test-software.id" to "test-software",
                    "kms.providers.test-software.keystore.type" to "memory",
                    "kms.providers.test-software.keystore.id" to "test-memory-keystore",
                ),
            )
            app.userContextManager.destroyAll()

            val context = app.userContextManager.getAnonymous()
            val session = context.sessionContextManager.createOrGetFromId("verifier-session", principalType = com.sphereon.di.context.PrincipalType.USER)
            val sessionGraph = session.graph

            val dispatcher = (sessionGraph as HttpAdapterDispatcher.Graph).httpAdapterDispatcher

            // Request without query_id or dcql_query should fail
            val input =
                CreateAuthorizationRequestInput(
                    clientId = "https://test.example.com",
                    qrCodeOptions = QrCodeOptions(),
                )

            val createResponse =
                dispatcher.dispatchSelected(
                    app,
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = "/oid4vp/backend/auth/requests",
                        headers = mapOf("Content-Type" to "application/json"),
                        body = json.encodeToString(CreateAuthorizationRequestInput.serializer(), input),
                    ),
                )

            assertEquals(400, createResponse.statusCode, "Should return 400 for missing query parameters")
        }

    @Test
    fun `error handling - get non-existent session`() =
        runTest {
            val testScope = TestScope()
            val app = createUniversalOid4vpTestAppGraph(testScope)

            DefaultPrincipalMapPropertySource.addProperties(
                mapOf(
                    "kms.providers.test-software.type" to "software",
                    "kms.providers.test-software.id" to "test-software",
                    "kms.providers.test-software.keystore.type" to "memory",
                    "kms.providers.test-software.keystore.id" to "test-memory-keystore",
                ),
            )
            app.userContextManager.destroyAll()

            val context = app.userContextManager.getAnonymous()
            val session = context.sessionContextManager.createOrGetFromId("verifier-session", principalType = com.sphereon.di.context.PrincipalType.USER)
            val sessionGraph = session.graph

            val dispatcher = (sessionGraph as HttpAdapterDispatcher.Graph).httpAdapterDispatcher

            val statusResponse =
                dispatcher.dispatchSelected(
                    app,
                    GenericHttpRequest(
                        method = "GET",
                        path = "/oid4vp/backend/auth/requests/non-existent-correlation-id",
                    ),
                )

            assertEquals(404, statusResponse.statusCode, "Should return 404 for non-existent session")
        }

    @Test
    fun `error handling - delete non-existent session`() =
        runTest {
            val testScope = TestScope()
            val app = createUniversalOid4vpTestAppGraph(testScope)

            DefaultPrincipalMapPropertySource.addProperties(
                mapOf(
                    "kms.providers.test-software.type" to "software",
                    "kms.providers.test-software.id" to "test-software",
                    "kms.providers.test-software.keystore.type" to "memory",
                    "kms.providers.test-software.keystore.id" to "test-memory-keystore",
                ),
            )
            app.userContextManager.destroyAll()

            val context = app.userContextManager.getAnonymous()
            val session = context.sessionContextManager.createOrGetFromId("verifier-session", principalType = com.sphereon.di.context.PrincipalType.USER)
            val sessionGraph = session.graph

            val dispatcher = (sessionGraph as HttpAdapterDispatcher.Graph).httpAdapterDispatcher

            val deleteResponse =
                dispatcher.dispatchSelected(
                    app,
                    GenericHttpRequest(
                        method = "DELETE",
                        path = "/oid4vp/backend/auth/requests/non-existent-correlation-id",
                    ),
                )

            assertEquals(404, deleteResponse.statusCode, "Should return 404 for non-existent session")
        }

    /**
     * Full E2E test with:
     * - Real SD-JWT VC issuance
     * - Real holder VP presentation with selective disclosure
     * - Real DCQL query validation
     * - Real OID4VP session management
     */
    @Test
    fun `full e2e flow - create session, holder issues SD-JWT VC, creates VP, submits via direct_post`() =
        runTest {
            val testScope = TestScope()
            val app = createUniversalOid4vpTestAppGraph(testScope)

            // Configure real software KMS
            DefaultPrincipalMapPropertySource.addProperties(
                mapOf(
                    "kms.providers.test-software.type" to "software",
                    "kms.providers.test-software.id" to "test-software",
                    "kms.providers.test-software.keystore.type" to "memory",
                    "kms.providers.test-software.keystore.id" to "test-memory-keystore",
                    "kms.providers.test-software.keystore.keyVisibility" to "private",
                    "kms.providers.test-software.keystore.overwriteAlias" to "true",
                ),
            )
            app.userContextManager.destroyAll()

            // ====== VERIFIER SETUP ======
            val verifierContext = app.userContextManager.getAnonymous()
            val verifierSession = verifierContext.sessionContextManager.createOrGetFromId("verifier-session", principalType = com.sphereon.di.context.PrincipalType.USER)
            val verifierGraph = verifierSession.graph

            val rpService = (verifierGraph as Oid4VpVerifierServiceImpl.Graph).oid4vpVerifierService

            // DCQL query requesting specific claims from SD-JWT VC
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "pid_credential",
                                format = "dc+sd-jwt",
                                meta = sdJwtVcMeta("urn:test:pid"),
                                claims =
                                    listOf(
                                        DcqlClaimQuery(path = claimsPathPointer("given_name")),
                                        DcqlClaimQuery(path = claimsPathPointer("family_name")),
                                        DcqlClaimQuery(path = claimsPathPointer("birthdate")),
                                    ),
                            ),
                        ),
                )

            // Create Universal OID4VP session via REST API
            val dispatcher = (verifierGraph as HttpAdapterDispatcher.Graph).httpAdapterDispatcher

            val input =
                CreateAuthorizationRequestInput(
                    dcqlQuery = dcqlQuery,
                    clientId = "https://verifier.example.com",
                    state = "test-state-e2e",
                    // Note: nonce is generated internally by the Universal OID4VP implementation
                )

            val createRequest =
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path = "/oid4vp/backend/auth/requests",
                    headers = mapOf("Content-Type" to "application/json"),
                    body = json.encodeToString(CreateAuthorizationRequestInput.serializer(), input),
                )

            val createResponse = dispatcher.dispatchSelected(app, createRequest)
            assertEquals(201, createResponse.statusCode, "Expected 201 Created")

            val universalOutput = json.decodeFromString(CreateAuthorizationRequestOutput.serializer(), createResponse.body!!)
            val correlationId = universalOutput.correlationId
            assertNotNull(correlationId)
            // Status is available via GET /backend/auth/requests/{correlation_id}, not on CreateAuthorizationRequestOutput

            // Retrieve the underlying authorization request for direct_post handling
            val sessionResult = rpService.authorizationSessionStore.getByCorrelationId(correlationId).getOrThrow()
            assertNotNull(sessionResult)
            val authRequest = sessionResult.authorizationRequest

            // ====== HOLDER SETUP ======
            val holderContext = app.userContextManager.getAnonymous()
            val holderSession = holderContext.sessionContextManager.createOrGetFromId("holder-session", principalType = com.sphereon.di.context.PrincipalType.USER)
            val holderGraph = holderSession.graph

            val holderKms = holderGraph.asKeyManagerServiceGraph().keyManagerService
            val sdJwtService = (holderGraph as SdJwtServiceImpl.Graph).sdJwtService

            // Generate issuer key for SD-JWT VC
            val issuerKeyPair =
                holderKms.generateKeyAsync(
                    providerId = "test-software",
                    alias = "issuer-signing-key",
                    use = JwkUse.sig,
                    keyOperations = arrayOf(KeyOperations.SIGN, KeyOperations.VERIFY),
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                    keyVisibility = KeyVisibility.PRIVATE,
                )
            val issuerKeyInfo: ManagedKeyInfoType<*> = issuerKeyPair.joseToManagedKeyInfo(KeyVisibility.PRIVATE)
            val issuer =
                ManagedOptsKeyInfo(
                    identifier = issuerKeyInfo,
                    context =
                        IdentifierContext(
                            clientId = "test-pid-issuer",
                            clientIdScheme = "jwt_vc_json",
                            issuer = "https://issuer.example.com",
                        ),
                )

            // Generate holder key for key binding
            val holderKeyPair =
                holderKms.generateKeyAsync(
                    providerId = "test-software",
                    alias = "holder-binding-key",
                    use = JwkUse.sig,
                    keyOperations = arrayOf(KeyOperations.SIGN, KeyOperations.VERIFY),
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                )
            val holderKeyInfo: ManagedKeyInfoType<*> = holderKeyPair.joseToManagedKeyInfo(KeyVisibility.PRIVATE)
            val holderPublicKeyInfo: ManagedKeyInfoType<*> = holderKeyPair.joseToManagedKeyInfo(KeyVisibility.PUBLIC)

            val holder =
                ManagedOptsKeyInfo(
                    identifier = holderKeyInfo,
                    context =
                        IdentifierContext(
                            clientId = "test-holder",
                            clientIdScheme = "jwt_vc_json",
                            issuer = "https://holder.example.com",
                        ),
                )

            // Create SD-JWT VC with claims matching DCQL query
            val holderPublicJwk = holderPublicKeyInfo.key as com.sphereon.crypto.core.jose.Jwk
            val minimalJwk = holderPublicJwk.toMinimalJwk()
            val cnfValue =
                buildJsonObject {
                    put("jwk", minimalJwk.toJsonObject())
                }

            // Get the nonce from the created session for holder binding
            val sessionNonce =
                sessionResult.authorizationRequest.nonce
                    ?: error("Session should have a nonce")

            val vcPayload =
                sdJwtPayload {
                    iss("https://issuer.example.com")
                    claim("vct", "https://example.com/PersonIdentificationData")
                    claimSd("given_name", "Alice")
                    claimSd("family_name", "Wonderland")
                    claimSd("birthdate", "1990-01-15")
                    claimSd("nationality", "DE") // Extra claim not in DCQL - should not be disclosed
                    claim("cnf", cnfValue)
                }

            val issueResult = sdJwtService.issueSdJwt(IssueSdJwtArgs(issuer = issuer, payload = vcPayload))
            assertTrue(issueResult.isOk, "SD-JWT VC issuance should succeed")
            val sdJwtVc = issueResult.value.sdJwt

            // Create VP presentation with selective disclosure (only claims requested by DCQL)
            val disclosureSelection =
                SdMap(
                    mapOf(
                        "given_name" to SdField(sd = true),
                        "family_name" to SdField(sd = true),
                        "birthdate" to SdField(sd = true),
                        // nationality is NOT disclosed
                    ),
                )

            val presentResult =
                sdJwtService.presentSdJwt(
                    PresentSdJwtArgs(
                        sdJwt = sdJwtVc,
                        disclosureSelection = disclosureSelection,
                        holderKey = holder,
                        audience = "https://verifier.example.com",
                        nonce = sessionNonce,
                    ),
                )

            assertTrue(presentResult.isOk, "VP presentation creation should succeed")
            val vpPresentation = presentResult.value.presentation
            assertNotNull(vpPresentation)

            // Verify presentation has Key Binding JWT
            assertTrue(
                vpPresentation.contains("~") && vpPresentation.split("~").size >= 3,
                "Presentation should have KB-JWT appended",
            )

            // ====== SUBMIT VP VIA DIRECT_POST (simulated) ======
            // In a real flow, the wallet would POST to the response_uri
            // Here we directly call the verifier service to handle the response

            // For DCQL, vp_token must be a JSON object mapping credential query IDs to presentations
            // Format: { "pid_credential": "eyJ...~...~..." }
            val vpToken = vpTokenOf("pid_credential", vpPresentation)
            val vpTokenJson =
                json.encodeToString(
                    kotlinx.serialization.json.JsonElement
                        .serializer(),
                    vpToken.toJson(),
                )

            val responseParams =
                mapOf(
                    "vp_token" to vpTokenJson,
                    "state" to "test-state-e2e",
                )

            val handleResult =
                rpService.handleDirectPostResponse(
                    HandleDirectPostResponseArgs(
                        trustedAuthentications = listOf(
                            TrustedAuthenticationResolution(
                                controller = "https://issuer.example.com",
                                identifier = ExternalIdentifierJwkOpts(identifier = issuerKeyPair.jose.publicJwk),
                                purpose = TrustedAuthenticationPurpose.CREDENTIAL_ISSUER,
                            ),
                        ),
                        responseParams = responseParams,
                        originalRequest = authRequest,
                        dcqlQuery = dcqlQuery,
                        redirectUri = "https://frontend.example.com/callback",
                    ),
                )
            assertTrue(handleResult.isOk, "Direct post handling should succeed")
            val handled = handleResult.getOrThrow()

            // Extract response_code from redirect URI
            val responseCode = Url(handled.redirectUri).parameters["response_code"]
            assertNotNull(responseCode, "Response code should be present in redirect URI")

            // ====== VERIFY SESSION STATUS VIA UNIVERSAL OID4VP API ======
            val statusRequest =
                GenericHttpRequest(
                    method = "GET",
                    path = "/oid4vp/backend/auth/requests/$correlationId",
                )

            val statusResponse = dispatcher.dispatchSelected(app, statusRequest)
            assertEquals(200, statusResponse.statusCode)

            val statusOutput = json.decodeFromString(GetAuthorizationRequestStatusOutput.serializer(), statusResponse.body!!)
            assertEquals(correlationId, statusOutput.correlationId)

            // Status should be AUTHORIZATION_RESPONSE_RECEIVED or AUTHORIZATION_RESPONSE_VERIFIED
            assertTrue(
                statusOutput.status == AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_RECEIVED ||
                    statusOutput.status == AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED,
                "Session status should indicate response was received/verified, got: ${statusOutput.status}",
            )

            // ====== RETRIEVE AND VERIFY VP TOKEN ======
            val retrievedResponse =
                rpService
                    .retrieveAuthorizationResponse(
                        com.sphereon.openid.oid4vp.verifier.RetrieveAuthorizationResponseArgs(
                            responseCode = responseCode,
                            markAsUsed = true,
                        ),
                    ).getOrThrow()

            assertEquals("test-state-e2e", retrievedResponse.state)
            assertEquals(1, retrievedResponse.parsedResponse.vpToken.presentations.size, "Should have one VP presentation")

            // Clean up - delete session
            val deleteRequest =
                GenericHttpRequest(
                    method = "DELETE",
                    path = "/oid4vp/backend/auth/requests/$correlationId",
                )
            val deleteResponse = dispatcher.dispatchSelected(app, deleteRequest)
            assertEquals(204, deleteResponse.statusCode)
        }

    /**
     * Full E2E test with JARM (JWT Secured Authorization Response Mode):
     * - Creates a regular OID4VP session
     * - Holder creates JARM-encrypted authorization response (simulating direct_post.jwt)
     * - Verifier decrypts and parses the JARM response
     *
     * This tests the encrypted response flow for privacy-preserving credential exchange.
     * Note: The Universal OID4VP REST API doesn't expose JARM configuration - it's an internal
     * protocol detail. This test demonstrates the JARM create/verify commands work correctly.
     */
    @Test
    fun `full e2e flow with JARM encrypted response`() =
        runTest {
            val testScope = TestScope()
            val app = createUniversalOid4vpTestAppGraph(testScope)

            // Configure real software KMS
            DefaultPrincipalMapPropertySource.addProperties(
                mapOf(
                    "kms.providers.test-software.type" to "software",
                    "kms.providers.test-software.id" to "test-software",
                    "kms.providers.test-software.keystore.type" to "memory",
                    "kms.providers.test-software.keystore.id" to "test-memory-keystore",
                    "kms.providers.test-software.keystore.keyVisibility" to "private",
                    "kms.providers.test-software.keystore.overwriteAlias" to "true",
                ),
            )
            app.userContextManager.destroyAll()

            // ====== VERIFIER SETUP ======
            val verifierContext = app.userContextManager.getAnonymous()
            val verifierSession = verifierContext.sessionContextManager.createOrGetFromId("verifier-jarm-session", principalType = com.sphereon.di.context.PrincipalType.USER)
            val verifierGraph = verifierSession.graph

            val rpService = (verifierGraph as Oid4VpVerifierServiceImpl.Graph).oid4vpVerifierService
            val verifierKms = verifierGraph.asKeyManagerServiceGraph().keyManagerService

            // Generate verifier RSA encryption key for JARM (RSA for RSA-OAEP key wrapping)
            val verifierEncryptionKeyPair =
                verifierKms.generateKeyAsync(
                    providerId = "test-software",
                    alias = "verifier-encryption-key",
                    use = JwkUse.enc,
                    keyOperations = arrayOf(KeyOperations.WRAP_KEY, KeyOperations.UNWRAP_KEY),
                    alg = SignatureAlgorithm.RSA_SHA256, // Use RSA for RSA-OAEP
                    keyVisibility = KeyVisibility.PRIVATE,
                )
            val verifierEncryptionKeyInfo: ManagedKeyInfoType<*> = verifierEncryptionKeyPair.joseToManagedKeyInfo(KeyVisibility.PRIVATE)
            val verifierEncryptionPublicKeyInfo: ManagedKeyInfoType<*> = verifierEncryptionKeyPair.joseToManagedKeyInfo(KeyVisibility.PUBLIC)

            // DCQL query requesting specific claims from SD-JWT VC
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "pid_credential",
                                format = "dc+sd-jwt",
                                meta = sdJwtVcMeta("urn:test:pid"),
                                claims =
                                    listOf(
                                        DcqlClaimQuery(path = claimsPathPointer("given_name")),
                                        DcqlClaimQuery(path = claimsPathPointer("family_name")),
                                    ),
                            ),
                        ),
                )

            // Create Universal OID4VP session via REST API
            val dispatcher = (verifierGraph as HttpAdapterDispatcher.Graph).httpAdapterDispatcher

            val input =
                CreateAuthorizationRequestInput(
                    dcqlQuery = dcqlQuery,
                    clientId = "https://verifier.example.com",
                    state = "test-state-jarm",
                )

            val createRequest =
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path = "/oid4vp/backend/auth/requests",
                    headers = mapOf("Content-Type" to "application/json"),
                    body = json.encodeToString(CreateAuthorizationRequestInput.serializer(), input),
                )

            val createResponse = dispatcher.dispatchSelected(app, createRequest)
            assertEquals(201, createResponse.statusCode, "Expected 201 Created")

            val universalOutput = json.decodeFromString(CreateAuthorizationRequestOutput.serializer(), createResponse.body!!)
            val correlationId = universalOutput.correlationId
            assertNotNull(correlationId)
            // Status is available via GET /backend/auth/requests/{correlation_id}, not on CreateAuthorizationRequestOutput

            // Retrieve the underlying authorization request
            val sessionResult = rpService.authorizationSessionStore.getByCorrelationId(correlationId).getOrThrow()
            assertNotNull(sessionResult)
            val authRequest = sessionResult.authorizationRequest

            // ====== HOLDER SETUP ======
            val holderContext = app.userContextManager.getAnonymous()
            val holderSession = holderContext.sessionContextManager.createOrGetFromId("holder-jarm-session", principalType = com.sphereon.di.context.PrincipalType.USER)
            val holderGraph = holderSession.graph

            val holderKms = holderGraph.asKeyManagerServiceGraph().keyManagerService
            val sdJwtService = (holderGraph as SdJwtServiceImpl.Graph).sdJwtService

            // Generate issuer key for SD-JWT VC
            val issuerKeyPair =
                holderKms.generateKeyAsync(
                    providerId = "test-software",
                    alias = "issuer-signing-key-jarm",
                    use = JwkUse.sig,
                    keyOperations = arrayOf(KeyOperations.SIGN, KeyOperations.VERIFY),
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                    keyVisibility = KeyVisibility.PRIVATE,
                )
            val issuerKeyInfo: ManagedKeyInfoType<*> = issuerKeyPair.joseToManagedKeyInfo(KeyVisibility.PRIVATE)
            val issuer =
                ManagedOptsKeyInfo(
                    identifier = issuerKeyInfo,
                    context =
                        IdentifierContext(
                            clientId = "test-pid-issuer",
                            clientIdScheme = "jwt_vc_json",
                            issuer = "https://issuer.example.com",
                        ),
                )

            // Generate holder key for key binding
            val holderKeyPair =
                holderKms.generateKeyAsync(
                    providerId = "test-software",
                    alias = "holder-binding-key-jarm",
                    use = JwkUse.sig,
                    keyOperations = arrayOf(KeyOperations.SIGN, KeyOperations.VERIFY),
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                )
            val holderKeyInfo: ManagedKeyInfoType<*> = holderKeyPair.joseToManagedKeyInfo(KeyVisibility.PRIVATE)
            val holderPublicKeyInfo: ManagedKeyInfoType<*> = holderKeyPair.joseToManagedKeyInfo(KeyVisibility.PUBLIC)

            val holder =
                ManagedOptsKeyInfo(
                    identifier = holderKeyInfo,
                    context =
                        IdentifierContext(
                            issuer = "https://holder.example.com",
                        ),
                )

            // Create SD-JWT VC with claims matching DCQL query
            val holderPublicJwk = holderPublicKeyInfo.key as com.sphereon.crypto.core.jose.Jwk
            val minimalJwk = holderPublicJwk.toMinimalJwk()
            val cnfValue =
                buildJsonObject {
                    put("jwk", minimalJwk.toJsonObject())
                }

            val sessionNonce =
                sessionResult.authorizationRequest.nonce
                    ?: error("Session should have a nonce")

            val vcPayload =
                sdJwtPayload {
                    iss("https://issuer.example.com")
                    claim("vct", "https://example.com/PersonIdentificationData")
                    claimSd("given_name", "Bob")
                    claimSd("family_name", "Builder")
                    claimSd("birthdate", "1985-03-20")
                    claim("cnf", cnfValue)
                }

            val issueResult = sdJwtService.issueSdJwt(IssueSdJwtArgs(issuer = issuer, payload = vcPayload))
            assertTrue(issueResult.isOk, "SD-JWT VC issuance should succeed")
            val sdJwtVc = issueResult.value.sdJwt

            // Create VP presentation with selective disclosure
            val disclosureSelection =
                SdMap(
                    mapOf(
                        "given_name" to SdField(sd = true),
                        "family_name" to SdField(sd = true),
                    ),
                )

            val presentResult =
                sdJwtService.presentSdJwt(
                    PresentSdJwtArgs(
                        sdJwt = sdJwtVc,
                        disclosureSelection = disclosureSelection,
                        holderKey = holder,
                        audience = "https://verifier.example.com",
                        nonce = sessionNonce,
                    ),
                )

            assertTrue(presentResult.isOk, "VP presentation creation should succeed")
            val vpPresentation = presentResult.value.presentation
            assertNotNull(vpPresentation)

            // ====== CREATE JARM ENCRYPTED RESPONSE ======
            // For DCQL, vp_token must be a JSON object
            val vpToken = vpTokenOf("pid_credential", vpPresentation)
            // Build response parameters as JSON object for JARM
            val responseParameters =
                kotlinx.serialization.json.buildJsonObject {
                    put("vp_token", vpToken.toJson())
                }

            // Create JARM encrypted response using the verifier's public encryption key
            val registry = (holderGraph as SessionScopedCommandRegistry.Graph).sessionScopedCommandRegistry

            @Suppress("UNCHECKED_CAST")
            val createJarmCommand = registry.get(CreateJarmResponseCommand.COMMAND_ID) as CreateJarmResponseCommand
            val encryptionRecipient =
                ManagedOptsKeyInfo(
                    identifier = verifierEncryptionPublicKeyInfo,
                    context =
                        IdentifierContext(
                            clientId = "https://verifier.example.com",
                            clientIdScheme = "pre-registered",
                        ),
                )

            val jarmArgs = CreateJarmResponseArgs(
                responseParameters = responseParameters,
                state = "test-state-jarm",
                issuer = "https://holder.example.com",
                audience = "https://verifier.example.com",
                encryptionRecipient = encryptionRecipient,
                jarmConfig =
                    JarmConfig(
                        encryptionAlgorithm = "RSA-OAEP",
                        contentEncryptionAlgorithm = "A256GCM",
                        mode = JarmMode.ENCRYPTED,
                    ),
                appendStandardJwtClaims = false,
            )
            val jarmResult = createJarmCommand.execute(jarmArgs)

            assertTrue(jarmResult.isOk, "JARM creation should succeed: $jarmResult")
            val jarmJwt = jarmResult.value.jarmJwt
            assertNotNull(jarmJwt)
            assertTrue(jarmJwt.split(".").size == 5, "JARM JWE should have 5 parts")

            // ====== VERIFIER PARSES JARM RESPONSE ======
            // The "response" parameter contains the JARM JWT per RFC 9101
            val verifierDecryptionKey =
                ManagedOptsKeyInfo(
                    identifier = verifierEncryptionKeyInfo,
                    context =
                        IdentifierContext(
                            clientId = "https://verifier.example.com",
                            clientIdScheme = "pre-registered",
                        ),
                )

            val jweService = (verifierGraph as JweServiceImpl.Graph).jweService
            suspend fun decryptPayload(token: String): JsonObject {
                val decrypted = jweService.decryptJwe(DecryptJweArgs(JweCompact.parse(token), verifierDecryptionKey)).getOrThrow()
                return json.parseToJsonElement(requireNotNull(decrypted.plaintext).decodeToString()).jsonObject
            }
            val payload = decryptPayload(jarmJwt)
            assertIs<JsonObject>(payload["vp_token"], "Final encrypted responses contain the DCQL map, not a serialized JSON string")
            assertEquals(vpToken.toJson(), payload["vp_token"])
            assertEquals("test-state-jarm", payload["state"]?.jsonPrimitive?.content)
            for (claim in listOf("iss", "aud", "exp", "iat")) {
                assertFalse(payload.containsKey(claim), "Response-parameter envelopes must not synthesize $claim")
            }
            val oauthJarm = createJarmCommand.execute(jarmArgs.copy(appendStandardJwtClaims = true)).getOrThrow()
            val oauthPayload = decryptPayload(oauthJarm.jarmJwt)
            assertEquals("https://holder.example.com", oauthPayload["iss"]?.jsonPrimitive?.content)
            assertEquals("https://verifier.example.com", oauthPayload["aud"]?.jsonPrimitive?.content)
            assertTrue(oauthPayload.containsKey("exp"))
            assertTrue(oauthPayload.containsKey("iat"))
            for (mode in listOf(JarmMode.SIGNED, JarmMode.SIGNED_ENCRYPTED)) {
                val invalid = createJarmCommand.execute(jarmArgs.copy(jarmConfig = jarmArgs.jarmConfig.copy(mode = mode)))
                assertTrue(invalid.isErr, "Signed OAuth JARM cannot disable its standard JWT claims")
                assertEquals("Signed JARM responses require standard JWT claims", invalid.error.message.defaultMessage)
            }

            val parseResult =
                rpService.parseAuthorizationResponse(
                    ParseAuthorizationResponseArgs(
                        responseParams = mapOf("response" to jarmJwt),
                        originalRequest = authRequest,
                        jarmDecryptionKey = verifierDecryptionKey,
                        jarmExpectedAudience = "https://verifier.example.com",
                    ),
                )

            assertTrue(parseResult.isOk, "JARM parsing should succeed: $parseResult")
            val parsedResponse = parseResult.value

            // Verify the parsed response contains the correct data
            assertNotNull(parsedResponse.vpToken)
            assertEquals(1, parsedResponse.vpToken.presentations.size, "Should have one VP presentation")
            assertEquals("test-state-jarm", parsedResponse.state)
            assertEquals(JarmMode.ENCRYPTED, parsedResponse.jarmMode, "Should be encrypted mode")

            // Verify the presentation can be extracted
            val extractedPresentation = parsedResponse.vpToken.getSinglePresentation("pid_credential")
            assertNotNull(extractedPresentation, "Should be able to extract presentation by query ID")
            assertTrue(extractedPresentation.contains("~"), "Presentation should be SD-JWT format")

            // ====== VERIFY SESSION STATUS VIA UNIVERSAL OID4VP API ======
            val statusRequest =
                GenericHttpRequest(
                    method = "GET",
                    path = "/oid4vp/backend/auth/requests/$correlationId",
                )

            val statusResponse = dispatcher.dispatchSelected(app, statusRequest)
            assertEquals(200, statusResponse.statusCode)

            val statusOutput = json.decodeFromString(GetAuthorizationRequestStatusOutput.serializer(), statusResponse.body!!)
            assertEquals(correlationId, statusOutput.correlationId)

            // Clean up - delete session
            val deleteRequest =
                GenericHttpRequest(
                    method = "DELETE",
                    path = "/oid4vp/backend/auth/requests/$correlationId",
                )
            val deleteResponse = dispatcher.dispatchSelected(app, deleteRequest)
            assertEquals(204, deleteResponse.statusCode)
        }
}
