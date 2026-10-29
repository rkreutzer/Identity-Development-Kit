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

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.asErrorResult
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.crypto.resolution.IIdentifierMethod
import com.sphereon.crypto.resolution.extern.ExternalIdentifierOpts
import com.sphereon.crypto.resolution.extern.ExternalIdentifierOptsOrResult
import com.sphereon.crypto.resolution.extern.ExternalIdentifierResult
import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.JwaCurve
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkSet
import com.sphereon.crypto.core.jose.tryGenerateJwkThumbprint
import com.sphereon.crypto.resolution.extern.MultiExternalIdentifierService
import com.sphereon.di.session.SessionContext
import com.sphereon.ktor.http.client.provider.HttpClientEngineType
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.ktor.http.client.provider.UrlValidationPolicy
import com.sphereon.oauth2.common.jarm.CreateJarmResponseArgs
import com.sphereon.oauth2.common.jarm.CreateJarmResponseCommand
import com.sphereon.oauth2.common.jarm.CreateJarmResponseResult
import com.sphereon.oauth2.common.jarm.JarmConfig
import com.sphereon.oauth2.common.jarm.JarmMode
import com.sphereon.oauth2.common.model.AuthorizationErrorResponse
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.common.ClientMetadata
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.common.buildOid4vpAuthorizationResponse
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.SubmissionResult
import com.sphereon.openid.oid4vp.holder.SubmitAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.holder.JarmOptions
import com.sphereon.openid.oid4vp.holder.PreparedOid4vpJweRecipientBinding
import com.sphereon.openid.oid4vp.holder.VerifierInfo
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.HttpSend
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.plugins.plugin
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.test.assertFalse
import kotlinx.serialization.json.JsonObject

/**
 * Tests for SubmitAuthorizationResponseCommandImpl.
 *
 * These tests verify the authorization response submission logic:
 * - Direct POST submission
 * - Fragment redirect mode
 * - Query redirect mode
 * - Error handling (missing URI, missing vp_token)
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class SubmitAuthorizationResponseCommandImplTest {
    @Test
    fun `test dc_api returns authorization data without HTTP submission`() =
        runTest {
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = createMockHttpClientFactory(responseStatus = HttpStatusCode.InternalServerError),
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                    state("dc-api-state")
                }

            val result =
                command.execute(
                    SubmitAuthorizationResponseArgs(
                        resolvedRequest = createResolvedRequestDirectPost(responseUri = ""),
                        response = response,
                        responseMode = ResponseMode.DC_API,
                    ),
                )

            val digitalCredential = assertIs<SubmissionResult.DigitalCredential>(result.value)
            assertEquals("dc-api-state", (digitalCredential.data["state"] as? JsonPrimitive)?.content)
            assertTrue(digitalCredential.data.containsKey("vp_token"))
        }


    private fun invalidRequest(mode: ResponseMode = ResponseMode.DIRECT_POST, withEncryption: Boolean = false): ResolvedOid4vpRequest {
        val base = createResolvedRequestDirectPost()
        val error = AuthorizationErrorResponse(error = "invalid_request", state = base.request.state)
        return base.copy(
            request = base.request.copy(redirectUri = null, responseMode = mode.value, nonce = "nonce"),
            authorizationError = error,
            clientMetadata = if (withEncryption) ClientMetadata(jwks = JwkSet(arrayOf(Jwk(
                kty = JwaKeyType.EC, crv = JwaCurve.P_256,
                x = "0_3S7HedSywaxlekdt6Or8pkcR13hQaCPMqt9cuZBVc",
                y = "ZVXSCL3HlnMQWKrwMyIAe5wsAIWd3Eu1misKFr3POdA",
                use = "enc", alg = JwaAlgorithm.ECDH_ES, kid = "error-recipient",
            )))) else null,
        )
    }

    @Test
    fun directPostErrorContainsOnlyProtocolErrorAndOriginalState() = runTest {
        val resolved = invalidRequest()
        var requests = 0
        val command = SubmitAuthorizationResponseCommandImpl(
            TestExecutionContext.createExecution(),
            createMockHttpClientFactory(onHttpRequest = { request ->
                requests++
                val form = (request.body as FormDataContent).formData
                assertEquals(setOf("error", "state"), form.names())
                assertEquals("invalid_request", form["error"])
                assertEquals(resolved.request.state, form["state"])
                assertEquals("https://verifier.example.com/response", request.url.toString())
            }),
            createMockExternalIdentifierService(),
            createMockJarmCommand(onExecute = { error("Plain protocol error must not create a JWT") }),
        )
        val result = command.execute(SubmitAuthorizationResponseArgs(resolvedRequest = resolved, errorResponse = resolved.authorizationError))
        assertIs<SubmissionResult.Success>(result.getOrThrow())
        assertEquals(1, requests)
    }

    @Test
    fun encryptedErrorHasBareErrorPayloadWithoutCredentialOrInventedIssuerEvenWhenNonceIsMissing() = runTest {
        val resolved = invalidRequest(ResponseMode.DIRECT_POST_JWT, withEncryption = true).let { it.copy(request = it.request.copy(nonce = null)) }
        var encrypted = 0
        var requests = 0
        val command = SubmitAuthorizationResponseCommandImpl(
            TestExecutionContext.createExecution(),
            createMockHttpClientFactory(onHttpRequest = { request ->
                requests++
                val form = (request.body as FormDataContent).formData
                assertEquals(setOf("response"), form.names())
                assertEquals("mock.jarm.jwt", form["response"])
            }),
            createMockExternalIdentifierService(),
            createMockJarmCommand(onArguments = { args ->
                encrypted++
                assertEquals(JsonObject(mapOf("error" to JsonPrimitive("invalid_request"), "state" to JsonPrimitive("test-state"))), args.responseParameters)
                assertEquals(null, args.issuer)
                assertEquals(null, args.signingKey)
                assertEquals(null, args.protectedHeaderOverrides)
                assertFalse(args.appendStandardJwtClaims)
                assertEquals(JarmMode.ENCRYPTED, args.jarmConfig.mode)
            }),
        )
        assertIs<SubmissionResult.Success>(command.execute(SubmitAuthorizationResponseArgs(resolvedRequest = resolved, errorResponse = resolved.authorizationError)).getOrThrow())
        assertEquals(1, encrypted)
        assertEquals(1, requests)
    }

    @Test
    fun encryptionFailureMaySendPlainErrorBeforeAnyHttpAttempt() = runTest {
        val resolved = invalidRequest(ResponseMode.DIRECT_POST_JWT, withEncryption = true)
        var requests = 0
        val command = SubmitAuthorizationResponseCommandImpl(
            TestExecutionContext.createExecution(),
            createMockHttpClientFactory(onHttpRequest = { request ->
                requests++
                assertEquals(setOf("error", "state"), (request.body as FormDataContent).formData.names())
            }),
            createMockExternalIdentifierService(),
            createMockJarmCommand(failure = IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Encryption failed")),
        )
        assertIs<SubmissionResult.Success>(command.execute(SubmitAuthorizationResponseArgs(resolvedRequest = resolved, errorResponse = resolved.authorizationError)).getOrThrow())
        assertEquals(1, requests)
    }

    @Test
    fun rejectedHttpResponseDoesNotRetryErrorWithoutEncryption() = runTest {
        val resolved = invalidRequest(ResponseMode.DIRECT_POST_JWT, withEncryption = true)
        var requests = 0
        val command = SubmitAuthorizationResponseCommandImpl(
            TestExecutionContext.createExecution(),
            createMockHttpClientFactory(responseStatus = HttpStatusCode.BadRequest, onHttpRequest = { request ->
                requests++
                assertEquals(setOf("response"), (request.body as FormDataContent).formData.names())
            }),
            createMockExternalIdentifierService(), createMockJarmCommand(),
        )
        assertIs<SubmissionResult.Error>(command.execute(SubmitAuthorizationResponseArgs(resolvedRequest = resolved, errorResponse = resolved.authorizationError)).getOrThrow())
        assertEquals(1, requests)
    }

    @Test
    fun invalidRequestsCannotPresentAndUnvalidatedClientsOrChangedStateCannotReceiveErrors() = runTest {
        val resolved = invalidRequest()
        val command = SubmitAuthorizationResponseCommandImpl(
            TestExecutionContext.createExecution(),
            createMockHttpClientFactory(onRequest = { error("Rejected request must not perform HTTP") }),
            createMockExternalIdentifierService(), createMockJarmCommand(onExecute = { error("Rejected request must not create a JWT") }),
        )
        val success = buildOid4vpAuthorizationResponse { vpToken("pid", "credential-must-not-leave") }
        assertTrue(command.execute(SubmitAuthorizationResponseArgs(resolvedRequest = resolved, response = success)).isErr)
        assertTrue(command.execute(SubmitAuthorizationResponseArgs(resolvedRequest = resolved.copy(verifierInfo = resolved.verifierInfo.copy(clientIdValid = false)), errorResponse = resolved.authorizationError)).isErr)
        assertTrue(command.execute(SubmitAuthorizationResponseArgs(resolvedRequest = resolved, errorResponse = resolved.authorizationError!!.copy(state = "changed"))).isErr)
    }

    @Test
    fun dcApiProtocolErrorsAreSingleErrorMemberForBothResponseModes() = runTest {
        val command = SubmitAuthorizationResponseCommandImpl(
            TestExecutionContext.createExecution(),
            createMockHttpClientFactory(onRequest = { error("DC API must not perform HTTP") }),
            createMockExternalIdentifierService(), createMockJarmCommand(onExecute = { error("DC API errors must not be encrypted") }),
        )
        for (mode in listOf(ResponseMode.DC_API, ResponseMode.DC_API_JWT)) {
            val resolved = invalidRequest(mode)
            val result = command.execute(SubmitAuthorizationResponseArgs(resolvedRequest = resolved, errorResponse = resolved.authorizationError)).getOrThrow()
            assertEquals(JsonObject(mapOf("error" to JsonPrimitive("invalid_request"))), assertIs<SubmissionResult.DigitalCredential>(result).data)
        }
    }

    /**
     * Create a resolved request for direct_post mode
     */
    private fun createResolvedRequestDirectPost(
        responseUri: String = "https://verifier.example.com/response",
        state: String? = "test-state",
    ): ResolvedOid4vpRequest {
        val authRequest =
            AuthorizationRequest(
                clientId = "test-client",
                redirectUri = "https://verifier.example.com/callback",
                responseType = "vp_token",
                state = state,
                responseMode = "direct_post",
                additionalParameters =
                    mapOf(
                        "nonce" to JsonPrimitive("test-nonce"),
                        "response_uri" to JsonPrimitive(responseUri),
                    ),
            )

        return ResolvedOid4vpRequest(
            request = authRequest,
            dcqlQuery = null,
            clientMetadata = null,
            verifierInfo =
                VerifierInfo(
                    clientId = "test-client",
                    clientIdScheme = ClientIdScheme.PRE_REGISTERED,
                    displayName = "Test Verifier",
                ),
        )
    }

    /**
     * Create a resolved request for fragment/query mode
     */
    private fun createResolvedRequestRedirect(
        redirectUri: String = "https://verifier.example.com/callback",
        state: String? = "test-state",
    ): ResolvedOid4vpRequest {
        val authRequest =
            AuthorizationRequest(
                clientId = "test-client",
                redirectUri = redirectUri,
                responseType = "vp_token",
                state = state,
                additionalParameters =
                    mapOf(
                        "nonce" to JsonPrimitive("test-nonce"),
                    ),
            )

        return ResolvedOid4vpRequest(
            request = authRequest,
            dcqlQuery = null,
            clientMetadata = null,
            verifierInfo =
                VerifierInfo(
                    clientId = "test-client",
                    clientIdScheme = ClientIdScheme.PRE_REGISTERED,
                    displayName = "Test Verifier",
                ),
        )
    }

    /**
     * Create a mock HttpClientFactory for testing
     */
    private fun createMockHttpClientFactory(
        responseStatus: HttpStatusCode = HttpStatusCode.OK,
        responseBody: String = """{"redirect_uri": "https://verifier.example.com/complete"}""",
        onRequest: () -> Unit = {},
        onHttpRequest: (HttpRequestData) -> Unit = {},
    ): HttpClientFactory =
        object : HttpClientFactory {
            override fun createClient(options: HttpClientOptions): HttpClient =
                HttpClient(
                    MockEngine { request ->
                        onRequest()
                        onHttpRequest(request)
                        respond(
                            content = responseBody,
                            status = responseStatus,
                            headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()),
                        )
                    },
                ) {
                    install(ContentNegotiation) {
                        json(
                            Json {
                                ignoreUnknownKeys = true
                                encodeDefaults = true
                            },
                        )
                    }
                }

            override fun isSupportedOptions(options: HttpClientOptions): Boolean = true

            override fun getEngineTypesSupported(): List<HttpClientEngineType> = listOf(HttpClientEngineType.CIO)

            override fun getEngineTypeDefault(): HttpClientEngineType = HttpClientEngineType.CIO
        }

    /**
     * Create a mock external identifier service for testing
     */
    private fun createMockExternalIdentifierService(): MultiExternalIdentifierService =
        object : MultiExternalIdentifierService {
            override val supportedIdentifierMethods: List<IIdentifierMethod> = emptyList()

            override suspend fun isSupportedIdentifier(identifier: Any): Boolean = false

            override suspend fun isSupportedIdentifierMethod(identifierMethod: IIdentifierMethod): Boolean = false

            override suspend fun isSupportedOpts(opts: ExternalIdentifierOptsOrResult): Boolean = false

            override suspend fun asSupportedOpts(opts: ExternalIdentifierOptsOrResult): IdkResult<ExternalIdentifierOpts, IdkErrorType> =
                IdkError.COMMAND_ARG_NOT_SUPPORTED_ERROR(message = "Not implemented in test").asErrorResult()

            override suspend fun resolve(opts: ExternalIdentifierOptsOrResult): IdkResult<ExternalIdentifierResult, IdkErrorType> =
                IdkError.COMMAND_ARG_NOT_SUPPORTED_ERROR(message = "Not implemented in test").asErrorResult()
        }

    /**
     * Create a mock CreateJarmResponseCommand for testing
     */
    private fun createMockJarmCommand(onExecute: () -> Unit = {}, onArguments: (CreateJarmResponseArgs) -> Unit = {}, failure: IdkError? = null): CreateJarmResponseCommand =
        object : CreateJarmResponseCommand {
            override val commandId: String = CreateJarmResponseCommand.COMMAND_ID
            override val isEnabled: Boolean = true
            override val inputTypeToken: TypeToken<CreateJarmResponseArgs> = typeToken<CreateJarmResponseArgs>()
            override val outputTypeToken: TypeToken<CreateJarmResponseResult> = typeToken<CreateJarmResponseResult>()

            override suspend fun execute(args: CreateJarmResponseArgs): IdkResult<CreateJarmResponseResult, IdkError> {
                onExecute()
                onArguments(args)
                failure?.let { return Err(it) }
                return Ok(
                    CreateJarmResponseResult(
                        jarmJwt = "mock.jarm.jwt",
                        mode = args.jarmConfig.mode,
                    ),
                )
            }
        }

    // =============================
    // Fragment Mode Tests
    // =============================

    @Test
    fun `test fragment mode builds correct redirect URI`() =
        runTest {
            val mockFactory = createMockHttpClientFactory()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            val resolvedRequest = createResolvedRequestRedirect()
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                    state("test-state")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.FRAGMENT)
            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val submissionResult = result.value
            assertIs<SubmissionResult.Redirect>(submissionResult)

            // Verify redirect URI structure
            assertTrue(submissionResult.redirectUri.startsWith("https://verifier.example.com/callback#"))
            assertTrue(submissionResult.redirectUri.contains("vp_token="))
            assertTrue(submissionResult.redirectUri.contains("state=test-state"))
        }

    @Test
    fun `test fragment mode with multiple credentials`() =
        runTest {
            val mockFactory = createMockHttpClientFactory()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            val resolvedRequest = createResolvedRequestRedirect()
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken(
                        mapOf(
                            "query1" to listOf("jwt1.payload.sig1"),
                            "query2" to listOf("jwt2.payload.sig2"),
                        ),
                    )
                    state("test-state")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.FRAGMENT)
            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val submissionResult = result.value
            assertIs<SubmissionResult.Redirect>(submissionResult)
            assertTrue(submissionResult.redirectUri.startsWith("https://verifier.example.com/callback#"))
            assertTrue(submissionResult.redirectUri.contains("vp_token="))
        }

    @Test
    fun `test fragment mode without state`() =
        runTest {
            val mockFactory = createMockHttpClientFactory()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            val resolvedRequest = createResolvedRequestRedirect(state = null)
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.FRAGMENT)
            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val submissionResult = result.value
            assertIs<SubmissionResult.Redirect>(submissionResult)

            // Should not contain state parameter
            assertTrue(submissionResult.redirectUri.startsWith("https://verifier.example.com/callback#vp_token="))
            assertTrue(!submissionResult.redirectUri.contains("state="))
        }

    // =============================
    // Query Mode Tests
    // =============================

    @Test
    fun `test query mode builds correct redirect URI`() =
        runTest {
            val mockFactory = createMockHttpClientFactory()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            val resolvedRequest = createResolvedRequestRedirect()
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                    state("test-state")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.QUERY)
            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val submissionResult = result.value
            assertIs<SubmissionResult.Redirect>(submissionResult)

            // Verify query string structure
            assertTrue(submissionResult.redirectUri.startsWith("https://verifier.example.com/callback?"))
            assertTrue(submissionResult.redirectUri.contains("vp_token="))
            assertTrue(submissionResult.redirectUri.contains("state=test-state"))
        }

    @Test
    fun `test query mode with existing query parameters`() =
        runTest {
            val mockFactory = createMockHttpClientFactory()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            // redirect_uri already has query params
            val resolvedRequest =
                createResolvedRequestRedirect(
                    redirectUri = "https://verifier.example.com/callback?session=abc123",
                )
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                    state("test-state")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.QUERY)
            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val submissionResult = result.value
            assertIs<SubmissionResult.Redirect>(submissionResult)

            // Should append with & since there's already a ?
            assertTrue(submissionResult.redirectUri.contains("session=abc123"))
            assertTrue(submissionResult.redirectUri.contains("vp_token="))
        }

    // =============================
    // Direct Post Mode Tests
    // =============================

    @Test
    fun `test direct_post success with redirect_uri in response`() =
        runTest {
            val mockFactory =
                createMockHttpClientFactory(
                    responseStatus = HttpStatusCode.OK,
                    responseBody = """{"redirect_uri": "https://verifier.example.com/complete?session=xyz"}""",
                )
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            val resolvedRequest = createResolvedRequestDirectPost()
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                    state("test-state")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.DIRECT_POST)
            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val submissionResult = result.value
            assertIs<SubmissionResult.Success>(submissionResult)
            assertEquals("https://verifier.example.com/complete?session=xyz", submissionResult.redirectUri)
        }

    @Test
    fun `test direct_post success without redirect_uri`() =
        runTest {
            val mockFactory =
                createMockHttpClientFactory(
                    responseStatus = HttpStatusCode.OK,
                    responseBody = """{}""",
                )
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            val resolvedRequest = createResolvedRequestDirectPost()
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.DIRECT_POST)
            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val submissionResult = result.value
            assertIs<SubmissionResult.Success>(submissionResult)
            assertEquals(null, submissionResult.redirectUri)
        }

    @Test
    fun `test direct_post error response`() =
        runTest {
            val mockFactory =
                createMockHttpClientFactory(
                    responseStatus = HttpStatusCode.BadRequest,
                    responseBody = """{"error": "invalid_request", "error_description": "Invalid VP token"}""",
                )
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            val resolvedRequest = createResolvedRequestDirectPost()
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "invalid-token")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.DIRECT_POST)
            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val submissionResult = result.value
            assertIs<SubmissionResult.Error>(submissionResult)
            assertEquals("invalid_request", submissionResult.error)
            assertEquals("Invalid VP token", submissionResult.errorDescription)
        }

    @Test
    fun `test direct_post missing response_uri fails`() =
        runTest {
            val mockFactory = createMockHttpClientFactory()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            // Create request without response_uri
            val authRequest =
                AuthorizationRequest(
                    clientId = "test-client",
                    redirectUri = "https://verifier.example.com/callback",
                    responseType = "vp_token",
                    responseMode = "direct_post",
                    additionalParameters =
                        mapOf(
                            "nonce" to JsonPrimitive("test-nonce"),
                            // No response_uri!
                        ),
                )
            val resolvedRequest =
                ResolvedOid4vpRequest(
                    request = authRequest,
                    dcqlQuery = null,
                    clientMetadata = null,
                    verifierInfo =
                        VerifierInfo(
                            clientId = "test-client",
                            clientIdScheme = ClientIdScheme.PRE_REGISTERED,
                        ),
                )
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.DIRECT_POST)
            val result = command.execute(args)

            assertIs<Err<*>>(result)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("response_uri", ignoreCase = true),
            )
        }

    // =============================
    // Validation Tests
    // =============================

    @Test
    fun `test missing vp_token fails`() =
        runTest {
            val mockFactory = createMockHttpClientFactory()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            val resolvedRequest = createResolvedRequestRedirect()
            // Response without vp_token
            val response =
                buildOid4vpAuthorizationResponse {
                    state("test-state")
                    // No vpToken!
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.FRAGMENT)
            val result = command.execute(args)

            assertIs<Err<*>>(result)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("vp_token", ignoreCase = true),
            )
        }

    @Test
    fun `test http scheme rejected for non-localhost`() =
        runTest {
            val mockFactory = createMockHttpClientFactory()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            // Create request with HTTP (not HTTPS) URI
            val resolvedRequest =
                createResolvedRequestDirectPost(
                    responseUri = "http://verifier.example.com/response",
                )
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.DIRECT_POST)
            val result = command.execute(args)

            assertIs<Err<*>>(result)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("HTTPS", ignoreCase = true),
            )
        }

    @Test
    fun `test http scheme allowed for localhost`() =
        runTest {
            val mockFactory = createMockHttpClientFactory()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            // localhost is allowed for testing
            val resolvedRequest =
                createResolvedRequestDirectPost(
                    responseUri = "http://localhost:8080/response",
                )
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.DIRECT_POST)
            val result = command.execute(args)

            // Should succeed (validation should pass)
            assertIs<Ok<*>>(result)
        }

    @Test
    fun `test direct_post_jwt mode without jarmOptions returns error`() =
        runTest {
            val mockFactory = createMockHttpClientFactory()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            val resolvedRequest = createResolvedRequestDirectPost()
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.DIRECT_POST_JWT)
            val result = command.execute(args)

            // DIRECT_POST_JWT mode requires jarmOptions - without it, should return ILLEGAL_ARGUMENT error
            assertIs<Err<*>>(result)
            assertTrue(result.error.code.contains("ILLEGAL_ARGUMENT"))
        }

    @Test
    fun `final direct_post jwt refuses signed only before JARM signing`() =
        runTest {
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = createMockHttpClientFactory(),
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )
            val request = createResolvedRequestDirectPost()
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                }

            val result =
                command.execute(
                    SubmitAuthorizationResponseArgs(
                        resolvedRequest = request,
                        response = response,
                        responseMode = ResponseMode.DIRECT_POST_JWT,
                        jarmOptions = JarmOptions(issuer = "wallet", jarmConfig = JarmConfig.signed()),
                    ),
                )

            assertIs<Err<*>>(result)
            assertTrue(result.error.message.defaultMessage.contains("unsigned encrypted"))
        }

    @Test
    fun `final dc_api jwt requires response JWE recipient to match transcript JWK`() =
        runTest {
            val selectedForTranscript =
                Jwk(
                    kty = JwaKeyType.EC,
                    crv = JwaCurve.P_256,
                    x = "0_3S7HedSywaxlekdt6Or8pkcR13hQaCPMqt9cuZBVc",
                    y = "ZVXSCL3HlnMQWKrwMyIAe5wsAIWd3Eu1misKFr3POdA",
                    use = "enc",
                    alg = JwaAlgorithm.ECDH_ES,
                    kid = "transcript-key",
                )
            val notSelectedForTranscript =
                selectedForTranscript.copy(
                    x = "eR0Yq1ZC1TZ6T5FKKjJfJ7H6yEqWa7LKvdp6sY2yodw",
                    kid = "recipient-drift-key",
                    alg = null,
                )
            val callerOrigin = "https://wallet.example.test"
            val dcApiClientId = "origin:$callerOrigin"
            fun dcApiRequest(metadata: ClientMetadata) =
                createResolvedRequestDirectPost().copy(
                    request =
                        createResolvedRequestDirectPost().request.copy(
                            clientId = dcApiClientId,
                            redirectUri = null,
                            responseMode = ResponseMode.DC_API_JWT.value,
                            nonce = "test-nonce",
                            additionalParameters =
                                mapOf(
                                    "nonce" to JsonPrimitive("test-nonce"),
                                    DIGITAL_CREDENTIAL_ORIGIN_PARAMETER to JsonPrimitive(callerOrigin),
                                ),
                        ),
                    verifierInfo = createResolvedRequestDirectPost().verifierInfo.copy(
                        clientId = dcApiClientId,
                        clientIdScheme = ClientIdScheme.ORIGIN,
                    ),
                    clientMetadata = metadata,
                )
            val matchingRequest = dcApiRequest(ClientMetadata(jwks = JwkSet(arrayOf(selectedForTranscript))))
            val driftedRequest = dcApiRequest(ClientMetadata(jwks = JwkSet(arrayOf(notSelectedForTranscript, selectedForTranscript))))
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                }
            var httpRequests = 0
            var jarmExecutions = 0
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = createMockHttpClientFactory(onRequest = { httpRequests++ }),
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(
                        onExecute = { jarmExecutions++ },
                        onArguments = { args ->
                            assertFalse(args.appendStandardJwtClaims)
                            assertIs<JsonObject>(args.responseParameters["vp_token"])
                        },
                    ),
                )
            val binding =
                PreparedOid4vpJweRecipientBinding(
                    publicJwkJson = Jwk.from(selectedForTranscript.toPublicKey()).toJsonString(),
                    rfc7638Thumbprint = tryGenerateJwkThumbprint(selectedForTranscript).getOrThrow(),
                    keyEncryptionAlgorithm = "ECDH-ES",
                    contentEncryptionAlgorithm = JarmConfig.DEFAULT_CONTENT_ENCRYPTION_ALG,
                    responseMode = ResponseMode.DC_API_JWT.value,
                    clientId = dcApiClientId,
                    authorizationRequestNonce = "test-nonce",
                    responseUri = null,
                    redirectUri = null,
                    callerOrigin = callerOrigin,
                )
            val options = JarmOptions(issuer = "wallet", jarmConfig = JarmConfig.encrypted("ECDH-ES"))

            val matchingResult =
                command.execute(
                    SubmitAuthorizationResponseArgs(
                        resolvedRequest = matchingRequest,
                        response = response,
                        responseMode = ResponseMode.DC_API_JWT,
                        jarmOptions = options,
                        preparedOid4vpJweRecipientBinding = binding,
                    ),
                )
            assertIs<Ok<*>>(matchingResult)
            assertEquals(0, httpRequests)
            assertEquals(1, jarmExecutions)

            val result =
                command.execute(
                    SubmitAuthorizationResponseArgs(
                        resolvedRequest = driftedRequest,
                        response = response,
                        responseMode = ResponseMode.DC_API_JWT,
                        jarmOptions = options,
                        preparedOid4vpJweRecipientBinding = binding,
                    ),
                )

            assertIs<Err<*>>(result)
            assertTrue(result.error.message.defaultMessage.contains("does not match the prepared DeviceAuthentication binding"))
            assertEquals(0, httpRequests)
            assertEquals(1, jarmExecutions)
        }

    @Test
    fun `prepared recipient binding rejects changed nonce response uri and caller origin`() =
        runTest {
            val encryptionJwk =
                Jwk(
                    kty = JwaKeyType.EC,
                    crv = JwaCurve.P_256,
                    x = "0_3S7HedSywaxlekdt6Or8pkcR13hQaCPMqt9cuZBVc",
                    y = "ZVXSCL3HlnMQWKrwMyIAe5wsAIWd3Eu1misKFr3POdA",
                    use = "enc",
                    alg = JwaAlgorithm.ECDH_ES,
                    kid = "enc-key",
                )
            val callerOrigin = "https://wallet.example.test"
            val dcApiClientId = "origin:$callerOrigin"
            val base =
                createResolvedRequestDirectPost().copy(
                    request =
                        createResolvedRequestDirectPost().request.copy(
                            clientId = dcApiClientId,
                            redirectUri = null,
                            responseMode = ResponseMode.DC_API_JWT.value,
                            nonce = "test-nonce",
                            additionalParameters = mapOf(DIGITAL_CREDENTIAL_ORIGIN_PARAMETER to JsonPrimitive(callerOrigin)),
                        ),
                    verifierInfo = createResolvedRequestDirectPost().verifierInfo.copy(
                        clientId = dcApiClientId,
                        clientIdScheme = ClientIdScheme.ORIGIN,
                    ),
                    clientMetadata = ClientMetadata(jwks = JwkSet(arrayOf(encryptionJwk))),
                )
            val binding =
                PreparedOid4vpJweRecipientBinding(
                    publicJwkJson = Jwk.from(encryptionJwk.toPublicKey()).toJsonString(),
                    rfc7638Thumbprint = tryGenerateJwkThumbprint(encryptionJwk).getOrThrow(),
                    keyEncryptionAlgorithm = "ECDH-ES",
                    contentEncryptionAlgorithm = JarmConfig.DEFAULT_CONTENT_ENCRYPTION_ALG,
                    responseMode = ResponseMode.DC_API_JWT.value,
                    clientId = dcApiClientId,
                    authorizationRequestNonce = "test-nonce",
                    responseUri = null,
                    redirectUri = null,
                    callerOrigin = callerOrigin,
                )
            var httpRequests = 0
            var jarmExecutions = 0
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = createMockHttpClientFactory(onRequest = { httpRequests++ }),
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(onExecute = { jarmExecutions++ }),
                )
            val response = buildOid4vpAuthorizationResponse { vpToken("test", "eyJhbGciOiJFUzI1NiJ9.payload.signature") }
            val options = JarmOptions(issuer = "wallet", jarmConfig = JarmConfig.encrypted("ECDH-ES"))

            val baseline =
                command.execute(
                    SubmitAuthorizationResponseArgs(
                        base,
                        response,
                        ResponseMode.DC_API_JWT,
                        options,
                        binding,
                    ),
                )
            assertIs<Ok<*>>(baseline)
            assertEquals(0, httpRequests)
            assertEquals(1, jarmExecutions)

            suspend fun assertTranscriptMutationRejected(changed: ResolvedOid4vpRequest) {
                val result =
                    command.execute(
                        SubmitAuthorizationResponseArgs(
                            changed,
                            response,
                            ResponseMode.DC_API_JWT,
                            options,
                            binding,
                        ),
                    )
                assertIs<Err<*>>(result)
                assertTrue(result.error.message.defaultMessage.contains("transcript inputs changed"))
                assertEquals(0, httpRequests)
                assertEquals(1, jarmExecutions)
            }

            assertTranscriptMutationRejected(
                base.copy(request = base.request.copy(nonce = "changed")),
            )
            assertTranscriptMutationRejected(
                base.copy(request = base.request.copy(additionalParameters = base.request.additionalParameters + ("response_uri" to JsonPrimitive("https://other.example/response")))),
            )
            assertTranscriptMutationRejected(
                base.copy(request = base.request.copy(additionalParameters = base.request.additionalParameters + (DIGITAL_CREDENTIAL_ORIGIN_PARAMETER to JsonPrimitive("https://other.example")))),
            )
            assertTranscriptMutationRejected(
                base.copy(request = base.request.copy(clientId = "origin:https://other.example")),
            )
            assertTranscriptMutationRejected(
                base.copy(request = base.request.copy(responseMode = ResponseMode.DIRECT_POST_JWT.value)),
            )
            assertTranscriptMutationRejected(
                base.copy(request = base.request.copy(redirectUri = "https://verifier.example.com/callback")),
            )
        }

    @Test
    fun `legacy four argument submit remains compatible for selected mdoc and unselected alternatives`() =
        runTest {
            val encryptionJwk =
                Jwk(
                    kty = JwaKeyType.EC,
                    crv = JwaCurve.P_256,
                    x = "0_3S7HedSywaxlekdt6Or8pkcR13hQaCPMqt9cuZBVc",
                    y = "ZVXSCL3HlnMQWKrwMyIAe5wsAIWd3Eu1misKFr3POdA",
                    use = "enc",
                    alg = JwaAlgorithm.ECDH_ES,
                    kid = "enc-key",
                )
            val callerOrigin = "https://wallet.example.test"
            val dcApiClientId = "origin:$callerOrigin"
            val request =
                createResolvedRequestDirectPost().copy(
                    request =
                        createResolvedRequestDirectPost().request.copy(
                            clientId = dcApiClientId,
                            redirectUri = null,
                            responseMode = ResponseMode.DC_API_JWT.value,
                            nonce = "test-nonce",
                            additionalParameters = mapOf(DIGITAL_CREDENTIAL_ORIGIN_PARAMETER to JsonPrimitive(callerOrigin)),
                        ),
                    verifierInfo = createResolvedRequestDirectPost().verifierInfo.copy(
                        clientId = dcApiClientId,
                        clientIdScheme = ClientIdScheme.ORIGIN,
                    ),
                    dcqlQuery =
                        DcqlQuery(
                            credentials =
                                listOf(
                                    DcqlCredentialQuery(
                                        id = "mdl",
                                        format = "mso_mdoc",
                                        meta = Json.parseToJsonElement("""{"doctype_value":"org.example.mdl"}""").jsonObject,
                                    ),
                                    DcqlCredentialQuery(
                                        id = "sd",
                                        format = "dc+sd-jwt",
                                        meta = Json.parseToJsonElement("""{"vct_values":["https://example.test/vct"]}""").jsonObject,
                                    ),
                                ),
                        ),
                    clientMetadata = ClientMetadata(jwks = JwkSet(arrayOf(encryptionJwk))),
                )
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = createMockHttpClientFactory(),
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )
            val options = JarmOptions(issuer = "wallet", jarmConfig = JarmConfig.encrypted("ECDH-ES"))
            val mdocResponse = buildOid4vpAuthorizationResponse { vpToken("mdl", "bWV0YQ") }
            val legacyMdocSubmit =
                command.execute(
                    SubmitAuthorizationResponseArgs(request, mdocResponse, ResponseMode.DC_API_JWT, options),
                )
            assertIs<Ok<*>>(legacyMdocSubmit)

            val alternativeResponse =
                buildOid4vpAuthorizationResponse { vpToken("sd", "eyJhbGciOiJFUzI1NiJ9.payload.signature") }
            val nonMdocAlternative =
                command.execute(
                    SubmitAuthorizationResponseArgs(request, alternativeResponse, ResponseMode.DC_API_JWT, options),
                )
            assertIs<Ok<*>>(nonMdocAlternative)
        }

    @Test
    fun `prepared encrypted response cannot be downgraded before plain submission or JARM`() =
        runTest {
            var httpRequests = 0
            var jarmExecutions = 0
            val encryptionJwk =
                Jwk(
                    kty = JwaKeyType.EC,
                    crv = JwaCurve.P_256,
                    x = "0_3S7HedSywaxlekdt6Or8pkcR13hQaCPMqt9cuZBVc",
                    y = "ZVXSCL3HlnMQWKrwMyIAe5wsAIWd3Eu1misKFr3POdA",
                    use = "enc",
                    alg = JwaAlgorithm.ECDH_ES,
                    kid = "enc-key",
                )
            val callerOrigin = "https://wallet.example.test"
            val dcApiClientId = "origin:$callerOrigin"
            val request =
                createResolvedRequestDirectPost().copy(
                    request =
                        createResolvedRequestDirectPost().request.copy(
                            clientId = dcApiClientId,
                            redirectUri = null,
                            responseMode = ResponseMode.DC_API_JWT.value,
                            nonce = "test-nonce",
                            additionalParameters = mapOf(DIGITAL_CREDENTIAL_ORIGIN_PARAMETER to JsonPrimitive(callerOrigin)),
                        ),
                    verifierInfo = createResolvedRequestDirectPost().verifierInfo.copy(
                        clientId = dcApiClientId,
                        clientIdScheme = ClientIdScheme.ORIGIN,
                    ),
                    clientMetadata = ClientMetadata(jwks = JwkSet(arrayOf(encryptionJwk))),
                )
            val response = buildOid4vpAuthorizationResponse { vpToken("mdl", "bWV0YQ") }
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = createMockHttpClientFactory(onRequest = { httpRequests++ }),
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(onExecute = { jarmExecutions++ }),
                )
            val binding =
                PreparedOid4vpJweRecipientBinding(
                    publicJwkJson = Jwk.from(encryptionJwk.toPublicKey()).toJsonString(),
                    rfc7638Thumbprint = tryGenerateJwkThumbprint(encryptionJwk).getOrThrow(),
                    keyEncryptionAlgorithm = "ECDH-ES",
                    contentEncryptionAlgorithm = JarmConfig.DEFAULT_CONTENT_ENCRYPTION_ALG,
                    responseMode = ResponseMode.DC_API_JWT.value,
                    clientId = dcApiClientId,
                    authorizationRequestNonce = "test-nonce",
                    responseUri = null,
                    redirectUri = null,
                    callerOrigin = callerOrigin,
                )

            val result =
                command.execute(
                    SubmitAuthorizationResponseArgs(
                        resolvedRequest = request,
                        response = response,
                        responseMode = ResponseMode.DIRECT_POST,
                        jarmOptions = JarmOptions(issuer = "wallet", jarmConfig = JarmConfig.encrypted("ECDH-ES")),
                        preparedOid4vpJweRecipientBinding = binding,
                    ),
                )

            assertIs<Err<*>>(result)
            assertTrue(result.error.message.defaultMessage.contains("transcript inputs changed"))
            assertEquals(0, httpRequests)
            assertEquals(0, jarmExecutions)
        }

    // =============================
    // Response Mode Detection Tests
    // =============================

    @Test
    fun `test response mode defaults to request response_mode`() =
        runTest {
            val mockFactory = createMockHttpClientFactory()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            val resolvedRequest = createResolvedRequestDirectPost()
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                }

            // Don't specify responseMode - should use request's response_mode (direct_post)
            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response)
            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val submissionResult = result.value
            assertIs<SubmissionResult.Success>(submissionResult) // direct_post returns Success
        }

    @Test
    fun `test response mode override works`() =
        runTest {
            val mockFactory = createMockHttpClientFactory()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = mockFactory,
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )

            // Request says direct_post, but we override to fragment
            val resolvedRequest = createResolvedRequestDirectPost()
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                }

            val args = SubmitAuthorizationResponseArgs(resolvedRequest, response, ResponseMode.FRAGMENT)
            val result = command.execute(args)

            assertIs<Ok<*>>(result)
            val submissionResult = result.value
            assertIs<SubmissionResult.Redirect>(submissionResult) // Fragment returns Redirect
        }

    @Test
    fun `test direct_post to an internal or non-https response_uri is refused under the counterparty egress rule`() =
        runTest {
            val requestedPolicies = mutableListOf<UrlValidationPolicy?>()
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = createPolicyEnforcingHttpClientFactory(requestedPolicies),
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                    state("test-state")
                }

            for (responseUri in listOf(
                "https://127.0.0.1/response",
                "https://[::1]/response",
                "https://10.0.0.5/response",
                "https://169.254.169.254/latest",
                "https://localhost/response",
                "http://verifier.example.com/response",
            )) {
                val result =
                    command.execute(
                        SubmitAuthorizationResponseArgs(createResolvedRequestDirectPost(responseUri = responseUri), response, ResponseMode.DIRECT_POST),
                    )
                assertIs<Err<*>>(result, responseUri)
            }
            assertEquals(UrlValidationPolicy.COUNTERPARTY_EGRESS, requestedPolicies.distinct().single())
        }

    @Test
    fun `test direct_post to a public https response_uri is allowed under the counterparty egress rule`() =
        runTest {
            val command =
                SubmitAuthorizationResponseCommandImpl(
                    execution = TestExecutionContext.createExecution(),
                    httpClientFactory = createPolicyEnforcingHttpClientFactory(mutableListOf()),
                    externalIdentifierService = createMockExternalIdentifierService(),
                    createJarmCommand = createMockJarmCommand(),
                )
            val response =
                buildOid4vpAuthorizationResponse {
                    vpToken("test_query", "eyJhbGciOiJFUzI1NiJ9.payload.signature")
                    state("test-state")
                }

            val result =
                command.execute(
                    SubmitAuthorizationResponseArgs(
                        createResolvedRequestDirectPost(responseUri = "https://verifier.example.com/response"),
                        response,
                        ResponseMode.DIRECT_POST,
                    ),
                )

            assertIs<Ok<*>>(result)
        }

    /** A mock factory that applies the requested URL policy to every request, as the platform factories do. */
    private fun createPolicyEnforcingHttpClientFactory(requestedPolicies: MutableList<UrlValidationPolicy?>): HttpClientFactory =
        object : HttpClientFactory {
            override fun createClient(options: HttpClientOptions): HttpClient {
                requestedPolicies += options.urlValidation
                val client =
                    HttpClient(
                        MockEngine {
                            respond(
                                content = "{}",
                                status = HttpStatusCode.OK,
                                headers = headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()),
                            )
                        },
                    )
                options.urlValidation?.let { policy ->
                    client.plugin(HttpSend).intercept { request ->
                        policy.validate(request.url.build())
                        execute(request)
                    }
                }
                return client
            }

            override fun isSupportedOptions(options: HttpClientOptions): Boolean = true

            override fun getEngineTypesSupported(): List<HttpClientEngineType> = listOf(HttpClientEngineType.CIO)

            override fun getEngineTypeDefault(): HttpClientEngineType = HttpClientEngineType.CIO
        }
}
