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

package com.sphereon.oauth2.server.authorization.impl.http.command.authorization

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.oauth2.common.model.OAuth2ResponseMode
import com.sphereon.oauth2.server.authorization.command.AuthorizationErrorResponseData
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestOutcome
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationErrorResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationErrorResponseCommand
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestArgs
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestCommand
import com.sphereon.oauth2.server.authorization.impl.http.DefaultOAuth2ServerBaseUrlResolver
import com.sphereon.oauth2.server.authorization.impl.http.command.TestMutableOidcLoginSessionIdProvider
import com.sphereon.oauth2.server.authorization.impl.http.command.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.impl.http.command.TestSessionExecution
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AuthorizeHttpEndpointCommandImplTest {
    private class FakeAuthorizeRequestCommand(
        private val handler: suspend (HandleAuthorizeRequestArgs) -> IdkResult<AuthorizationRequestOutcome, IdkError>,
    ) : HandleAuthorizeRequestCommand {
        override val commandId: String get() = "test.authorize-request"
        override val inputTypeToken get() = typeToken<HandleAuthorizeRequestArgs>()
        override val outputTypeToken get() = typeToken<AuthorizationRequestOutcome>()
        override val isEnabled: Boolean = true

        override suspend fun supports(args: Any): Boolean = args is HandleAuthorizeRequestArgs

        override suspend fun execute(args: HandleAuthorizeRequestArgs): IdkResult<AuthorizationRequestOutcome, IdkError> = handler(args)
    }

    private class FakeCreateErrorResponseCommand : CreateAuthorizationErrorResponseCommand {
        override val commandId: String get() = CreateAuthorizationErrorResponseCommand.COMMAND_ID
        override val inputTypeToken get() = typeToken<CreateAuthorizationErrorResponseArgs>()
        override val outputTypeToken get() = typeToken<AuthorizationErrorResponseData>()
        override val isEnabled: Boolean = true

        override suspend fun supports(args: Any): Boolean = args is CreateAuthorizationErrorResponseArgs

        override suspend fun execute(args: CreateAuthorizationErrorResponseArgs): IdkResult<AuthorizationErrorResponseData, IdkError> =
            Ok(
                AuthorizationErrorResponseData(
                    error = args.error,
                    errorDescription = args.errorDescription,
                    state = args.state,
                    redirectUri = "${args.redirectUri}?error=${args.error}",
                    responseMode = args.responseMode,
                ),
            )
    }

    @Test
    fun authInitiated_returns302WithProviderUrl() =
        runTest {
            val command =
                AuthorizeHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleAuthorizeRequestCommands =
                        setOf(
                            FakeAuthorizeRequestCommand {
                                Ok(AuthorizationRequestOutcome.AuthInitiated(authProviderRedirectUrl = "https://idp.example/login?state=x"))
                            },
                        ),
                    createAuthorizationErrorResponseCommand = FakeCreateErrorResponseCommand(),
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    loginSessionIdProvider = TestMutableOidcLoginSessionIdProvider(),
                )

            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/authorize",
                    queryParameters = mapOf("client_id" to "c", "response_type" to "code"),
                    headers = mapOf("Host" to "as.example"),
                )
            val result = command.execute(request)

            assertTrue(result.isOk)
            assertEquals(302, result.value.statusCode)
            assertEquals("https://idp.example/login?state=x", result.value.headers["Location"])
        }

    @Test
    fun preRedirectError_returns400JsonError() =
        runTest {
            val command =
                AuthorizeHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleAuthorizeRequestCommands =
                        setOf(
                            FakeAuthorizeRequestCommand {
                                Ok(
                                    AuthorizationRequestOutcome.PreRedirectError(
                                        error = "invalid_request",
                                        errorDescription = "missing client_id",
                                    ),
                                )
                            },
                        ),
                    createAuthorizationErrorResponseCommand = FakeCreateErrorResponseCommand(),
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    loginSessionIdProvider = TestMutableOidcLoginSessionIdProvider(),
                )

            val request = GenericHttpRequest(method = "GET", path = "/authorize")
            val result = command.execute(request)

            assertTrue(result.isOk)
            assertEquals(400, result.value.statusCode)
            assertTrue(result.value.body!!.contains("invalid_request"))
        }

    @Test
    fun postRedirectError_redirectsViaResponseMode() =
        runTest {
            val command =
                AuthorizeHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleAuthorizeRequestCommands =
                        setOf(
                            FakeAuthorizeRequestCommand {
                                Ok(
                                    AuthorizationRequestOutcome.PostRedirectError(
                                        error = "invalid_scope",
                                        errorDescription = "scope not permitted",
                                        redirectUri = "https://client.example/cb",
                                        state = "abc",
                                        responseMode = OAuth2ResponseMode.QUERY,
                                    ),
                                )
                            },
                        ),
                    createAuthorizationErrorResponseCommand = FakeCreateErrorResponseCommand(),
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    loginSessionIdProvider = TestMutableOidcLoginSessionIdProvider(),
                )

            val request = GenericHttpRequest(method = "GET", path = "/authorize")
            val result = command.execute(request)

            assertTrue(result.isOk)
            assertEquals(302, result.value.statusCode)
            assertEquals("https://client.example/cb?error=invalid_scope", result.value.headers["Location"])
        }

    @Test
    fun requestNotSupported_redirects302ToTrustedRedirect() =
        runTest {
            // OIDF Basic RP tests (e.g. OIDCCEnsureRequestObjectStandardClaimSupports) accept a
            // post-redirect `request_not_supported` rejection in lieu of full Request Object
            // processing. Verify the adapter delivers it as a 302 to the validated redirect URI.
            val command =
                AuthorizeHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleAuthorizeRequestCommands =
                        setOf(
                            FakeAuthorizeRequestCommand {
                                Ok(
                                    AuthorizationRequestOutcome.PostRedirectError(
                                        error = "request_not_supported",
                                        errorDescription = "request parameter is not supported",
                                        redirectUri = "https://client.example.org/cb",
                                        state = "xyz",
                                        responseMode = OAuth2ResponseMode.QUERY,
                                    ),
                                )
                            },
                        ),
                    createAuthorizationErrorResponseCommand = FakeCreateErrorResponseCommand(),
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    loginSessionIdProvider = TestMutableOidcLoginSessionIdProvider(),
                )

            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/authorize",
                    queryParameters =
                        mapOf(
                            "response_type" to "code",
                            "client_id" to "oidf-static-client",
                            "redirect_uri" to "https://client.example.org/cb",
                            "scope" to "openid",
                            "state" to "xyz",
                            "nonce" to "n1",
                            "request" to "stub",
                        ),
                )
            val result = command.execute(request)

            assertTrue(result.isOk)
            assertEquals(302, result.value.statusCode)
            val location = result.value.headers["Location"]!!
            assertTrue(location.startsWith("https://client.example.org/cb"), "Location must point at trusted redirect URI, got: $location")
            assertTrue(location.contains("error=request_not_supported"), "Location must carry error=request_not_supported, got: $location")
        }

    @Test
    fun noSupportingCommand_returns500() =
        runTest {
            val command =
                AuthorizeHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleAuthorizeRequestCommands = emptySet(),
                    createAuthorizationErrorResponseCommand = FakeCreateErrorResponseCommand(),
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    loginSessionIdProvider = TestMutableOidcLoginSessionIdProvider(),
                )

            val request = GenericHttpRequest(method = "GET", path = "/authorize")
            val result = command.execute(request)

            assertTrue(result.isOk)
            assertEquals(500, result.value.statusCode)
        }

    @Test
    fun supportsBothGetAndPost() =
        runTest {
            val command =
                AuthorizeHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleAuthorizeRequestCommands =
                        setOf(
                            FakeAuthorizeRequestCommand {
                                Ok(AuthorizationRequestOutcome.AuthInitiated(authProviderRedirectUrl = "https://idp.example/login"))
                            },
                        ),
                    createAuthorizationErrorResponseCommand = FakeCreateErrorResponseCommand(),
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    loginSessionIdProvider = TestMutableOidcLoginSessionIdProvider(),
                )
            assertTrue(command.supports(GenericHttpRequest(method = "GET", path = "/authorize")))
            assertTrue(command.supports(GenericHttpRequest(method = "POST", path = "/authorize")))
        }

    @Test
    fun getAndPostProduceIdenticalDispatch() =
        runTest {
            val getCaptured = mutableListOf<HandleAuthorizeRequestArgs>()
            val postCaptured = mutableListOf<HandleAuthorizeRequestArgs>()

            val getCommand =
                AuthorizeHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleAuthorizeRequestCommands =
                        setOf(
                            FakeAuthorizeRequestCommand { args ->
                                getCaptured += args
                                Ok(AuthorizationRequestOutcome.AuthInitiated(authProviderRedirectUrl = "https://idp.example/login"))
                            },
                        ),
                    createAuthorizationErrorResponseCommand = FakeCreateErrorResponseCommand(),
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    loginSessionIdProvider = TestMutableOidcLoginSessionIdProvider(),
                )

            val postCommand =
                AuthorizeHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleAuthorizeRequestCommands =
                        setOf(
                            FakeAuthorizeRequestCommand { args ->
                                postCaptured += args
                                Ok(AuthorizationRequestOutcome.AuthInitiated(authProviderRedirectUrl = "https://idp.example/login"))
                            },
                        ),
                    createAuthorizationErrorResponseCommand = FakeCreateErrorResponseCommand(),
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    loginSessionIdProvider = TestMutableOidcLoginSessionIdProvider(),
                )

            val getRequest =
                GenericHttpRequest(
                    method = "GET",
                    path = "/authorize",
                    queryParameters =
                        mapOf(
                            "client_id" to "client-1",
                            "response_type" to "code",
                            "scope" to "openid profile",
                            "redirect_uri" to "https://client.example/cb",
                            "state" to "xyz",
                        ),
                    headers = mapOf("Host" to "as.example"),
                )

            val postBody =
                "client_id=client-1" +
                    "&response_type=code" +
                    "&scope=openid%20profile" +
                    "&redirect_uri=https%3A%2F%2Fclient.example%2Fcb" +
                    "&state=xyz"
            val postRequest =
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path = "/authorize",
                    body = postBody,
                    headers =
                        mapOf(
                            "Host" to "as.example",
                            "Content-Type" to "application/x-www-form-urlencoded",
                        ),
                )

            val getResult = getCommand.execute(getRequest)
            val postResult = postCommand.execute(postRequest)

            assertTrue(getResult.isOk)
            assertTrue(postResult.isOk)
            assertEquals(getResult.value.statusCode, postResult.value.statusCode)
            assertEquals(getResult.value.headers["Location"], postResult.value.headers["Location"])
            assertEquals(1, getCaptured.size)
            assertEquals(1, postCaptured.size)
            assertEquals(getCaptured.single().queryParameters, postCaptured.single().queryParameters)
            assertEquals(getCaptured.single().returnUrl, postCaptured.single().returnUrl)
        }

    @Test
    fun postWithoutFormUrlEncodedContentTypeReturns400() =
        runTest {
            val command =
                AuthorizeHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleAuthorizeRequestCommands =
                        setOf(
                            FakeAuthorizeRequestCommand { error("ServiceCommand must not be invoked when Content-Type is wrong") },
                        ),
                    createAuthorizationErrorResponseCommand = FakeCreateErrorResponseCommand(),
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    loginSessionIdProvider = TestMutableOidcLoginSessionIdProvider(),
                )

            val request =
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path = "/authorize",
                    body = "{\"client_id\":\"client-1\"}",
                    headers = mapOf("Content-Type" to "application/json"),
                )

            val result = command.execute(request)

            assertTrue(result.isOk)
            assertEquals(400, result.value.statusCode)
            assertTrue(result.value.body!!.contains("invalid_request"))
        }

    @Test
    fun getConflictingRequestWrappersRejectBeforeHandlerSelection() = runTest {
        assertHttpWrapperConflict("GET")
    }

    @Test
    fun formPostConflictingRequestWrappersRejectBeforeHandlerSelection() = runTest {
        assertHttpWrapperConflict("POST")
    }

    private suspend fun assertHttpWrapperConflict(method: String) {
        var calls = 0
        val endpoint = AuthorizeHttpEndpointCommandImpl(
            execution = TestSessionExecution(),
            handleAuthorizeRequestCommands = setOf(FakeAuthorizeRequestCommand {
                calls++
                Ok(AuthorizationRequestOutcome.AuthInitiated(authProviderRedirectUrl = "https://idp.example/login"))
            }),
            createAuthorizationErrorResponseCommand = FakeCreateErrorResponseCommand(),
            configProvider = TestOAuth2ServersConfigProvider(),
            baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
            loginSessionIdProvider = TestMutableOidcLoginSessionIdProvider(),
        )
        val cases = listOf(
            "request=a.b.c&request_uri=https%3A%2F%2Frp.example%2Frequest.jwt" to mapOf("request" to "a.b.c", "request_uri" to "https://rp.example/request.jwt"),
            "request=a.b.c&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aone-use" to mapOf("request" to "a.b.c", "request_uri" to "urn:ietf:params:oauth:request_uri:one-use"),
            "request=&request_uri=https%3A%2F%2Frp.example%2Frequest.jwt" to mapOf("request" to "", "request_uri" to "https://rp.example/request.jwt"),
            "request=a.b.c&request_uri=" to mapOf("request" to "a.b.c", "request_uri" to ""),
            "request=&request_uri=" to mapOf("request" to "", "request_uri" to ""),
        )
        for ((body, parameters) in cases) {
            val result = endpoint.execute(GenericHttpRequest(
                method = method,
                path = "/authorize",
                queryParameters = if (method == "GET") parameters else emptyMap(),
                headers = if (method == "POST") mapOf("Content-Type" to "application/x-www-form-urlencoded") else emptyMap(),
                bodySupplier = { if (method == "POST") body else null },
            ))
            assertTrue(result.isOk)
            assertEquals(400, result.value.statusCode)
            assertTrue(result.value.body!!.contains("invalid_request"))
            assertEquals(0, calls, "Conflicting wrappers must not reach a handler or stored PAR retrieval")
        }
        // Single-wrapper controls must still be dispatched, including a stored-PAR URI wrapper.
        for (parameters in listOf(mapOf("request" to "a.b.c"), mapOf("request_uri" to "urn:ietf:params:oauth:request_uri:one-use"))) {
            val body = if (parameters.containsKey("request")) "request=a.b.c" else "request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aone-use"
            val result = endpoint.execute(GenericHttpRequest(
                method = method,
                path = "/authorize",
                queryParameters = if (method == "GET") parameters else emptyMap(),
                headers = if (method == "POST") mapOf("Content-Type" to "application/x-www-form-urlencoded") else emptyMap(),
                bodySupplier = { if (method == "POST") body else null },
            ))
            assertTrue(result.isOk)
            assertEquals(302, result.value.statusCode)
        }
        assertEquals(2, calls)
    }
}
