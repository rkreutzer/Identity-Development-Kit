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

package com.sphereon.oauth2.server.authorization.impl.http.command.token

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.oauth2.common.model.TokenResponse
import com.sphereon.oauth2.server.authorization.audit.NoOpOAuth2AuditEmitter
import com.sphereon.oauth2.server.authorization.command.token.HandleTokenRequestArgs
import com.sphereon.oauth2.server.authorization.command.token.HandleTokenRequestCommand
import com.sphereon.oauth2.server.authorization.dpop.DpopNonceManager
import com.sphereon.oauth2.server.authorization.impl.http.DefaultOAuth2ServerBaseUrlResolver
import com.sphereon.oauth2.server.authorization.impl.http.command.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.impl.http.command.TestSessionExecution
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TokenHttpEndpointCommandImplTest {
    private class FakeHandleTokenRequestCommand(
        private val handler: suspend (HandleTokenRequestArgs) -> IdkResult<TokenResponse, IdkError>,
    ) : HandleTokenRequestCommand {
        override val commandId: String get() = HandleTokenRequestCommand.COMMAND_ID
        override val inputTypeToken get() = typeToken<HandleTokenRequestArgs>()
        override val outputTypeToken get() = typeToken<TokenResponse>()
        override val isEnabled: Boolean = true

        override suspend fun supports(args: Any): Boolean = args is HandleTokenRequestArgs

        override suspend fun execute(args: HandleTokenRequestArgs): IdkResult<TokenResponse, IdkError> = handler(args)
    }

    @Test
    fun success_renders200WithJsonBodyAndCacheControl() =
        runTest {
            var captured: HandleTokenRequestArgs? = null
            val command =
                TokenHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleTokenRequestCommand =
                        FakeHandleTokenRequestCommand { args ->
                            captured = args
                            Ok(TokenResponse(accessToken = "at", tokenType = "Bearer", expiresIn = 3600))
                        },
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    dpopNonceManager = lazyOf(TokenTestNonceManager),
                    clientCertificateExtractor = NoOpClientCertificateExtractor,
                    auditEmitter = NoOpOAuth2AuditEmitter,
                )

            val request =
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path = "/token",
                    body = "grant_type=client_credentials",
                    headers = mapOf("Host" to "as.example", "Content-Type" to "application/x-www-form-urlencoded"),
                )

            val result = command.execute(request)

            assertTrue(result.isOk)
            val response = result.value
            assertEquals(200, response.statusCode)
            assertEquals("application/json", response.headers["Content-Type"])
            assertEquals("no-store", response.headers["Cache-Control"])
            assertEquals("no-cache", response.headers["Pragma"])
            assertTrue(response.body!!.contains("access_token"))
            assertEquals(
                "grant_type" to listOf("client_credentials"),
                captured
                    ?.requestBody
                    ?.entries
                    ?.first()
                    ?.toPair(),
            )
            assertEquals("http://as.example/token", captured?.httpUrl)
        }

    @Test
    fun nonceManagerIsOnlyResolvedForADpopRequest() =
        runTest {
            var nonceManagerResolutions = 0
            val command =
                TokenHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleTokenRequestCommand =
                        FakeHandleTokenRequestCommand {
                            Ok(TokenResponse(accessToken = "at", tokenType = "Bearer", expiresIn = 3600))
                        },
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    dpopNonceManager =
                        lazy {
                            nonceManagerResolutions++
                            TokenTestNonceManager
                        },
                    clientCertificateExtractor = NoOpClientCertificateExtractor,
                    auditEmitter = NoOpOAuth2AuditEmitter,
                )
            val headers = mapOf("Host" to "as.example", "Content-Type" to "application/x-www-form-urlencoded")

            val bearer =
                command.execute(
                    GenericHttpRequest.withTextBody(method = "POST", path = "/token", body = "grant_type=client_credentials", headers = headers),
                )

            assertTrue(bearer.isOk)
            assertFalse(bearer.value.headers.containsKey("DPoP-Nonce"))
            assertEquals(0, nonceManagerResolutions, "A request without a DPoP proof must not construct the nonce manager")

            val dpop =
                command.execute(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = "/token",
                        body = "grant_type=client_credentials",
                        headers = headers + ("DPoP" to "proof"),
                    ),
                )

            assertEquals("test-nonce-current", dpop.value.headers["DPoP-Nonce"])
            assertEquals(1, nonceManagerResolutions)
        }

    @Test
    fun missingBody_rendersInvalidRequest() =
        runTest {
            val command =
                TokenHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleTokenRequestCommand =
                        FakeHandleTokenRequestCommand {
                            error("Should not be called when body is missing")
                        },
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    dpopNonceManager = lazyOf(TokenTestNonceManager),
                    clientCertificateExtractor = NoOpClientCertificateExtractor,
                    auditEmitter = NoOpOAuth2AuditEmitter,
                )

            val request = GenericHttpRequest(method = "POST", path = "/token")
            val result = command.execute(request)

            assertTrue(result.isOk)
            assertEquals(400, result.value.statusCode)
            assertTrue(result.value.body!!.contains("invalid_request"))
        }

    @Test
    fun serviceCommandError_rendersErrorWithBasicChallenge() =
        runTest {
            val command =
                TokenHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleTokenRequestCommand =
                        FakeHandleTokenRequestCommand {
                            Err(IdkError.fromString(code = "invalid_client", message = "bad creds"))
                        },
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    dpopNonceManager = lazyOf(TokenTestNonceManager),
                    clientCertificateExtractor = NoOpClientCertificateExtractor,
                    auditEmitter = NoOpOAuth2AuditEmitter,
                )

            val request =
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path = "/token",
                    body = "grant_type=client_credentials",
                    headers = mapOf("Authorization" to "Basic dXNlcjpwYXNz"),
                )

            val result = command.execute(request)

            assertTrue(result.isOk)
            assertEquals(401, result.value.statusCode)
            assertEquals("Basic realm=\"oauth2\"", result.value.headers["WWW-Authenticate"])
            assertTrue(result.value.body!!.contains("invalid_client"))
            assertFalse(result.value.body!!.contains("bad creds"))
        }

    @Test
    fun invalidClientWithoutHttpAuthentication_returns400WithoutChallenge() =
        runTest {
            val command =
                TokenHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleTokenRequestCommand =
                        FakeHandleTokenRequestCommand {
                            Err(IdkError.fromString(code = "invalid_client", message = "secret detail"))
                        },
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    dpopNonceManager = lazyOf(TokenTestNonceManager),
                    clientCertificateExtractor = NoOpClientCertificateExtractor,
                    auditEmitter = NoOpOAuth2AuditEmitter,
                )

            val result =
                command.execute(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = "/token",
                        body = "grant_type=client_credentials",
                    ),
                )

            assertTrue(result.isOk)
            assertEquals(400, result.value.statusCode)
            assertTrue(result.value.body!!.contains("\"error\":\"invalid_client\""))
            assertFalse(result.value.body!!.contains("secret detail"))
            assertEquals(null, result.value.headers["WWW-Authenticate"])
        }

    @Test
    fun unauthorizedClient_is400WithStandardWireCode() =
        runTest {
            val command =
                TokenHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    handleTokenRequestCommand =
                        FakeHandleTokenRequestCommand {
                            Err(IdkError.fromString(code = "unauthorized_client", message = "policy detail"))
                        },
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    dpopNonceManager = lazyOf(TokenTestNonceManager),
                    clientCertificateExtractor = NoOpClientCertificateExtractor,
                    auditEmitter = NoOpOAuth2AuditEmitter,
                )

            val result =
                command.execute(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = "/token",
                        body = "grant_type=client_credentials",
                    ),
                )

            assertTrue(result.isOk)
            assertEquals(400, result.value.statusCode)
            assertTrue(result.value.body!!.contains("\"error\":\"unauthorized_client\""))
            assertFalse(result.value.body!!.contains("policy detail"))
        }

    @Test
    fun dpopNonceAndAttestationChallengeHeadersSurviveTokenEndpointMapping() =
        runTest {
            suspend fun responseFor(error: IdkError): com.sphereon.core.api.http.GenericHttpResponse {
                val command =
                    TokenHttpEndpointCommandImpl(
                        execution = TestSessionExecution(),
                        handleTokenRequestCommand = FakeHandleTokenRequestCommand { Err(error) },
                        configProvider = TestOAuth2ServersConfigProvider(),
                        baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                        dpopNonceManager = lazyOf(TokenTestNonceManager),
                        clientCertificateExtractor = NoOpClientCertificateExtractor,
                        auditEmitter = NoOpOAuth2AuditEmitter,
                    )
                val result =
                    command.execute(
                        GenericHttpRequest.withTextBody(
                            method = "POST",
                            path = "/token",
                            body = "grant_type=client_credentials",
                            headers = mapOf("DPoP" to "proof"),
                        ),
                    )
                assertTrue(result.isOk)
                return result.value
            }

            val dpopResponse =
                responseFor(
                    IdkError(
                        code = "use_dpop_nonce",
                        message = IdkError.Message(i18nKey = "test.nonce", defaultMessage = "private nonce error"),
                        meta = mapOf("dpop_nonce" to "fresh-dpop-nonce"),
                    ),
                )
            val attestationResponse =
                responseFor(
                    IdkError(
                        code = "use_attestation_challenge",
                        message = IdkError.Message(i18nKey = "test.challenge", defaultMessage = "private challenge error"),
                        meta = mapOf("attestation_challenge" to "fresh-attestation-challenge"),
                    ),
                )

            assertEquals("fresh-dpop-nonce", dpopResponse.headers["DPoP-Nonce"])
            assertEquals("fresh-attestation-challenge", attestationResponse.headers["OAuth-Client-Attestation-Challenge"])
            assertFalse(dpopResponse.body!!.contains("private nonce error"))
            assertFalse(attestationResponse.body!!.contains("private challenge error"))
        }
}

/** Test stub: no-op nonce manager that returns fixed values; used by tests not exercising nonces. */
private object TokenTestNonceManager : DpopNonceManager {
    override suspend fun currentNonce(): String = "test-nonce-current"

    override suspend fun rotate(): String = "test-nonce-rotated"

    override suspend fun isValid(nonce: String): Boolean = true
}

/** Test stub: no-cert extractor used by tests that don't exercise mTLS client auth. */
private object NoOpClientCertificateExtractor :
    com.sphereon.oauth2.server.authorization.command.clientauth.ClientCertificateExtractor {
    override suspend fun extractCertificate(
        request: com.sphereon.core.api.http.GenericHttpRequest,
    ): com.sphereon.core.api.IdkResult<ByteArray?, com.sphereon.oauth2.server.authorization.error.AuthorizationServerError> =
        com.sphereon.core.api
            .Ok(null)
}
