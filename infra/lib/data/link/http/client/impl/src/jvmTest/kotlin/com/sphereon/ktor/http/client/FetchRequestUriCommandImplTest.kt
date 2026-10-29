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

package com.sphereon.ktor.http.client

import com.sphereon.core.api.Err
import com.sphereon.core.api.Ok
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.core.defaults.app.staticMinimalTestAppGraph
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import io.ktor.client.HttpClient
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.cio.CIO
import io.ktor.server.engine.EmbeddedServer
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.contentType
import io.ktor.server.request.receiveParameters
import io.ktor.server.response.respond
import io.ktor.server.response.respondText
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Comprehensive tests for FetchRequestUriCommandImpl.
 *
 * Uses embedded CIO server for HTTP testing.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FetchRequestUriCommandImplTest {
    // 3-level DI hierarchy: App → User → Session
    private val app = staticMinimalTestAppGraph(this, "test-app", "test", "1.0.0")
    private val user = app.userContextManager.getAnonymous()
    private val session = user.sessionContextManager.getAnonymous()
    private val execution = session.asCoreApiServiceGraph().serviceExecution

    private var server: EmbeddedServer<*, *>? = null

    @AfterEach
    fun cleanup() {
        server?.stop(0, 0)
        server = null
    }

    private suspend fun startTestServer(module: Application.() -> Unit): Int {
        val running =
            embeddedServer(CIO, host = "127.0.0.1", port = 0) {
                module()
            }.start(wait = false)
        server = running
        return running.engine.resolvedConnectors().single().port
    }

    private fun getCommand(clientFactory: () -> HttpClient = { HttpClient() }): FetchRequestUriCommand {
        val httpClientFactory =
            com.sphereon.ktor.http.client.provider.HttpClientOptions.createDefault().let {
                object : com.sphereon.ktor.http.client.provider.HttpClientFactory {
                    override fun createClient(options: com.sphereon.ktor.http.client.provider.HttpClientOptions) = clientFactory()

                    override fun isSupportedOptions(options: com.sphereon.ktor.http.client.provider.HttpClientOptions) = true

                    override fun getEngineTypesSupported() = listOf(com.sphereon.ktor.http.client.provider.HttpClientEngineType.CIO)

                    override fun getEngineTypeDefault() = com.sphereon.ktor.http.client.provider.HttpClientEngineType.CIO
                }
            }
        return FetchRequestUriCommandImpl(execution, httpClientFactory)
    }

    @Test
    fun postRequestUriUsesJwtAcceptAndUtf8FormEncodingWithOrWithoutOptionalFields() =
        testApplication {
            val inputs =
                mapOf(
                    "empty" to (null to null),
                    "metadata" to ("""{"client_name":"Wallet & café = +","vp_formats_supported":{}}""" to null),
                    "nonce" to (null to "nonce + & = é"),
                    "both" to ("""{"client_name":"Wallet & café = +"}""" to "nonce + & = é"),
                )
            application {
                routing {
                    post("/request/{scenario}") {
                        val (metadata, nonce) = inputs.getValue(requireNotNull(call.parameters["scenario"]))
                        assertEquals("application/oauth-authz-req+jwt", call.request.headers[HttpHeaders.Accept])
                        assertEquals(ContentType.Application.FormUrlEncoded, call.request.contentType().withoutParameters())
                        val form = call.receiveParameters()
                        assertEquals(metadata, form["wallet_metadata"])
                        assertEquals(nonce, form["wallet_nonce"])
                        assertEquals(listOfNotNull(metadata?.let { "wallet_metadata" }, nonce?.let { "wallet_nonce" }).toSet(), form.names())
                        call.respondText("signed.request.jwt", ContentType.parse("application/oauth-authz-req+jwt"))
                    }
                }
            }
            for ((scenario, input) in inputs) {
                val result =
                    getCommand { createClient {} }.execute(
                        FetchRequestUriArgs(
                            requestUri = "http://localhost/request/$scenario",
                            httpMethod = RequestUriMethod.POST,
                            walletMetadataJson = input.first,
                            walletNonce = input.second,
                        ),
                    )
                assertTrue(result is Ok, "POST request_uri failed for $scenario: $result")
                assertEquals("signed.request.jwt", result.value.content)
            }
        }

    @Test
    fun testFetchJwtRequestObject() =
        runTest {
            // Mock JWT request object (from RFC 9101 example)
            val mockJwt =
                "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsyYmRjIn0." +
                    "eyJpc3MiOiJodHRwczovL2NsaWVudC5leGFtcGxlLm9yZy9jYiIsImF1ZCI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tIiwi" +
                    "cmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIiwiY2xpZW50X2lkIjoiaHR0cHM6Ly9jbGllbnQuZXhhbXBsZS5vcmcvY2IiLCJyZWRp" +
                    "cmVjdF91cmkiOiJodHRwczovL2NsaWVudC5leGFtcGxlLm9yZy9jYiJ9.signature"

            val port =
                startTestServer {
                    routing {
                        get("/request/abc123") {
                            call.respondText(mockJwt, ContentType.parse("application/jwt"))
                        }
                    }
                }

            val sessionContext = session.sessionContext
            val command = getCommand()

            val args =
                FetchRequestUriArgs(
                    requestUri = "http://localhost:$port/request/abc123",
                    expectedContentType = "application/jwt",
                )

            val result = command.execute(args)

            assertTrue(result is Ok)
            val fetched = (result as Ok).value
            assertEquals(mockJwt, fetched.content)
            assertEquals("application/jwt", fetched.contentType)
            assertEquals("http://localhost:$port/request/abc123", fetched.requestUri)
        }

    @Test
    fun testFetchJsonRequestObject() =
        runTest {
            val jsonContent = """{"response_type":"vp_token","client_id":"https://client.example.org/cb"}"""

            val port =
                startTestServer {
                    routing {
                        get("/request/def456") {
                            call.respondText(jsonContent, ContentType.Application.Json)
                        }
                    }
                }

            val sessionContext = session.sessionContext
            val command = getCommand()

            val args =
                FetchRequestUriArgs(
                    requestUri = "http://localhost:$port/request/def456",
                    httpClientOptions = HttpClientOptions.createDefault(),
                    expectedContentType = "application/json",
                )

            val result = command.execute(args)

            assertTrue(result is Ok)
            val fetched = (result as Ok).value
            assertEquals(jsonContent, fetched.content)
            assertTrue(fetched.contentType!!.contains("application/json"))
        }

    @Test
    fun testHttpsValidation() =
        runTest {
            val sessionContext = session.sessionContext
            val command = getCommand()

            // HTTP should fail (not localhost)
            val args =
                FetchRequestUriArgs(
                    requestUri = "http://verifier.example.com/request/abc123",
                )

            val result = command.execute(args)

            assertTrue(result is Err)
            val error = (result as Err).error
            assertTrue(error.message.defaultMessage.contains("HTTPS", ignoreCase = true))
        }

    @Test
    fun testLocalhostHttpAllowed() =
        runTest {
            val port =
                startTestServer {
                    routing {
                        get("/request/test123") {
                            call.respondText("test content")
                        }
                    }
                }

            val sessionContext = session.sessionContext
            val command = getCommand()

            // HTTP localhost should be allowed (for testing)
            val args =
                FetchRequestUriArgs(
                    requestUri = "http://localhost:$port/request/test123",
                )

            val result = command.execute(args)

            // Should succeed
            assertTrue(result is Ok)
            val fetched = (result as Ok).value
            assertEquals("test content", fetched.content)
        }

    @Test
    fun testBlankUriValidation() =
        runTest {
            val sessionContext = session.sessionContext
            val command = getCommand()

            val args = FetchRequestUriArgs(requestUri = "")

            val result = command.execute(args)

            assertTrue(result is Err)
            val error = (result as Err).error
            assertTrue(error.message.defaultMessage.contains("blank", ignoreCase = true))
        }

    @Test
    fun testInvalidUriValidation() =
        runTest {
            val sessionContext = session.sessionContext
            val command = getCommand()

            val args = FetchRequestUriArgs(requestUri = "not-a-valid-url")

            val result = command.execute(args)

            assertTrue(result is Err)
            val error = (result as Err).error
            // "not-a-valid-url" is parsed as a relative URI, so HTTP client tries to fetch and fails
            assertTrue(error.message.defaultMessage.contains("Failed to fetch request URI", ignoreCase = true))
        }

    @Test
    fun test404NotFound() =
        runTest {
            val port =
                startTestServer {
                    routing {
                        get("/request/notfound") {
                            call.respond(HttpStatusCode.NotFound, "Not found")
                        }
                    }
                }

            val sessionContext = session.sessionContext
            val command = getCommand()

            val args =
                FetchRequestUriArgs(
                    requestUri = "http://localhost:$port/request/notfound",
                )

            val result = command.execute(args)

            assertTrue(result is Err)
            val error = (result as Err).error
            assertTrue(error.message.defaultMessage.contains("404", ignoreCase = true))
        }

    @Test
    fun testContentTypeValidationFailure() =
        runTest {
            val port =
                startTestServer {
                    routing {
                        get("/request/wrong-type") {
                            call.respondText("some content", ContentType.Text.Plain)
                        }
                    }
                }

            val sessionContext = session.sessionContext
            val command = getCommand()

            val args =
                FetchRequestUriArgs(
                    requestUri = "http://localhost:$port/request/wrong-type",
                    expectedContentType = "application/jwt",
                )

            val result = command.execute(args)

            assertTrue(result is Err)
            val error = (result as Err).error
            assertTrue(error.message.defaultMessage.contains("content type", ignoreCase = true))
        }

    @Test
    fun testEmptyResponseBody() =
        runTest {
            val port =
                startTestServer {
                    routing {
                        get("/request/empty") {
                            call.respondText("")
                        }
                    }
                }

            val sessionContext = session.sessionContext
            val command = getCommand()

            val args =
                FetchRequestUriArgs(
                    requestUri = "http://localhost:$port/request/empty",
                )

            val result = command.execute(args)

            assertTrue(result is Err)
            val error = (result as Err).error
            assertTrue(error.message.defaultMessage.contains("empty", ignoreCase = true))
        }

    @Test
    fun testOid4vpRequestUriFormat() =
        runTest {
            // Typical OID4VP request_uri JWT content
            val jwtContent = "eyJhbGciOiJFUzI1NiIsInR5cCI6Im9hdXRoLWF1dGh6LXJlcStqd3QifQ.eyJjbGllbnRfaWQiOiJodHRwczovL3ZlcmlmaWVyLmV4YW1wbGUuY29tIiwicmVzcG9uc2VfdHlwZSI6InZwX3Rva2VuIn0.signature"

            val port =
                startTestServer {
                    routing {
                        get("/request/12345-abcde-67890") {
                            call.respondText(jwtContent, ContentType.parse("application/oauth-authz-req+jwt"))
                        }
                    }
                }

            val sessionContext = session.sessionContext
            val command = getCommand()

            val args =
                FetchRequestUriArgs(
                    requestUri = "http://localhost:$port/request/12345-abcde-67890",
                    expectedContentType = "application/oauth-authz-req+jwt",
                )

            val result = command.execute(args)

            assertTrue(result is Ok)
            val fetched = (result as Ok).value
            assertEquals(jwtContent, fetched.content)
            assertNotNull(fetched.contentType)
            assertTrue(fetched.contentType!!.contains("oauth-authz-req+jwt"))
        }

    @Test
    fun testHttpClientOptionsPassedThrough() =
        runTest {
            val port =
                startTestServer {
                    routing {
                        get("/request/test") {
                            call.respondText("test content")
                        }
                    }
                }

            val sessionContext = session.sessionContext
            val command = getCommand()

            // Custom HTTP client options
            val customOptions =
                HttpClientOptions(
                    enableContentNegotiation = true,
                    enableHttpCache = false,
                    enableLogging = true,
                )

            val args =
                FetchRequestUriArgs(
                    requestUri = "http://localhost:$port/request/test",
                    httpClientOptions = customOptions,
                )

            val result = command.execute(args)

            // Should succeed with custom options
            assertTrue(result is Ok)
        }
}
