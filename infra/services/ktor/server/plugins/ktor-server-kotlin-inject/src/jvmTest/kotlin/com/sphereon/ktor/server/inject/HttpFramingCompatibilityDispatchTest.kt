package com.sphereon.ktor.server.inject

import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.HttpAdapter
import com.sphereon.core.api.http.describe.*
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteMatch
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.server.inject.resolver.FixedTenantResolver
import dev.zacsweers.metro.*
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.*
import io.ktor.http.content.OutgoingContent
import io.ktor.server.application.*
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.request.path
import io.ktor.server.response.respond
import io.ktor.server.testing.testApplication
import io.ktor.utils.io.ByteWriteChannel
import kotlinx.coroutines.runBlocking
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

/**
 * Real CIO + normal application catalog/session dispatcher; this is an owning unit fixture, not live authentication evidence.
 * The engine supports a single chunked transfer coding; broader coding lists remain unsupported by this adapter.
 */
class HttpFramingCompatibilityDispatchTest {
    @Test
    fun supportedChunkedCodingAndFixedLengthReachTheNormalSelectedAdapterWithExactDecodedBody() = runBlocking {
        CompatibilityFramingAdapter.hits.set(0)
        val graph = createTestAppGraph(application = Unit, appId = "framing-compatibility")
        val server = embeddedServer(CIO, host = "127.0.0.1", port = 0) {
            install(KotlinInjectPlugin) {
                appGraph = graph
                tenantResolver = FixedTenantResolver("framing-unit-tenant")
            }
            installUniversalHttpAdapters()
        }.start(wait = false)
        try {
            val port = server.engine.resolvedConnectors().first().port
            val payload = "coding-body"
            val requests = listOf(
                "Transfer-Encoding: chunked\r\n" to "${payload.length.toString(16)}\r\n$payload\r\n0\r\n\r\n",
                "Transfer-Encoding: \tChUnKeD \t\r\n" to "${payload.length.toString(16)}\r\n$payload\r\n0\r\n\r\n",
                "Content-Length: ${payload.length}\r\n" to payload,
            )
            for ((framing, body) in requests) {
                Socket("127.0.0.1", port).use { socket ->
                    socket.soTimeout = 5_000
                    val request = "DELETE /framing-compatible HTTP/1.1\r\nHost: localhost\r\nContent-Type: text/plain\r\n" + framing +
                        "Connection: close\r\n\r\n" + body
                    socket.getOutputStream().write(request.toByteArray(StandardCharsets.US_ASCII))
                    socket.getOutputStream().flush()
                    val reader = socket.getInputStream().bufferedReader(StandardCharsets.ISO_8859_1)
                    val status = reader.readLine() ?: error("Closed before a response")
                    assertTrue(status.contains(" 204 "), "Supported coding must dispatch normally: $status")
                    while (true) { val line = reader.readLine() ?: error("Truncated response headers"); if (line.isEmpty()) break }
                    assertEquals("", reader.readText())
                }
            }
            assertEquals(3, CompatibilityFramingAdapter.hits.get())
        } finally {
            server.stop(gracePeriodMillis = 100, timeoutMillis = 1_000)
            graph.destroy()
        }
    }

    @Test
    fun testHostMalformedFramingUsesTyped400WithoutConstructingDispatcherOrGenericFallback() = testApplication {
        var pipelineHits = 0
        var fallbackHits = 0
        application {
            intercept(ApplicationCallPipeline.Plugins) {
                pipelineHits++
                call.attributes.put(SelectedHttpAdapterRouteAttribute, HttpAdapterRouteMatch(
                    adapterId = "test.framing", method = "POST", originalPath = call.request.path(),
                    normalizedPath = "/framing-testhost", matchedPathPattern = "/framing-testhost",
                    handlerCommandId = "test.framing.body", tenantIdFromPath = null,
                ))
            }
            // No session is installed: successful 400 must occur before dispatcher construction.
            installUniversalHttpAdapters {
                errorHandler = { call, _ -> fallbackHits++; call.respond(HttpStatusCode.InternalServerError) }
            }
        }
        val response = client.post("/framing-testhost") {
            setBody(object : OutgoingContent.WriteChannelContent() {
                override val contentLength: Long? = null
                override val headers = headersOf(HttpHeaders.TransferEncoding, "gzip")
                override suspend fun writeTo(channel: ByteWriteChannel) = Unit
            })
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
        assertEquals("close", response.headers[HttpHeaders.Connection])
        assertEquals(1, pipelineHits)
        assertEquals(0, fallbackHits)
    }
}

private fun compatibilityDescription() = HttpAdapterDescription(
    id = "test.framing-compatible", mount = HttpAdapterMount(serverPrefix = "", adapterBasePath = ""),
    endpoints = listOf(HttpEndpointDescriptor(
        method = com.sphereon.core.api.http.describe.HttpMethod.DELETE, pathPattern = "/framing-compatible", handlerCommandId = "test.framing.body",
        authPolicy = EndpointAuthPolicy.PUBLIC,
    )),
)

@Inject
@ContributesIntoSet(AppScope::class, binding = binding<HttpAdapterDescriptorProvider>())
class CompatibilityFramingDescriptor : HttpAdapterDescriptorProvider {
    override val id = "test.framing-compatible"
    override fun describe() = compatibilityDescription()
}

@Inject
@ContributesIntoMap(SessionScope::class, binding = binding<HttpAdapter>())
@StringKey("test.framing-compatible")
class CompatibilityFramingAdapter : HttpAdapter {
    companion object { val hits = AtomicInteger() }
    override val id = "test.framing-compatible"
    override fun describe() = compatibilityDescription()
    override suspend fun handleResolvedRequest(request: GenericHttpRequest, route: HttpAdapterRouteMatch): GenericHttpResponse {
        check(request.method == "DELETE" && request.path == "/framing-compatible")
        check(request.body == "coding-body") { "Chunked body was not preserved by normal conversion" }
        hits.incrementAndGet()
        return GenericHttpResponse(statusCode = 204)
    }
}
