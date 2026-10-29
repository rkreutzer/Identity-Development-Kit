package com.sphereon.ktor.server.inject

import com.sphereon.core.api.http.dispatch.HttpAdapterRouteMatch
import io.ktor.http.HttpStatusCode
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.request.path
import io.ktor.server.response.respond
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import java.io.BufferedReader
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Exercises dispatchUniversal's framing-error mapping and connection close on a real CIO socket. */
class UniversalHttpAdapterFramingDispatchTest {
    @Test
    fun malformedFramingUsesUniversal400CloseAndNeverDispatchesPipelinedRequest() = runBlocking {
        val markerHits = AtomicInteger()
        val genericErrorHandlerHits = AtomicInteger()
        val universalPipelineHits = AtomicInteger()
        val server = embeddedServer(CIO, host = "127.0.0.1", port = 0) {
            intercept(ApplicationCallPipeline.Plugins) {
                universalPipelineHits.incrementAndGet()
                call.attributes.put(SelectedHttpAdapterRouteAttribute, selectedRoute(call.request.path()))
            }
            routing {
                get("/marker") {
                    markerHits.incrementAndGet()
                    call.respond(HttpStatusCode.NoContent)
                }
            }
            installUniversalHttpAdapters {
                errorHandler = { call, _ ->
                    genericErrorHandlerHits.incrementAndGet()
                    call.respond(HttpStatusCode.InternalServerError)
                }
            }
        }.start(wait = false)
        try {
            val port = server.engine.resolvedConnectors().first().port
            val malformedRequests = listOf(
                "DELETE /resource/bad-cl HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 2x\r\nConnection: keep-alive\r\n\r\n",
                "DELETE /resource/cl-te HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n",
                "DELETE /resource/te HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: gzip\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n",
                "DELETE /resource/te-identity HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: identity\r\nConnection: keep-alive\r\n\r\n",
                "DELETE /resource/te-list HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: identity, chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n",
                "DELETE /resource/te-order HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked, identity\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n",
                "DELETE /resource/duplicate-te HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: identity\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n",
                "DELETE /resource/multiple-cl HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
            )
            malformedRequests.forEachIndexed { index, request ->
                val queued = request + "GET /marker HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                val response = rawResponseAndEof(port, queued)
                assertTrue(response.status.startsWith("HTTP/1.") && response.status.contains(" 400 "),
                    "malformed framing case $index should receive the production HTTP 400, got ${response.status}")
                assertTrue(response.headers.any { it.equals("Connection: close", ignoreCase = true) },
                    "malformed framing case $index should request connection close")
                assertTrue(!response.trailingText.contains(Regex("HTTP/1\\.[01] \\d{3}")),
                    "malformed framing case $index must close before a pipelined response")
            }
            assertEquals(0, universalPipelineHits.get(), "the engine must reject malformed wire framing before any application handler")
            assertEquals(0, markerHits.get(), "pipelined requests must not dispatch after malformed framing")
            assertEquals(0, genericErrorHandlerHits.get(), "framing failures must use the dedicated production 400 branch")
        } finally {
            server.stop(gracePeriodMillis = 100, timeoutMillis = 1_000)
        }
    }

    private fun selectedRoute(path: String) = HttpAdapterRouteMatch(
        adapterId = "test.framing",
        method = "DELETE",
        originalPath = path,
        normalizedPath = "/resource",
        matchedPathPattern = "/resource/{id}",
        handlerCommandId = "test.framing.delete",
        tenantIdFromPath = null,
        maxRequestBodyBytes = null,
    )

    private fun rawResponseAndEof(port: Int, request: String): RawResponse = Socket("127.0.0.1", port).use { socket ->
        socket.soTimeout = 5_000
        val reader = socket.getInputStream().bufferedReader(StandardCharsets.ISO_8859_1)
        socket.getOutputStream().write(request.toByteArray(StandardCharsets.US_ASCII))
        socket.getOutputStream().flush()
        val status = reader.readLine() ?: error("server closed before returning an HTTP status line")
        val headers = mutableListOf<String>()
        while (true) {
            val line = reader.readLine() ?: error("server closed before completing response headers")
            if (line.isEmpty()) break
            headers += line
        }
        RawResponse(status, headers, reader.readText())
    }

    private data class RawResponse(val status: String, val headers: List<String>, val trailingText: String)
}
