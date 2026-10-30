package com.sphereon.ktor.server.inject

import com.sphereon.core.api.http.GenericHttpBody
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.cio.CIO
import io.ktor.server.engine.embeddedServer
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.routing.delete
import io.ktor.server.routing.get
import io.ktor.server.routing.routing
import java.io.BufferedReader
import java.net.Socket
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class UniversalHttpAdapterRequestFramingTest {
    @Test
    fun http10AndHttp11UnframedDeleteRespondBeforeClientEofAndPreserveFramedBodies() = runBlocking {
        val bodies = ConcurrentHashMap<String, GenericHttpBody>()
        val server = embeddedServer(CIO, host = "127.0.0.1", port = 0) {
            routing {
                delete("/resource/{id}") {
                    val request = call.toGenericHttpRequest()
                    bodies[call.parameters["id"]!!] = request.bodyContent
                    call.respond(HttpStatusCode.NoContent)
                }
            }
        }.start(wait = false)
        try {
            val port = server.engine.resolvedConnectors().first().port
            val h10 = rawResponse(port, "DELETE /resource/h10 HTTP/1.0\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n")
            assertTrue(isStatus(h10, 204), "HTTP/1.0 unframed request should complete while client socket remains open")

            val h11Pair = rawKeepAlivePair(
                port,
                "DELETE /resource/h11 HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nConnection: keep-alive\r\n\r\n",
                "DELETE /resource/zero HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
            assertTrue(isStatus(h11Pair.first, 204), "HTTP/1.1 unframed keep-alive request should complete before EOF")
            assertTrue(isStatus(h11Pair.second, 204), "same-connection Content-Length: 0 control should complete")

            val json = "{\"ok\":true}"
            val chunkSize = json.encodeToByteArray().size.toString(16)
            val chunked = rawResponse(
                port,
                "DELETE /resource/chunked HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n$chunkSize\r\n$json\r\n0\r\n\r\n",
            )
            val fixed = rawResponse(
                port,
                "DELETE /resource/fixed HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: ${json.encodeToByteArray().size}\r\nConnection: close\r\n\r\n$json",
            )
            assertTrue(isStatus(chunked, 204))
            assertTrue(isStatus(fixed, 204))
            assertEquals(GenericHttpBody.Empty, bodies["h10"])
            assertEquals(GenericHttpBody.Empty, bodies["h11"])
            assertEquals(GenericHttpBody.Empty, bodies["zero"])
            assertEquals(GenericHttpBody.Text(json), bodies["chunked"])
            assertEquals(GenericHttpBody.Text(json), bodies["fixed"])
        } finally {
            server.stop(gracePeriodMillis = 100, timeoutMillis = 1_000)
        }
    }

    @Test
    fun malformedFramingRejectsAndClosesBeforePipelinedRequestDispatch() = runBlocking {
        val dispatched = AtomicInteger()
        val markerHits = AtomicInteger()
        val server = embeddedServer(CIO, host = "127.0.0.1", port = 0) {
            routing {
                delete("/resource/{id}") {
                    try {
                        call.toGenericHttpRequest()
                        dispatched.incrementAndGet()
                        call.respond(HttpStatusCode.NoContent)
                    } catch (_: IllegalArgumentException) {
                        call.response.header(HttpHeaders.Connection, "close")
                        call.respond(HttpStatusCode.BadRequest)
                    }
                }
                get("/marker") {
                    markerHits.incrementAndGet()
                    call.respond(HttpStatusCode.NoContent)
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
                val pipelined = request + "GET /marker HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
                val (status, eof) = rawResponseAndEof(port, pipelined)
                assertTrue(isStatus(status, 400), "malformed framing case $index should receive HTTP 400, got $status")
                assertTrue(!eof.contains(Regex("HTTP/1\\.[01] \\d{3}")), "malformed framing case $index must not process a queued request")
            }
            assertEquals(0, dispatched.get(), "rejected requests must not dispatch")
            assertEquals(0, markerHits.get(), "pipelined requests must not dispatch after framing rejection")
        } finally {
            server.stop(gracePeriodMillis = 100, timeoutMillis = 1_000)
        }
    }

    private fun rawResponse(port: Int, request: String): String = Socket("127.0.0.1", port).use { socket ->
        socket.soTimeout = 5_000
        val reader = socket.getInputStream().bufferedReader(StandardCharsets.ISO_8859_1)
        socket.getOutputStream().write(request.toByteArray(StandardCharsets.US_ASCII))
        socket.getOutputStream().flush()
        readStatusAndHeaders(reader)
    }

    private fun rawKeepAlivePair(port: Int, first: String, second: String): Pair<String, String> = Socket("127.0.0.1", port).use { socket ->
        socket.soTimeout = 5_000
        val reader = socket.getInputStream().bufferedReader(StandardCharsets.ISO_8859_1)
        val output = socket.getOutputStream()
        output.write(first.toByteArray(StandardCharsets.US_ASCII))
        output.flush()
        val firstStatus = readStatusAndHeaders(reader)
        output.write(second.toByteArray(StandardCharsets.US_ASCII))
        output.flush()
        firstStatus to readStatusAndHeaders(reader)
    }

    private fun rawResponseAndEof(port: Int, request: String): Pair<String, String> = Socket("127.0.0.1", port).use { socket ->
        socket.soTimeout = 5_000
        val reader = socket.getInputStream().bufferedReader(StandardCharsets.ISO_8859_1)
        socket.getOutputStream().write(request.toByteArray(StandardCharsets.US_ASCII))
        socket.getOutputStream().flush()
        val status = readStatusAndHeaders(reader)
        status to reader.readText()
    }

    private fun readStatusAndHeaders(reader: BufferedReader): String {
        val status = reader.readLine() ?: error("server closed before returning an HTTP status line")
        while (reader.readLine()?.isNotEmpty() == true) Unit
        return status
    }

    private fun isStatus(line: String, code: Int): Boolean =
        line.startsWith("HTTP/1.") && line.contains(" $code ")
}
