package com.sphereon.ktor.server.inject.http

import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.http.content.OutgoingContent
import io.ktor.server.request.*
import io.ktor.server.response.respondText
import io.ktor.server.routing.*
import io.ktor.server.testing.testApplication
import io.ktor.utils.io.*
import kotlin.test.*

class BoundedRequestBodyTest {
    @Test fun unknownLengthOverflowIsRejectedDuringRead() = testApplication {
        var dispatched = false
        application {
            routing {
                put("/bounded") {
                    assertEquals("chunked", call.request.headers[HttpHeaders.TransferEncoding])
                    assertEquals(null, call.request.headers[HttpHeaders.ContentLength])
                    try {
                        call.request.toGenericHttpRequest(call, 32)
                        dispatched = true
                        call.respondText("accepted")
                    } catch (_: RequestBodyTooLargeException) {
                        call.respondText("too large", status = HttpStatusCode.PayloadTooLarge)
                    }
                }
            }
        }
        val response = client.put("/bounded") {
            setBody(object : OutgoingContent.WriteChannelContent() {
                override val contentType = ContentType.Application.OctetStream
                override val contentLength: Long? = null
                // TestHost supplies a decoded stream; retain its real HTTP/1 chunked framing.
                override val headers = io.ktor.http.headersOf(io.ktor.http.HttpHeaders.TransferEncoding, "chunked")
                override suspend fun writeTo(channel: ByteWriteChannel) {
                    channel.writeFully(ByteArray(33) { 42 })
                }
            })
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, response.status)
        assertFalse(dispatched)
    }

    @Test fun failedChannelNeverBecomesSuccessfulPartialBody() = kotlinx.coroutines.test.runTest {
        val channel = ByteChannel(autoFlush = true)
        channel.writeFully(byteArrayOf(1, 2, 3))
        channel.close(java.io.IOException("Truncated upload"))
        val failure = runCatching { readBoundedRequestBytes(channel, 32) }.exceptionOrNull()
        assertNotNull(failure)
    }

    @Test fun exactBoundPreservesBinaryBytes() = testApplication {
        val bytes = byteArrayOf(0, -1, 42, -128)
        application {
            routing { put("/bounded") {
                val request = call.request.toGenericHttpRequest(call, bytes.size)
                assertContentEquals(bytes, request.bodyContent.asBytesOrNull())
                call.respondText("accepted")
            } }
        }
        assertEquals(HttpStatusCode.OK, client.put("/bounded") {
            contentType(ContentType.Application.OctetStream); setBody(bytes)
        }.status)
    }
}
