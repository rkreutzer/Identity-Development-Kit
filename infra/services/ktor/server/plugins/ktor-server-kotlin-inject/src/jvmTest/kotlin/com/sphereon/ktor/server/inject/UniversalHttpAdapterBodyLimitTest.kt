package com.sphereon.ktor.server.inject

import com.sphereon.core.api.http.dispatch.HttpAdapterRouteMatch
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.server.application.ApplicationCallPipeline
import io.ktor.server.application.call
import io.ktor.server.request.path
import io.ktor.server.response.respondText
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import io.ktor.server.testing.testApplication
import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith

class UniversalHttpAdapterBodyLimitTest {
    @Test
    fun declaredOversizeReturns413BeforeDispatcherCreation() = testApplication {
        var reachedFallbackHandler = false
        application {
            intercept(ApplicationCallPipeline.Plugins) {
                call.attributes.put(SelectedHttpAdapterRouteAttribute, boundedRoute(call.request.path()))
            }
            installUniversalHttpAdapters {
                errorHandler = { call, _ ->
                    reachedFallbackHandler = true
                    call.respondText("unexpected dispatch", status = HttpStatusCode.InternalServerError)
                }
            }
        }
        val response = client.post("/api/custom/registration") {
            setBody(ByteArray(33))
        }
        assertEquals(HttpStatusCode.PayloadTooLarge, response.status)
        assertFalse(reachedFallbackHandler)
    }

    @Test
    fun unknownLengthOverflowReturns413BeforeDispatcherCreation() = testApplication {
        var reachedFallbackHandler = false
        application {
            intercept(ApplicationCallPipeline.Plugins) {
                assertEquals("chunked", call.request.headers[io.ktor.http.HttpHeaders.TransferEncoding])
                assertEquals(null, call.request.headers[io.ktor.http.HttpHeaders.ContentLength])
                call.attributes.put(SelectedHttpAdapterRouteAttribute, boundedRoute(call.request.path()))
            }
            installUniversalHttpAdapters {
                pathPrefix = "/api/custom"
                errorHandler = { call, _ ->
                    reachedFallbackHandler = true
                    call.respondText("unexpected dispatch", status = HttpStatusCode.InternalServerError)
                }
            }
        }
        val response = client.post("/api/custom/registration") {
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
        assertFalse(reachedFallbackHandler)
    }

    @Test
    fun exactBoundPreservesBinaryBytes() = testApplication {
        val bytes = byteArrayOf(0, -1, 42, -128)
        application {
            routing {
                post("/bounded") {
                    val request = call.toGenericHttpRequest(bytes.size)
                    assertContentEquals(bytes, request.bodyContent.asBytesOrNull())
                    call.respondText("accepted")
                }
            }
        }
        assertEquals(HttpStatusCode.OK, client.post("/bounded") { setBody(bytes) }.status)
    }

    @Test
    fun existingNoArgumentConverterRetainsUnboundedUploadBehavior() = testApplication {
        val bytes = ByteArray(4096) { 13 }
        application {
            routing {
                post("/upload") {
                    assertContentEquals(bytes, call.toGenericHttpRequest().bodyContent.asBytesOrNull())
                    call.respondText("accepted")
                }
            }
        }
        assertEquals(HttpStatusCode.OK, client.post("/upload") { setBody(bytes) }.status)
    }

    @Test
    fun cancelledBoundedReadPropagatesCancellation() = runTest {
        val channel = ByteChannel(autoFlush = true)
        channel.cancel(CancellationException("request cancelled"))
        assertFailsWith<CancellationException> { readUniversalBoundedRequestBytes(channel, 32) }
    }

    @Test
    fun failedStreamNeverDispatchesPartialBody() = runTest {
        val channel = ByteChannel(autoFlush = true)
        channel.writeFully(byteArrayOf(1, 2, 3))
        channel.cancel(java.io.IOException("truncated upload"))
        assertFailsWith<java.io.IOException> { readUniversalBoundedRequestBytes(channel, 32) }
    }

    private fun boundedRoute(path: String) = HttpAdapterRouteMatch(
        adapterId = "test.registration",
        method = "POST",
        originalPath = path,
        normalizedPath = "/registration",
        matchedPathPattern = "/registration",
        handlerCommandId = "test.registration.handler",
        tenantIdFromPath = null,
        maxRequestBodyBytes = 32,
    )
}
