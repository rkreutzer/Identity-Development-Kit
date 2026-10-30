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
 *
 */

@file:Suppress("TooGenericExceptionCaught") // HTTP adapter must handle any exception during request body reading

package com.sphereon.ktor.server.inject.http

import com.sphereon.core.api.http.GenericHttpBody
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.LazyMap
import com.sphereon.core.api.http.command.CommandBackedHttpAdapter
import com.sphereon.ktor.server.inject.resolveHttpRequestBodyFraming
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.ApplicationRequest
import io.ktor.server.request.contentType
import io.ktor.server.request.httpMethod
import io.ktor.server.request.httpVersion
import io.ktor.server.request.path
import io.ktor.server.request.receiveChannel
import io.ktor.server.request.receiveText
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.utils.io.writeFully
import io.ktor.utils.io.readAvailable
import java.io.ByteArrayOutputStream
import com.sphereon.ktor.server.inject.BaseTenantIdAttribute as SharedBaseTenantIdAttribute

/**
 * Per-call attribute holding the Layer 1 resolved base tenant id.
 *
 * Set by a tenant-resolution Ktor intercept (typically driven by the validated
 * JWT authority or a configured public-route mapping). Read by
 * [toGenericHttpRequest], which copies it into typed in-process request
 * metadata. It is never represented as an HTTP header.
 *
 * Defined here rather than under a specific plugin so VDX-transport-server-ktor
 * can stamp it from a lightweight intercept and the IDK request conversion
 * code can read it, without either module needing to depend on a particular
 * tenant-resolution plugin implementation.
 */
@Deprecated(
    message = "Use com.sphereon.ktor.server.inject.BaseTenantIdAttribute",
    replaceWith = ReplaceWith("BaseTenantIdAttribute", "com.sphereon.ktor.server.inject.BaseTenantIdAttribute"),
)
val BaseTenantIdAttribute get() = SharedBaseTenantIdAttribute

/**
 * Stamp the resolved base tenant id onto the call. Idempotent — calling it
 * multiple times with the same value is fine; a different value overwrites
 * the previous one.
 */
fun ApplicationCall.setBaseTenantId(tenantId: String) {
    attributes.put(BaseTenantIdAttribute, tenantId)
}

/**
 * Convert Ktor ApplicationRequest to framework-agnostic GenericHttpRequest.
 *
 * This is the standard implementation for converting Ktor requests to the
 * framework-agnostic GenericHttpRequest used by HttpAdapters and Commands.
 *
 * Performance optimizations:
 * - Lazy maps: headers/query params use lazy delegates (only allocated when accessed)
 * - Optimized header joining: only join multi-value headers when needed
 * - Smart body detection: only reads body when Content-Type is JSON or Content-Length > 0
 *
 * Note: Ktor's receiveText() is a suspend function that can only be called once,
 * so body must be read immediately (cannot be lazily loaded like in Spring).
 *
 * @param call The ApplicationCall containing request context
 * @return A GenericHttpRequest suitable for use with HttpAdapters
 */
suspend fun ApplicationRequest.toGenericHttpRequest(call: ApplicationCall, maxBodyBytes: Int? = null): GenericHttpRequest {
    require(maxBodyBytes == null || maxBodyBytes >= 0)
    val path = this.path()
    val method = this.httpMethod.value
    val request = this

    // Validate raw framing before the best-effort body-read catch below.
    val framing = resolveHttpRequestBodyFraming(
        request.httpVersion,
        request.headers.getAll(HttpHeaders.ContentLength).orEmpty(),
        request.headers.getAll(HttpHeaders.TransferEncoding).orEmpty(),
    )
    val contentLength = framing.contentLength

    // Read body immediately (Ktor's receiveText is suspend and can only be called once).
    // Chunked clients do not always send Content-Length, so body-capable methods must still
    // be read when the length is unknown.
    val bodyContent =
        try {
            val contentType = request.contentType()
            if (maxBodyBytes != null && contentLength != null && contentLength > maxBodyBytes) throw RequestBodyTooLargeException()
            if (framing.shouldReadBody) {
                if (maxBodyBytes != null) {
                    val bytes = readBoundedRequestBytes(call.receiveChannel(), maxBodyBytes)
                    if (contentType.isTextLikeRequestBody()) GenericHttpBody.Text(bytes.decodeToString()) else GenericHttpBody.Bytes(bytes)
                } else
                if (contentType.isTextLikeRequestBody()) {
                    GenericHttpBody.Text(call.receiveText())
                } else {
                    GenericHttpBody.Bytes(call.receiveBodyBytes())
                }
            } else {
                GenericHttpBody.Empty
            }
        } catch (receiveFailure: Exception) {
            if (maxBodyBytes != null || receiveFailure is kotlinx.coroutines.CancellationException) throw receiveFailure
            // A silently-empty body turned a valid revision-CAS DELETE into an undiagnosable
            // "EOF" decode error downstream; name the cause so the next one is one log line.
            io.ktor.util.logging.KtorSimpleLogger("KtorHttpExtensions")
                .warn("Request body read failed for $method $path: ${receiveFailure.message}")
            GenericHttpBody.Empty
        }

    // Layer 1 tenant id, resolved by validated JWT authority or an explicitly
    // configured public-route resolver and carried only as typed in-process state.
    val resolvedBaseTenantId: String? = call.attributes.getOrNull(BaseTenantIdAttribute)

    return GenericHttpRequest(
        method = method,
        path = path,
        // Lazy headers — avoid allocation and string joining if never accessed. Backed by a
        // case-insensitive TreeMap (RFC 9110 §5.1: header names are case-insensitive) so any
        // upstream case normalisation does not affect downstream lookups.
        headers =
            LazyMap {
                val headerMap: MutableMap<String, String> = java.util.TreeMap(String.CASE_INSENSITIVE_ORDER)
                request.headers.entries().forEach { (key, values) ->
                    headerMap[key] =
                        if (values.size == 1) {
                            values[0]
                        } else {
                            values.joinToString(",")
                        }
                }
                headerMap
            },
        resolvedTenantId = resolvedBaseTenantId,
        // Preserve multi-value occurrence (RFC 9110 §5.3 / RFC 9449 §4.1). Ktor's CIO engine
        // emits `entries()` as one entry per *occurrence*, so feeding that into a Map collapses
        // duplicates. `names()` + `getAll()` is the only way to get the full list per name.
        multiValueHeaders =
            request.headers
                .names()
                .associateWith { name -> request.headers.getAll(name) ?: emptyList() },
        // Lazy query parameters - avoid allocation if never accessed
        queryParameters =
            LazyMap {
                val queryMap = mutableMapOf<String, String?>()
                request.queryParameters.entries().forEach { (key, values) ->
                    queryMap[key] =
                        if (values.size == 1) {
                            values[0]
                        } else {
                            values.joinToString(",")
                        }
                }
                queryMap
            },
        bodyContent = bodyContent,
    )
}

private fun ContentType?.isTextLikeRequestBody(): Boolean {
    val value = this?.toString()?.lowercase().orEmpty()
    return value.startsWith("text/") ||
        value.contains("json") ||
        value.contains("xml") ||
        value.startsWith("application/x-www-form-urlencoded")
}

// DELETE carries a body on revision-CAS admin routes (the OpenAPI requires it); dropping it
// turned a valid delete into "Expected start of the object '{', but had 'EOF'".
/** Overflow is handled as 413 by the server, never converted to an empty body. */
class RequestBodyTooLargeException : IllegalArgumentException("Request body exceeds endpoint byte limit")

internal suspend fun readBoundedRequestBytes(channel: io.ktor.utils.io.ByteReadChannel, maxBytes: Int): ByteArray {
    require(maxBytes >= 0)
    val out = ByteArrayOutputStream(minOf(maxBytes, DEFAULT_BUFFER_SIZE))
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    while (!channel.isClosedForRead) {
        val count = channel.readAvailable(buffer, 0, minOf(buffer.size.toLong(), maxBytes.toLong() - out.size() + 1).toInt())
        if (count < 0) break
        if (count > maxBytes - out.size()) {
            channel.cancel(RequestBodyTooLargeException())
            throw RequestBodyTooLargeException()
        }
        if (count > 0) out.write(buffer, 0, count)
    }
    channel.closedCause?.let { throw it }
    return out.toByteArray()
}

private suspend fun ApplicationCall.receiveBodyBytes(): ByteArray {
    val channel = receiveChannel()
    val out = ByteArrayOutputStream()
    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
    while (!channel.isClosedForRead) {
        val read = channel.readAvailable(buffer, 0, buffer.size)
        if (read < 0) break
        if (read > 0) out.write(buffer, 0, read)
    }
    return out.toByteArray()
}

/**
 * Respond with a GenericHttpResponse.
 *
 * Converts a framework-agnostic GenericHttpResponse to a Ktor response.
 *
 * Performance optimization: Single header iteration (not duplicated for body != null case).
 *
 * @param response The GenericHttpResponse from an HttpAdapter
 */
suspend fun ApplicationCall.respondWithGeneric(response: GenericHttpResponse) {
    val status = HttpStatusCode.fromValue(response.statusCode)
    val contentType = ContentType.parse(response.contentType ?: "application/json")

    // Add headers once (not duplicated between if/else branches)
    this.response.headers.apply {
        val repeatedNames = response.multiValueHeaders.keys.map(String::lowercase).toSet()
        response.headers.forEach { (key, value) ->
            if (key.lowercase() !in repeatedNames) append(key, value)
        }
        response.multiValueHeaders.forEach { (key, values) ->
            values.forEach { value -> append(key, value) }
        }
    }

    // Respond based on body content type
    when (val bodyContent = response.bodyContent) {
        is GenericHttpBody.Bytes -> {
            this.respondBytes(
                bytes = bodyContent.value,
                contentType = contentType,
                status = status,
            )
        }

        is GenericHttpBody.LazyBytes -> {
            val bytes = bodyContent.value
            if (bytes != null) {
                this.respondBytes(bytes = bytes, contentType = contentType, status = status)
            } else {
                this.respond(status)
            }
        }

        is GenericHttpBody.Text -> {
            this.respondText(
                text = bodyContent.value,
                contentType = contentType,
                status = status,
            )
        }

        is GenericHttpBody.LazyText -> {
            val text = bodyContent.value
            if (text != null) {
                this.respondText(text = text, contentType = contentType, status = status)
            } else {
                this.respond(status)
            }
        }

        is GenericHttpBody.Empty -> {
            this.respond(status)
        }

        is GenericHttpBody.TextStream -> {
            this.respondBytesWriter(contentType = contentType, status = status) {
                bodyContent.flow.collect { chunk ->
                    writeFully(chunk.encodeToByteArray())
                    flush()
                }
            }
        }
    }
}
