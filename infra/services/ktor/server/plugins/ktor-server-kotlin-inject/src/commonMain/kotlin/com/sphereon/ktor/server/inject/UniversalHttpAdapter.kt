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

package com.sphereon.ktor.server.inject

import com.sphereon.core.api.http.GenericHttpBody
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.dispatch.HttpAdapterDispatcher
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteMatch
import com.sphereon.core.api.session.CommandInvocationContext
import dev.zacsweers.metro.createGraph
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.log
import io.ktor.server.request.contentType
import io.ktor.server.request.httpMethod
import io.ktor.server.request.httpVersion
import io.ktor.server.request.path
import io.ktor.server.request.receiveChannel
import io.ktor.server.request.receiveText
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondBytes
import io.ktor.server.response.respondBytesWriter
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import io.ktor.util.AttributeKey
import io.ktor.utils.io.core.readBytes
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readRemaining
import io.ktor.utils.io.writeFully
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.flowOn

/**
 * Per-call attribute holding the Layer 1 resolved base tenant id.
 *
 * Tenant-resolution plugins stamp this key after validating JWT authority or
 * resolving a public route. Ktor request converters copy it into typed
 * [GenericHttpRequest] metadata; it is never represented as an HTTP header.
 */
val BaseTenantIdAttribute: AttributeKey<String> = AttributeKey("sphereon.tenant.baseTenantId")

/**
 * Per-call attribute holding the VALIDATED bearer-token claims input.
 *
 * Auth/tenant-resolution plugins that validate an `Authorization: Bearer ...`
 * token (signature, `iss`, `exp`, ...) stamp the resulting
 * [com.sphereon.core.defaults.context.ValidatedJwtClaimsInput] here. The
 * [com.sphereon.ktor.server.inject.interceptor.UserContextInterceptor] consumes
 * it when creating the per-request session so the session context surfaces the
 * validated JWT via `sessionContext.context.secureDetails?.jwt` — the seam
 * commands use to read authorization claims (e.g. `roles`) off the request's
 * token. Absent for anonymous requests; downstream endpoints that require
 * token-borne claims reject on their own.
 */
val ValidatedJwtClaimsAttribute: AttributeKey<com.sphereon.core.defaults.context.ValidatedJwtClaimsInput> =
    AttributeKey("sphereon.auth.validatedJwtClaims")

/**
 * Per-call attribute holding the principal classification that the plugin which validated the
 * bearer token derived for it.
 *
 * The identity pipeline classifies a token from its claims alone. A host may apply its own
 * ingress policy on top of that (for example treating an external tenant service client as a
 * tenant principal rather than a workload). When the host's command transport keys the same
 * `tenant:principal` user context with that policy, the request-scoped context created here must
 * use the identical classification, or whichever path runs second is rejected with
 * "Principal classification mismatch for existing context". Set this next to
 * [ValidatedJwtClaimsAttribute]; when absent, the pipeline's classification is used.
 */
val AuthoritativePrincipalTypeAttribute: AttributeKey<com.sphereon.di.context.PrincipalType> =
    AttributeKey("sphereon.auth.authoritativePrincipalType")

/**
 * Per-call attribute holding the receiver audience the host ingress verified the bearer was issued
 * for, the service's own configured audience.
 *
 * Set it next to [ValidatedJwtClaimsAttribute] only after the validated token's audience contains
 * that service audience. The request session then exposes its secure details as a
 * [com.sphereon.di.context.PreauthorizedServiceBearer] for exactly this one audience, the contract
 * a binary transport ingress gives command code. Absent means the bearer was not verified for this
 * service.
 */
val ValidatedServiceAudienceAttribute: AttributeKey<String> =
    AttributeKey("sphereon.auth.validatedServiceAudience")

/** Marks Ktor routes whose method/path must be selected from the AppScope HTTP catalog. */
val UniversalHttpAdapterRouteAttribute: AttributeKey<Boolean> =
    AttributeKey("sphereon.http.universalAdapterRoute")

internal data class UniversalHttpAdapterRoutePolicy(
    val pathPrefix: String?,
    val allowedAdapterIds: Set<String>?,
) {
    fun selectionPath(requestPath: String): String {
        val prefix = pathPrefix ?: return requestPath
        require(requestPath == prefix || requestPath.startsWith("$prefix/")) {
            "Request path '$requestPath' is outside universal HTTP mount '$prefix'"
        }
        return requestPath.removePrefix(prefix).ifEmpty { "/" }
    }
}

/** Immutable route-mount policy consumed before SessionScope creation. */
internal val UniversalHttpAdapterRoutePolicyAttribute: AttributeKey<UniversalHttpAdapterRoutePolicy> =
    AttributeKey("sphereon.http.universalAdapterRoutePolicy")

/**
 * The immutable AppScope catalog result trusted by the SessionScope dispatcher.
 *
 * This is transport state, deliberately kept off [GenericHttpRequest] so the public KMP request
 * contract and its JS export/equality semantics remain unchanged.
 */
val SelectedHttpAdapterRouteAttribute: AttributeKey<HttpAdapterRouteMatch> =
    AttributeKey("sphereon.http.selectedAdapterRoute")

/**
 * Configuration for the Universal HTTP Adapter exposure.
 */
class UniversalHttpAdapterConfig {
    /**
     * Optional path prefix for the catch-all route.
     * If null, the catch-all handles all routes not matched by other explicit routes.
     * If set (e.g., "/api"), only routes starting with that prefix are handled.
     */
    var pathPrefix: String? = null

    /** Optional explicit adapter allow-list for a narrowly mounted service surface. */
    var allowedAdapterIds: Set<String>? = null

    /**
     * Whether to enable verbose logging for dispatched requests.
     */
    var verboseLogging: Boolean = false

    /**
     * Custom error handler for exceptions during dispatch.
     * If null, a default 500 response is returned.
     */
    var errorHandler: (suspend (ApplicationCall, Throwable) -> Unit)? = null

    /**
     * Route prefixes served WITHOUT the [corsInstaller]. Use for browser top-level-navigation
     * endpoints (e.g. the OAuth2 AS `/login` and `/authorize` form POSTs): a navigation following a
     * cross-origin OIDC redirect carries an opaque `Origin: null`, which a CORS allow-list rejects
     * with 403 before the handler runs — even though browsers never apply CORS to navigations.
     * Both the exact prefix and its subpaths are routed CORS-free; everything else keeps CORS.
     * CSRF for such endpoints is the login double-submit (`session_code`) + cookie, not Origin.
     */
    var corsExemptPrefixes: List<String> = emptyList()

    /**
     * Optional route-scoped plugin installer (typically `install(CORS) { ... }`) applied to the XHR
     * catch-all route but NOT to [corsExemptPrefixes]. Provided by the caller so this module needs
     * no CORS dependency. When null, no route-scoped plugin is installed (default).
     */
    var corsInstaller: (Route.() -> Unit)? = null
}

/**
 * Shared dispatch: convert the Ktor call to a [GenericHttpRequest], run it through the
 * SessionScope [HttpAdapterDispatcher], and write the [GenericHttpResponse] back.
 */
private suspend fun ApplicationCall.dispatchUniversal(config: UniversalHttpAdapterConfig) {
    try {
        val selectedRoute =
            attributes.getOrNull(SelectedHttpAdapterRouteAttribute)
                ?: error("Universal HTTP dispatch requires an AppScope-selected route")
        val genericRequest =
            this.toGenericHttpRequest(selectedRoute.maxRequestBodyBytes).let { request ->
                request.copy(path = config.routePolicy().selectionPath(request.path))
            }
        val dispatcher = (this.sessionInstance.graph as HttpAdapterDispatcher.Graph).httpAdapterDispatcher
        if (config.verboseLogging) {
            this.application.log.info("Dispatching: ${genericRequest.method} ${genericRequest.path}")
        }
        val genericResponse = dispatchUniversalHttpRequest(dispatcher, genericRequest, selectedRoute)
        this.respondWithGenericResponse(genericResponse)
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (framing: InvalidHttpRequestFramingException) {
        if (framing.closeConnection) this.response.header(HttpHeaders.Connection, "close")
        this.respond(HttpStatusCode.BadRequest)
    } catch (_: UniversalHttpRequestBodyTooLargeException) {
        this.respondText(
            text = "Request body exceeds endpoint byte limit",
            contentType = ContentType.Text.Plain,
            status = HttpStatusCode.PayloadTooLarge,
        )
    } catch (expected: Throwable) {
        val handler = config.errorHandler
        if (handler != null) {
            handler(this, expected)
        } else {
            this.application.log.error("Error in UniversalHttpAdapter dispatch", expected)
            this.respondText(
                text = "Internal server error",
                contentType = ContentType.Text.Plain,
                status = HttpStatusCode.InternalServerError,
            )
        }
    }
}

/** The network ingress owns a fresh boundary even when the handler has no standalone command. */
internal suspend fun dispatchUniversalHttpRequest(
    dispatcher: HttpAdapterDispatcher,
    request: GenericHttpRequest,
    route: HttpAdapterRouteMatch,
): GenericHttpResponse = withContext(CommandInvocationContext.externalBoundary()) {
    val response = dispatcher.dispatch(request, route)
    val body = response.bodyContent
    if (body is GenericHttpBody.TextStream) {
        // A lazy body outlives dispatch. A declared command owns the stream; an inline handler's
        // first command remains an external root when the body is collected later by Ktor.
        val invocation = if (route.commandId == null) CommandInvocationContext.externalBoundary()
            else CommandInvocationContext.externalCommand()
        response.copy(bodyContent = GenericHttpBody.TextStream(body.flow.flowOn(invocation), body.charset))
    } else response
}

/**
 * Installs the Universal HTTP Adapter exposure, which routes all HTTP requests
 * to the catalog-driven [HttpAdapterDispatcher].
 *
 * This is the OSS-first generic exposure mechanism for Ktor. It:
 * - Converts Ktor [ApplicationCall] to [GenericHttpRequest] with lazy body reading
 * - Delegates to the [HttpAdapterDispatcher] obtained from SessionScope
 * - Converts the [GenericHttpResponse] back to a Ktor response
 *
 * **Prerequisites:**
 * - The `KotlinInject` plugin must be installed on the application
 * - [HttpAdapterDispatcher] must be contributed to SessionScope via kotlin-inject/anvil
 *
 * **Usage:**
 * ```kotlin
 * fun Application.module() {
 *     install(KotlinInject) {
 *         appGraph = { createGraph<MyAppGraph>() }
 *         // ... other config
 *     }
 *
 *     installUniversalHttpAdapters {
 *         pathPrefix = "/api"  // optional
 *     }
 * }
 * ```
 *
 * @param configure Optional configuration block
 */
fun Application.installUniversalHttpAdapters(configure: UniversalHttpAdapterConfig.() -> Unit = {}) {
    val config = UniversalHttpAdapterConfig().apply(configure)
    val routePolicy = config.routePolicy()

    routing {
        // CORS-exempt navigation prefixes (e.g. the AS /login, /authorize) are routed WITHOUT the
        // caller's route-scoped CORS installer, so a browser navigation POST carrying `Origin: null`
        // is not 403'd by CORS before dispatch. Constant prefixes outscore the catch-all tailcard,
        // so only these exact paths + their subpaths bypass CORS; everything else keeps it.
        val installer = config.corsInstaller
        if (installer != null) {
            for (prefix in config.corsExemptPrefixes) {
                route(prefix) {
                    attributes.put(UniversalHttpAdapterRouteAttribute, true)
                    attributes.put(UniversalHttpAdapterRoutePolicyAttribute, routePolicy)
                    handle { call.dispatchUniversal(config) }
                }
                route("$prefix/{...}") {
                    attributes.put(UniversalHttpAdapterRouteAttribute, true)
                    attributes.put(UniversalHttpAdapterRoutePolicyAttribute, routePolicy)
                    handle { call.dispatchUniversal(config) }
                }
            }
        }

        // Catch-all route (XHR API surface). The caller's CORS installer, when present, is applied
        // route-scoped HERE — not globally — so it never reaches the exempt navigation prefixes.
        fun Route.installDispatchHandler() {
            attributes.put(UniversalHttpAdapterRouteAttribute, true)
            attributes.put(UniversalHttpAdapterRoutePolicyAttribute, routePolicy)
            installer?.invoke(this)
            handle { call.dispatchUniversal(config) }
        }
        val prefix = config.pathPrefix
        if (prefix == null) {
            route("{...}") { installDispatchHandler() }
        } else {
            route(prefix) { installDispatchHandler() }
            route("$prefix/{...}") { installDispatchHandler() }
        }
    }
}

/**
 * Alternative installation that mounts under a specific base path.
 *
 * **Usage:**
 * ```kotlin
 * routing {
 *     route("/api") {
 *         installUniversalHttpAdapters()
 *     }
 * }
 * ```
 */
fun Route.installUniversalHttpAdapters(configure: UniversalHttpAdapterConfig.() -> Unit = {}) {
    val config = UniversalHttpAdapterConfig().apply(configure)
    val routePolicy = config.routePolicy()

    // Create a catch-all under this route
    route("{...}") {
        attributes.put(UniversalHttpAdapterRouteAttribute, true)
        attributes.put(UniversalHttpAdapterRoutePolicyAttribute, routePolicy)
        handle { call.dispatchUniversal(config) }
    }
}

/**
 * Marks an explicit Ktor route for application-scoped HTTP catalog selection before request scope
 * construction. The route handler must consume [SelectedHttpAdapterRouteAttribute] and dispatch
 * that exact match; it must not repeat route selection after SessionScope exists.
 */
fun Route.markUniversalHttpAdapterRoute(
    pathPrefix: String? = null,
    allowedAdapterIds: Set<String>? = null,
) {
    val routePolicy =
        UniversalHttpAdapterConfig()
            .apply {
                this.pathPrefix = pathPrefix
                this.allowedAdapterIds = allowedAdapterIds
            }.routePolicy()
    attributes.put(UniversalHttpAdapterRouteAttribute, true)
    attributes.put(UniversalHttpAdapterRoutePolicyAttribute, routePolicy)
}

private fun UniversalHttpAdapterConfig.routePolicy(): UniversalHttpAdapterRoutePolicy {
    val normalizedPrefix =
        pathPrefix
            ?.trim()
            ?.takeIf { it.isNotEmpty() && it != "/" }
            ?.let { if (it.startsWith('/')) it else "/$it" }
            ?.trimEnd('/')
    val normalizedAdapterIds = allowedAdapterIds?.toSet()
    require(normalizedAdapterIds == null || normalizedAdapterIds.isNotEmpty()) {
        "allowedAdapterIds must be null or non-empty"
    }
    return UniversalHttpAdapterRoutePolicy(normalizedPrefix, normalizedAdapterIds)
}

/**
 * Converts a Ktor [ApplicationCall] to a [GenericHttpRequest].
 *
 * This implementation:
 * - Preserves the full request path (including query string separately)
 * - Extracts headers as a map
 * - Extracts query parameters as a map
 * - Provides a lazy body supplier to defer reading the request body
 */
suspend fun ApplicationCall.toGenericHttpRequest(): GenericHttpRequest = toGenericHttpRequest(null)

/** A descriptor-selected byte limit is checked before dispatch, including unknown-length bodies. */
suspend fun ApplicationCall.toGenericHttpRequest(maxRequestBodyBytes: Int?): GenericHttpRequest {
    require(maxRequestBodyBytes == null || maxRequestBodyBytes >= 0)
    val method = request.httpMethod.value
    val path = request.path()
    val resolvedBaseTenantId = attributes.getOrNull(BaseTenantIdAttribute)

    // Extract headers (joined for the scalar map) plus the raw multi-value view so consumers
    // that need single-occurrence semantics (RFC 9449 §4.1) can detect duplicates.
    val headers = request.headers.entries().associate { (name, values) -> name to values.joinToString(", ") }
    // RFC 9110 §5.3 / RFC 9449 §4.1: a header may appear multiple times. Some Ktor engines
    // (CIO included) emit `entries()` as one entry per occurrence, which silently collapses
    // duplicates when fed straight into `.associate { }`. Use `names()` + `getAll()` so the
    // multi-value list reflects every wire-level occurrence.
    val multiValueHeaders =
        request.headers
            .names()
            .associateWith { name -> request.headers.getAll(name) ?: emptyList() }

    // Extract query parameters
    val queryParameters =
        request.queryParameters
            .entries()
            .associate { (name, values) -> name to values.firstOrNull().orEmpty() }

    // Keep decoded occurrences separate: a delimiter can be part of an individual value.
    val multiValueQueryParameters =
        request.queryParameters
            .names()
            .associateWith { name -> request.queryParameters.getAll(name)?.toList() ?: emptyList() }

    // Path parameters from Ktor routing (if any)
    val pathParameters =
        parameters
            .entries()
            .filter { (key, _) -> key != "..." } // Filter out the catch-all parameter
            .associate { (name, values) -> name to values.firstOrNull().orEmpty() }

    // Validate raw framing before the best-effort body-read catch below.
    val framing = resolveHttpRequestBodyFraming(
        request.httpVersion,
        request.headers.getAll(HttpHeaders.ContentLength).orEmpty(),
        request.headers.getAll(HttpHeaders.TransferEncoding).orEmpty(),
    )
    val contentLength = framing.contentLength

    // Read the body once and cache it since Ktor request bodies can only be consumed once.
    val bodyContent =
        try {
            if (maxRequestBodyBytes != null && contentLength != null && contentLength > maxRequestBodyBytes) {
                throw UniversalHttpRequestBodyTooLargeException()
            }
            if (framing.shouldReadBody) {
                if (maxRequestBodyBytes != null) {
                    val bytes = readUniversalBoundedRequestBytes(receiveChannel(), maxRequestBodyBytes)
                    if (request.contentType().isTextLikeRequestBody()) GenericHttpBody.Text(bytes.decodeToString())
                    else GenericHttpBody.Bytes(bytes)
                } else if (request.contentType().isTextLikeRequestBody()) {
                    GenericHttpBody.Text(receiveText())
                } else {
                    GenericHttpBody.Bytes(receiveChannel().readRemaining().readBytes())
                }
            } else {
                GenericHttpBody.Empty
            }
        } catch (receiveFailure: Exception) {
            if (maxRequestBodyBytes != null || receiveFailure is CancellationException) throw receiveFailure
            GenericHttpBody.Empty
        }

    // RFC 8705: when the engine terminated TLS with `verifyClient = true` and the peer
    // presented a certificate, surface the chain (DER, leaf-first) so commonMain code (the
    // OAuth2 AS client-cert extractor and the resource-server cnf.x5t#S256 validator) can act
    // on it without depending on Ktor types. Population of the chain is handled by the
    // platform hook [extractClientCertificateChain]; commonMain returns `null`, the JVM
    // expect/actual reads the engine's peer cert chain.
    val clientCertificateChain = extractClientCertificateChain()

    return GenericHttpRequest(
        method = method,
        path = path,
        headers = headers,
        resolvedTenantId = resolvedBaseTenantId,
        multiValueHeaders = multiValueHeaders,
        queryParameters = queryParameters,
        multiValueQueryParameters = multiValueQueryParameters,
        pathParameters = pathParameters,
        bodyContent = bodyContent,
        clientCertificateChain = clientCertificateChain,
    )
}

/** Transport overflow is handled as HTTP 413 instead of a successful empty or partial body. */
class UniversalHttpRequestBodyTooLargeException : IllegalArgumentException("Request body exceeds endpoint byte limit")

internal suspend fun readUniversalBoundedRequestBytes(channel: ByteReadChannel, maxBytes: Int): ByteArray {
    require(maxBytes >= 0)
    val chunks = mutableListOf<ByteArray>()
    val buffer = ByteArray(8192)
    var size = 0
    while (!channel.isClosedForRead) {
        // Consume at most one byte past the bound, without overflowing Int for a large limit.
        val length = minOf(buffer.size.toLong(), maxBytes.toLong() - size + 1).toInt()
        val count = channel.readAvailable(buffer, 0, length)
        if (count < 0) break
        if (count > maxBytes - size) {
            channel.cancel(UniversalHttpRequestBodyTooLargeException())
            throw UniversalHttpRequestBodyTooLargeException()
        }
        if (count > 0) {
            chunks.add(buffer.copyOf(count))
            size += count
        }
    }
    channel.closedCause?.let { throw it }
    val bytes = ByteArray(size)
    var offset = 0
    for (chunk in chunks) {
        chunk.copyInto(bytes, offset)
        offset += chunk.size
    }
    return bytes
}

private fun ContentType.isTextLikeRequestBody(): Boolean {
    val value = toString().lowercase()
    return value.startsWith("text/") ||
        value.contains("json") ||
        value.contains("xml") ||
        value.startsWith("application/x-www-form-urlencoded")
}

internal data class HttpRequestBodyFraming(val contentLength: Long?, val shouldReadBody: Boolean)

internal class InvalidHttpRequestFramingException(
    message: String,
    val closeConnection: Boolean,
) : IllegalArgumentException(message)

/** Validate raw framing fields before the best-effort body-read catch can hide errors. */
internal fun resolveHttpRequestBodyFraming(
    httpVersion: String,
    contentLengthFields: List<String>,
    transferEncodingFields: List<String>,
): HttpRequestBodyFraming {
    val http10 = httpVersion == "HTTP/1.0"
    val http11 = httpVersion == "HTTP/1.1"
    val isHttp1 = httpVersion.startsWith("HTTP/1.")
    fun invalid(reason: String): Nothing = throw InvalidHttpRequestFramingException(reason, closeConnection = isHttp1)
    if (isHttp1 && !http10 && !http11) invalid("Unsupported HTTP/1.x version")

    val contentLength = when (contentLengthFields.size) {
        0 -> null
        1 -> {
            val field = contentLengthFields.single().trim(' ', '\t')
            if (field.isEmpty() || field.any { it !in '0'..'9' }) invalid("Invalid Content-Length")
            field.toLongOrNull() ?: invalid("Invalid Content-Length")
        }
        else -> invalid("Multiple Content-Length fields")
    }

    if (transferEncodingFields.isNotEmpty()) {
        if (!http11 || contentLength != null) invalid("Unsupported or ambiguous Transfer-Encoding")
        val codings = transferEncodingFields.flatMap { field -> field.split(',') }
            .map { it.trim(' ', '\t').lowercase() }
        if (codings.last() != "chunked" || codings.count { it == "chunked" } != 1 ||
            codings.any { it != "identity" && it != "chunked" }
        ) {
            invalid("Unsupported or ambiguous Transfer-Encoding")
        }
        return HttpRequestBodyFraming(contentLength = null, shouldReadBody = true)
    }

    val shouldReadBody = contentLength?.let { it > 0L } ?: !isHttp1
    return HttpRequestBodyFraming(contentLength, shouldReadBody)
}

/**
 * Platform hook for extracting the TLS client certificate chain (DER, leaf-first) from a
 * Ktor [ApplicationCall]. The JVM `actual` reads the engine's peer chain (e.g. Netty / CIO
 * with `verifyClient = true`); other platforms have no mTLS surface so the actual returns
 * `null`.
 */
internal expect fun ApplicationCall.extractClientCertificateChain(): List<ByteArray>?

/**
 * Responds to a Ktor call with a [GenericHttpResponse]. Routes binary payloads
 * ([GenericHttpBody.Bytes] / [GenericHttpBody.LazyBytes]) through Ktor's `respondBytes` so
 * non-UTF-8 content (PNG, PDF, raw protobuf, etc.) round-trips byte-identical without going
 * through `decodeToString()`. Text payloads use `respondText` and preserve the negotiated
 * content type from the response headers.
 */
suspend fun ApplicationCall.respondWithGenericResponse(response: GenericHttpResponse) {
    val repeatedNames = response.multiValueHeaders.keys.map(String::lowercase).toSet()
    response.headers.forEach { (name, value) ->
        if (name.lowercase() !in repeatedNames) this.response.headers.append(name, value)
    }
    response.multiValueHeaders.forEach { (name, values) ->
        values.forEach { value -> this.response.headers.append(name, value) }
    }

    // Determine content type from response headers or default to application/json
    val contentType =
        response.contentType?.let {
            ContentType.parse(it)
        } ?: ContentType.Application.Json

    val statusCode = HttpStatusCode.fromValue(response.statusCode)

    when (val bodyContent = response.bodyContent) {
        is GenericHttpBody.Bytes -> {
            respondBytes(bytes = bodyContent.value, contentType = contentType, status = statusCode)
        }

        is GenericHttpBody.LazyBytes -> {
            val bytes = bodyContent.value
            if (bytes != null) {
                respondBytes(bytes = bytes, contentType = contentType, status = statusCode)
            } else {
                respond(statusCode)
            }
        }

        is GenericHttpBody.Text -> {
            respondText(text = bodyContent.value, contentType = contentType, status = statusCode)
        }

        is GenericHttpBody.LazyText -> {
            val text = bodyContent.value
            if (text != null) {
                respondText(text = text, contentType = contentType, status = statusCode)
            } else {
                respond(statusCode)
            }
        }

        is GenericHttpBody.Empty -> {
            respond(statusCode)
        }

        is GenericHttpBody.TextStream -> {
            respondBytesWriter(contentType = contentType, status = statusCode) {
                bodyContent.flow.collect { chunk ->
                    writeFully(chunk.encodeToByteArray())
                    flush()
                }
            }
        }
    }
}
