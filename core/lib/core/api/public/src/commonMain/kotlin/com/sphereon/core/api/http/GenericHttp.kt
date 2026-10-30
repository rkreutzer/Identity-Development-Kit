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

package com.sphereon.core.api.http

import com.sphereon.core.compat.JsExportCompat
import kotlin.jvm.JvmStatic

/**
 * Lazy map that only creates the underlying map when first accessed.
 * This avoids allocations for maps that are never used.
 *
 * Performance benefit: For requests where headers or query parameters are never accessed,
 * this completely avoids the map allocation and iteration cost.
 */
@JsExportCompat
class LazyMap<K, V>(
    private val initializer: () -> Map<K, V>,
) : Map<K, V> {
    private val delegate: Map<K, V> by lazy(initializer)

    override val entries: Set<Map.Entry<K, V>> get() = delegate.entries
    override val keys: Set<K> get() = delegate.keys
    override val size: Int get() = delegate.size
    override val values: Collection<V> get() = delegate.values

    override fun containsKey(key: K): Boolean = delegate.containsKey(key)

    override fun containsValue(value: V): Boolean = delegate.containsValue(value)

    override fun get(key: K): V? = delegate.get(key)

    override fun isEmpty(): Boolean = delegate.isEmpty()
}

/**
 * Framework-agnostic HTTP request abstraction.
 *
 * Can be created from:
 * - Spring HttpServletRequest
 * - Ktor ApplicationCall
 * - AWS Lambda APIGatewayProxyRequestEvent
 * - Azure HttpRequestMessage
 * - Google Cloud HttpRequest
 *
 * This abstraction allows routing logic to be defined once in commonMain
 * and reused across all HTTP frameworks and serverless platforms.
 *
 * **Body handling:**
 * - Use [bodyContent] for the typed body model supporting text and binary
 * - Use [body] (String?) for backward compatibility with existing code
 *
 * Performance optimizations:
 * - Lazy body reading (only when accessed)
 * - Lazy map access (headers/query params)
 * - Cached path pattern matching
 */
data class GenericHttpRequest(
    val method: String,
    val path: String,
    val pathParameters: Map<String, String> = emptyMap(),
    val queryParameters: Map<String, String?> = emptyMap(),
    val headers: Map<String, String> = emptyMap(),
    /** Tenant established by validated authentication, never from request data. */
    val resolvedTenantId: String? = null,
    /**
     * Raw multi-value header view, preserving each `name → List<value>` arrival shape from the
     * underlying transport. RFC 9110 §5.3 allows multiple field lines with the same name; the
     * scalar [headers] map collapses these by joining with `,`, which is sufficient for headers
     * whose grammar permits comma-list (e.g. `Accept`, `Cache-Control`) but loses information
     * for headers that MUST appear at most once.
     *
     * Consumers that need to enforce single-occurrence semantics (e.g. RFC 9449 §4.1: a single
     * `DPoP` HTTP header is REQUIRED) should look here instead of inspecting [headers] for a
     * fragile comma-presence heuristic. Empty by default so existing in-process call sites that
     * synthesise a [GenericHttpRequest] from a scalar map continue to work; transport adapters
     * (the Ktor / Universal HTTP adapters) populate it from their underlying multi-map.
     */
    val multiValueHeaders: Map<String, List<String>> = emptyMap(),
    /**
     * Lazy body supplier - only invoked when body is accessed.
     * This avoids reading the request body for GET/DELETE requests.
     *
     * @see bodyContent for the typed body model
     */
    private val bodySupplier: (() -> String?)? = null,
    /**
     * The typed body content supporting both text and binary payloads.
     *
     * When [bodySupplier] is provided, this defaults to a [GenericHttpBody.LazyText].
     * For binary payloads, construct with an explicit [GenericHttpBody.Bytes] or [GenericHttpBody.LazyBytes].
     */
    val bodyContent: GenericHttpBody = bodySupplier?.let { GenericHttpBody.ofLazyText(it) } ?: GenericHttpBody.Empty,
    /**
     * TLS client certificate chain presented at the transport handshake (DER-encoded, leaf
     * first). Populated by the platform HTTP adapter when:
     *  - the server terminates TLS itself with `verifyClient = true` and the peer presented a
     *    certificate, or
     *  - the upstream proxy forwards the cert via the operator-configured trusted header (e.g.
     *    `X-Forwarded-Client-Cert`) and the AS resolves it to DER.
     *
     * `null` means no certificate is available on this request, which is the common case for
     * non-mTLS endpoints. Used by RFC 8705 client authentication (`tls_client_auth` /
     * `self_signed_tls_client_auth`) and by the resource-server `cnf.x5t#S256` validation.
     */
    val clientCertificateChain: List<ByteArray>? = null,
    /** Ingress path retained by route dispatch before mount and tenant prefixes are stripped. */
    val originalPath: String? = null,
    /**
     * Decoded query occurrences, preserving each value without joining delimiters.
     * Transport adapters populate this view; scalar-only in-process callers may leave it empty.
     * A present key is authoritative even when its list is empty or contains one value.
     */
    val multiValueQueryParameters: Map<String, List<String>> = emptyMap(),
) {
    /**
     * Request body as String - lazily loaded only when accessed.
     * For GET/DELETE requests where body is never accessed, this saves memory and I/O.
     *
     * This is a convenience accessor for backward compatibility.
     * For typed access (including binary), use [bodyContent].
     */
    val body: String? by lazy {
        bodyContent.asTextOrNull()
    }

    /**
     * Request body as ByteArray - lazily loaded only when accessed.
     * Useful for binary payloads (Protobuf, CBOR, etc.).
     */
    val bodyBytes: ByteArray? by lazy {
        bodyContent.asBytesOrNull()
    }

    /**
     * Content-Type header value, if present.
     */
    val contentType: String?
        get() = headers["Content-Type"] ?: headers["content-type"]

    /**
     * Accept header values, parsed into a list.
     */
    val accept: List<String>
        get() =
            (headers["Accept"] ?: headers["accept"])
                ?.split(",")
                ?.map { it.trim().substringBefore(";") }
                ?: emptyList()

    /**
     * Convenience accessors
     */
    val pathParams: Map<String, String> get() = pathParameters
    val queryParams: Map<String, String?> get() = queryParameters

    /**
     * Check if this request matches a method and path pattern.
     *
     * Pattern syntax:
     * - `/keys` - exact match
     * - `/keys/{id}` - path parameter
     * - `/keys/{id}/subresource` - multiple segments with parameter
     *
     * @param method HTTP method (case-insensitive)
     * @param pattern Path pattern with optional {param} placeholders
     * @return true if request matches the pattern
     */
    fun matches(
        method: String,
        pattern: String,
    ): Boolean =
        this.method.equals(method, ignoreCase = true) &&
            matchesPathPattern(this.path, pattern)

    /**
     * Extract path parameters from the request path based on a pattern.
     * Returns a new request with extracted parameters merged into pathParameters.
     *
     * Example:
     * ```
     * val request = GenericHttpRequest(method = "GET", path = "/keys/key123")
     * val withParams = request.withExtractedParams("/keys/{aliasOrKid}")
     * // withParams.pathParams["aliasOrKid"] == "key123"
     * ```
     */
    fun withExtractedParams(pattern: String): GenericHttpRequest {
        val params = extractPathParams(this.path, pattern)
        return copy(pathParameters = pathParameters + params)
    }

    /**
     * Copy method that preserves the bodySupplier and bodyContent for lazy loading.
     *
     * NOTE: This overload shadows the data class auto-generated `copy(...)` because the
     * defaults must explicitly forward [bodySupplier] / [bodyContent] / [multiValueHeaders]
     * / [originalPath] / [multiValueQueryParameters]
     * from `this`. Forgetting to thread any of them silently drops the field on every
     * downstream `request.copy(path = ...)` call (e.g. base-path stripping in
     * [com.sphereon.core.api.http.command.CommandBackedHttpAdapter.stripAdapterBasePath])
     * — which is how RFC 9449 §4.1 multi-DPoP detection lost the multi-value view.
     */
    fun copy(
        method: String = this.method,
        path: String = this.path,
        pathParameters: Map<String, String> = this.pathParameters,
        queryParameters: Map<String, String?> = this.queryParameters,
        headers: Map<String, String> = this.headers,
        resolvedTenantId: String? = this.resolvedTenantId,
        multiValueHeaders: Map<String, List<String>> = this.multiValueHeaders,
        clientCertificateChain: List<ByteArray>? = this.clientCertificateChain,
        originalPath: String? = this.originalPath,
        multiValueQueryParameters: Map<String, List<String>> = this.multiValueQueryParameters,
    ): GenericHttpRequest =
        GenericHttpRequest(
            method = method,
            path = path,
            pathParameters = pathParameters,
            queryParameters = queryParameters,
            headers = headers,
            resolvedTenantId = resolvedTenantId,
            multiValueHeaders = multiValueHeaders,
            bodySupplier = bodySupplier,
            bodyContent = bodyContent,
            clientCertificateChain = clientCertificateChain,
            originalPath = originalPath,
            multiValueQueryParameters = multiValueQueryParameters,
        )

    companion object {
        /**
         * Creates a request with text body content.
         */
        @JvmStatic
        fun withTextBody(
            method: String,
            path: String,
            body: String?,
            pathParameters: Map<String, String> = emptyMap(),
            queryParameters: Map<String, String?> = emptyMap(),
            headers: Map<String, String> = emptyMap(),
        ): GenericHttpRequest =
            GenericHttpRequest(
                method = method,
                path = path,
                pathParameters = pathParameters,
                queryParameters = queryParameters,
                headers = headers,
                bodyContent = GenericHttpBody.ofText(body),
            )

        /**
         * Creates a request with binary body content.
         */
        @JvmStatic
        fun withBinaryBody(
            method: String,
            path: String,
            body: ByteArray?,
            pathParameters: Map<String, String> = emptyMap(),
            queryParameters: Map<String, String?> = emptyMap(),
            headers: Map<String, String> = emptyMap(),
        ): GenericHttpRequest =
            GenericHttpRequest(
                method = method,
                path = path,
                pathParameters = pathParameters,
                queryParameters = queryParameters,
                headers = headers,
                bodyContent = GenericHttpBody.ofBytes(body),
            )
    }
}

/**
 * Framework-agnostic HTTP response abstraction.
 *
 * Can be converted to:
 * - Spring ResponseEntity
 * - Ktor ApplicationCall.respond()
 * - AWS Lambda APIGatewayProxyResponseEvent
 * - Azure HttpResponseMessage
 * - Google Cloud HttpResponse
 *
 * **Body handling:**
 * - Use [bodyContent] for the typed body model supporting text and binary
 * - Use [body] (String?) for backward compatibility with existing code
 */
@JsExportCompat
data class GenericHttpResponse(
    val statusCode: Int,
    val headers: Map<String, String> = emptyMap(),
    /**
     * Response body as String (backward compatible).
     *
     * For typed access including binary, use [bodyContent].
     */
    val body: String? = null,
    /**
     * The typed body content supporting both text and binary payloads.
     *
     * When [body] is provided, this defaults to [GenericHttpBody.Text].
     * For binary responses, construct with explicit [GenericHttpBody.Bytes].
     */
    val bodyContent: GenericHttpBody = body?.let { GenericHttpBody.Text(it) } ?: GenericHttpBody.Empty,
    /**
     * Response fields that must remain separate field lines at the transport boundary.
     *
     * Values here take precedence over a case-insensitively matching entry in [headers].
     * This is required for fields such as `Set-Cookie`, which cannot be comma-folded without
     * changing browser semantics. Empty by default to preserve all existing constructors.
     */
    val multiValueHeaders: Map<String, List<String>> = emptyMap(),
) {
    /**
     * Response body as ByteArray.
     * Useful for binary payloads (Protobuf, CBOR, etc.).
     */
    val bodyBytes: ByteArray?
        get() = bodyContent.asBytesOrNull()

    /**
     * Content-Type header value, if present.
     */
    val contentType: String?
        get() =
            headers["Content-Type"] ?: headers["content-type"] ?: multiValueHeaders.entries
                .firstOrNull { it.key.equals("Content-Type", ignoreCase = true) }
                ?.value
                ?.firstOrNull()

    companion object {
        /**
         * Creates a response with text body content.
         */
        @JvmStatic
        fun withTextBody(
            statusCode: Int,
            body: String?,
            headers: Map<String, String> = emptyMap(),
        ): GenericHttpResponse =
            GenericHttpResponse(
                statusCode = statusCode,
                headers = headers,
                body = body,
                bodyContent = GenericHttpBody.ofText(body),
            )

        /**
         * Creates a response with binary body content. The text [body] is left null so transport
         * adapters that fall back to the String accessor never see a `decodeToString` of arbitrary
         * bytes; correctness for non-UTF-8 payloads requires routing through [bodyContent].
         */
        @JvmStatic
        fun withBinaryBody(
            statusCode: Int,
            body: ByteArray?,
            headers: Map<String, String> = emptyMap(),
        ): GenericHttpResponse =
            GenericHttpResponse(
                statusCode = statusCode,
                headers = headers,
                body = null,
                bodyContent = GenericHttpBody.ofBytes(body),
            )

        /**
         * Creates a response whose body is written incrementally from a text chunk flow
         * (e.g. Server-Sent Events). [body] stays null so transports never buffer via the
         * String accessor.
         */
        @JvmStatic
        fun withTextStreamBody(
            statusCode: Int,
            flow: kotlinx.coroutines.flow.Flow<String>,
            headers: Map<String, String> = emptyMap(),
        ): GenericHttpResponse =
            GenericHttpResponse(
                statusCode = statusCode,
                headers = headers,
                body = null,
                bodyContent = GenericHttpBody.ofTextStream(flow),
            )
    }
}

/**
 * Compiled path pattern for efficient matching.
 *
 * Pattern syntax:
 * - Literal segment: `/keys` matches the segment `keys` exactly.
 * - Single-segment placeholder: `/keys/{id}` matches one segment and captures it as `id`.
 * - Suffixed placeholder: `/keys/{id}:validate` captures `id` while requiring the literal
 *   `:validate` suffix in the same segment.
 * - Greedy placeholder: `/blobs/{path+}` captures one or more segments. Following
 *   literal segments (for example `/blobs/{path+}/content`) remain required.
 * - Tail wildcard: `/login/assets/{path...}` matches zero or more remaining segments and captures
 *   them joined by `/` (no leading slash). The wildcard token MUST be the last token in the
 *   pattern; placing it mid-path is rejected at compile time.
 *
 * Pre-splits the pattern to avoid repeated string operations.
 */
@JsExportCompat
class CompiledPathPattern private constructor(
    val pattern: String,
    private val segments: List<Segment>,
) {
    sealed class Segment {
        data class Literal(
            val value: String,
        ) : Segment()

        data class Parameter(
            val name: String,
            val suffix: String = "",
        ) : Segment()

        /**
         * Tail wildcard: matches zero or more remaining path segments. Must appear as the last
         * token in a pattern. The captured value is the remaining segments joined by `/` with no
         * leading slash (empty string if there are zero remaining segments).
         */
        data class TailWildcard(
            val name: String,
        ) : Segment()
    }

    private val tailWildcardIndex: Int = segments.indexOfFirst { it is Segment.TailWildcard }
    private val hasTailWildcard: Boolean = tailWildcardIndex >= 0
    private val hasGreedyParameter: Boolean = segments.any { it is Segment.Parameter && it.name.endsWith("+") }

    /**
     * Specificity score: literal segments have weight 2 and suffixed parameters have weight 1.
     * Higher means more specific, so a literal beats a suffixed parameter, which in turn beats a
     * plain parameter.
     * Use this to resolve ambiguity when multiple patterns match the same path.
     */
    val specificity: Int =
        segments.sumOf { segment ->
            when (segment) {
                is Segment.Literal -> 2
                is Segment.Parameter -> if (segment.suffix.isNotEmpty()) 1 else 0
                is Segment.TailWildcard -> 0
            }
        }

    /**
     * Check if a path matches this compiled pattern.
     */
    fun matches(path: String): Boolean {
        val pathSegments = splitPath(path)
        if (hasGreedyParameter) return matchGreedySegments(pathSegments) != null

        if (!hasTailWildcard) {
            if (pathSegments.size != segments.size) {
                return false
            }
            return pathSegments.zip(segments).all { (pathSeg, patternSeg) ->
                when (patternSeg) {
                    is Segment.Parameter -> patternSeg.matches(pathSeg)
                    is Segment.Literal -> pathSeg == patternSeg.value
                    is Segment.TailWildcard -> true
                }
            }
        }

        // Tail-wildcard matching: every leading token must consume exactly one segment;
        // the wildcard then absorbs zero or more remaining segments.
        if (pathSegments.size < tailWildcardIndex) {
            return false
        }
        for (i in 0 until tailWildcardIndex) {
            val patternSeg = segments[i]
            val pathSeg = pathSegments[i]
            val ok =
                when (patternSeg) {
                    is Segment.Parameter -> patternSeg.matches(pathSeg)
                    is Segment.Literal -> pathSeg == patternSeg.value
                    is Segment.TailWildcard -> true // unreachable: tailWildcardIndex bounds us
                }
            if (!ok) return false
        }
        return true
    }

    /**
     * Extract path parameters from a path. Captured parameter values are percent-decoded
     * (see [percentDecode]) so clients that follow RFC 3986 / OpenAPI codegen norms by
     * encoding reserved characters (e.g. `did%3Ajwk%3A...` for `did:jwk:...`) match the
     * same record as clients that send the unencoded form. Without this, the captured
     * group is the raw URL segment and the downstream lookup misses on every encoded
     * request — a 404 that's invisible to local-curl smoke-tests but trivially reproducible
     * with any generated client.
     */
    fun extractParams(path: String): Map<String, String> {
        val pathSegments = splitPath(path)
        if (hasGreedyParameter) {
            return matchGreedySegments(pathSegments)?.associate { (segment, range) ->
                val captured = pathSegments.subList(range.first, range.last + 1)
                when (segment) {
                    is Segment.Parameter -> {
                        val greedy = segment.name.endsWith("+")
                        val name = if (greedy) segment.name.removeSuffix("+") else segment.name
                        val value = if (greedy) captured.joinToString("/") { it.percentDecode() }
                            else segment.capture(captured.single()).percentDecode()
                        name to value
                    }
                    is Segment.TailWildcard -> segment.name to captured.joinToString("/") { it.percentDecode() }
                    is Segment.Literal -> error("Literal segments do not capture parameters")
                }
            } ?: emptyMap()
        }

        if (!hasTailWildcard) {
            if (!matches(path)) {
                return emptyMap()
            }
            return pathSegments
                .zip(segments)
                .mapNotNull { (pathSeg, patternSeg) ->
                    when (patternSeg) {
                        is Segment.Parameter -> patternSeg.name to patternSeg.capture(pathSeg).percentDecode()
                        is Segment.Literal -> null
                        is Segment.TailWildcard -> null
                    }
                }.toMap()
        }

        if (pathSegments.size < tailWildcardIndex) {
            return emptyMap()
        }
        // Validate leading literals before extracting; mismatched literal => no params.
        // Literals are compared in their wire (encoded) form because pattern declarations
        // never carry encoded reserved chars in practice — decoding only applies to
        // captured parameter values.
        for (i in 0 until tailWildcardIndex) {
            val patternSeg = segments[i]
            val pathSeg = pathSegments[i]
            val matches =
                when (patternSeg) {
                    is Segment.Literal -> pathSeg == patternSeg.value
                    is Segment.Parameter -> patternSeg.matches(pathSeg)
                    is Segment.TailWildcard -> true
                }
            if (!matches) {
                return emptyMap()
            }
        }
        val params = mutableMapOf<String, String>()
        for (i in 0 until tailWildcardIndex) {
            val patternSeg = segments[i]
            if (patternSeg is Segment.Parameter) {
                params[patternSeg.name] = patternSeg.capture(pathSegments[i]).percentDecode()
            }
        }
        val tail = segments[tailWildcardIndex] as Segment.TailWildcard
        // Tail-wildcard captures multiple segments; decode each one independently so a `/`
        // inside an individual encoded segment doesn't get mistaken for a separator.
        params[tail.name] = pathSegments.drop(tailWildcardIndex).joinToString("/") { it.percentDecode() }
        return params
    }

    /** Match greedily using suffix feasibility. Reconstruct capture ranges only after a complete
     * match; each greedy row retains its longest viable endpoint without repeated scans. */
    internal fun matchGreedySegments(
        pathSegments: List<String>,
        onTransition: (() -> Unit)? = null,
    ): List<Pair<Segment, IntRange>>? {
        val pathSize = pathSegments.size
        val next = Array(segments.size + 1) { IntArray(pathSize + 1) { -1 } }
        next[segments.size][pathSize] = pathSize

        for (patternIndex in segments.indices.reversed()) {
            val segment = segments[patternIndex]
            val row = next[patternIndex]
            val suffix = next[patternIndex + 1]
            var longestEnd = -1
            for (pathIndex in pathSize downTo 0) {
                onTransition?.invoke()
                row[pathIndex] = when {
                    segment is Segment.TailWildcard -> pathSize
                    segment is Segment.Parameter && segment.name.endsWith("+") -> {
                        // Descending indices encounter the largest viable suffix start first.
                        // The endpoint must be strictly beyond this start: greedy is nonempty.
                        if (longestEnd < 0 && pathIndex < pathSize && suffix[pathIndex + 1] >= 0) {
                            longestEnd = pathIndex + 1
                        }
                        longestEnd
                    }
                    pathIndex == pathSize || suffix[pathIndex + 1] < 0 -> -1
                    segment is Segment.Literal ->
                        if (segment.value == pathSegments[pathIndex]) pathIndex + 1 else -1
                    segment is Segment.Parameter ->
                        if (segment.matches(pathSegments[pathIndex])) pathIndex + 1 else -1
                    else -> error("All segment types are handled above")
                }
            }
        }

        if (next[0][0] < 0) return null
        val captures = mutableListOf<Pair<Segment, IntRange>>()
        var pathIndex = 0
        for (patternIndex in segments.indices) {
            onTransition?.invoke()
            val segment = segments[patternIndex]
            val end = next[patternIndex][pathIndex]
            if (segment !is Segment.Literal) captures.add(segment to (pathIndex until end))
            pathIndex = end
        }
        return captures
    }

    companion object {
        // Cache compiled patterns to avoid repeated parsing
        private val cache = mutableMapOf<String, CompiledPathPattern>()

        /**
         * Compile a path pattern for efficient matching.
         * Results are cached to avoid recompiling the same pattern.
         *
         * Throws [IllegalArgumentException] if a tail-wildcard token (`{name...}`) appears
         * anywhere other than the last position.
         */
        @JvmStatic
        fun compile(pattern: String): CompiledPathPattern =
            cache.getOrPut(pattern) {
                val rawSegments = splitPath(pattern)
                val segments =
                    rawSegments.mapIndexed { index, segment ->
                        if (segment.startsWith("{") && segment.contains("}")) {
                            val closingBraceIndex = segment.indexOf('}')
                            val inner = segment.substring(1, closingBraceIndex)
                            val suffix = segment.substring(closingBraceIndex + 1)
                            if (inner.endsWith("...")) {
                                if (suffix.isNotEmpty()) {
                                    return@mapIndexed Segment.Literal(segment)
                                }
                                require(index == rawSegments.lastIndex) {
                                    "Tail-wildcard token '$segment' must be the last segment in pattern '$pattern'"
                                }
                                val name = inner.removeSuffix("...")
                                require(name.isNotEmpty()) {
                                    "Tail-wildcard token must declare a name in pattern '$pattern'"
                                }
                                Segment.TailWildcard(name)
                            } else {
                                if (inner.endsWith("+")) {
                                    require(inner.removeSuffix("+").isNotEmpty()) { "Greedy token must declare a name in pattern '$pattern'" }
                                    require(!inner.removeSuffix("+").endsWith("+")) { "Greedy token '$segment' must use exactly one trailing '+' in pattern '$pattern'" }
                                    require(suffix.isEmpty()) { "Greedy token '$segment' must occupy an entire segment in pattern '$pattern'" }
                                }
                                Segment.Parameter(inner, suffix)
                            }
                        } else {
                            Segment.Literal(segment)
                        }
                    }
                CompiledPathPattern(pattern, segments)
            }
    }

    private fun Segment.Parameter.matches(pathSegment: String): Boolean =
        suffix.isEmpty() || (pathSegment.length > suffix.length && pathSegment.endsWith(suffix))

    private fun Segment.Parameter.capture(pathSegment: String): String =
        if (suffix.isEmpty()) pathSegment else pathSegment.dropLast(suffix.length)
}

/**
 * Split path into non-empty segments (cached per path).
 */
private fun splitPath(path: String): List<String> = path.split('/').filter { it.isNotEmpty() }

/**
 * Match a request path against a pattern with placeholders.
 *
 * This function uses cached compiled patterns for efficiency.
 *
 * Examples:
 * - matchesPathPattern("/keys", "/keys") -> true
 * - matchesPathPattern("/keys/abc", "/keys/{id}") -> true
 * - matchesPathPattern("/keys/abc/def", "/keys/{id}") -> false
 * - matchesPathPattern("/keys", "/providers") -> false
 */
internal fun matchesPathPattern(
    path: String,
    pattern: String,
): Boolean = CompiledPathPattern.compile(pattern).matches(path)

/**
 * Extract path parameters from a request path based on a pattern.
 *
 * This function uses cached compiled patterns for efficiency.
 *
 * Examples:
 * - extractPathParams("/keys/abc", "/keys/{id}") -> {"id": "abc"}
 * - extractPathParams("/providers/p1/keys/k1", "/providers/{providerId}/keys/{keyId}")
 *   -> {"providerId": "p1", "keyId": "k1"}
 */
internal fun extractPathParams(
    path: String,
    pattern: String,
): Map<String, String> = CompiledPathPattern.compile(pattern).extractParams(path)
