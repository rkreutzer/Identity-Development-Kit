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

package com.sphereon.core.api.http.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.ConfigUnavailableException
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.CompiledPathPattern
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.HttpAdapter
import com.sphereon.core.api.http.describe.HttpAdapterDescription
import com.sphereon.core.api.http.describe.HttpAdapterMount
import com.sphereon.core.api.http.describe.OpenApiHints
import com.sphereon.core.api.http.error.DefaultRestErrorRenderer
import com.sphereon.core.api.http.error.HttpErrorRenderer
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteMatch
import com.sphereon.core.api.session.CommandId
import com.sphereon.core.api.session.ExecutionScopedAdapter
import com.sphereon.core.api.session.ICommandExecutionExtension
import com.sphereon.core.api.session.ICommandInitExtension
import com.sphereon.core.api.session.IEnhancedCommandExecutionExtension
import com.sphereon.di.context.MutableResolvedTenantIdProvider
import kotlin.coroutines.cancellation.CancellationException

data class ResolvedHttpRequest(
    val request: GenericHttpRequest,
    val route: HttpAdapterRouteMatch,
)

/**
 * Base class for HTTP adapters backed by the IDK command infrastructure.
 *
 * This adapter integrates [HttpAdapter] with [ExecutionScopedAdapter], enabling:
 * - **Lifecycle integration**: Automatic session registration via `onEnterScope`
 * - **Enablement/feature gating**: Commands and endpoints can be toggled via `isEnabled`
 * - **Extension hooks**: Before/during/after execution callbacks
 * - **Introspectable routing**: Endpoint commands expose their descriptors for catalog/dispatcher use
 *
 * ## Architecture
 *
 * A `CommandBackedHttpAdapter` is itself a command that:
 * - Takes a `GenericHttpRequest` as input
 * - Returns a `GenericHttpResponse` as output
 * - Delegates to child [HttpEndpointCommand]s based on request matching
 *
 * The AppScope route catalog chooses the handler identity. This SessionScope adapter then resolves
 * exactly that one endpoint command from [HttpEndpointCommandRegistry].
 *
 * ## Usage
 *
 * ```kotlin
 * class MyHttpAdapter(
 *     execution: SessionExecution,
 *     endpointCommandRegistry: HttpEndpointCommandRegistry,
 * ) : CommandBackedHttpAdapter(
 *     id = "example.http.adapter",
 *     execution = execution,
 *     mount = HttpAdapterMount(serverPrefix = "/api", adapterBasePath = "/my"),
 *     endpointCommandRegistry = endpointCommandRegistry,
 * )
 * ```
 *
 * ## Comparison with RoutedHttpAdapter
 *
 * - **RoutedHttpAdapter**: Lighter weight, routes are inline lambdas, no command lifecycle
 * - **CommandBackedHttpAdapter**: Full command integration, endpoints are standalone commands,
 *   supports enablement, extensions, and session lifecycle hooks
 *
 * Choose `RoutedHttpAdapter` for simple cases; use `CommandBackedHttpAdapter` when you need
 * command infrastructure features or want to expose individual endpoints as injectable commands.
 *
 * @param id Unique identifier for this adapter
 * @param execution The session execution context
 * @param mount The mount configuration for this adapter
 * @param isEnabled Whether this adapter is enabled (default: true)
 * @param initExtensions Initialization lifecycle hooks
 * @param executionExtensions Execution lifecycle hooks (before/during/after)
 * @param enhancedExecutionExtensions Enhanced execution extensions with suspend support and short-circuit capability
 */
abstract class CommandBackedHttpAdapter(
    override val id: String,
    execution: SessionExecution,
    protected val mount: HttpAdapterMount,
    private val endpointCommandRegistry: HttpEndpointCommandRegistry,
    isEnabled: Boolean = true,
    initExtensions: Array<ICommandInitExtension<ResolvedHttpRequest, GenericHttpResponse, IdkError>> = emptyArray(),
    executionExtensions: Array<ICommandExecutionExtension<ResolvedHttpRequest, GenericHttpResponse, IdkError>> = emptyArray(),
    enhancedExecutionExtensions: Array<IEnhancedCommandExecutionExtension<ResolvedHttpRequest, GenericHttpResponse, IdkError>> = emptyArray(),
    protected open val errorRenderer: HttpErrorRenderer = DefaultRestErrorRenderer(),
    /**
     * Per-adapter routable-slug peel policy. Defaults to [TenantPathPolicy.None] —
     * the path is matched as-is and no peel is attempted. Adapters that want
     * spec-correct OAuth2/OIDC URL routing override this:
     * - Discovery adapters: [TenantPathPolicy.WellKnownSuffix]
     * - Authorization / token / par / callback adapters: [TenantPathPolicy.LeadingSlug]
     */
    open val tenantPathPolicy: TenantPathPolicy = TenantPathPolicy.None,
) : ExecutionScopedAdapter<ResolvedHttpRequest, GenericHttpResponse, IdkError>(
        id = CommandId(id).value,
        isEnabled = isEnabled,
        initExtensions = initExtensions,
        executionExtensions = executionExtensions,
        execution = execution,
        enhancedExecutionExtensions = enhancedExecutionExtensions,
    ),
    HttpAdapter {
    /**
     * Slug lookup used by [TenantPathPolicy.LeadingSlug] / [TenantPathPolicy.WellKnownSuffix]
     * peeling. Defaults to a no-op implementation that returns null for every
     * lookup. Adapters with a
     * non-`None` [tenantPathPolicy] MUST override this with the AppScope-injected
     * [RoutableSlugLookup] binding (the EDK `lib-tenant-resolution-impl` module
     * contributes a postgres-backed implementation; without it, peels never
     * succeed and as-is matching applies).
     */
    protected open val routableSlugLookup: RoutableSlugLookup = NoOpRoutableSlugLookupSingleton

    /**
     * Mutable session-scoped tenant override. The dispatcher writes the descended
     * tenant id here on a successful peel and clears it after the matched
     * endpoint returns. Adapters
     * with a non-`None` [tenantPathPolicy] should override this with the
     * SessionScope-injected [MutableResolvedTenantIdProvider] binding so
     * `SessionExecution.tenantId` reflects the descended value during dispatch.
     */
    protected open val resolvedTenantIdProvider: MutableResolvedTenantIdProvider = NoopMutableResolvedTenantIdProvider

    /**
     * Optional OpenAPI hints for this adapter.
     */
    protected open val openApiHints: OpenApiHints? = null

    /**
     * Simplified constructor for common use cases.
     */
    constructor(
        id: String,
        execution: SessionExecution,
        mount: HttpAdapterMount,
        endpointCommandRegistry: HttpEndpointCommandRegistry,
        errorRenderer: HttpErrorRenderer = DefaultRestErrorRenderer(),
    ) : this(
        id = id,
        execution = execution,
        mount = mount,
        endpointCommandRegistry = endpointCommandRegistry,
        isEnabled = true,
        initExtensions = emptyArray(),
        executionExtensions = emptyArray(),
        enhancedExecutionExtensions = emptyArray(),
        errorRenderer = errorRenderer,
    )

    // ========== HttpAdapter implementation ==========

    override fun describe(): HttpAdapterDescription =
        HttpAdapterDescription(
            id = id,
            mount = mount.copy(tenantPathPolicy = tenantPathPolicy),
            endpoints = emptyList(),
            openApiHints = openApiHints,
        )

    override suspend fun handleResolvedRequest(
        request: GenericHttpRequest,
        route: HttpAdapterRouteMatch,
    ): GenericHttpResponse {
        val result = execute(ResolvedHttpRequest(request, route))
        return result.fold(
            success = { response -> response },
            failure = { error -> errorRenderer.render(error, request) },
        )
    }

    // ========== Command implementation ==========

    override suspend fun supports(args: Any): Boolean {
        if (!isEnabled) {
            return false
        }
        if (args !is ResolvedHttpRequest) {
            return false
        }
        return args.route.adapterId == id
    }

    override suspend fun doExecute(
        args: ResolvedHttpRequest,
        applyDuring: (ResolvedHttpRequest) -> ResolvedHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> {
        val resolvedRequest = applyDuring(args)
        val request = resolvedRequest.request
        val selectedRoute = resolvedRequest.route
        if (selectedRoute.adapterId != id) {
            return Err(
                IdkError.UNKNOWN_ERROR(
                    message = "Preselected adapter '${selectedRoute.adapterId}' does not match runtime adapter '$id'",
                ),
            )
        }
        val endpoint =
            endpointCommandRegistry.get(selectedRoute.handlerCommandId)
                ?: return Err(
                    IdkError.UNKNOWN_ERROR(
                        message = "No HTTP endpoint command '${selectedRoute.handlerCommandId}' is registered",
                    ),
                )
        val endpointIdentityError = validateSelectedEndpoint(selectedRoute, endpoint)
        if (endpointIdentityError != null) {
            return Err(IdkError.UNKNOWN_ERROR(message = endpointIdentityError))
        }
        if (!endpoint.isEnabled) {
            return Err(IdkError.NOT_FOUND_ERROR(message = "Not found: ${request.method} ${request.path}"))
        }
        // Opaque resource identifiers may contain encoded separators only in explicitly
        // declared single-segment parameters. Mount literals and tenant selectors remain strict.
        if (hasUnsafeEndpointPath(request.path, selectedRoute.matchedPathPattern, endpoint.encodedPathParameters)) {
            log.debug("[$id] Refusing unsafe path: ${request.method} ${request.path}")
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "request path contains forbidden tokens (path traversal or encoded slash)",
                ),
            )
        }
        log.debug("[$id] Processing request: ${request.method} ${request.path}")

        // Strip adapter base path before routing to endpoint commands
        val relativeRequest = stripAdapterBasePath(request)

        // Build the candidate set: 0-peel match + any successful peels under the
        // declared tenantPathPolicy. The longest peel that produces a matching
        // endpoint wins (ties broken by endpoint pattern specificity).
        val candidates = collectPeelCandidates(relativeRequest, endpoint)

        if (candidates.isEmpty()) {
            // RequiredSlug failed-to-peel and as-is also misses → distinct error
            // so the resolver layer above can tell "no tenant" from "no route".
            return when (val policy = tenantPathPolicy) {
                is TenantPathPolicy.LeadingSlug, is TenantPathPolicy.WellKnownSuffix -> {
                    if (policy.required) {
                        log.debug("[$id] tenant_unresolved: required peel failed for ${request.method} ${request.path}")
                        Err(
                            IdkError.NOT_FOUND_ERROR(
                                message = "tenant_unresolved: ${request.method} ${request.path}",
                            ),
                        )
                    } else {
                        log.debug("[$id] No matching endpoint for: ${request.method} ${request.path}")
                        Err(IdkError.NOT_FOUND_ERROR(message = "Not found: ${request.method} ${request.path}"))
                    }
                }

                TenantPathPolicy.None -> {
                    log.debug("[$id] No matching endpoint for: ${request.method} ${request.path}")
                    Err(IdkError.NOT_FOUND_ERROR(message = "Not found: ${request.method} ${request.path}"))
                }
            }
        }

        // Pick longest peel; tie-break by endpoint pattern specificity (most literal segments wins).
        val winner =
            candidates.maxWithOrNull(
                compareBy<PeelCandidate> { it.peelDepth }
                    .thenBy { candidate ->
                        // Multi-pattern descriptors compete on their best (most specific)
                        // alias — whichever URL the request actually hit.
                        candidate.endpoint.endpoint.pathPatterns
                            .maxOf { CompiledPathPattern.compile(it).specificity }
                    },
            )!!

        // Advance the session-scope tenant for the duration of this dispatch when a
        // peel changed it. Cleared in finally so the override doesn't leak.
        val previousOverride = resolvedTenantIdProvider.currentTenantId()
        val needsOverride = winner.descendedTenantId != null
        if (needsOverride) {
            resolvedTenantIdProvider.setCurrentTenantId(winner.descendedTenantId!!)
        }

        // Extract `{placeholder}` path parameters from the matched endpoint pattern and merge
        // them onto the request before executing. The Ktor catch-all route ("{...}") and
        // `toGenericHttpRequest` deliberately do NOT populate per-pattern path params (Ktor only
        // yields a tailcard), and the dispatcher matches by pattern without extracting — so without
        // this step `requirePathParam("catalogId")` etc. fail with "Missing required path parameter".
        // Pick the first of the endpoint's patterns that matches this (already base-path-stripped)
        // request; multi-pattern descriptors expose the same handler at several URLs.
        val matchedPattern =
            winner.endpoint.endpoint.pathPatterns
                .firstOrNull { winner.strippedRequest.matches(winner.endpoint.endpoint.method.name, it) }
        val requestWithParams =
            matchedPattern
                ?.let { winner.strippedRequest.withExtractedParams(it) }
                ?: winner.strippedRequest

        return try {
            winner.endpoint.execute(requestWithParams)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (unavailable: ConfigUnavailableException) {
            // A config read raced a lazy/remote config fetch that is not ready
            // yet (or the platform serving it is briefly unreachable). This is a
            // transient condition: surface it as 503 (UNAVAILABLE) so the caller
            // retries, instead of the generic 500 below.
            log.warn("[$id] Config unavailable while executing endpoint: ${unavailable.message}")
            Err(
                IdkError.SERVICE_UNAVAILABLE_ERROR(
                    message = unavailable.message ?: "Configuration temporarily unavailable",
                    throwable = unavailable,
                ),
            )
        } catch (expected: Exception) {
            log.error("[$id] Error executing endpoint: ${expected.message}", expected)
            Err(IdkError.UNKNOWN_ERROR(message = expected.message ?: "Internal error", exception = expected))
        } finally {
            if (needsOverride) {
                if (previousOverride != null) {
                    resolvedTenantIdProvider.setCurrentTenantId(previousOverride)
                } else {
                    resolvedTenantIdProvider.clearCurrentTenantId()
                }
            }
        }
    }

    /**
     * Internal record describing one peel candidate considered by the dispatcher.
     */
    private data class PeelCandidate(
        val peelDepth: Int,
        val endpoint: HttpEndpointCommand,
        val strippedRequest: GenericHttpRequest,
        /** Null when this candidate didn't change the session tenant. */
        val descendedTenantId: String?,
    )

    /**
     * Collect every (peel, endpoint) pair that produces a successful match. Always
     * considers the 0-peel as-is match first; then, if the policy allows, walks
     * up to `maxDepth` segments off the front (LeadingSlug) or off the tail
     * (WellKnownSuffix), validating each via [routableSlugLookup].
     *
     * Path peeling is short-circuit: as soon as a slug fails to resolve, we stop
     * descending in that direction (a slug is a prefix of further descent — if
     * the closer one isn't valid, the further one can't be either).
     */
    private suspend fun collectPeelCandidates(
        relativeRequest: GenericHttpRequest,
        endpoint: HttpEndpointCommand,
    ): List<PeelCandidate> {
        val candidates = mutableListOf<PeelCandidate>()

        // 0-peel: try as-is.
        if (endpoint.supports(relativeRequest)) {
            candidates += PeelCandidate(0, endpoint, relativeRequest, null)
        }

        when (val policy = tenantPathPolicy) {
            TenantPathPolicy.None -> Unit
            is TenantPathPolicy.LeadingSlug -> peelLeading(relativeRequest, policy.maxDepth, endpoint, candidates)
            is TenantPathPolicy.WellKnownSuffix -> peelTrailing(relativeRequest, policy.maxDepth, endpoint, candidates)
        }

        return candidates
    }

    private suspend fun peelLeading(
        relativeRequest: GenericHttpRequest,
        maxDepth: Int,
        endpoint: HttpEndpointCommand,
        out: MutableList<PeelCandidate>,
    ) {
        val segments = relativeRequest.path.split('/').filter { it.isNotEmpty() }
        var currentTenantId: String? = null
        val baseTenantId = relativeRequest.resolvedTenantId
        var parent: String? = baseTenantId
        var previousWasProtocolPrefix = false
        for (i in 1..minOf(maxDepth, segments.size)) {
            val seg = segments[i - 1]
            // Slug-shape gate before the DB hit. Stops peel at the first
            // non-slug segment — the remaining segments stay as-is for the
            // endpoint matcher.
            if (!isSafeSlugSegment(seg)) break
            val resolved =
                if (parent == null) {
                    routableSlugLookup.findRootBySlug(seg)
                } else {
                    routableSlugLookup.findChildBySlug(parent, seg)
                }
            if (resolved != null) {
                currentTenantId = resolved.tenantId
                parent = resolved.tenantId
                previousWasProtocolPrefix = false
            } else if (seg in PROTOCOL_PREFIX_SEGMENTS || previousWasProtocolPrefix) {
                // `/as/{instance}` and leftover `/{instance}` after a protocol
                // base-path strip are instance routing, not tenant slugs.
                previousWasProtocolPrefix = seg in PROTOCOL_PREFIX_SEGMENTS
            } else {
                break
            }

            val remainingPath = "/" + segments.drop(i).joinToString("/")
            val stripped = relativeRequest.copy(path = if (remainingPath == "/") "/" else remainingPath)
            if (endpoint.supports(stripped)) {
                out += PeelCandidate(i, endpoint, stripped, currentTenantId)
            }
        }
    }

    private suspend fun peelTrailing(
        relativeRequest: GenericHttpRequest,
        maxDepth: Int,
        endpoint: HttpEndpointCommand,
        out: MutableList<PeelCandidate>,
    ) {
        val segments = relativeRequest.path.split('/').filter { it.isNotEmpty() }
        // For trailing peel, the URL semantic order is parent-first, child-last:
        //   /.well-known/X/<parent>/<child>
        // The peel walks the tail right-to-left (child first), but the validation
        // chain is parent → child. We collect peeled candidates as we walk, then
        // descend the chain in URL order to validate.
        var currentTenantId: String? = null
        val baseTenantId = relativeRequest.resolvedTenantId
        for (peelCount in 1..minOf(maxDepth, segments.size)) {
            val peeled = segments.takeLast(peelCount)
            val remaining = segments.dropLast(peelCount)

            // Validate the peeled chain in URL order: outermost (left) first.
            // Each segment must be slug-shaped before we hit the DB; if any peeled
            // segment isn't a valid slug, this peelCount cannot resolve.
            if (peeled.any { !isSafeSlugSegment(it) }) continue
            // A protocol issuer path is mounted as `/as/{issuer}` (or the
            // equivalent `/oid4vci/{issuer}` / `/oid4vp/{issuer}`). The
            // protocol prefix is not a tenant-tree segment. In particular,
            // internal east-west readiness calls carry the platform host as
            // their transport host, so using [baseTenantId] here would make
            // `/as/acme` look up `acme` as a child of the platform tenant and
            // leave the request scoped to the platform when it is actually a
            // customer root. Resolve the issuer slug from the root in this
            // form, just as the external tenant host does.
            val protocolIssuerPath = peeled.firstOrNull() in PROTOCOL_PREFIX_SEGMENTS
            val lookupSegments = if (protocolIssuerPath) peeled.drop(1) else peeled
            var parent: String? = if (protocolIssuerPath) null else baseTenantId
            var lastResolved: String? = null
            var allResolved = true
            for (seg in lookupSegments) {
                val resolved =
                    if (parent == null) {
                        routableSlugLookup.findRootBySlug(seg)
                    } else {
                        routableSlugLookup.findChildBySlug(parent, seg)
                    }
                if (resolved == null) {
                    allResolved = false
                    break
                }
                parent = resolved.tenantId
                lastResolved = resolved.tenantId
            }
            if (!allResolved && !isOpaqueProtocolIssuerPath(peeled)) {
                // This peel depth doesn't produce a valid tenant chain — but a
                // deeper peel might (when the outer parent appears at
                // peelCount+1), or the suffix may be a protocol instance path
                // (`/as/{id}`) rather than a tenant tree.
                continue
            }
            currentTenantId = lastResolved

            val remainingPath = if (remaining.isEmpty()) "/" else "/" + remaining.joinToString("/")
            val stripped = relativeRequest.copy(path = remainingPath)
            if (endpoint.supports(stripped)) {
                out += PeelCandidate(peelCount, endpoint, stripped, currentTenantId)
            }
        }
    }

    /**
     * DNS-label-shaped (RFC 1123) plus the same `--`/trailing-`-`/`xn--` checks
     * applied at registration. Inlined here because the IDK dispatcher cannot
     * depend on the EDK `TenantSlug` validator; the rule must stay in lockstep
     * with the registration-side regex.
     */
    private fun isSafeSlugSegment(seg: String): Boolean =
        SAFE_SLUG_RE.matches(seg) &&
            !seg.contains("--") &&
            !seg.endsWith("-") &&
            !seg.startsWith("xn--")

    private fun validateSelectedEndpoint(
        route: HttpAdapterRouteMatch,
        endpoint: HttpEndpointCommand,
    ): String? {
        if (endpoint.id != route.handlerCommandId) {
            return "Resolved HTTP endpoint command '${endpoint.id}' does not match selected handler '${route.handlerCommandId}'"
        }
        if (!endpoint.endpoint.method.name.equals(route.method, ignoreCase = true)) {
            return "Resolved HTTP endpoint command '${endpoint.id}' has method ${endpoint.endpoint.method}, expected ${route.method}"
        }
        val catalogPatterns =
            endpoint.endpoint.pathPatterns.map { pattern ->
                when {
                    mount.adapterBasePath.isEmpty() || mount.adapterBasePath == "/" -> pattern
                    // The route catalog mounts an empty pattern at the base path, exactly like "/".
                    pattern.isEmpty() || pattern == "/" -> mount.adapterBasePath
                    else -> mount.adapterBasePath.trimEnd('/') + "/" + pattern.trimStart('/')
                }
            }
        if (route.matchedPathPattern !in catalogPatterns) {
            return "Resolved HTTP endpoint command '${endpoint.id}' does not declare selected pattern '${route.matchedPathPattern}'"
        }
        return null
    }

    companion object {
        private val SAFE_SLUG_RE = Regex("^[a-z][a-z0-9-]{0,62}$")

        /** Public protocol mount segments that are never tenant slugs. */
        private val PROTOCOL_PREFIX_SEGMENTS = setOf("as", "oid4vci", "oid4vp")

        /**
         * First path segment of a real protocol endpoint after the adapter base
         * (`/oid4vci`, `/oid4vp`). Anything else in that position is an instance id.
         */
        private val PROTOCOL_LEAF_FIRST_SEGMENTS =
            setOf(
                "backend",
                "credential",
                "deferredCredential",
                "nonce",
                "notification",
                "credentials",
                "invite",
                "request-uri",
                "request_uri",
                "auth",
                "direct_post",
                "account-action",
                "ready",
            )
    }

    private fun isOpaqueProtocolIssuerPath(peeled: List<String>): Boolean {
        if (peeled.isEmpty()) return false
        if (peeled.size == 1) return peeled[0] in PROTOCOL_PREFIX_SEGMENTS
        return peeled[0] in PROTOCOL_PREFIX_SEGMENTS && peeled.drop(1).all { isSafeSlugSegment(it) }
    }

    /**
     * After the adapter base (`/oid4vci`, `/oid4vp`) is removed, an instance id
     * may remain (`/acme/credential`). Strip that one segment when it is not
     * itself a protocol leaf.
     */
    private fun stripOptionalInstanceSegment(relativePath: String): String {
        val segments = relativePath.split('/').filter { it.isNotEmpty() }
        if (segments.size < 2) return if (relativePath.isEmpty()) "/" else relativePath
        val head = segments.first()
        if (!isSafeSlugSegment(head) || head in PROTOCOL_LEAF_FIRST_SEGMENTS || head in PROTOCOL_PREFIX_SEGMENTS) {
            return if (relativePath.startsWith("/")) relativePath else "/$relativePath"
        }
        val remaining = "/" + segments.drop(1).joinToString("/")
        return remaining
    }

    private fun String.lastPathSegment(): String = trim('/').substringAfterLast('/')

    /**
     * Strip the adapter's base path from the request path.
     *
     * Endpoint commands define paths relative to the adapter's base path.
     * For example, if the adapter has base path "/oid4vp" and receives a request
     * for "/oid4vp/request-uri/123", the endpoint command pattern is "/request-uri/{id}".
     */
    private fun stripAdapterBasePath(request: GenericHttpRequest): GenericHttpRequest {
        val basePath = mount.adapterBasePath
        if (basePath.isEmpty() || basePath == "/") {
            return request
        }
        val path = request.path
        if (path.startsWith(basePath)) {
            val relativePath =
                path.removePrefix(basePath).let {
                    if (it.isEmpty()) {
                        "/"
                    } else {
                        it
                    }
                }
            val routedPath =
                if (basePath.lastPathSegment() in PROTOCOL_PREFIX_SEGMENTS) {
                    stripOptionalInstanceSegment(relativePath)
                } else {
                    relativePath
                }
            return request.copy(path = routedPath)
        }

        val policy = tenantPathPolicy
        if (policy !is TenantPathPolicy.LeadingSlug) {
            return request
        }

        val baseSegments = basePath.split('/').filter { it.isNotEmpty() }
        val pathSegments = path.split('/').filter { it.isNotEmpty() }
        val maxDepth = policy.maxDepth
        for (peelDepth in 1..minOf(maxDepth, pathSegments.size)) {
            val afterSlug = pathSegments.drop(peelDepth)
            if (!afterSlug.startsWithSegments(baseSegments)) {
                continue
            }
            val relativeSegments = pathSegments.take(peelDepth) + afterSlug.drop(baseSegments.size)
            val relativePath = if (relativeSegments.isEmpty()) "/" else "/" + relativeSegments.joinToString("/")
            return request.copy(path = relativePath)
        }

        return request
    }

    private fun List<String>.startsWithSegments(prefix: List<String>): Boolean = size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }

}

/**
 * No-op [RoutableSlugLookup] used as the dispatcher's default when a subclass
 * with `tenantPathPolicy = None` declines to inject a real implementation.
 * Always returns null so adapters compile and dispatch without slug routing —
 * the safe default for adapters that never peel.
 */
private object NoOpRoutableSlugLookupSingleton : RoutableSlugLookup {
    override suspend fun findRootBySlug(slug: String): RoutableSlugLookup.Resolved? = null

    override suspend fun findChildBySlug(
        parentTenantId: String,
        slug: String
    ): RoutableSlugLookup.Resolved? = null
}

/**
 * No-op [MutableResolvedTenantIdProvider] used by the dispatcher when a subclass
 * with `tenantPathPolicy = None` declines to inject a real provider. Set/clear
 * are silently dropped; a peel that would otherwise advance the session tenant
 * never fires for None-policy adapters anyway.
 */
private object NoopMutableResolvedTenantIdProvider : MutableResolvedTenantIdProvider {
    override fun currentTenantId(): String? = null

    override fun setCurrentTenantId(tenantId: String) { /* no-op */ }

    override fun clearCurrentTenantId() { /* no-op */ }
}

/** Keep encoded resource data out of routing decisions; decoding happens once, after raw segment matching. */
internal fun hasUnsafeEndpointPath(path: String, pattern: String, encodedParameters: Set<String>): Boolean {
    val forbidden = listOf("..", "//", "%2f", "%5c", "\\")
    if (encodedParameters.isEmpty()) return forbidden.any { path.contains(it, ignoreCase = true) }
    if (path.contains("//") || path.contains('\\')) return true
    val values = path.split('/').filter { it.isNotEmpty() }
    val tokens = pattern.split('/').filter { it.isNotEmpty() }
    if (values.size != tokens.size) return true
    return values.indices.any { index ->
        val value = values[index]
        val name = tokens[index].removePrefix("{").removeSuffix("}")
        if (tokens[index] != "{$name}" || name !in encodedParameters) {
            forbidden.any { value.contains(it, ignoreCase = true) }
        } else {
            val dots = value.replace(Regex("%2[eE]"), ".")
            dots == "." || dots == ".." || value.any { it.code < 32 || it.code == 127 } ||
                value.indices.any { offset -> value[offset] == '%' &&
                    (offset + 2 >= value.length || value[offset + 1].digitToIntOrNull(16) == null ||
                        value[offset + 2].digitToIntOrNull(16) == null) }
        }
    }
}
