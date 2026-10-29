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

@file:Suppress("TooGenericExceptionCaught")

package com.sphereon.crypto.resolution.extern

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.asErrorResult
import com.sphereon.core.api.asOkResult
import com.sphereon.core.api.cache.CacheManager
import com.sphereon.core.api.cache.CacheRequirements
import com.sphereon.core.api.cache.CacheSerializers
import com.sphereon.core.api.cache.ScopedCache
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.crypto.core.ResolvedKeyInfo
import com.sphereon.crypto.core.ResolvedKeyInfoType
import com.sphereon.crypto.core.jose.JoseKeyOperations
import com.sphereon.crypto.core.jose.JwkSet
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.jose.JwkType
import com.sphereon.crypto.resolution.IdentifierMethodDefaults
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.ktor.http.client.provider.counterpartyEgressWhenHolder
import com.sphereon.ktor.http.client.provider.isCounterpartyEgress
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.plugins.HttpRequestRetry
import io.ktor.client.request.get
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes

/**
 * Resolves a JWKS from a remote URL (for example an OpenID `jwks_uri`).
 *
 * This service exists to ensure key retrieval is uniform and reusable across the IDK:
 * callers should rely on identifier resolution (crypto core) rather than ad-hoc HTTP fetching.
 */
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<JwksUrlExternalIdentifierResolutionService>())
@ContributesIntoSet(SessionScope::class, binding = binding<ExternalIdentifierService>())
class JwksUrlExternalIdentifierResolutionServiceImpl private constructor(
    execution: SessionExecution,
    private val httpClientFactory: HttpClientFactory,
    private val cacheManager: CacheManager?,
    @Suppress("UNUSED_PARAMETER")
    cacheManagerBinding: Unit,
) : ExternalIdentifierServiceAdapter<ExternalIdentifierResult.JwksUrl>(
        supportedIdentifierMethods = listOf(IdentifierMethodDefaults.JWKS_URL),
        execution = execution,
        commandId = COMMAND_ID,
    ),
    JwksUrlExternalIdentifierResolutionService {
    @Inject
    constructor(
        execution: SessionExecution,
        httpClientFactory: HttpClientFactory,
        cacheManager: CacheManager,
    ) : this(execution, httpClientFactory, cacheManager, Unit)

    constructor(
        execution: SessionExecution,
        httpClientFactory: HttpClientFactory,
    ) : this(execution, httpClientFactory, null, Unit)

    /**
     * Per-`jwks_uri` JWKS cache via the IDK [CacheManager] abstraction, so a peer whose JWKS
     * endpoint is briefly unavailable (e.g. mid rolling-restart) does not fail validation.
     * Keyed strictly by URL; a `kid` miss re-resolves (rotation); failures and empty results
     * are never cached. Null when no [CacheManager] is bound (optional dependency) — then every
     * call resolves fresh, exactly as before.
     */
    private val jwksCache: ScopedCache<String, JwkSet>? by lazy {
        cacheManager?.let { cm ->
            cm.getCache<String, JwkSet>(CACHE_NAMESPACE)
                ?: cm.createStringCache(
                    CacheRequirements.localOnly(CACHE_NAMESPACE),
                    CacheSerializers.json(JwkSet.serializer()),
                )
        }
    }

    override suspend fun doExecute(
        args: ExternalIdentifierOptsOrResult,
        applyDuring: (ExternalIdentifierOptsOrResult) -> ExternalIdentifierOptsOrResult,
    ): IdkResult<ExternalIdentifierResult.JwksUrl, IdkErrorType> {
        // Note: supports() validation is already performed by parent CommandAdapter.execute()
        val opts = asSupportedOpts(args).value
        val url = opts.identifier.trim()
        if (url.isBlank()) {
            log.warn("JWKS_RESOLUTION_REFUSED stage=input reason=empty_url")
            return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JWKS URL is blank").asErrorResult()
        }

        val requestedKid = opts.lookup.kid
        val jwkSet = resolveJwkSetCached(url, requestedKid).getOrElse {
            val code = it.code.takeIf { value -> value.matches(Regex("[A-Za-z0-9_.:-]{1,160}")) } ?: "unavailable"
            log.warn("JWKS_RESOLUTION_REFUSED stage=document-resolution code=$code")
            return it.asErrorResult()
        }

        @Suppress("UNCHECKED_CAST")
        val resolvedKeys =
            jwkSet.keys
                .mapNotNull {
                    try {
                        ResolvedKeyInfo.fromKey(it) as ResolvedKeyInfoType<JwkType>
                    } catch (expected: Exception) {
                        log.debug("JWKS key skipped stage=key-admission exception_type=${expected::class.simpleName}")
                        null
                    }
                }.toTypedArray()
        if (resolvedKeys.isEmpty()) {
            return IdkError.NOT_FOUND_ERROR(message = "JWKS from $url contains no keys").asErrorResult()
        }
        val purposeKeys = if (opts.purpose == JwksKeySelectionPurpose.ENCRYPTION) {
            resolvedKeys.filter { info ->
                val key = info.key
                val permitsEncryption = key.key_ops?.let { operations ->
                    operations.any {
                        it == JoseKeyOperations.ENCRYPT || it == JoseKeyOperations.WRAP_KEY ||
                            it == JoseKeyOperations.DERIVE_KEY || it == JoseKeyOperations.DERIVE_BITS
                    } &&
                        operations.all {
                            it == JoseKeyOperations.ENCRYPT || it == JoseKeyOperations.DECRYPT ||
                                it == JoseKeyOperations.WRAP_KEY || it == JoseKeyOperations.UNWRAP_KEY ||
                                it == JoseKeyOperations.DERIVE_KEY || it == JoseKeyOperations.DERIVE_BITS
                        }
                }
                val declaresEncryption = key.use == JwkUse.enc.value ||
                    (key.use == null && permitsEncryption == true)
                declaresEncryption && permitsEncryption != false &&
                    key.d == null && key.p == null && key.q == null && key.dP == null &&
                    key.dQ == null && key.qInv == null && key.k == null
            }.toTypedArray()
        } else {
            resolvedKeys
        }
        val selectedKey: com.sphereon.crypto.core.ResolvedKeyInfoType<JwkType> =
            when {
                !requestedKid.isNullOrBlank() -> {
                    purposeKeys.firstOrNull { it.kid == requestedKid }
                        ?: return IdkError.NOT_FOUND_ERROR(message = "No key with kid '$requestedKid' found in JWKS from $url").asErrorResult()
                }

                else -> {
                    // The default purpose verifies a signature, so keys published for
                    // encryption only (RFC 7517 `use: enc`) are not candidates; providers such
                    // as Keycloak publish one signing and one encryption key side by side.
                    val encryptionOnlyKids = jwkSet.keys.filter { it.use == JwkUse.enc.value }.mapNotNull { it.kid }.toSet()
                    purposeKeys.singleOrNull {
                        opts.purpose == JwksKeySelectionPurpose.ENCRYPTION ||
                            it.kid == null || it.kid !in encryptionOnlyKids
                    }
                        ?: return IdkError
                            .ILLEGAL_ARGUMENT_ERROR(
                                message = "JWKS from $url must contain exactly one usable key when kid is omitted",
                            ).asErrorResult()
                }
            }

        return ExternalIdentifierResult
            .JwksUrl(
                identifierOpts = opts,
                jwks = resolvedKeys,
                keyInfo = selectedKey,
                jwksUrl = url,
                selectedKid = requestedKid,
            ).asOkResult()
    }

    private fun logDocumentFailure(stage: String, exception: Exception) {
        val type = exception::class.simpleName
            ?.takeIf { it.matches(Regex("[A-Za-z0-9_]{1,160}")) } ?: "Exception"
        log.warn("JWKS_RESOLUTION_REFUSED stage=$stage exception_type=$type")
    }

    /**
     * Fetch the raw JWKS JSON. Bounded retry for transport errors and HTTP 5xx is configured
     * on the Ktor client via [jwksHttpClientOptions], so this function only maps the final
     * response into domain errors. A definite 4xx fails fast; a missing `kid` is surfaced by
     * the caller and never retried here.
     */
    private suspend fun fetchJwksJson(
        httpClient: HttpClient,
        url: String,
    ): IdkResult<String, IdkErrorType> {
        val response =
            try {
                httpClient.get(url)
            } catch (expected: Exception) {
                logDocumentFailure("transport", expected)
                return IdkError
                    .UNKNOWN_ERROR(
                        message = "JWKS endpoint $url unavailable after ${MAX_FETCH_RETRIES + 1} attempts (transport error: ${expected.message})",
                        exception = expected,
                    ).asErrorResult()
            }

        if (response.status != HttpStatusCode.OK) {
            log.warn("JWKS_RESOLUTION_REFUSED stage=http-status http_status=${response.status.value}")
            val prefix =
                if (response.status.value in 500..599) {
                    "JWKS endpoint $url unavailable after ${MAX_FETCH_RETRIES + 1} attempts"
                } else {
                    "Failed to fetch JWKS from $url"
                }
            return IdkError.UNKNOWN_ERROR(message = "$prefix: HTTP ${response.status.value}").asErrorResult()
        }

        return try {
            response.body<String>().asOkResult()
        } catch (expected: Exception) {
            logDocumentFailure("body-read", expected)
            IdkError
                .UNKNOWN_ERROR(
                    message = "JWKS endpoint $url returned an unreadable response body: ${expected.message}",
                    exception = expected,
                ).asErrorResult()
        }
    }

    /**
     * Resolve the JWKS for [url], serving a cached copy when it already contains the requested
     * key. On a cache miss OR a `kid` miss (rotation) the JWKS is fetched fresh (with
     * [fetchJwksJson]) and the cache updated. A fetch/parse failure, or a JWKS with no
     * usable key, is NEVER cached — so a transient peer outage never pins a failure and a
     * recovered peer is re-resolved on the next call.
     */
    private suspend fun resolveJwkSetCached(
        url: String,
        requestedKid: String?,
    ): IdkResult<JwkSet, IdkErrorType> {
        // A holder call and a server call never share a cached key set: the entry is keyed by the egress mode.
        val cacheKey = if (isCounterpartyEgress()) "holder|$url" else url
        jwksCache?.getApp(cacheKey)?.let { cached ->
            if (jwkSetContainsUsableKey(cached, requestedKid)) {
                return cached.asOkResult()
            }
        }

        val httpClient =
            try {
                httpClientFactory.createClient(jwksHttpClientOptions().counterpartyEgressWhenHolder())
            } catch (expected: Exception) {
                logDocumentFailure("client-create", expected)
                return IdkError.UNKNOWN_ERROR(message = "Failed to create HTTP client: ${expected.message}", exception = expected).asErrorResult()
            }

        val jwksJson =
            try {
                fetchJwksJson(httpClient, url).getOrElse { return it.asErrorResult() }
            } finally {
                try {
                    httpClient.close()
                } catch (expected: Exception) {
                    log.debug("HTTP client close failed: ${expected.message}")
                }
            }

        val jwkSet =
            try {
                JwkSet.fromJsonString(jwksJson)
            } catch (expected: Exception) {
                logDocumentFailure("invalid-json", expected)
                return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Invalid JWKS JSON from $url: ${expected.message}", throwable = expected).asErrorResult()
            }

        // Cache only a freshly-fetched JWKS that yields at least one usable key. Never cache a
        // failure or an empty/unusable result — that would reintroduce the durable-failure-cache
        // anti-pattern (a transient outage pinning a 401 until restart).
        if (jwkSetContainsUsableKey(jwkSet, requestedKid = null)) {
            jwksCache?.putApp(cacheKey, jwkSet, JWKS_CACHE_TTL)
        }
        return jwkSet.asOkResult()
    }

    /**
     * True when [jwkSet] yields at least one supported key and — when [requestedKid] is given —
     * a key carrying that `kid`. A requested `kid` absent from a cached set means it is stale
     * (rotation) and must be re-resolved, never rejected from the cache.
     */
    private fun jwkSetContainsUsableKey(
        jwkSet: JwkSet,
        requestedKid: String?,
    ): Boolean {
        val resolved =
            jwkSet.keys.mapNotNull {
                runCatching { ResolvedKeyInfo.fromKey(it) }.getOrNull()
            }
        if (resolved.isEmpty()) return false
        return requestedKid.isNullOrBlank() || resolved.any { it.kid == requestedKid }
    }

    private fun jwksHttpClientOptions(): HttpClientOptions =
        HttpClientOptions.createDefault().copy(
            additionalConfig = {
                followRedirects = false
                install(HttpRequestRetry) {
                    retryOnException(maxRetries = MAX_FETCH_RETRIES, retryOnTimeout = true)
                    retryOnServerErrors(maxRetries = MAX_FETCH_RETRIES)
                    delayMillis(respectRetryAfterHeader = true) { retry -> BASE_RETRY_BACKOFF_MILLIS * retry }
                }
            },
        )

    override suspend fun supports(args: Any): Boolean {
        val externalArgs = args as? ExternalIdentifierOptsOrResult ?: return false
        val methodSupported =
            externalArgs is ExternalIdentifierJwksUrlOpts ||
                externalArgs.method?.let { isSupportedIdentifierMethod(it) } == true
        return methodSupported && isSupportedIdentifier(externalArgs.identifier)
    }

    override suspend fun isSupportedIdentifier(identifier: Any): Boolean {
        // Do not try to infer the method from the URL shape; selection should be driven by opts.method (JWKS_URL).
        // HTTPS is required for remote production endpoints. HTTP is retained only for
        // in-network JWKS fetch: RFC 6761 loopback, Compose/K8s single-label Service DNS,
        // and Kubernetes cluster-local Service FQDNs. `.local` / `.internal` and RFC1918
        // literals stay rejected (SSRF). Public gateway hosts stay HTTPS-only.
        return identifier is String && isAllowedJwksUrl(identifier)
    }

    private fun isAllowedJwksUrl(identifier: String): Boolean {
        val url = identifier.trim()
        val schemeSeparator = url.indexOf("://")
        if (schemeSeparator <= 0) return false
        val explicitScheme = url.substring(0, schemeSeparator).lowercase()
        if (explicitScheme != "https" && explicitScheme != "http") return false

        val parsed = runCatching { Url(url) }.getOrNull() ?: return false
        val scheme = parsed.protocol.name.lowercase()
        if (scheme != explicitScheme) return false
        if (scheme == "https") return parsed.host.isNotBlank()
        return isInNetworkHttpJwksHost(parsed.host.lowercase())
    }

    private fun isInNetworkHttpJwksHost(host: String): Boolean {
        if (host.isBlank()) return false
        if (host == "localhost" || host == "127.0.0.1" || host == "::1" || host.endsWith(".localhost")) {
            return true
        }
        // Compose short names (`enterprise-platform`) and Helm same-namespace Service
        // DNS (`edk-sih-edk-enterprise-platform`, `…-platform-identity`) have no dot.
        if (!host.contains('.')) return true
        return host.endsWith(".svc") ||
            host.endsWith(".svc.cluster.local") ||
            host.endsWith(".cluster.local")
    }

    override suspend fun resolve(opts: ExternalIdentifierOptsOrResult): IdkResult<ExternalIdentifierResult.JwksUrl, IdkErrorType> = execute(opts)

    override suspend fun asSupportedOpts(opts: ExternalIdentifierOptsOrResult): IdkResult<ExternalIdentifierJwksUrlOpts, IdkErrorType> =
        if (isSupportedOpts(opts)) {
            (opts as ExternalIdentifierJwksUrlOpts).asOkResult()
        } else {
            IdkError.COMMAND_ARG_NOT_SUPPORTED_ERROR().asErrorResult()
        }

    companion object {
        const val COMMAND_ID = "crypto.resolution.jwksurl"

        /** Namespace for the per-`jwks_uri` JWKS cache. */
        const val CACHE_NAMESPACE = "crypto.resolution.jwks-cache"

        /**
         * Positive TTL for a cached JWKS. Signing keys rotate on human timescales, so a short
         * TTL balances freshness against peer availability; a `kid` miss re-resolves immediately
         * so a rotation still surfaces promptly, and failures are never cached.
         */
        val JWKS_CACHE_TTL: Duration = 10.minutes

        /**
         * Bounded Ktor retry for a TRANSIENT JWKS-endpoint condition (transport failure / HTTP
         * 5xx) — e.g. a peer briefly unreachable or not-yet-ready during a rolling restart.
         * A definite 4xx and a 200-with-missing-kid are NOT retried, and failures are never
         * cached, so a real auth problem still fails fast and a recovered peer is picked up
         * on the next request.
         */
        const val MAX_FETCH_RETRIES = 2
        private const val BASE_RETRY_BACKOFF_MILLIS = 200L
    }
}
