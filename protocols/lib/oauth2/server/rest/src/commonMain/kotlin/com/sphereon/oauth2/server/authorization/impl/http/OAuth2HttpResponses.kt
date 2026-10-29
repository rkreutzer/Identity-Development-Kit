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

// Role-neutral OAuth REST capability. Executable server startup remains in services-oauth2-as-rest.
package com.sphereon.oauth2.server.authorization.impl.http

import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.percentDecode
import com.sphereon.core.api.log.Log
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import dev.whyoleg.cryptography.random.CryptographyRandom
import io.ktor.http.Url
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

// Shared HTTP-layer helpers for the OAuth2 AS endpoint commands and adapters. Holds the wire
// primitives (request parsing, base URL resolution, RFC 6749 §5.2 error response shaping) so the
// per-endpoint [com.sphereon.core.api.http.command.HttpEndpointCommand] impls and the per-area
// [com.sphereon.core.api.http.command.CommandBackedHttpAdapter] subclasses produce identical wire
// output without duplicating logic.

/**
 * Categorises the response payload so [securityHeadersFor] can pick the right header subset.
 *
 * HTML pages need the full clickjacking + MIME-sniff + transport defenses; REST/JSON responses
 * have no clickable surface and so omit `X-Frame-Options` / CSP; binary asset responses get the
 * minimum (HSTS + nosniff) since they carry no markup or executable script. The categorisation
 * is wire-shape-driven, not endpoint-driven, so the same endpoint can return different headers
 * for different `Accept` outcomes.
 */
internal enum class ResponseCategory { HTML, REST, BINARY }

/**
 * Default browser security header set applied to every AS response. Per-realm overrides are
 * intentionally NOT wired in this first cut; the per-realm seam can be added later by threading
 * [com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig] through call sites that already
 * have a config provider in scope.
 *
 * Defaults:
 * - Strict-Transport-Security: 1-year max-age + includeSubDomains, on every response.
 * - X-Content-Type-Options: nosniff, on every response (defends MIME-sniffing of error bodies too).
 * - Referrer-Policy: no-referrer, on HTML+REST (not strictly needed on binary assets).
 * - X-Robots-Tag: none, on HTML+REST (binary assets are served once and cached).
 * - X-Frame-Options: SAMEORIGIN, on HTML only (clickjacking).
 * - Content-Security-Policy: HTML only — strict `default-src 'self'`. Pages containing inline
 *   `<style>` or `<script>` MUST pass a per-request nonce via [withSecurityHeaders]; the helper
 *   then expands the policy to `style-src 'self' 'nonce-X'; script-src 'self' 'nonce-X'`. With
 *   no nonce supplied the strict baseline applies — inline content is blocked, which is what we
 *   want when a renderer hasn't been audited for inline use.
 */
private const val DEFAULT_HSTS = "max-age=31536000; includeSubDomains"
private const val DEFAULT_FRAME_OPTIONS = "SAMEORIGIN"
private const val DEFAULT_NOSNIFF = "nosniff"
private const val DEFAULT_REFERRER_POLICY = "no-referrer"
private const val DEFAULT_ROBOTS_TAG = "none"

/**
 * Assemble the HTML Content-Security-Policy. With neither [nonce] nor [imageOrigins] this is the
 * strict `default-src 'self'` baseline. A [nonce] expands style-src/script-src for the page's
 * audited inline blocks. Non-empty [imageOrigins] adds an `img-src 'self' <origins...>` directive
 * so theme-supplied images hosted cross-origin (e.g. platform-hosted brand assets served to a
 * tenant-subdomain AS) may load; origins are emitted sorted for a deterministic header value.
 */
private fun htmlCsp(
    nonce: String?,
    imageOrigins: Set<String> = emptySet(),
): String =
    buildList {
        add("default-src 'self'")
        if (nonce != null) {
            add("style-src 'self' 'nonce-$nonce'")
            add("script-src 'self' 'nonce-$nonce'")
        }
        if (imageOrigins.isNotEmpty()) {
            add("img-src 'self' ${imageOrigins.sorted().joinToString(" ")}")
        }
        add("frame-ancestors 'self'")
        add("object-src 'none'")
    }.joinToString("; ")

/**
 * Generate a fresh CSP nonce: 16 cryptographically random bytes, base64url-without-padding.
 * 128-bit entropy is the W3C-recommended floor for nonces (see CSP3 §6.1) — far above the
 * brute-force threshold for an attacker observing the response, so the value can safely be
 * embedded in the response body and matched against the response header.
 *
 * Each call MUST produce a fresh nonce — reusing a nonce across responses lets an XSS payload
 * captured from one response replay against another.
 */
internal fun newCspNonce(): String = CryptographyRandom.nextBytes(16).encodeToBase64Url()

internal fun securityHeadersFor(
    category: ResponseCategory,
    nonce: String? = null,
    imageOrigins: Set<String> = emptySet(),
): Map<String, String> =
    when (category) {
        ResponseCategory.HTML -> {
            mapOf(
                "Strict-Transport-Security" to DEFAULT_HSTS,
                "X-Frame-Options" to DEFAULT_FRAME_OPTIONS,
                "X-Content-Type-Options" to DEFAULT_NOSNIFF,
                "Content-Security-Policy" to htmlCsp(nonce, imageOrigins),
                "Referrer-Policy" to DEFAULT_REFERRER_POLICY,
                "X-Robots-Tag" to DEFAULT_ROBOTS_TAG,
            )
        }

        ResponseCategory.REST -> {
            mapOf(
                "Strict-Transport-Security" to DEFAULT_HSTS,
                "X-Content-Type-Options" to DEFAULT_NOSNIFF,
                "Referrer-Policy" to DEFAULT_REFERRER_POLICY,
                "X-Robots-Tag" to DEFAULT_ROBOTS_TAG,
            )
        }

        ResponseCategory.BINARY -> {
            mapOf(
                "Strict-Transport-Security" to DEFAULT_HSTS,
                "X-Content-Type-Options" to DEFAULT_NOSNIFF,
            )
        }
    }

/**
 * Merge [securityHeadersFor] defaults into this response, with call-site headers taking
 * precedence. The override order lets specific endpoints (e.g. an iframe-served session-status
 * page) opt out of `X-Frame-Options: SAMEORIGIN` by writing the conflicting value themselves;
 * the common case (Content-Type / Cache-Control / Set-Cookie) does not collide with any security
 * header so both sets coexist.
 *
 * Pass [nonce] when the response body contains inline `<style>` or `<script>` — the CSP is then
 * expanded with `'nonce-X'` for those source directives so the inline blocks (which MUST carry
 * the matching `nonce="X"` attribute) execute.
 *
 * Pass [imageOrigins] when the HTML references theme-supplied images on other origins; the CSP
 * `img-src` is extended with exactly those origins (see [htmlCsp]).
 */
internal fun GenericHttpResponse.withSecurityHeaders(
    category: ResponseCategory,
    nonce: String? = null,
    imageOrigins: Set<String> = emptySet(),
): GenericHttpResponse = copy(headers = securityHeadersFor(category, nonce, imageOrigins) + headers)

/**
 * Pick the [ResponseCategory] for a response by inspecting its `Content-Type`. Used by the
 * per-area HTTP adapter to apply [securityHeadersFor] uniformly without each endpoint needing to
 * declare its category. Unknown / missing Content-Type falls back to [ResponseCategory.REST]
 * (the safest default since the REST set carries every header that applies independently of
 * content shape: HSTS + nosniff + Referrer-Policy + X-Robots-Tag).
 */
internal fun GenericHttpResponse.responseCategoryFromContentType(): ResponseCategory {
    val ct = (headers["Content-Type"] ?: headers["content-type"])?.lowercase() ?: return ResponseCategory.REST
    return when {
        ct.startsWith("text/html") -> ResponseCategory.HTML

        ct.startsWith("image/") ||
            ct.startsWith("font/") ||
            ct.startsWith("audio/") ||
            ct.startsWith("video/") ||
            ct.startsWith("application/octet-stream") ||
            ct.startsWith("application/wasm") ||
            ct.startsWith("application/font") -> ResponseCategory.BINARY

        else -> ResponseCategory.REST
    }
}

/**
 * Read `X-Forwarded-Proto` and project to `https` / `http`. Untrusted by itself: any client can
 * send this header. Callers SHOULD prefer [effectiveScheme] which consults the configured
 * issuer first and only falls back to this header when the operator has explicitly opted in
 * via [com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.trustForwardedHeaders].
 */
internal fun GenericHttpRequest.forwardedScheme(): String {
    val proto =
        headers["x-forwarded-proto"]
            ?: headers["X-Forwarded-Proto"]
            ?: headers["X-FORWARDED-PROTO"]
    return if (proto.equals("https", ignoreCase = true)) "https" else "http"
}

internal fun GenericHttpRequest.hostHeader(): String = headers["host"] ?: headers["Host"] ?: "localhost"

/**
 * Resolve the outbound URL scheme defended against header injection.
 *
 * Resolution order:
 *   1. If the server config carries an `issuer`, parse its scheme. Operator-controlled, no
 *      attacker influence.
 *   2. Else if `trustForwardedHeaders` is `true`, read `X-Forwarded-Proto` (legacy behavior;
 *      safe only when a single trusted reverse proxy terminates the request). A one-time WARN
 *      is emitted on first use to flag that the deployment is exposed to header-injection
 *      rewrites of the issuer scheme.
 *   3. Else default to `https`. With no issuer and no header trust the AS cannot know the
 *      transport scheme; `https` is the safest assumption (cookies get `Secure`, browsers
 *      refuse to send them on HTTP — operator notices and configures issuer).
 */
internal fun GenericHttpRequest.effectiveScheme(configProvider: OAuth2ServersConfigProvider): String {
    val server = configProvider.serverConfig
    val configuredScheme = server.issuer?.let { schemeFromUrlOrNull(it) }
    if (configuredScheme != null) return configuredScheme
    if (server.trustForwardedHeaders) {
        warnUntrustedHeaderFallbackOnce()
        return forwardedScheme()
    }
    return "https"
}

/**
 * One-time WARN flagging the unsafe header-trust fallback. Operators with `issuer` unset and
 * `trustForwardedHeaders=true` (the legacy default) accept a class of attack where an upstream
 * actor can rewrite `X-Forwarded-Proto` / `Host` to make the AS mint tokens with an attacker-
 * chosen `iss`. Logging once per JVM at the first vulnerable request is enough for operator
 * visibility without per-request log spam.
 *
 * `Volatile` semantics on the flag are not portable across all KMP targets and the worst-case
 * race here is a duplicated WARN line on the first concurrent burst of requests on a fresh JVM,
 * which is harmless. Plain `var` with a non-atomic read/write is acceptable.
 */
private var unsafeFallbackWarned: Boolean = false

private fun warnUntrustedHeaderFallbackOnce() {
    if (!unsafeFallbackWarned) {
        unsafeFallbackWarned = true
        Log.app().withTag("oauth2.security").warn(
            "OAuth2 server has no `issuer` configured and `trustForwardedHeaders=true`. " +
                "Outbound URLs are derived from `X-Forwarded-Proto` / `Host` request headers, " +
                "which are attacker-controlled in deployments where the AS is not strictly " +
                "behind a single trusted reverse proxy. Set `oauth2.servers.<as-id>.issuer` " +
                "to a fixed external URL (recommended) or set `trustForwardedHeaders=false` " +
                "to refuse header-derived scheme/host resolution.",
        )
    }
}

/**
 * Resolve the outbound host header defended against header injection. Same precedence as
 * [effectiveScheme]: configured issuer wins; absent that, the legacy `Host` header is honored
 * only when `trustForwardedHeaders` is true; otherwise falls back to `localhost` so the
 * operator notices the misconfiguration and sets [com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.issuer].
 */
internal fun GenericHttpRequest.effectiveHost(configProvider: OAuth2ServersConfigProvider): String {
    val server = configProvider.serverConfig
    val configuredHost = server.issuer?.let { hostFromUrlOrNull(it) }
    if (configuredHost != null) return configuredHost
    return if (server.trustForwardedHeaders) hostHeader() else "localhost"
}

/**
 * Parse the scheme from an absolute URL (e.g. `https://as.example.com/auth` → `https`). Returns
 * null when the input does not begin with a `<scheme>://` prefix.
 */
private fun schemeFromUrlOrNull(url: String): String? {
    val sep = url.indexOf("://")
    if (sep <= 0) return null
    return url.substring(0, sep).lowercase().takeIf { it.isNotEmpty() }
}

/**
 * Parse the authority (host + optional port) from an absolute URL. Strips path / query / fragment.
 * Returns null when the input does not begin with a `<scheme>://<authority>` prefix.
 */
private fun hostFromUrlOrNull(url: String): String? {
    val sep = url.indexOf("://")
    if (sep <= 0) return null
    val rest = url.substring(sep + 3)
    val pathStart = rest.indexOfFirst { it == '/' || it == '?' || it == '#' }
    val authority = if (pathStart < 0) rest else rest.substring(0, pathStart)
    return authority.takeIf { it.isNotEmpty() }
}

/**
 * Resolve the base URL for outbound URLs (issuer / redirect / etc.). Prefers the configured
 * issuer (correct behind reverse proxies that strip path prefixes); otherwise reconstructs from
 * [effectiveScheme] + [effectiveHost] which honor the
 * [com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.trustForwardedHeaders] gate.
 */
fun GenericHttpRequest.resolveBaseUrl(
    configProvider: OAuth2ServersConfigProvider,
    tenantPath: String? = null,
): String {
    val configuredIssuer = configProvider.serverConfig.issuer?.trimEnd('/')
    if (configuredIssuer != null) {
        return if (tenantPath != null) "$configuredIssuer/$tenantPath" else configuredIssuer
    }
    val host = effectiveHost(configProvider)
    val scheme = effectiveScheme(configProvider)
    return if (tenantPath != null) "$scheme://$host/$tenantPath" else "$scheme://$host"
}

/**
 * True when [candidate] is an absolute URL on the same origin as [trustedBase] (scheme + host +
 * optional issuer path) AND its path contains `/authorize/callback`. Used to reject a reflected,
 * off-origin `return_url` before it reaches a form action or post-login resume.
 *
 * The `startsWith("$base/")` check (with the explicit trailing slash on a trailing-slash-trimmed
 * base) is robust against host-suffix (`as.example.org.evil.com`), userinfo (`as.example.org@evil`),
 * and query-param prefix-spoof (`evil/?x=<base>`) attacks: none of those continue with `/` directly
 * after the trusted origin string.
 */
internal fun isSameOriginCallback(
    candidate: String,
    trustedBase: String,
): Boolean {
    // Scheme and host are case-insensitive (RFC 3986 §3.1/§3.2.2). Normalize both sides before the
    // origin prefix check so a mixed-case but same-origin callback is not spuriously rejected.
    val normalizedCandidate = candidate.lowercase()
    val base = trustedBase.trimEnd('/').lowercase()
    if (base.isEmpty()) return false
    if (!normalizedCandidate.startsWith("$base/")) return false
    val path = normalizedCandidate.substringBefore('?').substringBefore('#')
    return path.contains("/authorize/callback")
}

/**
 * Build the full request URL used for DPoP `htu` binding (RFC 9449 §4.2).
 *
 * The wallet computes `htu` from the URL it actually targeted; the AS must reconstruct the same
 * URL from its inbound request. When the AS sits behind a path-stripping reverse proxy the
 * inbound `path` no longer carries the deployment's external prefix, so reconstructing from
 * `scheme + host + path` alone yields the wrong URL. When [configProvider] is supplied and the
 * server has an `issuer` configured, that issuer is the canonical external root (scheme + host
 * + any path prefix) and the inbound path is appended to it. Otherwise we fall back to
 * [effectiveScheme] + [effectiveHost] + path which honor the
 * [com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.trustForwardedHeaders] gate.
 */
internal fun GenericHttpRequest.buildFullUrl(configProvider: OAuth2ServersConfigProvider? = null): String {
    val configuredIssuer = configProvider?.serverConfig?.issuer?.trimEnd('/')
    if (configuredIssuer != null) {
        return "$configuredIssuer$path"
    }
    if (configProvider == null) {
        // Legacy callers (no config). Fall back to the unguarded header-derived shape so we do
        // not silently change behavior for callers that have not yet adopted the configProvider.
        val host = hostHeader()
        val scheme = forwardedScheme()
        return "$scheme://$host$path"
    }
    val host = effectiveHost(configProvider)
    val scheme = effectiveScheme(configProvider)
    return "$scheme://$host$path"
}

/**
 * Parse a form-encoded request body into a multi-value map. Format:
 * `key1=value1&key2=value2&key2=value3`. Returns `Map<String, List<String>>` to support repeated
 * parameters (e.g., `resource=A&resource=B` per RFC 8693 / RFC 8707).
 */
internal fun parseFormBody(body: String?): Map<String, List<String>>? {
    if (body == null || body.isBlank()) {
        return null
    }
    return try {
        body
            .split('&')
            .mapNotNull { param ->
                val parts = param.split('=', limit = 2)
                if (parts.size == 2) {
                    parts[0].percentDecode(plusAsSpace = true) to parts[1].percentDecode(plusAsSpace = true)
                } else {
                    null
                }
            }.groupBy({ it.first }, { it.second })
    } catch (_: Exception) {
        null
    }
}

/**
 * Returns `true` if the client authenticated (or attempted to) via HTTP Basic. `/token` uses it
 * to distinguish Basic-auth 401 responses from non-HTTP client-auth failures (400); introspection
 * and revocation challenge every 401, even when no credentials were sent.
 */
internal fun isBasicAuthorizationHeaderInternal(headers: Map<String, String>): Boolean {
    val auth = headers["Authorization"] ?: headers["authorization"] ?: return false
    return auth.trim().startsWith("Basic ", ignoreCase = true)
}

/**
 * Ensure every 401 from a client-authenticated OAuth endpoint carries an applicable HTTP
 * authentication challenge. Introspection and revocation require a challenge even when credentials
 * are absent; an existing scheme-specific challenge is retained.
 */
internal fun GenericHttpResponse.withWwwAuthenticateIfBasicInternal(basicWasAttempted: Boolean): GenericHttpResponse {
    if (!basicWasAttempted) return this
    return withWwwAuthenticateIfMissingInternal()
}

internal fun GenericHttpResponse.withWwwAuthenticateIfMissingInternal(): GenericHttpResponse {
    if (statusCode != 401) return this
    if (headers.keys.any { it.equals("WWW-Authenticate", ignoreCase = true) }) return this
    return copy(headers = headers + ("WWW-Authenticate" to "Basic realm=\"oauth2\""))
}

/**
 * Render a pre-redirect /authorize error as a simple HTML page. RFC 6749 §4.1.2.1 explicitly
 * forbids redirecting on missing/invalid client_id or redirect_uri — the user-agent stays on
 * the AS, so a JSON body in the browser address bar is the wrong shape. Browsers see HTML;
 * machine clients (curl, conformance harness) still see the same `error` / `error_description`
 * tuple in the body — just rendered as readable text rather than a JSON document.
 *
 * The user-facing copy is written for an end user who landed here unexpectedly: a plain-
 * English sentence per error code, plus a hint to return to the originating app. Operator-
 * facing detail (the raw `error` code, full `error_description` including spec URNs, and
 * request-shape params like `client_id` / `redirect_uri` / `scope`) is tucked behind a
 * `<details>` toggle so it's available for support without dumping it on every visitor.
 */
internal fun oauth2HtmlErrorPage(
    statusCode: Int,
    error: String,
    errorDescription: String? = null,
    requestParams: Map<String, String> = emptyMap(),
): GenericHttpResponse {
    val invalidRequestMessage =
        "The application sent a request the authorization server couldn't process. " +
            "This often happens when a sign-in attempt has been reused, has expired, or was tampered with."
    val friendlyMessage =
        when (error) {
            "invalid_request" -> invalidRequestMessage
            "invalid_client" -> "The application isn't recognized by this authorization server."
            "unauthorized_client" -> "The application isn't permitted to make this kind of request."
            "access_denied" -> "Access was denied. You may have cancelled the sign-in, or the server declined to grant the requested permissions."
            "unsupported_response_type" -> "The application asked for a response type this server doesn't support."
            "invalid_scope" -> "The application requested permissions this server doesn't recognize."
            "server_error" -> "Something went wrong on the authorization server. Please try again in a moment."
            "temporarily_unavailable" -> "The authorization server is temporarily unavailable. Please try again in a moment."
            "login_required", "interaction_required", "consent_required" -> "Sign-in is required to continue. Return to the application and start over."
            else -> "The authorization server couldn't complete this request."
        }
    val safeFriendly = htmlEscape(friendlyMessage)
    val safeError = htmlEscape(error)
    val safeDesc = errorDescription?.let { htmlEscape(it) } ?: ""
    // Per-response CSP nonce — stamps both the inline <style> and inline <script> below so the
    // strict `default-src 'self'` policy emitted by [withSecurityHeaders] permits exactly these
    // two blocks and nothing else (no XSS payload can guess the nonce).
    val nonce = newCspNonce()
    val safeNonce = htmlEscape(nonce)
    val descRow =
        if (safeDesc.isNotEmpty()) {
            "<dt>error_description</dt><dd><code>$safeDesc</code></dd>"
        } else {
            ""
        }

    // Surface the most useful request-shape params in the technical details — anything else
    // would crowd the panel without helping diagnose the typical failure modes.
    val interestingParamKeys = listOf("client_id", "redirect_uri", "scope", "response_type", "request_uri", "state")
    val paramRows =
        interestingParamKeys
            .mapNotNull { k -> requestParams[k]?.takeIf { it.isNotBlank() }?.let { k to it } }
            .joinToString("") { (k, v) ->
                "<dt>${htmlEscape(k)}</dt><dd><code>${htmlEscape(v)}</code></dd>"
            }

    val body =
        """
        <!doctype html>
        <html lang="en"><head><meta charset="utf-8">
        <title>Authorization error</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style nonce="$safeNonce">
        body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#202537;color:#fbfbfb;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:32px}
        .card{background:#fbfbfb;color:#303030;border-radius:8px;padding:48px;max-width:600px;width:100%;border:1px solid #c4c4c4;position:relative;overflow:hidden}
        .card::before{content:'';position:absolute;top:0;left:0;right:0;height:8px;background:linear-gradient(172deg,#7276f7 0%,#7c40e8 100%)}
        h1{margin:0 0 16px;font-size:22px;font-weight:600}
        .desc{margin:0 0 12px;color:#4a4d6b;font-size:14px;line-height:1.5}
        .return{margin-top:24px;color:#4a4d6b;font-size:14px;line-height:1.5}
        details{margin-top:28px;border-top:1px solid #e3e3ea;padding-top:16px}
        summary{cursor:pointer;color:#7276f7;font-size:13px;font-weight:500;outline:none;user-select:none}
        summary:hover{color:#5a5fd1}
        details[open] summary{margin-bottom:12px}
        .details-actions{display:flex;justify-content:flex-end;margin:0 0 8px}
        .copy-btn{display:inline-flex;align-items:center;gap:6px;background:none;border:1px solid #d4d4dc;color:#6c6f8a;font-size:12px;font-family:inherit;padding:4px 10px;border-radius:4px;cursor:pointer;transition:all .15s ease}
        .copy-btn:hover{background:#f5f5fa;color:#303030;border-color:#a8a8b8}
        .copy-btn.copied{color:#2d8f4f;border-color:#2d8f4f;background:#eef9f2}
        .copy-btn svg{width:13px;height:13px}
        dl{margin:8px 0 0;display:grid;grid-template-columns:max-content 1fr;gap:6px 14px;font-size:13px}
        dt{color:#6c6f8a;font-weight:500}
        dd{margin:0;word-break:break-all}
        code{background:#f0f0f5;padding:2px 6px;border-radius:4px;font-size:12.5px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
        </style></head>
        <body><div class="card">
        <h1>Authorization request failed</h1>
        <p class="desc">$safeFriendly</p>
        <p class="return">Return to the application that started this flow and try again.</p>
        <details>
        <summary>Technical details</summary>
        <div class="details-actions">
        <button type="button" class="copy-btn" id="copy-details" aria-label="Copy technical details as JSON">
        <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <rect x="5" y="5" width="9" height="9" rx="1.5"/>
        <path d="M3 11V3.5A1.5 1.5 0 0 1 4.5 2H11"/>
        </svg>
        <span class="copy-btn-label">Copy as JSON</span>
        </button>
        </div>
        <dl id="tech-details">
        <dt>timestamp</dt><dd><code>${kotlin.time.Clock.System.now()}</code></dd>
        <dt>error</dt><dd><code>$safeError</code></dd>
        $descRow
        $paramRows
        </dl>
        </details>
        </div>
        <script nonce="$safeNonce">
        (function(){
            var btn = document.getElementById('copy-details');
            var dl = document.getElementById('tech-details');
            if (!btn || !dl) return;
            btn.addEventListener('click', function(){
                var entries = {};
                var nodes = dl.children;
                var key = null;
                for (var i = 0; i < nodes.length; i++) {
                    var el = nodes[i];
                    if (el.tagName === 'DT') {
                        key = el.textContent.trim();
                    } else if (el.tagName === 'DD' && key !== null) {
                        entries[key] = el.textContent.trim();
                        key = null;
                    }
                }
                var json = JSON.stringify(entries, null, 2);
                var label = btn.querySelector('.copy-btn-label');
                var done = function(){
                    btn.classList.add('copied');
                    if (label) label.textContent = 'Copied';
                    setTimeout(function(){
                        btn.classList.remove('copied');
                        if (label) label.textContent = 'Copy as JSON';
                    }, 1800);
                };
                if (navigator.clipboard && navigator.clipboard.writeText) {
                    navigator.clipboard.writeText(json).then(done, function(){ fallback(json, done); });
                } else {
                    fallback(json, done);
                }
            });
            function fallback(text, onDone){
                var ta = document.createElement('textarea');
                ta.value = text;
                ta.setAttribute('readonly', '');
                ta.style.position = 'absolute';
                ta.style.left = '-9999px';
                document.body.appendChild(ta);
                ta.select();
                try { document.execCommand('copy'); onDone(); }
                catch (e) { /* clipboard unavailable; leave the button untouched */ }
                document.body.removeChild(ta);
            }
        })();
        </script>
        </body></html>
        """.trimIndent()
    return GenericHttpResponse(
        statusCode = statusCode,
        headers =
            mapOf(
                "Content-Type" to "text/html;charset=UTF-8",
                "Cache-Control" to "no-store",
                "Pragma" to "no-cache",
            ),
        body = body,
    ).withSecurityHeaders(ResponseCategory.HTML, nonce = nonce)
}

private fun htmlEscape(s: String): String =
    buildString(s.length) {
        for (c in s) {
            when (c) {
                '&' -> append("&amp;")
                '<' -> append("&lt;")
                '>' -> append("&gt;")
                '"' -> append("&quot;")
                '\'' -> append("&#39;")
                else -> append(c)
            }
        }
    }

/**
 * Build an RFC 6749 §5.2-conformant OAuth2 error response: `application/json`,
 * `Cache-Control: no-store`, `Pragma: no-cache`, body with `error` and optional
 * `error_description`.
 */
internal fun oauth2ErrorResponse(
    statusCode: Int,
    error: String,
    errorDescription: String? = null,
    jsonFormat: Json,
): GenericHttpResponse {
    val errorBody =
        buildMap {
            put("error", error)
            if (errorDescription != null) {
                put("error_description", errorDescription)
            }
        }
    return GenericHttpResponse(
        statusCode = statusCode,
        headers =
            mapOf(
                "Content-Type" to "application/json",
                "Cache-Control" to "no-store",
                "Pragma" to "no-cache",
            ),
        body = jsonFormat.encodeToString(errorBody),
    ).withSecurityHeaders(ResponseCategory.REST)
}

/**
 * Cookie name carrying the opaque `oidc_login_sid` browser-login session id between the
 * authorization endpoint and subsequent requests. Bound to the AS host, `HttpOnly` and
 * `SameSite=Lax`; `Secure` is asserted when the resolved scheme is HTTPS.
 */
internal const val OIDC_LOGIN_COOKIE_NAME: String = "oidc_login_sid"

/**
 * Read the `oidc_login_sid` cookie value from a `Cookie` header, if present. Returns `null` when
 * no cookie header is present, the header is malformed, or the named cookie is absent. Does not
 * URL-decode beyond simple split semantics: the session id is generated as URL-safe base64 by
 * the AS, so no encoding is applied on write either.
 */
internal fun GenericHttpRequest.loginSessionCookieValue(): String? {
    val header = headers["cookie"] ?: headers["Cookie"] ?: return null
    return header
        .splitToSequence(';')
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .mapNotNull { entry ->
            val eq = entry.indexOf('=')
            if (eq <= 0) {
                null
            } else {
                val name = entry.substring(0, eq).trim()
                val value = entry.substring(eq + 1).trim()
                if (name == OIDC_LOGIN_COOKIE_NAME) value else null
            }
        }.firstOrNull()
        ?.takeIf { it.isNotBlank() }
}

/**
 * Build the `Set-Cookie` header value for the `oidc_login_sid` cookie. Always `HttpOnly` and
 * `SameSite=Lax` (OIDC redirect flows are top-level navigations, not third-party); [secure] is
 * driven by the resolved request scheme so local HTTP development remains functional.
 *
 * The cookie is host-bound (no `Domain` attribute) and scoped to `Path=/` so it applies to
 * `/authorize`, `/authorize/callback`, and any future logout endpoint mounted on the same host.
 */
internal fun loginSessionCookieHeader(
    sessionId: String,
    secure: Boolean,
): String {
    val attrs =
        buildList {
            add("$OIDC_LOGIN_COOKIE_NAME=$sessionId")
            add("Path=/")
            add("HttpOnly")
            add("SameSite=Lax")
            if (secure) add("Secure")
        }
    return attrs.joinToString("; ")
}

/**
 * Cookie name carrying the per-render `tab_id` used as the cookie-bound half of the login
 * form's CSRF defense. Set on `GET /login`, read on `POST /login`. Path is scoped to
 * `/login` so it's not exposed to the rest of the AS surface, and the cookie is scrubbed
 * (set with `Max-Age=0`) on successful submit so it doesn't outlive the form round-trip.
 */
internal const val OIDC_LOGIN_CSRF_COOKIE_NAME: String = "oidc_login_csrf"

/**
 * Read the `oidc_login_csrf` cookie value from a `Cookie` header, if present. Mirrors
 * [loginSessionCookieValue] but extracts the CSRF tab-binding cookie instead.
 */
internal fun GenericHttpRequest.loginCsrfCookieValue(): String? {
    val header = headers["cookie"] ?: headers["Cookie"] ?: return null
    return header
        .splitToSequence(';')
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .mapNotNull { entry ->
            val eq = entry.indexOf('=')
            if (eq <= 0) {
                null
            } else {
                val name = entry.substring(0, eq).trim()
                val value = entry.substring(eq + 1).trim()
                if (name == OIDC_LOGIN_CSRF_COOKIE_NAME) value else null
            }
        }.firstOrNull()
        ?.takeIf { it.isNotBlank() }
}

/**
 * Build the `Set-Cookie` header value for the `oidc_login_csrf` cookie. `HttpOnly` so JS
 * cannot read or write it, `SameSite=Strict` because the login form POST is always
 * same-origin and there's no legitimate cross-site reason for the cookie to travel.
 * `Path=/login` confines the cookie's scope to the login surface only — no point in
 * sending it to `/token`, `/jwks`, etc.
 */
internal fun loginCsrfCookieHeader(
    tabId: String,
    secure: Boolean,
    path: String,
): String {
    require(path.startsWith('/') && ';' !in path && '\r' !in path && '\n' !in path) {
        "Login CSRF cookie path must be an absolute safe path"
    }
    val attrs =
        buildList {
            add("$OIDC_LOGIN_CSRF_COOKIE_NAME=$tabId")
            add("Path=$path")
            add("HttpOnly")
            add("SameSite=Strict")
            if (secure) add("Secure")
        }
    return attrs.joinToString("; ")
}

/**
 * Build a `Set-Cookie` header value that scrubs the `oidc_login_csrf` cookie (`Max-Age=0`).
 * Emitted on successful `POST /login` so the one-shot cookie doesn't outlive the form
 * round-trip — defense in depth against a downstream XSS or referrer leak harvesting it.
 */
internal fun loginCsrfCookieScrubHeader(
    secure: Boolean,
    path: String,
): String {
    require(path.startsWith('/') && ';' !in path && '\r' !in path && '\n' !in path) {
        "Login CSRF cookie path must be an absolute safe path"
    }
    val attrs =
        buildList {
            add("$OIDC_LOGIN_CSRF_COOKIE_NAME=")
            add("Path=$path")
            add("HttpOnly")
            add("SameSite=Strict")
            add("Max-Age=0")
            if (secure) add("Secure")
        }
    return attrs.joinToString("; ")
}

/** Resolve the externally visible login path from the trusted authorization-server base URL. */
internal fun loginCsrfCookiePath(trustedBaseUrl: String): String {
    val basePath = Url(trustedBaseUrl).encodedPath.trimEnd('/')
    return if (basePath.isEmpty()) "/login" else "$basePath/login"
}

/**
 * Per-code mapping from known AS/core errors to wire OAuth codes. Endpoint context selects the
 * client-auth status; unrecognized errors are sanitized as server failures.
 */
internal enum class OAuth2ErrorEndpoint { TOKEN, INTROSPECTION, REVOCATION, OTHER }

private val OAUTH2_ERROR_MAPPING: Map<String, String> =
    mapOf(
        "invalid_request" to "invalid_request",
        "invalid_client" to "invalid_client",
        "unauthorized_client" to "unauthorized_client",
        "invalid_grant" to "invalid_grant",
        "unsupported_grant_type" to "unsupported_grant_type",
        "invalid_scope" to "invalid_scope",
        "invalid_target" to "invalid_target",
        "access_denied" to "access_denied",
        "unsupported_response_type" to "unsupported_response_type",
        "request_not_supported" to "request_not_supported",
        "request_uri_not_supported" to "request_uri_not_supported",
        "invalid_request_object" to "invalid_request_object",
        "invalid_request_uri" to "invalid_request_uri",
        "invalid_authorization_details" to "invalid_authorization_details",
        "insufficient_user_authentication" to "insufficient_user_authentication",
        "interaction_required" to "interaction_required",
        "temporarily_unavailable" to "temporarily_unavailable",
        "invalid_dpop_proof" to "invalid_dpop_proof",
        "use_dpop_nonce" to "use_dpop_nonce",
        "invalid_client_attestation" to "invalid_client_attestation",
        "use_attestation_challenge" to "use_attestation_challenge",
        "use_fresh_attestation" to "use_fresh_attestation",
        // RFC 8628 §3.5 token-endpoint error codes for the device-code grant. All four return
        // HTTP 400 per RFC 6749 §5.2 with the literal wire `error` code; the spec does not define
        // separate status codes for the polling lifecycle.
        "authorization_pending" to "authorization_pending",
        "slow_down" to "slow_down",
        "expired_token" to "expired_token",
        "server_error" to "server_error",
        "storage_error" to "server_error",
        "session_not_found" to "invalid_request",
        "client_not_found" to "invalid_client",
        "UNAUTHORIZED" to "invalid_client",
        "FORBIDDEN" to "access_denied",
        "ILLEGAL_ARGUMENT_ERROR" to "invalid_request",
        "COMMAND_ARG_NOT_SUPPORTED_ERROR" to "invalid_request",
        "COMMAND_NOT_AUTHORIZED" to "access_denied",
        "COMMAND_DISABLED" to "temporarily_unavailable",
        "TIMEOUT" to "temporarily_unavailable",
        "SERVICE_UNAVAILABLE" to "temporarily_unavailable",
    )

/**
 * Map an [IdkError] to an HTTP response. Uses error codes from `AuthorizationServerError`
 * (preserved through [IdkError]).
 *
 * RFC 9449 §8: when the error is `use_dpop_nonce`, the fresh nonce travels through `meta`
 * (key `dpop_nonce`) and is rendered as a `DPoP-Nonce` response header so the client can
 * retry the request with the current nonce.
 *
 * When [execution] is supplied, logs retain the resolved status, OAuth2 code, IDK code, and
 * message key. Error text and metadata are deliberately omitted because they may contain secrets.
 */
internal fun mapOAuth2ErrorToResponse(
    error: IdkError,
    jsonFormat: Json,
    execution: com.sphereon.core.api.context.SessionExecution? = null,
    endpoint: OAuth2ErrorEndpoint = OAuth2ErrorEndpoint.OTHER,
    httpAuthenticationAttempted: Boolean = false,
): GenericHttpResponse {
    // A generic core authorization refusal at /token means the presented grant is not acceptable.
    // Keep protocol errors with explicit codes (including RFC 8628 access_denied) unchanged.
    val endpointAwareErrorCode =
        when (error.code) {
            "FORBIDDEN", "COMMAND_NOT_AUTHORIZED" ->
                if (endpoint == OAuth2ErrorEndpoint.TOKEN) "invalid_grant" else "access_denied"
            else -> OAUTH2_ERROR_MAPPING[error.code]
        }
    val errorCode = endpointAwareErrorCode
    val isTemporaryFailure = errorCode == "temporarily_unavailable"
    val isServerFailure = errorCode == "server_error" || errorCode == null
    val clientAuthenticationFailure = errorCode == "invalid_client"
    val status =
        when {
            isTemporaryFailure -> 503
            isServerFailure -> 500
            clientAuthenticationFailure && endpoint in setOf(OAuth2ErrorEndpoint.INTROSPECTION, OAuth2ErrorEndpoint.REVOCATION) -> 401
            clientAuthenticationFailure && endpoint == OAuth2ErrorEndpoint.TOKEN && httpAuthenticationAttempted -> 401
            else -> 400
        }
    val wireError = if (isServerFailure) "server_error" else errorCode!!
    val errorDescription =
        when {
            isTemporaryFailure -> "The authorization server is temporarily unavailable."
            isServerFailure -> "An unexpected error occurred."
            else -> null
        }
    val response = oauth2ErrorResponse(status, wireError, errorDescription, jsonFormat)
    if (execution != null) {
        val log = execution.log.logManager.withTag("OAuth2HttpResponses")
        // The reason names the refused check (for example which token-exchange rule failed); the wire
        // response keeps it out of error_description, so this log line is the only place it surfaces.
        log.warn(
            "OAuth2 error response status=${response.statusCode} oauth2_error=$wireError idk_code=${error.code} " +
                "error_key=${error.message.i18nKey} reason=${error.message.defaultMessage}",
        )
    }
    if (error.code == "use_dpop_nonce") {
        val freshNonce = error.meta["dpop_nonce"] as? String
        if (freshNonce != null) {
            return response.copy(headers = response.headers + ("DPoP-Nonce" to freshNonce))
        }
    }
    if (error.code == "use_attestation_challenge") {
        val challenge = error.meta["attestation_challenge"] as? String
        if (challenge != null) {
            return response.copy(headers = response.headers + ("OAuth-Client-Attestation-Challenge" to challenge))
        }
    }
    return response
}
