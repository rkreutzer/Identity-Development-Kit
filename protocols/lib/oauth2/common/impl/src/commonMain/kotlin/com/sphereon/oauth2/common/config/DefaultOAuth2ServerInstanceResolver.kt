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

package com.sphereon.oauth2.common.config

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

/**
 * Default IDK implementation: matches the request URL against each configured
 * server's `issuer`, then `issuerTemplate`. Single-AS deployments short-circuit
 * to the only configured id. Multi-AS deployments fall back to
 * [OAuth2ServersConfig.defaultServer] when no discriminator matches.
 *
 * Issuer matching is segment-aware: the issuer `/as/acme` covers `/as/acme` and `/as/acme/...`,
 * never `/as/acme2`.
 *
 * A request under a sibling issuer path of a configured issuer (`/as/new` next to `/as/default`)
 * names a server this view may not contain yet, so the configuration is reloaded from its backing
 * stores once. When no server is hosted at that path after the reload the request resolves to a
 * [IdkError.NOT_FOUND_ERROR]: serving it as the default server would answer under the wrong
 * issuer. Requests outside issuer paths (`/token`, root `/.well-known/...`) keep the default server.
 *
 * A URL that names an issuer path (`/.well-known/<metadata>/<issuer-path>`,
 * `/<issuer-path>/.well-known/<metadata>` or `/as/{issuer}/...`) is answered only by the server
 * whose issuer has exactly that path, after at most one reload. It never falls back to the single,
 * default or bare-origin server, so the platform tenant's bare-origin server answers its own bare
 * URLs only.
 *
 * Tenant-aware routing strategies are contributed by higher layers via a
 * binding that replaces this default.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<OAuth2ServerInstanceResolver>())
class DefaultOAuth2ServerInstanceResolver(
    private val configProvider: OAuth2ServersConfigProvider,
) : OAuth2ServerInstanceResolver {
    override suspend fun resolve(request: GenericHttpRequest): IdkResult<String, IdkError> {
        // A URL that names an issuer path (metadata suffix or prefix form, or `/as/{issuer}`) is
        // answered only by the server whose issuer has exactly that path. It never falls back to
        // the single, default or bare-origin server. The host is not compared: east-west calls
        // carry the platform host while naming the tenant issuer path.
        namedIssuerPath(request.path)?.let { named ->
            val current = configProvider.getConfig()
            val selected = current.serverPublishing(named) ?: configProvider.reloadConfig().serverPublishing(named)
            if (selected != null) return Ok(selected)
            // A server without a static issuer or template takes its identity from the request
            // (the base URL resolver), so configuration cannot tell which path it owns; leave
            // that deployment shape to the selection below. Statically issued servers fail closed.
            if (configProvider.getConfig().servers.values.none { it.issuer == null && it.issuerTemplate == null }) {
                return Err(IdkError.NOT_FOUND_ERROR(message = "No authorization server is hosted at issuer path '$named'"))
            }
        }

        val requestUrl = request.requestUrl()
        val current = configProvider.getConfig()
        val all =
            if (current.matchingServerId(requestUrl) == null && current.addressesUnknownSiblingIssuer(requestUrl)) {
                configProvider.reloadConfig()
            } else {
                current
            }
        val instances = all.servers

        val match = all.matchingServerId(requestUrl)
        if (match != null) {
            return Ok(match)
        }

        if (all.addressesUnknownSiblingIssuer(requestUrl)) {
            return Err(
                IdkError.NOT_FOUND_ERROR(message = "No authorization server is hosted at '$requestUrl'"),
            )
        }

        if (instances.size == 1) {
            return Ok(instances.keys.single())
        }

        val defaultId = all.defaultServer
        if (instances.containsKey(defaultId)) {
            return Ok(defaultId)
        }

        return Err(
            IdkError.INVALID_STATE(
                message =
                    "Cannot resolve OAuth2 AS instance for request URL '$requestUrl' " +
                        "(configured ids: ${instances.keys}, defaultServer '$defaultId' not in servers map).",
            ),
        )
    }

    /** Id of the server whose issuer (or issuer template) path is exactly [issuerPath]. */
    private fun OAuth2ServersConfig.serverPublishing(issuerPath: String): String? =
        servers.entries.firstOrNull { (_, cfg) ->
            cfg.issuer?.let { pathOf(it) == issuerPath } == true ||
                cfg.issuerTemplate?.let { templatePathRegex(it).matches(issuerPath) } == true
        }?.key

    private fun OAuth2ServersConfig.matchingServerId(requestUrl: String): String? =
        servers.entries.firstOrNull { (_, cfg) -> matches(requestUrl, cfg) }?.key

    /**
     * True when [requestUrl] sits directly under the parent path of a configured issuer without
     * being under that issuer itself, e.g. `https://host/as/new/authorize` next to the configured
     * `https://host/as/default`. Issuers at an origin root have no sibling paths.
     */
    private fun OAuth2ServersConfig.addressesUnknownSiblingIssuer(requestUrl: String): Boolean =
        servers.values.any { cfg ->
            val issuer = cfg.issuer?.trimEnd('/') ?: return@any false
            val schemeEnd = issuer.indexOf("://")
            if (schemeEnd < 0) return@any false
            val pathStart = issuer.indexOf('/', schemeEnd + 3)
            if (pathStart < 0) return@any false
            val parent = issuer.substring(0, issuer.lastIndexOf('/'))
            parent.length > pathStart && requestUrl.startsWith("$parent/") && !requestUrl.isUnderIssuer(issuer)
        }

    private fun String.isUnderIssuer(issuer: String): Boolean {
        val base = issuer.trimEnd('/')
        if (!startsWith(base)) return false
        return length == base.length || this[base.length] == '/' || this[base.length] == '?'
    }

    private fun matches(
        requestUrl: String,
        cfg: OAuth2ServerInstanceConfig,
    ): Boolean {
        cfg.issuer?.let { issuer ->
            if (requestUrl.isUnderIssuer(issuer)) return true
        }
        cfg.issuerTemplate?.let { template ->
            if (templateMatches(template, requestUrl)) return true
        }
        return false
    }

    private fun templateMatches(
        template: String,
        requestUrl: String,
    ): Boolean {
        val regexBody =
            buildString {
                var i = 0
                while (i < template.length) {
                    val ch = template[i]
                    if (ch == '{') {
                        val close = template.indexOf('}', i)
                        if (close < 0) {
                            append(escapeRegex(template.substring(i)))
                            break
                        }
                        append("[^/]+")
                        i = close + 1
                    } else {
                        append(escapeRegex(ch.toString()))
                        i++
                    }
                }
            }
        val pattern = Regex("^$regexBody(/.*)?$")
        return pattern.containsMatchIn(requestUrl) || pattern.matches(requestUrl)
    }

    private fun escapeRegex(literal: String): String =
        buildString(literal.length) {
            for (c in literal) {
                if (c in REGEX_META) append('\\')
                append(c)
            }
        }

    private companion object {
        private val REGEX_META = setOf('.', '+', '*', '?', '(', ')', '[', ']', '{', '}', '|', '^', '$', '\\', '/')
    }
}

/**
 * Reconstruct the full request URL from forwarded headers + path so the resolver can
 * compare against `issuer` / `issuerTemplate` discriminators. Mirrors the
 * forwarded-header handling used by the OAuth2 HTTP adapter's `resolveBaseUrl`.
 */
private fun GenericHttpRequest.requestUrl(): String {
    val proto =
        headers["x-forwarded-proto"]
            ?: headers["X-Forwarded-Proto"]
            ?: headers["X-FORWARDED-PROTO"]
    val scheme = if (proto.equals("https", ignoreCase = true)) "https" else "http"
    val host = headers["host"] ?: headers["Host"] ?: "localhost"
    return "$scheme://$host${issuerRelativePath(path)}"
}

private val WELL_KNOWN_METADATA_PATHS =
    listOf(
        "/.well-known/oauth-authorization-server",
        "/.well-known/openid-configuration",
    )

/**
 * RFC 8414 section 3.1 inserts the well-known name between the host and the issuer path, so
 * `/.well-known/oauth-authorization-server/as/acme` describes the issuer `/as/acme`. Removing the
 * inserted name lets such a request match that issuer like every other request under it.
 */
private fun issuerRelativePath(path: String): String =
    WELL_KNOWN_METADATA_PATHS.firstNotNullOfOrNull { wellKnown ->
        path.takeIf { it.startsWith("$wellKnown/") }?.removePrefix(wellKnown)
    } ?: path

/**
 * Issuer path a request URL names, or `null` when it names none. The metadata suffix form
 * (`/.well-known/<name>/<issuer-path>`), the prefix form (`/<issuer-path>/.well-known/<name>`)
 * and the hosted issuer form (`/as/{issuer}/...`) name an issuer; bare URLs such as `/token` or
 * `/.well-known/openid-configuration` do not.
 */
internal fun namedIssuerPath(rawPath: String): String? {
    val path = rawPath.substringBefore('?').substringBefore('#').trimEnd('/')
    for (wellKnown in WELL_KNOWN_METADATA_PATHS) {
        if (path.startsWith("$wellKnown/")) return path.removePrefix(wellKnown).trimEnd('/').takeIf { it.isNotEmpty() }
        if (path.endsWith(wellKnown) && path != wellKnown) return path.removeSuffix(wellKnown).trimEnd('/')
    }
    val segments = path.split('/').filter { it.isNotEmpty() }
    if (segments.size >= 2 && segments[0] == HOSTED_ISSUER_SEGMENT) return "/$HOSTED_ISSUER_SEGMENT/${segments[1]}"
    return null
}

private const val HOSTED_ISSUER_SEGMENT = "as"

/** Path of an issuer identifier, without a trailing slash; empty for a bare origin. */
private fun pathOf(issuer: String): String {
    val trimmed = issuer.trimEnd('/')
    val schemeEnd = trimmed.indexOf("://").takeIf { it >= 0 }?.plus(3) ?: return trimmed
    val pathStart = trimmed.indexOf('/', schemeEnd)
    return if (pathStart < 0) "" else trimmed.substring(pathStart)
}

/** Regex for the path part of an issuer template, each `{placeholder}` matching one segment. */
private fun templatePathRegex(template: String): Regex {
    val path = pathOf(template)
    val body =
        Regex("""\{[^}]*}""").split(path).joinToString("[^/]+") { Regex.escape(it) }
    return Regex("^$body$")
}
