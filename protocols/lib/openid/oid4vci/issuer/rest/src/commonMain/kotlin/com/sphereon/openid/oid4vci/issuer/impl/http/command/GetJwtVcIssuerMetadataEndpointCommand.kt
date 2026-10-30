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

package com.sphereon.openid.oid4vci.issuer.impl.http.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.command.HttpEndpointCommandAdapter
import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.core.api.http.command.requirePathParam
import com.sphereon.core.api.http.describe.EndpointAuthPolicy
import com.sphereon.core.api.http.describe.HttpEndpointDescriptor
import com.sphereon.core.api.http.describe.HttpMethod
import com.sphereon.core.api.http.describe.MediaType
import com.sphereon.core.api.http.response.jsonResponse
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vc.common.DisplayProperties
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.ContributesIntoMap
import dev.zacsweers.metro.StringKey
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.put

/**
 * SD-JWT VC Issuer Metadata endpoint (draft-ietf-oauth-sd-jwt-vc §3.5).
 *
 * Hosted at (per RFC 8615):
 *   - `/.well-known/jwt-vc-issuer`                         (issuer with no path)
 *   - `/.well-known/jwt-vc-issuer/{issuer_path}`           (issuer with a single-segment path,
 *                                                           e.g. `/oid4vci`)
 *
 * The response body is a JSON document:
 * ```
 * {
 *   "issuer": "<credential issuer identifier>",
 *   "jwks":   { "keys": [ ... ] }
 * }
 * ```
 * Each JWK Set entry carries the bare public key material (kty/crv/x/y or kty/n/e)
 * plus a `kid` that is **byte-identical** to the `kid` the issuer writes into the
 * protected header of every SD-JWT credential it signs. Both sides call the same
 * [IssuerKeyIdResolver] — no risk of divergence.
 */
interface GetJwtVcIssuerMetadataRootEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID = "oid4vci.sdjwtvc.issuer-metadata-root"
        val ENDPOINT =
            HttpEndpointDescriptor(
                method = HttpMethod.GET,
                pathPattern = "/.well-known/jwt-vc-issuer",
                produces = setOf(MediaType.ApplicationJson),
                operationId = "getJwtVcIssuerMetadataRoot",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("oid4vci-issuer", "sd-jwt-vc", "metadata"),
                summary = "SD-JWT VC Issuer Metadata (bare — for root-hosted issuers)",
                authPolicy = EndpointAuthPolicy.PUBLIC,
            )
    }
}

interface GetJwtVcIssuerMetadataScopedEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID = "oid4vci.sdjwtvc.issuer-metadata-scoped"
        val ENDPOINT =
            HttpEndpointDescriptor(
                method = HttpMethod.GET,
                pathPattern = "/.well-known/jwt-vc-issuer/{issuer_path}",
                produces = setOf(MediaType.ApplicationJson),
                operationId = "getJwtVcIssuerMetadataScoped",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("oid4vci-issuer", "sd-jwt-vc", "metadata"),
                summary = "SD-JWT VC Issuer Metadata (path-scoped — RFC 8615 insert)",
                authPolicy = EndpointAuthPolicy.PUBLIC,
            )
    }
}

/**
 * Internal factory that builds the JSON body. Reused by both the bare and
 * path-scoped endpoint variants.
 */
private suspend fun buildBody(
    configProvider: Oid4vciIssuerConfigProvider,
    keyIdResolver: IssuerKeyIdResolver,
): IdkResult<JsonObject, IdkError> {
    configProvider.prepare()
    val issuer = configProvider.issuerIdentifier.trimEnd('/')
    if (issuer.isEmpty()) {
        return Err(IdkError.fromString(code = "misconfigured", message = "Issuer identifier is not configured"))
    }

    // Pick the signing-mode to compute kids from. In this demo we only surface
    // credential-level modes; the top-level metadata signing key (if any) is
    // assumed to follow the same mode as credentials. Group aliases by mode so
    // each alias's kid is computed consistently with how it appears in headers.
    val credentialConfigs = configProvider.credentialSigningConfigs()
    val aliases = configProvider.signingKeyNames()
    val aliasToMode: Map<String, SigningKeyMode> =
        aliases.associateWith { alias ->
            // Find the first credential that uses this alias and use its mode; if none,
            // fall back to None (no kid).
            credentialConfigs.values.firstOrNull { it.signingKeyAlias == alias }?.signingKeyMode
                ?: credentialConfigs[alias]?.signingKeyMode
                ?: SigningKeyMode.None
        }

    val keys =
        aliases.mapNotNull { alias ->
            val publicJwk =
                keyIdResolver.resolvePublicJwk(alias).getOrElse {
                    // Skip silently if a specific alias cannot be loaded; we still want
                    // to serve what we have. Real deployments should alarm on this.
                    return@mapNotNull null
                }
            if (aliasToMode[alias] == SigningKeyMode.JwkThumbprint) {
                return@mapNotNull thumbprintSigningJwk(publicJwk).getOrElse { return Err(it) }
            }
            val kid =
                when (val mode = aliasToMode[alias]) {
                    is SigningKeyMode.Did -> {
                        keyIdResolver
                            .resolveDidVerificationMethodId(alias, mode.method)
                            .getOrElse { return@mapNotNull null }
                    }

                    // X5c, Federation and None do not identify a key through a kid here.
                    else -> {
                        null
                    }
                }
            buildJsonObject {
                publicJwk.forEach { (k, v) -> put(k, v) }
                if (kid != null) put("kid", JsonPrimitive(kid))
            }
        }
    val display: List<DisplayProperties>? = configProvider.display?.takeIf { it.isNotEmpty() }

    val body =
        buildJsonObject {
            put("issuer", JsonPrimitive(issuer))
            put(
                "jwks",
                buildJsonObject {
                    put("keys", buildJsonArray { keys.forEach { add(it) } })
                },
            )
            if (display != null) {
                put("display", jwtVcIssuerJson.encodeToJsonElement(display))
            }
        }
    return Ok(body)
}

/** Protocol JSON encoder with no defaults — keeps the body compact. */
private val jwtVcIssuerJson =
    kotlinx.serialization.json.Json {
        encodeDefaults = false
    }

private fun okJson(body: JsonObject): GenericHttpResponse =
    jsonResponse(200, jwtVcIssuerJson.encodeToString(JsonObject.serializer(), body))
        .copy(
            headers =
                mapOf(
                    "Content-Type" to "application/json",
                    "Cache-Control" to "public, max-age=3600",
                ),
        )

/** Bare `/.well-known/jwt-vc-issuer` — used when the issuer identifier has no path. */
@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(GetJwtVcIssuerMetadataRootEndpointCommand.COMMAND_ID)
class GetJwtVcIssuerMetadataRootEndpointCommandImpl(
    execution: SessionExecution,
    private val configProvider: Oid4vciIssuerConfigProvider,
    private val keyIdResolver: IssuerKeyIdResolver,
) : HttpEndpointCommandAdapter(
        id = GetJwtVcIssuerMetadataRootEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = GetJwtVcIssuerMetadataRootEndpointCommand.ENDPOINT,
    ),
    GetJwtVcIssuerMetadataRootEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> {
        applyDuring(args)
        val issuer = configProvider.issuerIdentifier.trimEnd('/')
        // Only serve the root variant when the issuer actually lives at the host root.
        if (pathOfIssuer(issuer).isNotEmpty()) {
            return Err(IdkError.NOT_FOUND_ERROR(message = "Issuer is path-scoped; use /.well-known/jwt-vc-issuer/<path>"))
        }
        return buildBody(configProvider, keyIdResolver).map { okJson(it) }
    }
}

/** Path-scoped `/.well-known/jwt-vc-issuer/{issuer_path}` — RFC 8615 insert form. */
@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(GetJwtVcIssuerMetadataScopedEndpointCommand.COMMAND_ID)
class GetJwtVcIssuerMetadataScopedEndpointCommandImpl(
    execution: SessionExecution,
    private val configProvider: Oid4vciIssuerConfigProvider,
    private val keyIdResolver: IssuerKeyIdResolver,
) : HttpEndpointCommandAdapter(
        id = GetJwtVcIssuerMetadataScopedEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = GetJwtVcIssuerMetadataScopedEndpointCommand.ENDPOINT,
    ),
    GetJwtVcIssuerMetadataScopedEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> {
        val req = applyDuring(args).withExtractedParams("/.well-known/jwt-vc-issuer/{issuer_path}")
        val requestedPath = req.requirePathParam("issuer_path").getOrElse { return Err(it) }
        val issuer = configProvider.issuerIdentifier.trimEnd('/')
        val expectedPath = pathOfIssuer(issuer)
        if (requestedPath != expectedPath) {
            return Err(
                IdkError.NOT_FOUND_ERROR(
                    message = "No SD-JWT VC issuer at '/$requestedPath'; this service serves '$expectedPath'",
                ),
            )
        }
        return buildBody(configProvider, keyIdResolver).map { okJson(it) }
    }
}

/** Extract the path component of `https://host/path` — returns "" when the issuer has no path. */
private fun pathOfIssuer(issuer: String): String {
    val schemeEnd = issuer.indexOf("://").let { if (it < 0) return "" else it + 3 }
    val firstSlash = issuer.indexOf('/', schemeEnd)
    return if (firstSlash < 0) "" else issuer.substring(firstSlash + 1).trim('/')
}
