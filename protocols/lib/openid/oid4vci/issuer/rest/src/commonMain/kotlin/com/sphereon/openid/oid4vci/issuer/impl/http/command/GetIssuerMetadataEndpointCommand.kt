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
import com.sphereon.core.api.http.describe.EndpointAuthPolicy
import com.sphereon.core.api.http.describe.HttpEndpointDescriptor
import com.sphereon.core.api.http.describe.HttpMethod
import com.sphereon.core.api.http.describe.MediaType
import com.sphereon.core.api.http.response.jsonResponse
import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.resolution.managed.ManagedIdentifierOpts
import com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult
import com.sphereon.crypto.resolution.managed.ManagedIdentifierResult
import com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService
import com.sphereon.crypto.resolution.tryManagedIdentifierToJwk
import com.sphereon.data.store.credential.design.PublicDesignAssetPaths
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vc.common.DisplayProperties
import com.sphereon.openid.oid4vci.common.model.CredentialIssuerMetadata
import com.sphereon.openid.oid4vci.common.model.MetadataCredentialRequestEncryption
import com.sphereon.openid.oid4vci.issuer.command.BuildIssuerMetadataArgs
import com.sphereon.openid.oid4vci.issuer.command.BuildIssuerMetadataCommand
import com.sphereon.openid.oid4vci.issuer.command.BuildSignedIssuerMetadataArgs
import com.sphereon.openid.oid4vci.issuer.command.BuildSignedIssuerMetadataCommand
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider
import com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver
import com.sphereon.openid.oid4vci.rest.Oid4vciRestConfigProvider
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.ContributesIntoMap
import dev.zacsweers.metro.StringKey
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.encodeToJsonElement

/**
 * Endpoint command for OID4VCI Issuer Metadata discovery.
 *
 * The set of URLs the issuer is reachable at depends on the path component of the
 * configured `oid4vci.issuer.identifier`:
 *
 * - **Bare-host issuer** (`https://host`) — served at `/.well-known/openid-credential-issuer`.
 * - **Path-bearing issuer** (`https://host/<issuer-path>`) — served at BOTH
 *   `/.well-known/openid-credential-issuer/<issuer-path>` (RFC 8414 §3 / RFC 8615
 *   well-known suffix form) and `/<issuer-path>/.well-known/openid-credential-issuer`
 *   (legacy issuer-path-prefix form). The bare URL is intentionally NOT served when
 *   the issuer carries a path: it would advertise discovery for an issuer
 *   identifier (`https://host`) that doesn't exist.
 *
 * The runtime-built descriptor lists every URL via [HttpEndpointDescriptor.pathPatterns],
 * so a single command instance routes under all alias URLs without parallel handler
 * wiring. The companion's [ENDPOINT] retains the bare descriptor for back-compat with
 * direct embedders (tests, external IDK consumers wiring the command without a
 * descriptor provider).
 */
interface GetIssuerMetadataEndpointCommand : HttpEndpointCommand {
    companion object {
        const val COMMAND_ID = "oid4vci.protocol.metadata"

        /** Well-known segment without any issuer-path expansion. */
        const val BARE_PATH = "/.well-known/openid-credential-issuer"

        private val producesMedia =
            setOf(
                MediaType.ApplicationJson,
                MediaType.Custom(ACCEPT_JWT),
                MediaType.Custom(ACCEPT_ISSUER_METADATA_JWT),
            )

        /** Pre-built bare descriptor — for back-compat embedders. */
        val ENDPOINT =
            HttpEndpointDescriptor(
                method = HttpMethod.GET,
                pathPattern = BARE_PATH,
                produces = producesMedia,
                operationId = "getIssuerMetadata",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("oid4vci-issuer", "metadata"),
                summary = "Get OID4VCI credential issuer metadata",
                authPolicy = EndpointAuthPolicy.PUBLIC,
            )

        /**
         * Path component of the issuer identifier, normalised to either an empty
         * string (bare-host issuer) or a single leading `/` followed by the path.
         * Trailing slashes are stripped so concatenation with [BARE_PATH] never
         * produces a double slash.
         */
        fun extractIssuerPath(issuerIdentifier: String): String {
            val normalised = issuerIdentifier.trimEnd('/')
            val schemeEnd = normalised.indexOf("://").takeIf { it >= 0 }?.plus(SCHEME_SEPARATOR_LENGTH) ?: 0
            val pathStart = normalised.indexOf('/', schemeEnd)
            return if (pathStart < 0) "" else normalised.substring(pathStart)
        }

        /**
         * Build the descriptor that exposes this command at the right URLs for the
         * configured issuer identifier. Path-bearing issuers get a single descriptor
         * with two path patterns (spec form first, legacy second) so the dispatcher
         * routes both URLs through the same handler instance.
         */
        fun descriptorFor(issuerIdentifier: String): HttpEndpointDescriptor {
            val issuerPath = extractIssuerPath(issuerIdentifier)
            val catalogPatterns =
                listOf(
                    BARE_PATH,
                    "$BARE_PATH/{issuerPath...}",
                    "/{issuerPath}$BARE_PATH",
                    "/{issuerPathParent}/{issuerPathChild}$BARE_PATH",
                )
            val configuredPatterns =
                if (issuerPath.isBlank()) {
                    emptyList()
                } else {
                    listOf("$BARE_PATH$issuerPath", "$issuerPath$BARE_PATH")
                }
            // App-scope routing is necessarily tenant-neutral. The session command must
            // declare those selected catalog aliases as well as its tenant-specific paths;
            // otherwise the command/route identity guard correctly refuses dispatch.
            val patterns = (catalogPatterns + configuredPatterns).distinct()
            return HttpEndpointDescriptor(
                method = HttpMethod.GET,
                pathPatterns = patterns,
                produces = producesMedia,
                operationId = "getIssuerMetadata",
                commandId = COMMAND_ID,
                handlerCommandId = COMMAND_ID,
                tags = setOf("oid4vci-issuer", "metadata"),
                summary = "Get OID4VCI credential issuer metadata",
                authPolicy = EndpointAuthPolicy.PUBLIC,
            )
        }

        /**
         * Resolve the most precise metadata routes available while the session graph is built.
         *
         * A multi-product issuer process constructs every HTTP adapter before dispatching the
         * selected request. An unrelated public route, such as a credential-design asset, must
         * therefore not fail merely because the default OID4VCI instance is not configured. In
         * that case the generic descriptor keeps metadata routing available and the actual
         * metadata request still performs strict identifier validation in [doExecute].
         */
        fun descriptorFor(configProvider: Oid4vciIssuerConfigProvider): HttpEndpointDescriptor =
            try {
                descriptorFor(configProvider.issuerIdentifier)
            } catch (_: IllegalArgumentException) {
                descriptorFor("")
            }

        /**
         * Spec-compliant OID4VCI 1.0 discovery descriptor. For issuer identifier
         * `https://host/<issuer-path>`, metadata lives at
         * `https://host/.well-known/openid-credential-issuer/<issuer-path>`.
         */
        fun specDescriptorFor(issuerIdentifier: String): HttpEndpointDescriptor {
            val issuerPath = extractIssuerPath(issuerIdentifier)
            val patterns =
                if (issuerPath.isBlank()) {
                    listOf(BARE_PATH, "$BARE_PATH/{issuerPath...}")
                } else {
                    listOf("$BARE_PATH$issuerPath")
                }
            return ENDPOINT.copy(pathPatterns = patterns)
        }

        /**
         * Legacy prefix discovery descriptor retained for older wallets that still
         * request `/<issuer-path>/.well-known/openid-credential-issuer`.
         */
        fun legacyPrefixDescriptorFor(issuerIdentifier: String): HttpEndpointDescriptor {
            val issuerPath = extractIssuerPath(issuerIdentifier)
            val patterns =
                if (issuerPath.isBlank()) {
                    listOf(
                        "/{issuerPath}$BARE_PATH",
                        "/{issuerPathParent}/{issuerPathChild}$BARE_PATH",
                    )
                } else {
                    listOf("$issuerPath$BARE_PATH")
                }
            return ENDPOINT.copy(pathPatterns = patterns)
        }

        /**
         * Issuer path named by a metadata request URL: the trailing path of the OID4VCI 1.0
         * suffix form (`/.well-known/openid-credential-issuer/<issuer-path>`), the leading path of
         * the legacy prefix form (`/<issuer-path>/.well-known/openid-credential-issuer`), or an
         * empty string for the bare well-known URL. Returns `null` for a path that is not a
         * metadata URL. The result is comparable with [extractIssuerPath].
         */
        fun requestedIssuerPath(requestPath: String): String? {
            val path = requestPath.substringBefore('?').substringBefore('#').trimEnd('/')
            return when {
                path == BARE_PATH -> ""
                path.startsWith("$BARE_PATH/") -> path.removePrefix(BARE_PATH)
                path.endsWith(BARE_PATH) -> path.removeSuffix(BARE_PATH)
                else -> null
            }
        }

        private const val SCHEME_SEPARATOR_LENGTH = 3
    }
}

@Inject
@SingleIn(SessionScope::class)
@ContributesIntoMap(SessionScope::class, binding = binding<HttpEndpointCommand>())
@StringKey(GetIssuerMetadataEndpointCommand.COMMAND_ID)
class GetIssuerMetadataEndpointCommandImpl(
    execution: SessionExecution,
    private val buildMetadataCommand: BuildIssuerMetadataCommand,
    private val buildSignedMetadataCommand: BuildSignedIssuerMetadataCommand,
    private val configProvider: Oid4vciIssuerConfigProvider,
    private val restConfigProvider: Oid4vciRestConfigProvider,
    private val multiManagedIdentifierService: MultiManagedIdentifierService,
    private val publicUrlResolver: Oid4vciIssuerPublicUrlResolver,
    private val issuerKeyIdResolver: IssuerKeyIdResolver? = null,
) : HttpEndpointCommandAdapter(
        id = GetIssuerMetadataEndpointCommand.COMMAND_ID,
        execution = execution,
        endpoint = GetIssuerMetadataEndpointCommand.descriptorFor(configProvider),
    ),
    GetIssuerMetadataEndpointCommand {
    override suspend fun doExecute(
        args: GenericHttpRequest,
        applyDuring: (GenericHttpRequest) -> GenericHttpRequest,
    ): IdkResult<GenericHttpResponse, IdkError> {
        val request = applyDuring(args)

        val publicUrls =
            publicUrlResolver
                .resolve(request, configProvider, restConfigProvider)
                .getOrElse { error ->
                    // A selected issuer without an active public binding (ended or removed) has
                    // no metadata. Answer 404 rather than a credential-request error.
                    if (error.code == NOT_FOUND_ERROR_CODE) return Ok(issuerMetadataNotFound())
                    return Err(error)
                }

        // The metadata URL names exactly one issuer. Dispatch strips the issuer path before this
        // command runs, so compare against the ingress path. A path-bearing request is answered
        // only by the issuer whose identifier carries that same path; anything else (an unknown
        // or ended instance, a sibling chosen by a host-level or tenant-default binding, or a
        // bare-origin issuer reached through an arbitrary suffix) is 404, never another issuer's
        // metadata. The bare well-known URL keeps its existing resolution.
        val requestedIssuerPath =
            GetIssuerMetadataEndpointCommand.requestedIssuerPath(request.originalPath ?: request.path)
        if (!requestedIssuerPath.isNullOrEmpty() &&
            requestedIssuerPath != GetIssuerMetadataEndpointCommand.extractIssuerPath(publicUrls.issuerIdentifier)
        ) {
            return Ok(issuerMetadataNotFound())
        }

        val acceptHeader = request.headers["Accept"] ?: request.headers["accept"] ?: ""
        val wantsJwt =
            acceptHeader.contains(ACCEPT_JWT, ignoreCase = true) ||
                acceptHeader.contains(ACCEPT_ISSUER_METADATA_JWT, ignoreCase = true)

        // Ensure design-derived credential configurations are built before we read them below.
        // For config-only providers this is a no-op (default interface method); for
        // HybridOid4vciIssuerConfigProvider it triggers buildDesigns() exactly once per session
        // without this module needing to depend on the impl class directly.
        configProvider.prepare()

        // Resolve `credential_request_encryption.jwks` from the KMS at request time so we
        // never store private key material in YAML / git. Mirrors how the OAuth2 AS publishes
        // its signing JWKS via `GetJwksCommandImpl`.
        val resolvedRequestEncryption =
            resolveCredentialRequestEncryption(configProvider.credentialRequestEncryption)
                .getOrElse { error -> return Err(error) }

        // Federation consumers resolve protocol keys from this same served metadata.
        // These are credential-scoped keys, separate from Entity Statement signing keys.
        val signingJwks = issuerThumbprintSigningJwks(configProvider, issuerKeyIdResolver)
            .getOrElse { error -> return Err(error) }

        val metadataResult =
            buildMetadataCommand.execute(
                BuildIssuerMetadataArgs(
                    issuerIdentifier = publicUrls.issuerIdentifier,
                    baseUrl = publicUrls.endpointBaseUrl,
                    authorizationServers = configProvider.authorizationServers,
                    credentialConfigurations = configProvider.credentialConfigurations,
                    display = configProvider.display,
                    credentialResponseEncryption = configProvider.credentialResponseEncryption,
                    credentialRequestEncryption = resolvedRequestEncryption,
                    batchCredentialIssuance = configProvider.batchCredentialIssuance,
                    preferredKeyStorageStatusPeriodSeconds = configProvider.preferredKeyStorageStatusPeriodSeconds,
                ),
            )

        val metadata =
            metadataResult
                .getOrElse { error ->
                    return Err(error)
                }
                // Resolve design-asset (logo / background) URIs embedded in the issuer + credential
                // `display` to ABSOLUTE per-tenant URLs, using the SAME base that produced
                // `credential_issuer` / endpoint URLs (publicUrls.endpointBaseUrl). Asset URIs are
                // stored RELATIVE so that in multi-tenant gateway mode each tenant's logo carries
                // that tenant's host. Done BEFORE signing + JSON encode so both surfaces agree.
                .withAbsoluteAssetUris(publicUrls.endpointBaseUrl)
                .withHostedVctUrls(publicUrls.issuerIdentifier)
                .let { metadata ->
                    if (signingJwks == null) metadata
                    else metadata.copy(additionalMetadata = metadata.additionalMetadata + ("jwks" to signingJwks))
                }

        val signingKey = configProvider.signingKey()

        if (wantsJwt && signingKey != null) {
            return buildSignedMetadataCommand
                .execute(
                    BuildSignedIssuerMetadataArgs(
                        metadata = metadata,
                        signingKey = signingKey,
                    ),
                ).map { jwt ->
                    GenericHttpResponse(statusCode = 200, headers = JWT_HEADERS, body = jwt.jwt)
                }
        }

        // JSON response: also populate signed_metadata when a signing key is configured
        if (signingKey != null) {
            return buildSignedMetadataCommand
                .execute(
                    BuildSignedIssuerMetadataArgs(
                        metadata = metadata,
                        signingKey = signingKey,
                    ),
                ).map { jwt ->
                    val enriched = metadata.copy(signedMetadata = jwt.jwt)
                    jsonResponse(200, protocolJson.encodeToString(enriched))
                }
        }

        return Ok(jsonResponse(200, protocolJson.encodeToString(metadata)))
    }

    /**
     * Walks the KMS to materialise the `credential_request_encryption.jwks` field whenever the
     * config provider supplied a [Oid4vciIssuerConfigProvider.credentialRequestDecryptionKey]
     * alias. The metadata template the config provider returns carries a placeholder `jwks`
     * (`{"keys": []}`) that we replace with the real public JWK here. When no decryption key
     * alias is configured (and no static jwks is in YAML either) the template arrives `null`
     * and we pass that through unchanged so the metadata field is omitted on the wire.
     *
     * Mirrors `GetJwksCommandImpl.executeInternal` — same `tryManagedIdentifierToJwk`
     * primitive, same kid-pinning rule (use `keyInfo.kid` when set so the published kid
     * matches what JWS / JWE signers stamp into headers).
     */
    private suspend fun resolveCredentialRequestEncryption(template: MetadataCredentialRequestEncryption?,): IdkResult<MetadataCredentialRequestEncryption?, IdkError> {
        if (template == null) return Ok(null)

        val decryptionOpts =
            configProvider.credentialRequestDecryptionKey()
                // A static-jwks template already carries real keys and is published as-is. A KMS-backed
                // template that resolves no key is dropped entirely rather than published with the
                // empty placeholder JWKS: advertising request encryption the issuer cannot honour
                // would invite wallets to encrypt to nothing.
                ?: return Ok(template.takeIf { it.jwks.publishesKeys() })

        val resolvedIdentifier: ManagedIdentifierOptsOrResult =
            if (decryptionOpts is ManagedIdentifierOpts && decryptionOpts !is ManagedIdentifierResult<*>) {
                multiManagedIdentifierService
                    .resolve(decryptionOpts)
                    .getOrElse { return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Failed to resolve credential_request_encryption decryption key: ${it.message}")) }
            } else {
                decryptionOpts
            }

        val jwkResult =
            tryManagedIdentifierToJwk(resolvedIdentifier).getOrElse { return Err(it) }
        val publicJwk =
            (jwkResult.identifier.toPublicKey() as? Jwk)
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Failed to convert credential_request_encryption key to public JWK"))

        // Pin kid to keyInfo.kid the same way the AS JWKS endpoint does, so a wallet that
        // includes `kid` in its JWE header can resolve back to the same KMS alias on decrypt.
        // Also stamp `use=enc` (RFC 7517 §4.2) and the default JWE key-management `alg`
        // (RFC 7517 §4.4) so RFC 7517 / OIDF `VCICheckCredentialRequestEncryptionSupported`
        // can confirm the key is intended for encryption — the suite rejects a JWK with no
        // `use` AND no JWE-compatible `alg` because it can't tell encryption keys from
        // signing keys. ECDH-ES is the only HAIP-permitted alg for P-256, so it's the
        // natural advertised default; wallets MAY still pick a more specific +A*KW variant.
        val publishedJwk =
            jwkResult.keyInfo.kid
                ?.takeIf { it.isNotBlank() }
                ?.let { keyInfoKid ->
                    if (publicJwk.kid == keyInfoKid) publicJwk else publicJwk.copy(kid = keyInfoKid)
                } ?: publicJwk
        val annotatedJwk = publishedJwk.asCredentialRequestEncryptionJwk()

        val publicJwkElement =
            Json.Default.encodeToJsonElement(Jwk.serializer(), annotatedJwk).let {
                it as? JsonObject ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Public JWK did not serialize to a JSON object"))
            }
        val realJwks = JsonObject(mapOf("keys" to JsonArray(listOf(publicJwkElement))))
        return Ok(template.copy(jwks = realJwks))
    }
}

/**
 * Projects a KMS public JWK into the OID4VCI credential-request-encryption contract.
 *
 * KMS provisioning uses the signature algorithm to select a P-256 keypair, so its public
 * JWK can carry `ES256`. That value is not valid JWE key-management metadata for a JWK
 * advertised with `use=enc`; holders must use ECDH-ES for this recipient key.
 */
internal fun Jwk.asCredentialRequestEncryptionJwk(): Jwk =
    copy(
        use = use ?: "enc",
        alg = JwaAlgorithm.ECDH_ES,
    )

/**
 * Returns a copy of this [CredentialIssuerMetadata] with every design-asset (logo / background)
 * URI embedded in the issuer-level and credential-level `display` resolved to an ABSOLUTE
 * per-tenant URL using [externalBaseUrl].
 *
 * Asset URIs are stored RELATIVE (content-addressed under
 * [PublicDesignAssetPaths.BASE_PATH]); this applies the same per-tenant host the issuer
 * advertises for `credential_issuer` / endpoint URLs, so a multi-tenant gateway emits each
 * tenant's own host. URIs that are already absolute, not design-asset paths, or null are left
 * untouched (see [PublicDesignAssetPaths.toAbsolute]).
 *
 * `internal` so it is directly unit-testable without wiring the full HTTP command.
 */
internal fun CredentialIssuerMetadata.withAbsoluteAssetUris(externalBaseUrl: String?): CredentialIssuerMetadata =
    copy(
        display = display?.map { it.withAbsoluteAssetUris(externalBaseUrl) },
        credentialConfigurationsSupported =
            credentialConfigurationsSupported.mapValues { (_, config) ->
                config.copy(
                    display = config.display?.map { it.withAbsoluteAssetUris(externalBaseUrl) },
                    credentialMetadata =
                        config.credentialMetadata?.let { meta ->
                            meta.copy(display = meta.display?.map { it.withAbsoluteAssetUris(externalBaseUrl) })
                        },
                )
            },
    )

private fun DisplayProperties.withAbsoluteAssetUris(externalBaseUrl: String?): DisplayProperties =
    copy(
        logo = logo?.let { it.copy(uri = PublicDesignAssetPaths.toAbsolute(it.uri, externalBaseUrl)) },
        backgroundImage =
            backgroundImage?.let { it.copy(uri = PublicDesignAssetPaths.toAbsolute(it.uri, externalBaseUrl)) },
    )

internal fun CredentialIssuerMetadata.withHostedVctUrls(externalBaseUrl: String?): CredentialIssuerMetadata =
    copy(
        credentialConfigurationsSupported =
            credentialConfigurationsSupported.mapValues { (_, config) ->
                config.copy(vct = config.vct?.toHostedVctUrl(externalBaseUrl))
            },
    )

fun String.toHostedVctUrl(externalBaseUrl: String?): String {
    val base = externalBaseUrl?.publicOrigin()?.takeIf { it.isNotBlank() } ?: return this
    val markerIndex = indexOf(HOSTED_VCT_PATH_MARKER)
    if (markerIndex < 0) return this
    val suffix = substring(markerIndex + HOSTED_VCT_PATH_MARKER.length).takeIf { it.isNotBlank() } ?: return this
    return "$base$HOSTED_VCT_PATH_MARKER$suffix"
}

fun String.isHostedVctMetadataUrl(): Boolean = indexOf(HOSTED_VCT_PATH_MARKER) >= 0

private const val HOSTED_VCT_PATH_MARKER = "/public/schema/vct/"

private const val NOT_FOUND_ERROR_CODE = "NOT_FOUND_ERROR"

/** 404 for a metadata URL that names no published credential issuer. */
private fun issuerMetadataNotFound(): GenericHttpResponse =
    oid4vciErrorResponse(
        statusCode = 404,
        errorCode = "not_found",
        description = "No credential issuer is published at this metadata URL",
    )

/** True when a `credential_request_encryption.jwks` value carries at least one real key. */
private fun JsonObject.publishesKeys(): Boolean = (this["keys"] as? JsonArray)?.isNotEmpty() == true

private fun String.publicOrigin(): String {
    val base = trimEnd('/')
    val schemeEnd = base.indexOf("://").takeIf { it >= 0 } ?: return base
    val authorityStart = schemeEnd + 3
    val pathStart = base.indexOf('/', authorityStart)
    return if (pathStart < 0) base else base.substring(0, pathStart)
}
