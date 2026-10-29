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

package com.sphereon.openid.oid4vci.issuer.impl.signing

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.PrincipalConfigService
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.di.session.SessionScope
import com.sphereon.did.manager.DidCreateOptions
import com.sphereon.did.manager.DidProviderRegistry
import com.sphereon.did.models.VerificationPurpose
import com.sphereon.did.resolver.DidResolutionResult
import com.sphereon.did.resolver.DidResolverRegistry
import com.sphereon.openid.oid4vci.issuer.spi.IssuerPublicJwkSource
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Provider
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * Resolves the `kid` string and bare public JWK for a signing key, in exactly the
 * same way the credential issuance path does. Centralising this here guarantees the
 * JWT-protected-header `kid` and the `kid` published in the issuer's JWKS are always
 * byte-identical.
 *
 * The key name reaching this resolver is server-resolved. It selects an existing key and never
 * creates one, and it is process-internal: it must not appear on a DTO, a REST response, or in an
 * error a caller can see.
 *
 * The resolver is DID-method-aware: for a DID-bound issuer (`did:jwk`, `did:key`, ...)
 * the kid is the DID URL of the assertion-method verification method — e.g.
 * `did:jwk:<canonical-b64url-jwk>#0`. The JWK production path (`JwkDidProviderImpl`)
 * canonicalises the public key before encoding the DID, so `resolveDidKid` is
 * deterministic from the key material.
 */
interface IssuerKeyIdResolver {
    /**
     * Returns the DID verification-method id ("`<did>#<fragment>`") for [keyAlias]
     * under the requested [didMethod].
     *
     * Fails if the KMS lookup, DID provider lookup, or DID creation fails.
     */
    suspend fun resolveDidVerificationMethodId(
        keyAlias: String,
        didMethod: String,
    ): IdkResult<String, IdkError>

    /**
     * Resolve a DID verification method for a known issuer identifier. Issuance callers already
     * hold the validated public issuer URL and must pass it here so hosted DID methods do not
     * depend on a generic principal-config lookup losing the active issuer-instance prefix.
     *
     * The default keeps third-party/test implementations source-compatible. Implementations that
     * support hosted DID methods should override it and use [issuerIdentifier] as the authoritative
     * host source.
     */
    suspend fun resolveDidVerificationMethodId(
        keyAlias: String,
        didMethod: String,
        issuerIdentifier: String,
    ): IdkResult<String, IdkError> = resolveDidVerificationMethodId(keyAlias, didMethod)

    /**
     * Validates an operator-selected assertionMethod DID URL against the actual signing key.
     * Implementations must fail when the DID cannot be resolved, the method is not an
     * assertionMethod, or its public material does not match [keyAlias].
     */
    suspend fun validateDidVerificationMethodId(
        keyAlias: String,
        verificationMethodId: String,
    ): IdkResult<String, IdkError> {
        val did = verificationMethodId.substringBefore('#')
        val method = did.removePrefix("did:").substringBefore(':')
        if (!did.startsWith("did:") || '#' !in verificationMethodId || method.isBlank()) {
            return Err(IdkError.fromString(code = "invalid_signing_verification_method", message = "The selected DID assertion method does not match the issuer signing key"))
        }
        val resolved = resolveDidVerificationMethodId(keyAlias, method).getOrElse { return Err(it) }
        return if (resolved == verificationMethodId) {
            Ok(resolved)
        } else {
            Err(IdkError.fromString(code = "invalid_signing_verification_method", message = "The selected DID assertion method does not match the issuer signing key"))
        }
    }

    /** Returns the bare public JWK (as a JsonObject) for [keyAlias]. */
    suspend fun resolvePublicJwk(keyAlias: String): IdkResult<JsonObject, IdkError>
}

@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<IssuerKeyIdResolver>())
class DefaultIssuerKeyIdResolver(
    private val kms: KeyManagerService,
    private val didProviderRegistry: DidProviderRegistry,
    private val didResolverRegistry: DidResolverRegistry,
    private val configService: PrincipalConfigService,
    private val publicJwkSource: Provider<IssuerPublicJwkSource?>? = null,
) : IssuerKeyIdResolver {
    override suspend fun resolveDidVerificationMethodId(
        keyAlias: String,
        didMethod: String,
    ): IdkResult<String, IdkError> = resolveDidVerificationMethodIdInternal(keyAlias, didMethod, issuerIdentifier = null)

    override suspend fun resolveDidVerificationMethodId(
        keyAlias: String,
        didMethod: String,
        issuerIdentifier: String,
    ): IdkResult<String, IdkError> = resolveDidVerificationMethodIdInternal(keyAlias, didMethod, issuerIdentifier)

    override suspend fun validateDidVerificationMethodId(
        keyAlias: String,
        verificationMethodId: String,
    ): IdkResult<String, IdkError> {
        val did = verificationMethodId.substringBefore('#')
        if (!did.startsWith("did:") || '#' !in verificationMethodId) {
            return Err(IdkError.fromString(code = "invalid_signing_verification_method", message = SIGNING_IDENTIFIER_INVALID))
        }
        val jwk = loadPublicJwk(keyAlias).getOrElse { return Err(it) }
        val resolution = didResolverRegistry.resolve(did).getOrElse { return Err(it) }
        val exactMatch = findPublishedAssertionMethodId(resolution, jwk)
        return exactMatch?.takeIf { it == verificationMethodId }?.let(::Ok)
            ?: Err(IdkError.fromString(code = "invalid_signing_verification_method", message = SIGNING_IDENTIFIER_INVALID))
    }

    private suspend fun resolveDidVerificationMethodIdInternal(
        keyAlias: String,
        didMethod: String,
        issuerIdentifier: String?,
    ): IdkResult<String, IdkError> {
        val jwk = loadPublicJwk(keyAlias).getOrElse { return Err(it) }
        val provider =
            didProviderRegistry.getProvider(didMethod)
                ?: return Err(IdkError.fromString(code = "unsupported_did_method", message = "DID method '$didMethod' is not registered"))
        // Web-resolved methods (did:web / did:webvh) bind the KMS key to a document hosted at a
        // host; unlike did:jwk/did:key the DID is NOT derived from the key, so the host must be
        // supplied. It is the host of the issuer identifier (the public HTTPS base URL).
        val domain =
            if (didMethod in WEB_RESOLVED_METHODS) {
                resolveDidWebDomain(issuerIdentifier)
                    ?: return Err(
                        IdkError.fromString(
                            code = "did_web_domain_unresolved",
                            message =
                                "did:$didMethod signing requires a host: set '$DID_WEB_DOMAIN_KEY' or a valid " +
                                    "absolute '$IDENTIFIER_KEY'.",
                        ),
                    )
            } else {
                null
            }
        val created =
            provider
                .create(
                    DidCreateOptions(
                        method = didMethod,
                        publicKeyJwk = jwk.toPublicKey(),
                        domain = domain,
                        // The issuer's signing key is an assertion key — credential proofs use the
                        // assertionMethod relationship, so the published did:web document MUST list it there.
                        purposes = if (didMethod in WEB_RESOLVED_METHODS) listOf(VerificationPurpose.ASSERTION_METHOD) else null,
                        // Descriptive, per-key fragment so each signing key has its own VM in the
                        // hosted document (e.g. did:web:host#PID) — no shared "#key-1" collision.
                        verificationMethodId = if (didMethod in WEB_RESOLVED_METHODS) keyAlias else null,
                    ),
                ).getOrElse { return Err(it) }
        // A hosted DID is not derived from this key. The authoritative document may use a
        // code-owned verification-method fragment that differs from the private KMS alias
        // (for example `issuer-assertion-tenant` vs `issuer-signing-tenant`). Resolve the
        // published document and select the assertion method by public material; emitting the
        // locally synthesised alias fragment would advertise a kid that the document does not
        // contain and verifiers could silently try the wrong key.
        if (didMethod in WEB_RESOLVED_METHODS) {
            val resolution = didResolverRegistry.resolve(created.did).getOrElse { return Err(it) }
            val publishedVmId =
                findPublishedAssertionMethodId(resolution, jwk)
                    ?: return Err(
                        IdkError.fromString(
                            code = "did_signing_method_unresolved",
                            message = SIGNING_IDENTIFIER_UNAVAILABLE,
                        ),
                    )
            return Ok(publishedVmId)
        }
        val vmId =
            created.verificationMethodsByPurpose[VerificationPurpose.ASSERTION_METHOD]
                ?.firstOrNull()
                ?.id
                ?: "${created.did}#0"
        return Ok(vmId)
    }

    override suspend fun resolvePublicJwk(keyAlias: String): IdkResult<JsonObject, IdkError> {
        val jwk = loadPublicJwk(keyAlias).getOrElse { return Err(it) }
        // Serialise the full JWK and strip non-public / private members — same rule as
        // JwkDidProviderImpl.canonicalBase64UrlJwk so the published JWKS entry key material
        // matches what the DID URL encodes for.
        val full =
            kotlinx.serialization.json
                .Json {
                    encodeDefaults = false
                }.let { j -> j.parseToJsonElement(j.encodeToString(jwk)) as JsonObject }
        val canonical =
            kotlinx.serialization.json.buildJsonObject {
                full.forEach { (k, v) -> if (k in PUBLIC_JWK_MEMBERS) put(k, v) }
            }
        return Ok(canonical)
    }

    /**
     * Resolve the did:web/webvh host: an explicit override, else the host of the issuer identifier
     * (the public HTTPS base URL, e.g. `https://issuer.example/oid4vci` -> `issuer.example`).
     */
    private fun resolveDidWebDomain(issuerIdentifier: String?): String? {
        issuerIdentifier?.let(::hostOf)?.let { return it }
        configService.getPropertyAsString(DID_WEB_DOMAIN_KEY)?.takeIf { it.isNotBlank() }?.let { return hostOf(it) }
        return configService.getPropertyAsString(IDENTIFIER_KEY)?.let { hostOf(it) }
    }

    /**
     * Loads the stored JWK for a server-resolved key name. The key must already exist; nothing is
     * created here. Both failure shapes answer identically and without echoing the name, which is
     * process-internal and must not reach a caller through an error message.
     */
    private suspend fun loadPublicJwk(keyName: String): IdkResult<Jwk, IdkError> {
        if (keyName.isBlank()) {
            return Err(IdkError.fromString(code = "signing_key_unavailable", message = SIGNING_KEY_UNAVAILABLE))
        }
        // Metro represents an absent optional provider binding with a provider of null.
        // Resolve that optional pointee once; a failing provider remains authoritative refusal.
        val managedPublicJwkSource =
            try {
                publicJwkSource?.invoke()
            } catch (_: Exception) {
                return Err(IdkError.fromString(code = "signing_key_unavailable", message = SIGNING_KEY_UNAVAILABLE))
            }
        if (managedPublicJwkSource != null) {
            val publicJwk = runCatching { managedPublicJwkSource.resolvePublicJwk(keyName) }.getOrNull()
            val jwk = publicJwk?.let { runCatching { Json.decodeFromJsonElement(Jwk.serializer(), it) }.getOrNull() }
                ?: return Err(IdkError.fromString(code = "signing_key_unavailable", message = SIGNING_KEY_UNAVAILABLE))
            return Ok(jwk)
        }
        val keyResult = kms.getKeyResult(KeyInfo<Nothing>(alias = keyName))
        if (keyResult.isErr) {
            return Err(IdkError.fromString(code = "signing_key_unavailable", message = SIGNING_KEY_UNAVAILABLE))
        }
        val jwk =
            keyResult.value.key?.key as? Jwk
                ?: return Err(IdkError.fromString(code = "signing_key_unavailable", message = SIGNING_KEY_UNAVAILABLE))
        return Ok(jwk)
    }

    companion object {
        /**
         * Members of a JWK that are legitimate to publish. Excludes the identity members
         * (`kid`, `use`, `key_ops`, `alg`) so the JWKS entry carries only the key material
         * that forms the thumbprint / DID identifier; the `kid` is added back by the
         * caller from the same resolver that produces the JWT-header kid.
         */
        private val PUBLIC_JWK_MEMBERS = setOf("kty", "crv", "x", "y", "n", "e")

        /** Methods whose DID is hosted at a web host (so the host must be supplied, not derived from the key). */
        private val WEB_RESOLVED_METHODS = setOf("web", "webvh")

        /**
         * Single refusal for every reason the signing key cannot be used, stated without the key
         * name so it cannot become a discovery oracle over the deployment's key material.
         */
        internal const val SIGNING_KEY_UNAVAILABLE = "The issuer signing key is unavailable"
        internal const val SIGNING_IDENTIFIER_UNAVAILABLE = "The issuer signing identifier is unavailable"
        internal const val SIGNING_IDENTIFIER_INVALID = "The selected DID assertion method does not match the issuer signing key"
        private const val IDENTIFIER_KEY = "oid4vci.issuer.identifier"
        private const val DID_WEB_DOMAIN_KEY = "oid4vci.issuer.signing.did-web-domain"

        /**
         * Authority of an absolute URL or bare authority. Non-default ports are significant in a
         * did:web identifier and must be retained for encoding by the DID provider.
         */
        internal fun hostOf(url: String): String? {
            val trimmed = url.trim()
            if (trimmed.isBlank()) return null
            val authority =
                (if (trimmed.contains("://")) trimmed.substringAfter("://") else trimmed)
                    .substringBefore('/')
                    .substringBefore('?')
                    .substringBefore('#')
            if ('@' in authority) return null
            return authority.takeIf { it.isNotBlank() }
        }
    }
}

/**
 * Finds the single assertion method whose public key material matches [signingKey]. Identity and
 * certificate metadata (`kid`, `use`, `alg`, `x5c`, ...) are deliberately ignored: DID documents
 * own the verification-method id while KMS owns the signing alias.
 */
internal fun findPublishedAssertionMethodId(
    resolution: DidResolutionResult,
    signingKey: Jwk,
): String? {
    if (!resolution.isSuccess()) return null
    val did = resolution.didDocument?.id?.takeIf { it.startsWith("did:") } ?: return null
    val expected = signingKey.publicMaterial()
    val matches =
        resolution
            .getAssertionMethods()
            .filter { method -> method.publicKeyJwk?.publicMaterial() == expected }
            .mapNotNull { method -> absoluteDidVerificationMethodId(did, method.id) }
            .distinct()
    return matches.singleOrNull()
}

/**
 * Converts a DID-document verification-method id to the full absolute DID URL required in a
 * JOSE `kid`. Only an already absolute id or a document-relative fragment is accepted.
 */
internal fun absoluteDidVerificationMethodId(
    did: String,
    verificationMethodId: String,
): String? =
    when {
        !did.startsWith("did:") -> null
        verificationMethodId.startsWith("$did#") && verificationMethodId.length > did.length + 1 -> verificationMethodId
        verificationMethodId.startsWith("#") && verificationMethodId.length > 1 -> "$did$verificationMethodId"
        else -> null
    }

private fun Jwk.publicMaterial(): JsonObject {
    val full =
        kotlinx.serialization.json
            .Json { encodeDefaults = false }
            .let { json -> json.parseToJsonElement(json.encodeToString(this)) as JsonObject }
    return kotlinx.serialization.json.buildJsonObject {
        full.forEach { (key, value) ->
            if (key in setOf("kty", "crv", "x", "y", "n", "e")) put(key, value)
        }
    }
}
