/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.sphereon.openid.oid4vci.issuer.impl.format

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.interop.getPublicKeyBytes
import com.sphereon.crypto.core.interop.toSubjectPublicKeyInfo
import com.sphereon.crypto.core.interop.toX509Certificate
import com.sphereon.crypto.core.jose.generateJwkThumbprintUri
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.x509.certificateChainFromX5c
import com.sphereon.crypto.core.x509.x5cWithoutTerminalSelfSignedRoot
import at.asitplus.awesn1.serialization.DER
import com.sphereon.openid.oid4vci.issuer.format.SigningKeyMode
import com.sphereon.openid.oid4vci.issuer.impl.signing.IssuerKeyIdResolver
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlinx.serialization.encodeToByteArray

/**
 * Resolve the issuer signing-key identifier for a protected JWT header.
 *
 * The alias and mode are resolved from issuer configuration before a format handler is called.
 * Request and credential payload values are deliberately absent from this API. Every explicitly
 * selected key-reference mode fails closed when its required public key material is unavailable;
 * [SigningKeyMode.None] is the only mode that intentionally emits no key identifier.
 */
internal suspend fun resolveIssuerSigningHeader(
    kms: KeyManagerService,
    issuerKeyIdResolver: IssuerKeyIdResolver,
    keyAlias: String,
    mode: SigningKeyMode,
    signingVerificationMethodId: String?,
    configuredX5c: Array<String>? = null,
): IdkResult<JsonObject?, IdkError> {
    return when (mode) {
        is SigningKeyMode.None -> Ok(null)

        is SigningKeyMode.Did -> {
            val selected =
                signingVerificationMethodId
                    ?: return Err(
                        IdkError.fromString(
                            code = "invalid_signing_verification_method",
                            message = "DID signing requires an exact assertionMethod verification method",
                        ),
                    )
            val validated = issuerKeyIdResolver.validateDidVerificationMethodId(keyAlias, selected).getOrElse { return Err(it) }
            didOfVerificationMethod(validated).getOrElse { return Err(it) }
            Ok(buildJsonObject { put("kid", JsonPrimitive(validated)) })
        }

        is SigningKeyMode.X5c -> resolveX5cHeader(
            keyAlias = keyAlias,
            kms = kms,
            configuredX5c = configuredX5c,
        )

        is SigningKeyMode.JwkThumbprint ->
            resolveWithConfiguredKeyMaterial(keyAlias, kms) { jwk ->
                buildJsonObject {
                    put("kid", JsonPrimitive(generateJwkThumbprintUri(jwk.toPublicKey())))
                }
            }

        is SigningKeyMode.Federation ->
            Err(IdkError.fromString(code = "unsupported_signing_mode", message = "OpenID Federation signing mode is not yet implemented"))
    }
}

private suspend fun resolveX5cHeader(
    keyAlias: String,
    kms: KeyManagerService,
    configuredX5c: Array<String>?,
): IdkResult<JsonObject?, IdkError> {
    val keyResult = kms.getKeyResult(KeyInfo<Nothing>(alias = keyAlias))
    val signingJwk = if (keyResult.isOk) keyResult.value.key?.key as? Jwk else null
    val kmsChain =
        if (keyResult.isOk) {
            (keyResult.value.key?.x5c ?: (keyResult.value.key?.key as? Jwk)?.x5c)
                ?.takeIf { it.isNotEmpty() }
        } else {
            null
        }
    val chain =
        when {
            kmsChain != null -> normalizeX5c(kmsChain).getOrElse { return Err(it) }
            configuredX5c != null -> normalizeX5c(configuredX5c).getOrElse { return Err(it) }
            else -> null
        }
    if (chain != null) {
        val key = signingJwk ?: return unavailableSigningMaterial()
        if (key.kty == JwaKeyType.oct) return unavailableSigningMaterial()
        if (!chainLeafMatchesSigningKey(chain, key)) return signingCertificateKeyMismatch()
    }
    return chain?.let { values ->
        Ok(buildJsonObject { put("x5c", JsonArray(values.map { JsonPrimitive(it) })) })
    } ?: unavailableSigningMaterial()
}

private fun chainLeafMatchesSigningKey(
    chain: Array<String>,
    signingJwk: Jwk,
): Boolean =
    runCatching {
        val certificateSpki = certificateChainFromX5c(chain).first().toX509Certificate().getPublicKeyBytes()
        val signingSpki = DER.encodeToByteArray(signingJwk.toPublicKey().toSubjectPublicKeyInfo())
        certificateSpki.contentEquals(signingSpki)
    }.getOrDefault(false)

private fun signingCertificateKeyMismatch(): IdkResult<JsonObject?, IdkError> =
    Err(
        IdkError.fromString(
            code = "signing_certificate_key_mismatch",
            message = "Issuer signing certificate leaf public key does not match the KMS signing key",
        ),
    )

/** Validate and normalize x5c from any resolved source using platform-neutral primitives. */
internal fun normalizeX5c(x5c: Array<String>): IdkResult<Array<String>?, IdkError> {
    val chain = x5c.map(String::trim).filter(String::isNotEmpty).toTypedArray()
    if (chain.isEmpty()) return Ok(null)
    return runCatching {
        certificateChainFromX5c(chain)
        x5cWithoutTerminalSelfSignedRoot(chain)
    }.fold(
        onSuccess = ::Ok,
        onFailure = {
            Err(
                IdkError.fromString(
                    code = "signing_certificate_chain_invalid",
                    message = "Configured issuer signing certificate chain is not valid x5c material",
                ),
            )
        },
    )
}

private suspend fun resolveWithConfiguredKeyMaterial(
    keyAlias: String,
    kms: KeyManagerService,
    build: (Jwk) -> JsonObject?,
): IdkResult<JsonObject?, IdkError> {
    val keyResult = kms.getKeyResult(KeyInfo<Nothing>(alias = keyAlias))
    if (keyResult.isErr) {
        return unavailableSigningMaterial()
    }
    val jwk = keyResult.value.key?.key as? Jwk ?: return unavailableSigningMaterial()
    return build(jwk)?.let(::Ok) ?: unavailableSigningMaterial()
}

private fun unavailableSigningMaterial(): IdkResult<JsonObject?, IdkError> =
    Err(
        IdkError.fromString(
            code = "signing_key_material_unavailable",
            message = "Configured issuer signing key material is unavailable",
        ),
    )

/**
 * The DID that roots a validated DID-URL verification method. A DID-signed credential names this
 * DID as its issuer (OID4VCI 1.0 §14.4), so the header `kid` and `issuer`/`iss` share one DID.
 */
internal fun didOfVerificationMethod(verificationMethodId: String): IdkResult<String, IdkError> {
    if (!verificationMethodId.startsWith("did:") || '#' !in verificationMethodId) {
        return Err(
            IdkError.fromString(
                code = "invalid_signing_verification_method",
                message = "DID signing requires a DID URL verification method",
            ),
        )
    }
    return Ok(verificationMethodId.substringBefore('#'))
}
