/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.openid.oid4vp.common.CredentialFormat
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.SelectedCredential
import com.sphereon.wallet.interaction.WalletApprovalOperation
import com.sphereon.sdjwt.SdJwtCodec
import com.sphereon.openid.oid4vp.holder.credentialDisclosurePathOptions
import com.sphereon.sdjwt.SdJwtPresentation
import com.sphereon.wallet.unit.SecureComponentUsage
import com.sphereon.wallet.wsca.Wsca
import com.sphereon.wallet.wsca.WscaSigningRequest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlin.time.Clock

data class Oid4vpSdJwtHolderBindingRequest(
    val walletUnitId: String,
    val operationBinding: String?,
    val request: ResolvedOid4vpRequest,
    val selectedCredentials: List<SelectedCredential>,
    /**
     * The Key Binding JWTs' `iat`. A presentation the holder approved is signed with the `iat` its
     * approval was prepared with, so every signing input is exactly the approved one.
     */
    val issuedAtEpochSeconds: Long? = null,
)

/**
 * Applies SD-JWT holder binding (RFC 9901 Key Binding JWT) to
 * [Oid4vpSdJwtHolderBindingRequest.selectedCredentials] BEFORE they reach the generic
 * [com.sphereon.openid.oid4vp.holder.Oid4vpHolderService]. Kept as an injectable seam - mirroring
 * the OID4VCI credential-request-proof seam
 * ([com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciCredentialRequestProofProvider]) -
 * because where [SelectedCredential.holderKeyRef] is resolved differs by
 * composition root:
 * - [passthrough] leaves credentials untouched, so the generic Oid4vpHolderService signs the Key
 *   Binding JWT through its configured holder-key resolver.
 * - [SecureComponentOid4vpSdJwtHolderBindingProvider] delegates Key Binding JWT signing to [Wsca].
 *   The selected WSCD resolves the alias and uses its configured KMS for the key operation. Which
 *   KMS implementation and route the WSCD uses remains a WSCD/deployment concern. After signing,
 *   the provider clears [SelectedCredential.holderKeyRef] and marks the prepared presentation so
 *   the downstream generic command validates it without signing it a second time.
 *
 * Every wallet composition root MUST wire the WSCA-backed implementation explicitly.
 */
fun interface Oid4vpSdJwtHolderBindingProvider {
    suspend fun applyHolderBinding(request: Oid4vpSdJwtHolderBindingRequest): IdkResult<List<SelectedCredential>, IdkError>

    /**
     * The holder-key signatures [applyHolderBinding] makes for [request], without making them, so
     * the holder can approve exactly those. Empty when this provider signs nothing with a holder key.
     */
    suspend fun prepareHolderBinding(request: Oid4vpSdJwtHolderBindingRequest): IdkResult<List<WalletApprovalOperation>, IdkError> = Ok(emptyList())
}

/**
 * WSCA/WSCD-backed SD-JWT holder binding. Reuses [SdJwtCodec] for parsing and presentation
 * serialization, then delegates the signature to [Wsca]. The selected WSCD resolves
 * [SelectedCredential.holderKeyRef] and performs the key operation with its configured KMS.
 * The KMS implementation and local or remote routing remain hidden behind the WSCA/WSCD boundary.
 */
class SecureComponentOid4vpSdJwtHolderBindingProvider(
    private val secureComponentCryptoSurfaceProvider: () -> Wsca,
) : Oid4vpSdJwtHolderBindingProvider {
    constructor(secureComponentCryptoSurface: Wsca) : this({ secureComponentCryptoSurface })

    private val secureComponentCryptoSurface: Wsca by lazy { secureComponentCryptoSurfaceProvider() }

    override suspend fun prepareHolderBinding(
        request: Oid4vpSdJwtHolderBindingRequest,
    ): IdkResult<List<WalletApprovalOperation>, IdkError> {
        val nonce = request.request.request.nonce
        val audience = request.request.verifierInfo.clientId
        val operations = mutableListOf<WalletApprovalOperation>()
        for (credential in request.selectedCredentials) {
            val holderKeyAlias = credential.holderKeyRef
            if (credential.credentialFormat?.isSdJwt != true || holderKeyAlias.isNullOrBlank() || nonce.isNullOrBlank()) continue
            val signing =
                keyBindingSigning(
                    walletUnitId = request.walletUnitId,
                    resolvedRequest = request.request,
                    credential = credential,
                    operationBinding = request.operationBinding,
                    audience = audience,
                    nonce = nonce,
                    holderKeyAlias = holderKeyAlias,
                    issuedAtEpochSeconds = request.issuedAtEpochSeconds,
                ).getOrElse { return Err(it) }
            val prepared = secureComponentCryptoSurface.prepareSign(signing.signingRequest).getOrElse { return Err(it) }
            operations += WalletApprovalOperation(keyRef = signing.signingRequest.keyRef.keyRef ?: signing.signingRequest.keyRef.keyId, operationHash = prepared.digestBinding)
        }
        return Ok(operations)
    }

    override suspend fun applyHolderBinding(
        request: Oid4vpSdJwtHolderBindingRequest,
    ): IdkResult<List<SelectedCredential>, IdkError> {
        val nonce = request.request.request.nonce
        val audience = request.request.verifierInfo.clientId
        val bound = mutableListOf<SelectedCredential>()
        for (credential in request.selectedCredentials) {
            val holderKeyAlias = credential.holderKeyRef
            val format = credential.credentialFormat
            if (format?.isSdJwt != true || holderKeyAlias.isNullOrBlank() || nonce.isNullOrBlank()) {
                // Nothing for this seam to add (no holder key, not an SD-JWT format), or the
                // downstream generic command will produce its own typed error (e.g. missing
                // nonce) - leave the credential untouched either way.
                bound += credential
                continue
            }
            val signing =
                keyBindingSigning(
                    walletUnitId = request.walletUnitId,
                    resolvedRequest = request.request,
                    credential = credential,
                    operationBinding = request.operationBinding,
                    audience = audience,
                    nonce = nonce,
                    holderKeyAlias = holderKeyAlias,
                    issuedAtEpochSeconds = request.issuedAtEpochSeconds,
                ).getOrElse { return Err(it) }
            val prepared = secureComponentCryptoSurface.prepareSign(signing.signingRequest).getOrElse { return Err(it) }
            val signature = secureComponentCryptoSurface.sign(prepared, signing.signingRequest).getOrElse { return Err(it) }
            val presentation = signing.keyBindingInput.complete(signature)
            bound +=
                credential.copy(
                    presentation = JsonPrimitive(presentation),
                    holderKeyRef = null,
                    sdJwtKeyBindingApplied = true,
                )
        }
        return Ok(bound)
    }

    private class KeyBindingSigning(
        val keyBindingInput: SdJwtPresentation.KeyBindingInput,
        val signingRequest: WscaSigningRequest,
    )

    /**
     * The RFC 9901 Section 4.3 input prepared by the shared SD-JWT module, and the WSCA request that
     * signs it. This adapter only delegates key resolution and signing to WSCA/WSCD; the selected
     * WSCD uses its configured KMS. Disclosure selection, `typ=kb+jwt`, payload construction, and
     * `sd_hash` remain standards logic in `lib/sdjwt`. With the same `iat` the input is the same,
     * which is what lets a holder approve it before it is signed.
     */
    private suspend fun keyBindingSigning(
        walletUnitId: String,
        resolvedRequest: ResolvedOid4vpRequest,
        credential: SelectedCredential,
        operationBinding: String?,
        audience: String,
        nonce: String,
        holderKeyAlias: String,
        issuedAtEpochSeconds: Long?,
    ): IdkResult<KeyBindingSigning, IdkError> {
        val attendedOperationBinding =
            operationBinding?.takeIf { it.isNotBlank() }
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "OID4VP holder binding requires attended operation binding"))
        val sdJwtPresentation =
            (credential.presentation as? JsonPrimitive)
                ?.takeIf { it.isString }
                ?.contentOrNull
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Selected SD-JWT credential '${credential.credentialId}' must be a JSON string"))
        val credentialQueryId = credential.credentialQueryId
        val sdJwt = SdJwtCodec.parse(sdJwtPresentation).getOrElse { return Err(it) }
        val selection =
            runCatching {
                SdJwtPresentation.select(
                    compact = sdJwtPresentation,
                    disclosurePaths =
                        SdJwtPresentation.firstSatisfiableDisclosurePaths(
                            compact = sdJwtPresentation,
                            options = resolvedRequest.credentialDisclosurePathOptions(credentialQueryId),
                        ),
                )
            }.getOrElse {
                return Err(IdkError.fromString(code = "oid4vp.disclosure_selection_failed", message = it.message ?: "Disclosure selection failed"))
            }

        val keyRef =
            secureComponentCryptoSurface
                .ensureKey(
                    walletUnitId = walletUnitId,
                    usage = SecureComponentUsage.WALLET_CREDENTIAL_PROOF,
                    algorithm = SignatureAlgorithm.ECDSA_SHA256,
                    keyAlias = holderKeyAlias,
                ).getOrElse { return Err(it) }
        val publicJwk =
            keyRef.publicKeyJwk
                ?: return Err(
                    IdkError.fromString(
                        code = "oid4vp.key_binding_key_missing_jwk",
                        message = "Secure-component holder key '${keyRef.keyId}' does not carry a public JWK",
                    ),
                )
        verifyCredentialHolderKey(sdJwt.payload.undisclosedPayload, publicJwk).getOrElse { return Err(it) }

        val keyBindingInput =
            SdJwtPresentation.keyBindingInput(
                selection = selection,
                audience = audience,
                nonce = nonce,
                algorithm = keyRef.algorithm,
                issuedAtEpochSeconds = issuedAtEpochSeconds ?: Clock.System.now().epochSeconds,
            )
        return Ok(
            KeyBindingSigning(
                keyBindingInput = keyBindingInput,
                signingRequest =
                    WscaSigningRequest(
                        walletUnitId = walletUnitId,
                        keyRef = keyRef,
                        signingInput = keyBindingInput.signingInput,
                        operationBinding = attendedOperationBinding,
                        audience = audience,
                        nonce = nonce,
                    ),
            ),
        )
    }

    /**
     * The KB-JWT MUST be signed by the key identified by the issued SD-JWT's `cnf.jwk`
     * or `cnf.kid` (for a did:jwk verification method).
     * Comparing only the alias would allow a lost or incorrectly re-provisioned alias to produce
     * a structurally valid presentation with a different key. Compare the RFC 7638 public key
     * members and fail before signing or submitting anything.
     */
    private fun verifyCredentialHolderKey(
        undisclosedPayload: JsonObject,
        resolvedPublicJwkJson: String,
    ): IdkResult<Unit, IdkError> {
        val confirmation = undisclosedPayload["cnf"] as? JsonObject
        val credentialJwk =
            (confirmation?.get("jwk") as? JsonObject)
                ?: (confirmation?.get("kid") as? JsonPrimitive)?.contentOrNull?.let(::didJwkKey)
                ?: return Err(
                    IdkError.fromString(
                        code = "oid4vp.key_binding_cnf_jwk_missing",
                        message = "SD-JWT credential does not contain a supported cnf.jwk or cnf.kid holder binding",
                    ),
                )
        val resolvedJwk =
            runCatching { Json.parseToJsonElement(resolvedPublicJwkJson) as? JsonObject }
                .getOrNull()
                ?: return Err(
                    IdkError.fromString(
                        code = "oid4vp.key_binding_key_invalid_jwk",
                        message = "Secure-component holder key does not carry a valid public JWK",
                    ),
                )
        if (!samePublicKey(credentialJwk, resolvedJwk)) {
            return Err(
                IdkError.fromString(
                    code = "oid4vp.key_binding_key_mismatch",
                    message = "Secure-component holder key does not match the SD-JWT credential cnf.jwk",
                ),
            )
        }
        return Ok(Unit)
    }

}

internal fun didJwkKey(verificationMethod: String): JsonObject? {
    val parts = verificationMethod.removePrefix("did:jwk:").split('#')
    if (!verificationMethod.startsWith("did:jwk:") || parts.size != 2 || parts[1] != "0" || parts[0].isEmpty()) return null
    return runCatching { Json.parseToJsonElement(parts[0].decodeFromBase64Url().decodeToString()) as? JsonObject }.getOrNull()
}

internal fun samePublicKey(
    first: JsonObject,
    second: JsonObject,
): Boolean {
    val members =
        when (first["kty"]?.jsonPrimitive?.contentOrNull) {
            "EC" -> listOf("kty", "crv", "x", "y")
            "RSA" -> listOf("kty", "n", "e")
            "OKP" -> listOf("kty", "crv", "x")
            else -> return false
        }
    return members.all { first[it] != null && first[it] == second[it] }
}
