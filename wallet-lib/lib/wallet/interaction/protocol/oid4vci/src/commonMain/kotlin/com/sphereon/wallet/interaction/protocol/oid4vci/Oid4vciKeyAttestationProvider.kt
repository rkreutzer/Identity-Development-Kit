/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.wallet.interaction.protocol.oid4vci

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.openid.oid4vci.common.model.KeyAttestationsRequired
import com.sphereon.wallet.unit.SecureComponentUsage
import com.sphereon.wallet.unit.WalletProviderAttestationSignerRef
import com.sphereon.wallet.unit.attestation.KeyAttestationIssueRequest
import com.sphereon.wallet.unit.attestation.WalletUnitAttestationProfile
import com.sphereon.wallet.wsca.Wsca

/**
 * Everything [Oid4vciKeyAttestationProvider] needs to obtain a compact key-attestation JWT for one
 * credential-request proof (OID4VCI 1.0 KA-on-demand: proof_types_supported.jwt.
 * key_attestations_required, carried on the proof JWT's `key_attestation` header per TS 119 472-3).
 *
 * [signingKeyId] identifies the SAME key [Oid4vciHolderIssuanceExecutor] signs the credential-
 * request proof with - the issuer-side verifier requires the proof's holder-binding key to be
 * present in the attestation's `attested_keys` (RFC 7638 thumbprint match), so a provider MUST
 * attest exactly this key, not a different one.
 */
data class Oid4vciKeyAttestationRequest(
    val walletUnitId: String,
    val walletAccountId: String,
    val operationBinding: String,
    val signingKeyId: String,
    val signingAlgorithm: String,
    val audience: String,
    val nonce: String,
    val signer: WalletProviderAttestationSignerRef? = null,
    val evidence: Map<String, String> = emptyMap(),
    val requirement: KeyAttestationsRequired? = null,
) {
    init {
        require(operationBinding.isNotBlank()) { "oid4vci_key_attestation_operation_binding_blank" }
    }
}

/**
 * Issues KA-on-demand through the selected wallet unit's WSCA. The signing key is resolved by its
 * opaque reference and the attestation is produced inside the WSCA/WSCD boundary; no key material
 * is exported to the interaction engine.
 */
class SecureComponentOid4vciKeyAttestationProvider(
    private val wscaProvider: () -> Wsca,
) : Oid4vciKeyAttestationProvider {
    constructor(wsca: Wsca) : this({ wsca })

    private val wsca: Wsca by lazy { wscaProvider() }

    override suspend fun attest(request: Oid4vciKeyAttestationRequest): IdkResult<String, IdkError> {
        if (!request.requirement?.keyStorage.isNullOrEmpty() || !request.requirement?.userAuthentication.isNullOrEmpty()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "OID4VCI key attestation cannot claim unevidenced key-storage or user-authentication assurance values"))
        }
        val algorithm =
            request.signingAlgorithm.toSignatureAlgorithmOrNull()
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "oid4vci_key_attestation_signing_algorithm_unsupported:${request.signingAlgorithm}",
                    ),
                )
        val key =
            wsca.ensureKey(
                walletUnitId = request.walletUnitId,
                usage = SecureComponentUsage.WALLET_CREDENTIAL_PROOF,
                algorithm = algorithm,
                keyAlias = request.signingKeyId,
            ).getOrElse { return Err(it) }
        val attestation =
            wsca.attestKeys(
                KeyAttestationIssueRequest(
                    walletUnitId = request.walletUnitId,
                    walletAccountId = request.walletAccountId,
                    operationBinding = request.operationBinding,
                    profile = WalletUnitAttestationProfile.OID4VCI_JWT,
                    attestedKeys = listOf(key),
                    audience = request.audience,
                    nonce = request.nonce,
                    signer = request.signer,
                    evidence = request.evidence,
                ),
            ).getOrElse { return Err(it) }
        return Ok(attestation.artifact.material.value)
    }
}

private fun String.toSignatureAlgorithmOrNull(): SignatureAlgorithm? =
    when (uppercase()) {
        "ES256" -> SignatureAlgorithm.ECDSA_SHA256
        "ES384" -> SignatureAlgorithm.ECDSA_SHA384
        "ES512" -> SignatureAlgorithm.ECDSA_SHA512
        "EDDSA" -> SignatureAlgorithm.ED25519
        else -> null
    }

/**
 * Obtains a compact key-attestation JWT for [Oid4vciHolderIssuanceExecutor]'s KA-on-demand proof
 * path. Kept as an injectable seam - mirroring [Oid4vciRefreshTokenGrantProvider] - rather than a
 * hard dependency on any specific wallet-unit/WSCA type: the actual attestation mechanics (WSCA
 * key resolution, `Wsca.attestKeys`/`WalletProvider.issueKeyAttestation`) belong at the composition-
 * root layer that already assembles the wallet unit, not duplicated inside the wallet-interaction
 * module.
 */
fun interface Oid4vciKeyAttestationProvider {
    suspend fun attest(request: Oid4vciKeyAttestationRequest): IdkResult<String, IdkError>

    companion object
}
