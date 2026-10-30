/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.wallet.interaction.protocol.oid4vp

import com.sphereon.core.api.encodeToHex
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.tryGenerateJwkThumbprint
import com.sphereon.openid.oid4vp.holder.*
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.common.responseUri
import com.sphereon.openid.oid4vp.common.selectEncryptedResponseJwk
import com.sphereon.wallet.interaction.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject

/** Private protocol facts, not authorization. The existing listed grant authorizes every signature. */
@Serializable
internal data class Oid4vpPreparedJwtPresentation(
    val sessionId: WalletInteractionSessionId,
    val walletUnitId: String,
    val operationBinding: String,
    val resolvedRequest: ResolvedOid4vpRequest,
    val selection: String,
    val selectedIds: Map<String, List<String>>,
    val issuedAt: Long,
    val expiresAt: Long,
    val prepared: HolderPreparedJwtVpResponse?,
    val signing: List<Oid4vpPreparedJwtSigning>,
    val mdocSigning: List<Oid4vpPreparedMdocSigning> = emptyList(),
    val baseOperationCount: Int = 0,
    val operations: List<WalletApprovalOperation>,
    /** Unkeyed SHA-256 corruption detection, not authentication; persisted approval and HSM consumption remain authoritative. */
    val integrity: String = "",
) {
    fun sealed(): Oid4vpPreparedJwtPresentation = copy(integrity = checksum())

    fun requireUsable(
        context: WalletInteractionContext,
        request: ResolvedOid4vpRequest,
        credentials: List<SelectedCredential>,
        ids: Map<String, List<String>>,
        binding: String?,
        now: Long,
        responseModeOverride: ResponseMode? = null,
    ) {
        require(integrity == checksum()) { "Prepared JWT presentation is corrupt" }
        require(context.executionOwner == ProtocolExecutionOwner.WALLET_BACKEND &&
            sessionId == context.sessionId && walletUnitId == context.walletUnitId &&
            operationBinding == binding && resolvedRequest == request && selectedIds == ids &&
            selection == selectionFingerprint(credentials)) { "Prepared JWT presentation context changed" }
        require(now < expiresAt && issuedAt <= now && expiresAt <= issuedAt + 120) { "Prepared JWT presentation expired" }
        require(prepared != null || mdocSigning.isNotEmpty())
        require(prepared != null || signing.isEmpty())
        require(signing.map { it.request } == prepared?.presentations.orEmpty().map { it.signingRequest })
        require(signing.all { it.walletUnitId == walletUnitId && it.operationBinding == operationBinding })
        require(mdocSigning.map { it.signing.credentialId } == credentials.filter { it.credentialFormat?.isMdoc == true }.map { it.credentialId })
        require(baseOperationCount in 0..operations.size)
        require(operations.drop(baseOperationCount) == mdocSigning.map { it.operation } + signing.map { it.approvalOperation() })
        require(mdocSigning.all { it.walletUnitId == walletUnitId && it.operationBinding == operationBinding })
        require(mdocSigning.map { it.signing.credentialId }.distinct().size == mdocSigning.size)
        val recipientBindings = mdocSigning.mapNotNull { it.signing.recipientBinding }.distinct()
        require(recipientBindings.size <= 1 &&
            (recipientBindings.isEmpty() || mdocSigning.all { it.signing.recipientBinding == recipientBindings.single() })) {
            "Prepared mdoc recipient binding is missing or inconsistent"
        }
        val finalResponseMode = responseModeOverride ?: ResponseMode.fromValue(request.request.responseMode.orEmpty())
        val requiresEncryptedJarm = finalResponseMode == ResponseMode.DIRECT_POST_JWT || finalResponseMode == ResponseMode.DC_API_JWT
        require(!requiresEncryptedJarm || mdocSigning.isEmpty() || recipientBindings.size == 1) {
            "Encrypted OID4VP mdoc response has no prepared recipient binding"
        }
        recipientBindings.singleOrNull()?.let { recipient ->
            require(
                recipient.responseMode == (request.request.responseMode ?: ResponseMode.DIRECT_POST.value) &&
                    recipient.clientId == request.request.clientId &&
                    recipient.authorizationRequestNonce == request.request.nonce &&
                    recipient.responseUri == request.request.responseUri &&
                    recipient.redirectUri == request.request.redirectUri,
            ) { "Prepared mdoc recipient binding does not match its authorization request" }
        }
        require(operations.all { it.keyRef.isNotBlank() && it.operationHash.isNotBlank() })
        require(operations.map { it.operationHash }.distinct().size == operations.size)
    }

    private fun checksum(): String = hash(Json.encodeToString(copy(integrity = "")).encodeToByteArray(), DigestAlg.SHA256).encodeToHex()

    companion object {
        fun selectionFingerprint(credentials: List<SelectedCredential>): String {
            // SelectedCredential's signing metadata is transient; include it explicitly in the binding.
            val jwtMetadata = credentials.map { credential ->
                listOf(credential.holderJwtVpSigningIdentifier?.let { Json.encodeToString(it) }, credential.holderSigningAlgorithm?.toString())
            }
            return hash((Json.encodeToString(credentials) + Json.encodeToString(jwtMetadata)).encodeToByteArray(), DigestAlg.SHA256).encodeToHex()
        }
    }
}

internal fun Oid4vpPreparedJwtSigning.approvalOperation(): WalletApprovalOperation =
    WalletApprovalOperation(keyRef = key.keyRef ?: key.keyId, operationHash = operationHash)

/**
 * The holder approval for these prepared signings, naming the one wallet account that owns their
 * keys; null when the prepared signings disagree on that account.
 */
internal fun Oid4vpPreparedJwtPresentation.approvalRequired(): Oid4vpPresentationPreparation.ApprovalRequired? {
    val accounts = (signing.map { it.walletAccountId } + mdocSigning.map { it.walletAccountId }).filterNotNull().distinct()
    if (accounts.size > 1) return null
    return Oid4vpPresentationPreparation.ApprovalRequired(operations, accounts.singleOrNull())
}

/**
 * Whether this prepared JWE recipient binding still names the verifier's response-encryption key.
 *
 * OID4VP 1.0 Annex B.2.6.1 binds the mdoc SessionTranscript to the RFC 7638 SHA-256 thumbprint of
 * the verifier JWK the response is encrypted to, and §8.3 takes that key from the request's
 * `client_metadata.jwks`. The stored thumbprint must therefore be the thumbprint of the stored
 * public JWK, and that JWK must be the request's selected encryption key.
 */
internal fun PreparedOid4vpJweRecipientBinding.matchesVerifierEncryptionKey(request: ResolvedOid4vpRequest): Boolean {
    val stored = runCatching { Json.parseToJsonElement(publicJwkJson).jsonObject }.getOrNull() ?: return false
    val storedJwk = Jwk.tryFromJsonObject(stored).getOrElse { return false }
    val requestJwk = request.clientMetadata?.selectEncryptedResponseJwk() ?: return false
    val storedThumbprint = tryGenerateJwkThumbprint(storedJwk).getOrElse { return false }
    val requestThumbprint = tryGenerateJwkThumbprint(requestJwk).getOrElse { return false }
    return storedThumbprint == rfc7638Thumbprint && requestThumbprint == rfc7638Thumbprint
}
