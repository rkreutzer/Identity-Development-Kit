/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vci

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.openid.oid4vci.common.model.CredentialNotificationEvent
import com.sphereon.openid.oid4vci.common.model.CredentialOffer
import com.sphereon.openid.oid4vci.common.model.CredentialRequestProofs
import com.sphereon.openid.oid4vci.common.model.CredentialResponse
import com.sphereon.openid.oid4vci.holder.CredentialRequestProofPreparationRequest
import com.sphereon.openid.oid4vci.holder.PreparedCredentialRequestProof
import com.sphereon.openid.oid4vci.holder.PreparedCredentialRequestProofBatch
import com.sphereon.wallet.interaction.WalletApprovalOperation
import com.sphereon.crypto.jose.jws.JwsIdentifierMode
import com.sphereon.openid.oid4vci.holder.CreatedProof
import com.sphereon.openid.oid4vci.holder.AuthorizationRequestResult
import com.sphereon.openid.oid4vci.holder.FollowUpIaeArgs
import com.sphereon.openid.oid4vci.holder.IaeHolderResult
import com.sphereon.openid.oid4vci.holder.InitiateIaeArgs
import com.sphereon.openid.oid4vci.holder.Oid4vciHolderService
import com.sphereon.openid.oid4vci.holder.ResolvedAuthorizationServer
import com.sphereon.openid.oid4vci.holder.ResolvedCredentialOffer
import com.sphereon.openid.oid4vci.holder.TokenResponseWithContext
import com.sphereon.oauth2.client.util.extractQueryParameters
import com.sphereon.oauth2.common.command.PrivateKeyJwtAssertionAssembly
import com.sphereon.oauth2.common.command.PrivateKeyJwtAssertionAssemblyRequest
import com.sphereon.oauth2.common.model.ClientAssertion
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.data.store.party.model.IdentifierType
import com.sphereon.wallet.credential.CredentialFormat
import com.sphereon.wallet.credential.CredentialLifecycleState
import com.sphereon.wallet.credential.CredentialRefreshMethod
import com.sphereon.wallet.credential.DeferredIssuanceState
import com.sphereon.wallet.credential.IdentifierRef
import com.sphereon.wallet.credential.IssuanceSession
import com.sphereon.wallet.credential.IssuanceSessionStatus
import com.sphereon.wallet.credential.KeyRef
import com.sphereon.wallet.credential.WalletHolderIdentifierKind
import com.sphereon.wallet.credential.WalletHolderVerificationMethod
import com.sphereon.wallet.credential.RetryPolicy
import com.sphereon.wallet.credential.WalletCredentialStore
import com.sphereon.wallet.WalletHolderVerificationMethodResolver
import com.sphereon.wallet.credential.WalletIssuanceSessionStore
import com.sphereon.wallet.interaction.WalletCredentialPreview
import com.sphereon.wallet.interaction.WalletInteractionAction
import com.sphereon.wallet.interaction.WalletInteractionContext
import com.sphereon.wallet.interaction.WalletInteractionFailureCodes
import com.sphereon.wallet.interaction.toDiagnosticDetails
import kotlinx.coroutines.CancellationException
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.interaction.WalletNestedPresentationExecutionResult
import com.sphereon.wallet.interaction.WalletNestedPresentationExecutor
import com.sphereon.wallet.interaction.WalletNestedPresentationRequest
import com.sphereon.wallet.interaction.WalletProtocol
import com.sphereon.wallet.unit.SecureComponentUsage
import com.sphereon.wallet.unit.WalletProviderAttestationSignerRef
import com.sphereon.wallet.wsca.Wsca
import com.sphereon.wallet.wsca.WscaClientAttestationAuthRequest
import com.sphereon.wallet.wsca.WscaDpopProofRequest
import com.sphereon.wallet.wsca.WscaSigningRequest
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.encodeToHex
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

data class Oid4vciHolderIssuanceOptions(
    /** Exact WSCA key aliases, one independently provisioned key per requested credential. */
    val signingKeyIds: List<String>,
    val operationBinding: String? = null,
    val signingAlgorithm: String = "ES256",
    val clientId: String? = null,
    val clientAuthenticationMethod: ClientAuthenticationMethod? = null,
    val dpopEnabled: Boolean = false,
    val redirectUri: String? = null,
    val credentialConfigurationId: String? = null,
    /** Number of credentials explicitly requested for this interaction. */
    val batchSize: Int = 1,
    val usePar: Boolean = false,
    val encryptCredentialRequest: Boolean = false,
    val iaeCodeVerifier: String? = null,
    val iaeCodeChallenge: String? = null,
    val iaeCodeChallengeMethod: String? = null,
    val haipTokenProofs: Oid4vciHaipTokenProofOptions? = null,
)

private data class CredentialRequestEncryptionSelection(
    val jwk: JsonObject,
    val alg: String,
    val enc: String,
)

/** Exactly one OID4VCI credential selector is placed on the Credential Request wire model. */
internal data class Oid4vciCredentialRequestTarget(
    val credentialConfigurationId: String? = null,
    val credentialIdentifier: String? = null,
)

/**
 * Namespaced launch attributes accepted by the OID4VCI wallet interaction API. These are
 * per-interaction protocol inputs, not process configuration. Composition roots may map them to
 * [Oid4vciHolderIssuanceOptions], while security-sensitive key ownership and attended-operation
 * authorization remain enforced by the wallet-unit/security-gate surfaces.
 */
object Oid4vciInteractionLaunchAttributes {
    const val SIGNING_ALGORITHM: String = "oid4vci.signing.algorithm"
    const val CLIENT_ID: String = "oid4vci.client.id"
    const val CLIENT_AUTHENTICATION_METHOD: String = com.sphereon.wallet.interaction.CapturedInteractionLaunchAttributes.OID4VCI_CLIENT_AUTHENTICATION_METHOD
    const val DPOP_ENABLED: String = com.sphereon.wallet.interaction.CapturedInteractionLaunchAttributes.OID4VCI_DPOP_ENABLED
    const val REDIRECT_URI: String = "oid4vci.redirect.uri"
    const val CREDENTIAL_CONFIGURATION_ID: String = "oid4vci.credential.configuration.id"
    const val CREDENTIAL_BATCH_SIZE: String = com.sphereon.wallet.interaction.CapturedInteractionLaunchAttributes.OID4VCI_CREDENTIAL_BATCH_SIZE
    const val USE_PAR: String = com.sphereon.wallet.interaction.CapturedInteractionLaunchAttributes.OID4VCI_USE_PAR
    const val ENCRYPT_CREDENTIAL_REQUEST: String = com.sphereon.wallet.interaction.CapturedInteractionLaunchAttributes.OID4VCI_ENCRYPT_CREDENTIAL_REQUEST
    const val IAE_CODE_VERIFIER: String = "oid4vci.iae.code.verifier"
    const val IAE_CODE_CHALLENGE: String = "oid4vci.iae.code.challenge"
    const val IAE_CODE_CHALLENGE_METHOD: String = "oid4vci.iae.code.challenge.method"
    const val HAIP_ENABLED: String = "oid4vci.haip.enabled"
    const val HAIP_WALLET_ACCOUNT_ID: String = "oid4vci.haip.wallet.account.id"
    const val HAIP_WALLET_NAME: String = "oid4vci.haip.wallet.name"
    const val HAIP_WALLET_VERSION: String = "oid4vci.haip.wallet.version"
    const val HAIP_CLIENT_INSTANCE_KEY_ALIAS: String = "oid4vci.haip.client.instance.key.alias"
    const val HAIP_CLIENT_INSTANCE_KEY_ALGORITHM: String = "oid4vci.haip.client.instance.key.algorithm"
    const val HAIP_ATTESTATION_SIGNER_ID: String = "oid4vci.haip.attestation.signer.id"
    const val HAIP_ATTESTATION_ISSUER: String = "oid4vci.haip.attestation.issuer"
    const val HAIP_ATTESTATION_PROVIDER_ID: String = "oid4vci.haip.attestation.provider.id"
    const val HAIP_ATTESTATION_KEY_ID: String = "oid4vci.haip.attestation.key.id"
    const val HAIP_ATTESTATION_SIGNING_ALGORITHM: String = "oid4vci.haip.attestation.signing.algorithm"
    const val HAIP_ATTESTATION_SIGNER_PROFILE: String = "oid4vci.haip.attestation.signer.profile"
    const val HAIP_ATTESTATION_X5C: String = "oid4vci.haip.attestation.x5c"
}

/**
 * Applies the non-secret, per-interaction OID4VCI launch attributes supplied by the wallet client.
 * These values travel with [WalletInteractionInput] and survive session restoration; they are not
 * process configuration. Key ownership and attended-operation authorization deliberately remain
 * outside this mapping.
 */
fun Oid4vciHolderIssuanceOptions.withLaunchAttributes(attributes: Map<String, String>): Oid4vciHolderIssuanceOptions {
    fun value(name: String): String? = attributes[name]?.trim()?.takeIf(String::isNotEmpty)

    fun boolean(
        name: String,
        fallback: Boolean,
    ): Boolean =
        value(name)?.let { raw ->
            when (raw.lowercase()) {
                "true" -> true
                "false" -> false
                else -> throw IllegalArgumentException("oid4vci.launch_attribute_boolean_invalid:$name")
            }
        } ?: fallback

    fun positiveInteger(
        name: String,
        fallback: Int,
    ): Int =
        value(name)?.let { raw ->
            raw.toIntOrNull()?.takeIf { it > 0 }
                ?: throw IllegalArgumentException("oid4vci.launch_attribute_positive_integer_invalid:$name")
        } ?: fallback

    return copy(
        signingAlgorithm = value(Oid4vciInteractionLaunchAttributes.SIGNING_ALGORITHM) ?: signingAlgorithm,
        clientId = value(Oid4vciInteractionLaunchAttributes.CLIENT_ID) ?: clientId,
        clientAuthenticationMethod =
            value(Oid4vciInteractionLaunchAttributes.CLIENT_AUTHENTICATION_METHOD)?.let { method ->
                ClientAuthenticationMethod.fromValue(method)
                    ?: throw IllegalArgumentException("oid4vci.launch_attribute_client_authentication_method_invalid:$method")
            } ?: clientAuthenticationMethod,
        dpopEnabled = boolean(Oid4vciInteractionLaunchAttributes.DPOP_ENABLED, dpopEnabled),
        redirectUri = value(Oid4vciInteractionLaunchAttributes.REDIRECT_URI) ?: redirectUri,
        credentialConfigurationId =
            value(Oid4vciInteractionLaunchAttributes.CREDENTIAL_CONFIGURATION_ID) ?: credentialConfigurationId,
        batchSize = positiveInteger(Oid4vciInteractionLaunchAttributes.CREDENTIAL_BATCH_SIZE, batchSize),
        usePar = boolean(Oid4vciInteractionLaunchAttributes.USE_PAR, usePar),
        encryptCredentialRequest =
            boolean(Oid4vciInteractionLaunchAttributes.ENCRYPT_CREDENTIAL_REQUEST, encryptCredentialRequest),
        iaeCodeVerifier = value(Oid4vciInteractionLaunchAttributes.IAE_CODE_VERIFIER) ?: iaeCodeVerifier,
        iaeCodeChallenge = value(Oid4vciInteractionLaunchAttributes.IAE_CODE_CHALLENGE) ?: iaeCodeChallenge,
        iaeCodeChallengeMethod =
            value(Oid4vciInteractionLaunchAttributes.IAE_CODE_CHALLENGE_METHOD) ?: iaeCodeChallengeMethod,
    )
}

data class Oid4vciHaipTokenProofOptions(
    val walletUnitId: String,
    val walletAccountId: String,
    val walletName: String,
    val walletVersion: String,
    val walletLink: String? = null,
    val clientInstanceKeyAlias: String? = null,
    val clientInstanceKeyAlgorithm: String = "ES256",
    val signer: WalletProviderAttestationSignerRef? = null,
    val attestationChallenge: String? = null,
    val evidence: Map<String, String> = emptyMap(),
)

data class Oid4vciTokenEndpointProofRequest(
    val context: WalletInteractionContext,
    val state: WalletInteractionState,
    val resolvedOffer: ResolvedCredentialOffer,
    val options: Oid4vciHolderIssuanceOptions,
    val tokenEndpoint: String,
    val authorizationServerIssuer: String? = null,
    val nonce: String? = null,
)

data class Oid4vciDpopProofRequest(
    val context: WalletInteractionContext,
    val state: WalletInteractionState,
    val resolvedOffer: ResolvedCredentialOffer,
    val options: Oid4vciHolderIssuanceOptions,
    val httpMethod: String,
    val httpUrl: String,
    val nonce: String? = null,
    val accessToken: String? = null,
)

data class Oid4vciTokenEndpointProofs(
    val dpopProofJwt: String? = null,
    val clientAttestationJwt: String? = null,
    val clientAttestationPopJwt: String? = null,
    val clientAuthentication: ClientAuthenticationConfig? = null,
) {
    init {
        require(clientAuthentication == null || clientAuthentication !is ClientAuthenticationConfig.AttestationJwt) {
            "attest_jwt_client_auth must use clientAttestationJwt/clientAttestationPopJwt headers in OID4VCI token proofs"
        }
    }
}

interface Oid4vciIssuanceOptionsProvider {
    /**
     * Resolves the per-interaction options. Implementations must not create holder keys here: the
     * executor asks for keys through [holderKeys] only once the token exchange has succeeded, so an
     * earlier failure never leaves an unused key behind.
     */
    suspend fun options(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        /** Existing aliases for reissuance/refresh; providers must not mint replacements. */
        existingHolderKeyAliases: List<String> = emptyList(),
    ): Oid4vciHolderIssuanceOptions

    /**
     * Returns the holder proof key aliases for the credential request, creating them when
     * [options] carry none. Called after authorization server discovery and the token exchange,
     * immediately before the proof is built. The default returns the aliases [options] already
     * carry, which suits providers that are handed fixed keys.
     */
    suspend fun holderKeys(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        options: Oid4vciHolderIssuanceOptions,
    ): List<String> = options.signingKeyIds
}

interface Oid4vciTokenEndpointProofsProvider {
    suspend fun proofs(request: Oid4vciTokenEndpointProofRequest): IdkResult<Oid4vciTokenEndpointProofs, IdkError>

    suspend fun dpopProof(request: Oid4vciDpopProofRequest): IdkResult<String?, IdkError> = Ok(null)

    companion object {
        val none: Oid4vciTokenEndpointProofsProvider =
            object : Oid4vciTokenEndpointProofsProvider {
                override suspend fun proofs(request: Oid4vciTokenEndpointProofRequest): IdkResult<Oid4vciTokenEndpointProofs, IdkError> =
                    Ok(Oid4vciTokenEndpointProofs())
            }
    }
}

class SecureComponentOid4vciTokenEndpointProofsProvider(
    private val secureComponentCryptoSurfaceProvider: () -> Wsca,
    private val privateKeyJwtAssertionAssembly: PrivateKeyJwtAssertionAssembly,
) : Oid4vciTokenEndpointProofsProvider {
    constructor(
        secureComponentCryptoSurface: Wsca,
        privateKeyJwtAssertionAssembly: PrivateKeyJwtAssertionAssembly,
    ) : this({ secureComponentCryptoSurface }, privateKeyJwtAssertionAssembly)

    private val secureComponentCryptoSurface: Wsca by lazy { secureComponentCryptoSurfaceProvider() }

    override suspend fun dpopProof(request: Oid4vciDpopProofRequest): IdkResult<String?, IdkError> {
        val haip = request.options.haipTokenProofs
        if (haip == null && !request.options.dpopEnabled) return Ok(null)
        val clientInstanceKey =
            secureComponentCryptoSurface
                .ensureKey(
                    walletUnitId = haip?.walletUnitId ?: request.context.walletUnitId,
                    usage = SecureComponentUsage.OAUTH_CLIENT_AUTHENTICATION,
                    algorithm = signatureAlgorithm(haip?.clientInstanceKeyAlgorithm ?: "ES256"),
                    keyAlias = haip?.let { clientInstanceKeyAlias(it, request.resolvedOffer) },
                ).getOrElse { return Err(it) }
        val dpop =
            secureComponentCryptoSurface
                .createDpopProof(
                    WscaDpopProofRequest(
                        walletUnitId = haip?.walletUnitId ?: request.context.walletUnitId,
                        operationBinding = requireOperationBinding(request.options),
                        keyRef = clientInstanceKey,
                        httpMethod = request.httpMethod,
                        httpUrl = request.httpUrl,
                        nonce = request.nonce,
                        accessToken = request.accessToken,
                    ),
                ).getOrElse { return Err(it) }
        return Ok(dpop.proofJwt)
    }

    override suspend fun proofs(request: Oid4vciTokenEndpointProofRequest): IdkResult<Oid4vciTokenEndpointProofs, IdkError> {
        val haip = request.options.haipTokenProofs
        if (haip == null) return finalProfileProofs(request)
        val clientId =
            request.options.clientId
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "HAIP token proofs require an OID4VCI client_id"))
        val authorizationServerIssuer =
            request.authorizationServerIssuer
                ?.takeIf { it.isNotBlank() }
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "HAIP token proofs require the authorization server issuer"))
        val clientInstanceKey =
            secureComponentCryptoSurface
                .ensureKey(
                    walletUnitId = haip.walletUnitId,
                    usage = SecureComponentUsage.OAUTH_CLIENT_AUTHENTICATION,
                    algorithm = signatureAlgorithm(haip.clientInstanceKeyAlgorithm),
                    keyAlias = clientInstanceKeyAlias(haip, request.resolvedOffer),
                ).getOrElse { return Err(it) }
        val dpop =
            dpopProof(
                Oid4vciDpopProofRequest(
                    context = request.context,
                    state = request.state,
                    resolvedOffer = request.resolvedOffer,
                    options = request.options,
                    httpMethod = "POST",
                    httpUrl = request.tokenEndpoint,
                    nonce = request.nonce,
                ),
            ).getOrElse { return Err(it) }
        val clientAuth =
            secureComponentCryptoSurface
                .createClientAttestationAuth(
                    WscaClientAttestationAuthRequest(
                        walletUnitId = haip.walletUnitId,
                        operationBinding = requireOperationBinding(request.options),
                        walletAccountId = haip.walletAccountId,
                        clientId = clientId,
                        audience = authorizationServerIssuer,
                        clientInstanceKey = clientInstanceKey,
                        walletName = haip.walletName,
                        walletVersion = haip.walletVersion,
                        walletLink = haip.walletLink,
                        signer = haip.signer,
                        challenge = haip.attestationChallenge,
                        evidence = haip.evidence,
                    ),
                ).getOrElse { return Err(it) }
        return Ok(
            Oid4vciTokenEndpointProofs(
                dpopProofJwt = dpop,
                clientAttestationJwt = clientAuth.clientAttestationJwt,
                clientAttestationPopJwt = clientAuth.clientAttestationPopJwt,
            ),
        )
    }

    private fun clientInstanceKeyAlias(haip: Oid4vciHaipTokenProofOptions, offer: ResolvedCredentialOffer): String =
        haip.clientInstanceKeyAlias ?: "oid4vci-client-" + hash(
            "oid4vci-client-v1\u0000${haip.walletUnitId}\u0000${offer.issuerMetadata.credentialIssuer}".encodeToByteArray(),
            DigestAlg.SHA256,
        ).encodeToHex()

    private suspend fun finalProfileProofs(request: Oid4vciTokenEndpointProofRequest): IdkResult<Oid4vciTokenEndpointProofs, IdkError> {
        val clientAuthenticationMethod = request.options.clientAuthenticationMethod
        if (clientAuthenticationMethod != ClientAuthenticationMethod.PRIVATE_KEY_JWT && !request.options.dpopEnabled) {
            return Ok(Oid4vciTokenEndpointProofs())
        }
        val clientId =
            request.options.clientId?.takeIf(String::isNotBlank)
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "OID4VCI client authentication requires client_id"))
        val keyRef =
            secureComponentCryptoSurface
                .ensureKey(
                    walletUnitId = request.context.walletUnitId,
                    usage = SecureComponentUsage.OAUTH_CLIENT_AUTHENTICATION,
                    algorithm = SignatureAlgorithm.ECDSA_SHA256,
                ).getOrElse { return Err(it) }
        val dpop =
            dpopProof(
                Oid4vciDpopProofRequest(
                    context = request.context,
                    state = request.state,
                    resolvedOffer = request.resolvedOffer,
                    options = request.options,
                    httpMethod = "POST",
                    httpUrl = request.tokenEndpoint,
                    nonce = request.nonce,
                ),
            ).getOrElse { return Err(it) }
        if (clientAuthenticationMethod != ClientAuthenticationMethod.PRIVATE_KEY_JWT) {
            return Ok(Oid4vciTokenEndpointProofs(dpopProofJwt = dpop))
        }
        val audience =
            request.authorizationServerIssuer?.takeIf(String::isNotBlank)
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "private_key_jwt requires the authorization server issuer audience"))
        val publicJwk =
            try {
                Json.decodeFromString(
                    Jwk.serializer(),
                    keyRef.publicKeyJwk
                        ?: return Err(IdkError.INVALID_STATE(message = "OAuth client key omitted its public JWK")),
                )
            } catch (expected: Exception) {
                return Err(IdkError.INVALID_STATE(message = "OAuth client key public JWK is invalid", throwable = expected))
            }
        val assembled =
            try {
                privateKeyJwtAssertionAssembly.assemble(
                    PrivateKeyJwtAssertionAssemblyRequest(clientId = clientId, audience = audience),
                    publicJwk,
                )
            } catch (expected: IllegalArgumentException) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = expected.message ?: "private_key_jwt assembly failed", throwable = expected))
            }
        val signingRequest =
            WscaSigningRequest(
                walletUnitId = request.context.walletUnitId,
                keyRef = keyRef,
                signingInput = assembled.signingInput,
                operationBinding = requireOperationBinding(request.options),
                audience = audience,
            )
        val prepared = secureComponentCryptoSurface.prepareSign(signingRequest).getOrElse { return Err(it) }
        val signature = secureComponentCryptoSurface.sign(prepared, signingRequest).getOrElse { return Err(it) }
        val assertion = privateKeyJwtAssertionAssembly.finish(assembled, signature)
        return Ok(
            Oid4vciTokenEndpointProofs(
                dpopProofJwt = dpop,
                clientAuthentication =
                    ClientAuthenticationConfig.PrivateKeyJwt(
                        ClientAssertion(
                            clientId = clientId,
                            assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                            assertion = assertion,
                        ),
                    ),
            ),
        )
    }
}

data class Oid4vciCredentialRequestProofRequest(
    val walletUnitId: String,
    val operationBinding: String? = null,
    val issuerUrl: String,
    val cNonce: String? = null,
    val signingKeyId: String,
    val signingAlgorithm: String = "ES256",
    val clientId: String? = null,
    val keyAttestationJwt: String? = null,
    /**
     * The holder's did:jwk `#0` verification method of [signingKeyId] when the credential is to be
     * bound to a DID (OID4VCI 1.0 section 12.2.4 `did:jwk`, Appendix F.1 `kid`); null for a JWK proof.
     */
    val holderDidVerificationMethod: String? = null,
)

/**
 * Creates the OID4VCI 1.0 Appendix F.1 credential-request JWT proofs (`typ=openid4vci-proof+jwt`)
 * in two steps: [prepareProofs] fixes each proof's exact signing input, the holder approves those
 * hashes, and [finalizeProofs] signs exactly what was prepared. Kept as an injectable seam -
 * mirroring [Oid4vciTokenEndpointProofsProvider] - so protocol orchestration does not own key
 * custody. Every production implementation must use [Wsca]; WSCA selects the WSCD and the selected
 * WSCD uses its configured KMS. There is no direct-KMS provider.
 */
interface Oid4vciCredentialRequestProofProvider {
    /** Prepares one proof per request, in request order, all issued at [iatEpochSeconds]. */
    suspend fun prepareProofs(
        requests: List<Oid4vciCredentialRequestProofRequest>,
        iatEpochSeconds: Long,
    ): IdkResult<PreparedCredentialRequestProofBatch, IdkError>

    /** Signs the prepared proofs and combines them into the OID4VCI `proofs` container. */
    suspend fun finalizeProofs(prepared: PreparedCredentialRequestProofBatch): IdkResult<CreatedProof, IdkError>
}

/**
 * Delegates to [Oid4vciHolderService]. The holder service itself signs through its injected [Wsca];
 * this adapter exists only for consumers of that command surface and is not an alternate custody
 * path.
 */
class HolderServiceOid4vciCredentialRequestProofProvider(
    private val holder: Oid4vciHolderService,
) : Oid4vciCredentialRequestProofProvider {
    override suspend fun prepareProofs(
        requests: List<Oid4vciCredentialRequestProofRequest>,
        iatEpochSeconds: Long,
    ): IdkResult<PreparedCredentialRequestProofBatch, IdkError> {
        if (requests.isEmpty()) {
            return Err(
                IdkError.fromString(
                    code = "oid4vci.credential_proof_requests_empty",
                    message = "At least one OID4VCI credential proof request is required",
                ),
            )
        }
        val proofs = mutableListOf<PreparedCredentialRequestProof>()
        for (request in requests) {
            val operationBinding =
                request.operationBinding?.takeIf(String::isNotBlank)
                    ?: return Err(IdkError.INVALID_STATE(message = "OID4VCI credential proofs require an attended operation binding"))
            val prepared =
                holder.prepareCredentialRequestProofs(
                    CredentialRequestProofPreparationRequest(
                        walletUnitId = request.walletUnitId,
                        operationBinding = operationBinding,
                        issuerUrl = request.issuerUrl,
                        cNonce = request.cNonce,
                        signingKeyIds = listOf(request.signingKeyId),
                        signingAlgorithm = request.signingAlgorithm,
                        clientId = request.clientId,
                        keyInclusionMode =
                            if (request.holderDidVerificationMethod != null) JwsIdentifierMode.DID.name else JwsIdentifierMode.JWK.name,
                        keyAttestationJwt = request.keyAttestationJwt,
                        iatEpochSeconds = iatEpochSeconds,
                        holderDidVerificationMethod = request.holderDidVerificationMethod,
                    ),
                ).getOrElse { return Err(it) }
            proofs += prepared.proofs
        }
        return Ok(PreparedCredentialRequestProofBatch(proofs))
    }

    override suspend fun finalizeProofs(prepared: PreparedCredentialRequestProofBatch): IdkResult<CreatedProof, IdkError> =
        holder.finalizeCredentialRequestProofs(prepared)
}

private fun requireOperationBinding(options: Oid4vciHolderIssuanceOptions): String =
    options.operationBinding?.takeIf { it.isNotBlank() }
        ?: error("OID4VCI secure-component operation requires attended authorization binding")

interface Oid4vciCredentialResponseReceiver {
    suspend fun receiveCredentialResponse(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        credentialResponse: CredentialResponse,
    ): List<WalletCredentialPreview>
}

data class Oid4vciRefreshTokenGrantRequest(
    val tokenEndpoint: String,
    val refreshToken: String,
    val clientId: String? = null,
    val dpopProofJwt: String? = null,
    val clientAttestationJwt: String? = null,
    val clientAttestationPopJwt: String? = null,
    val clientAuthentication: ClientAuthenticationConfig? = null,
)

/**
 * Executes the OAuth2 `refresh_token` grant (RFC 6749 Section 6) for wallet-initiated credential
 * refresh. The production adapter delegates to [Oid4vciHolderService.exchangeRefreshToken], while
 * this seam keeps the interaction executor independently testable.
 */
fun interface Oid4vciRefreshTokenGrantProvider {
    suspend fun exchangeRefreshToken(request: Oid4vciRefreshTokenGrantRequest): IdkResult<TokenResponseWithContext, IdkError>

    companion object
}

private data class Oid4vciPreparedProofSelection(
    val prepared: PreparedCredentialRequestProofBatch,
    val holderKeyAliases: List<String>,
)

class Oid4vciHolderIssuanceExecutor(
    private val holder: Oid4vciHolderService,
    private val optionsProvider: Oid4vciIssuanceOptionsProvider,
    private val credentialReceiver: Oid4vciCredentialResponseReceiver,
    private val nestedPresentationExecutor: WalletNestedPresentationExecutor,
    private val tokenEndpointProofsProvider: Oid4vciTokenEndpointProofsProvider = Oid4vciTokenEndpointProofsProvider.none,
    /**
     * Wallet-initiated refresh ([refreshCredential]) reads the existing credential record and its
     * stored refresh token through these two stores.
     */
    private val credentialStore: WalletCredentialStore,
    private val issuanceSessionStore: WalletIssuanceSessionStore,
    private val refreshTokenGrantProvider: Oid4vciRefreshTokenGrantProvider,
    /** KA-on-demand (OID4VCI 1.0 proof_types_supported.jwt.key_attestations_required). */
    private val keyAttestationProvider: Oid4vciKeyAttestationProvider,
    /**
     * Creates the credential-request JWT proof. See [Oid4vciCredentialRequestProofProvider] KDoc
     * for which of the two implementations a given composition root must wire.
     */
    private val credentialRequestProofProvider: Oid4vciCredentialRequestProofProvider,
    /**
     * Resolves the did:jwk verification method registered for a holder key, used when the
     * credential configuration binds credentials to `did:jwk`. Without it only JWK binding is offered.
     */
    private val holderVerificationMethodResolver: WalletHolderVerificationMethodResolver? = null,
) : Oid4vciIssuanceExecutor {
    override suspend fun requestCredential(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        action: WalletInteractionAction?,
    ): Oid4vciIssuanceExecutionResult = requestCredentialUnlogged(context, state, action).logged(context, "request_credential")

    private suspend fun requestCredentialUnlogged(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        action: WalletInteractionAction?,
    ): Oid4vciIssuanceExecutionResult {
        val sessionState = context.oid4vciState()
        if (state.status == WalletInteractionStatus.DeferredRetrievalPending) {
            return requestDeferredCredential(context, state, sessionState)
        }
        if (sessionState.iae?.pending == true) {
            return continueInteractiveAuthorization(context, state, sessionState, action)
        }

        val rawOffer =
            sessionState.entryPointRaw?.takeIf { it.isNotBlank() }
                ?: return failed(
                    code = WalletInteractionFailureCodes.OID4VCI_CREDENTIAL_OFFER_MISSING,
                    messageKey = "wallet.interaction.error.oid4vci_credential_offer_missing",
                    retryable = true,
                )

        val offer = holder.parseCredentialOffer(rawOffer)
        if (offer.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_OFFER_PARSE_FAILED, "wallet.interaction.error.oid4vci_offer_parse_failed", offer.error)
        }
        val resolved = holder.resolveCredentialOffer(offer.value)
        if (resolved.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_OFFER_RESOLVE_FAILED, "wallet.interaction.error.oid4vci_offer_resolve_failed", resolved.error)
        }

        val options =
            try {
                optionsProvider.options(context, state, resolved.value)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (cause: Exception) {
                return optionsUnavailable(WalletInteractionFailureCodes.OID4VCI_OPTIONS_UNAVAILABLE, "wallet.interaction.error.oid4vci_options_unavailable", cause)
            }

        sessionState.unfinishedIssuedToken()?.let { token ->
            return requestCredentialWithIssuedToken(
                context = context,
                state = state,
                resolvedOffer = resolved.value,
                options = options,
                clientId = sessionState.authorization?.clientId ?: sessionState.iae?.clientId ?: options.clientId,
                token = token,
                dpopProofFailureRetryable = sessionState.iae != null,
            )
        }

        val preAuthorizedGrant =
            resolved.value.offer.grants
                ?.preAuthorizedCode
        if (preAuthorizedGrant == null) {
            sessionState.authorizationCallback?.takeIf { it.isNotBlank() }?.let { callback ->
                return exchangeAuthorizationCodeAndRequestCredential(context, state, resolved.value, options, callback)
            }
            return buildAuthorizationRequest(context, state, resolved.value, options)
        }

        val authorizationServer = holder.selectAuthorizationServer(resolved.value.issuerMetadata, preAuthorizedGrant.authorizationServer)
        if (authorizationServer.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_SERVER_RESOLVE_FAILED, "wallet.interaction.error.oid4vci_authorization_server_resolve_failed", authorizationServer.error)
        }
        val challengedOptions = options.withAttestationChallenge(authorizationServer.value).getOrElse {
            return failed(WalletInteractionFailureCodes.OID4VCI_ATTESTATION_CHALLENGE_FAILED, "wallet.interaction.error.oid4vci_attestation_challenge_failed", it)
        }
        val tokenEndpoint = authorizationServer.value.tokenEndpoint
        val tokenProofs = tokenEndpointProofs(context, state, resolved.value, challengedOptions, tokenEndpoint, authorizationServer.value.issuer).getOrElse {
            return failed(WalletInteractionFailureCodes.OID4VCI_TOKEN_PROOFS_FAILED, "wallet.interaction.error.oid4vci_token_proofs_failed", it)
        }

        val token =
            exchangePreAuthorizedCodeWithDpopNonceRetry(
                context = context,
                state = state,
                resolvedOffer = resolved.value,
                options = challengedOptions,
                tokenEndpoint = tokenEndpoint,
                authorizationServerIssuer = authorizationServer.value.issuer,
                preAuthorizedCode = preAuthorizedGrant.preAuthorizedCode,
                txCode = sessionState.txCode,
                clientId = options.clientId,
                redirectUri = options.redirectUri,
                dpopProofJwt = tokenProofs.dpopProofJwt,
                clientAttestationJwt = tokenProofs.clientAttestationJwt,
                clientAttestationPopJwt = tokenProofs.clientAttestationPopJwt,
                clientAuthentication = tokenProofs.clientAuthentication,
            )
        if (token.isErr) {
            if (token.error.code == OAUTH_INVALID_GRANT && !sessionState.txCode.isNullOrBlank()) {
                return Oid4vciIssuanceExecutionResult.TxCodeRejected
            }
            return failed(WalletInteractionFailureCodes.OID4VCI_TOKEN_EXCHANGE_FAILED, "wallet.interaction.error.oid4vci_token_exchange_failed", token.error)
        }
        val issuedToken =
            Oid4vciPrivateSessionState.TokenLeg(
                accessToken = token.value.accessToken,
                refreshToken = token.value.refreshToken,
                tokenEndpoint = tokenEndpoint,
                cNonce = token.value.cNonce,
                authorizationDetails = token.value.authorizationDetails,
            )
        context.updateOid4vciState { it.copy(txCodeRejections = 0, tokens = issuedToken) }
        return requestCredentialWithIssuedToken(
            context = context,
            state = state,
            resolvedOffer = resolved.value,
            options = options,
            clientId = options.clientId,
            token = issuedToken,
            dpopProofFailureRetryable = false,
        )
    }

    /**
     * The access token of an exchange whose credential request never reached the proof stage, for
     * example because holder key provisioning failed. The grant behind it is spent, so a retry
     * continues from the proof nonce with this token instead of exchanging the grant again.
     */
    private fun Oid4vciPrivateSessionState.unfinishedIssuedToken(): Oid4vciPrivateSessionState.TokenLeg? =
        tokens?.takeIf { holderKeyAliases.isEmpty() }

    /**
     * Everything after a successful token response: proof nonce, holder keys, the proofs' signing
     * inputs, the holder's approval of exactly those proofs, the signatures, the credential request
     * and the response handling. Shared by the pre-authorized, authorization code and interactive
     * authorization legs and by the retry that reuses a stored token.
     *
     * The first pass prepares the proofs and returns [Oid4vciIssuanceExecutionResult.ProofApprovalRequired].
     * Once the holder has approved them, the next pass signs the prepared proofs unchanged.
     */
    private suspend fun requestCredentialWithIssuedToken(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        clientId: String?,
        token: Oid4vciPrivateSessionState.TokenLeg,
        dpopProofFailureRetryable: Boolean,
    ): Oid4vciIssuanceExecutionResult {
        val pending = context.oid4vciState().pendingProofs
        if (pending == null) {
            return prepareProofsForApproval(context, state, resolvedOffer, options, clientId, token)
        }
        if (!pending.approved) return pending.approvalRequired(options)

        val createdProof = credentialRequestProofProvider.finalizeProofs(pending.prepared).getOrElse { return credentialRequestProofFailure(it) }
        if (createdProof.proofs.proofValues.size != pending.prepared.proofs.size) {
            return credentialRequestProofFailure(
                IdkError.fromString(
                    code = "oid4vci.credential_batch_proof_count_mismatch",
                    message = "OID4VCI proof provider returned ${createdProof.proofs.proofValues.size} proofs for ${pending.prepared.proofs.size} prepared proofs",
                ),
            )
        }
        context.updateOid4vciState {
            it.copy(
                holderKeyAliases = pending.holderKeyAliases,
                credentialConfigurationId = pending.credentialConfigurationId,
                pendingProofs = null,
            )
        }
        val credentialDpopProof = credentialEndpointDpopProof(context, state, resolvedOffer, options, token.accessToken).getOrElse {
            return failed(
                WalletInteractionFailureCodes.OID4VCI_CREDENTIAL_DPOP_PROOF_FAILED,
                "wallet.interaction.error.oid4vci_credential_dpop_proof_failed",
                it,
                retryable = dpopProofFailureRetryable,
            )
        }
        val credential =
            requestCredentialWithDpopNonceRetry(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                accessToken = token.accessToken,
                dpopProofJwt = credentialDpopProof,
                credentialConfigurationId = pending.credentialConfigurationId,
                proofs = createdProof.proofs,
                tokenAuthorizationDetails = token.authorizationDetails,
            )
        if (credential.isErr) {
            if (credential.error.code == OID4VCI_INVALID_NONCE) {
                // The c_nonce expired while the holder was approving. The same holder keys sign
                // freshly prepared proofs once the holder approves those.
                context.updateOid4vciState { it.copy(holderKeyAliases = emptyList()) }
                return prepareProofsForApproval(context, state, resolvedOffer, options.copy(signingKeyIds = pending.holderKeyAliases), clientId, token)
            }
            return failed(WalletInteractionFailureCodes.OID4VCI_CREDENTIAL_REQUEST_FAILED, "wallet.interaction.error.oid4vci_credential_request_failed", credential.error)
        }
        return handleCredentialResponse(context, state, resolvedOffer, credential.value, options.isDpopBound())
    }

    private suspend fun prepareProofsForApproval(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        clientId: String?,
        token: Oid4vciPrivateSessionState.TokenLeg,
    ): Oid4vciIssuanceExecutionResult {
        val cNonce = resolveProofNonce(resolvedOffer, token.cNonce)
        if (cNonce.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_NONCE_REQUEST_FAILED, "wallet.interaction.error.oid4vci_nonce_request_failed", cNonce.error)
        }
        val credentialConfigurationId = selectCredentialConfigurationId(options, state, resolvedOffer)
        val proofSelection =
            prepareCredentialRequestProofs(
                context,
                state,
                resolvedOffer,
                credentialConfigurationId,
                cNonce.value,
                options,
                clientId,
            )
                .getOrElse { return credentialRequestProofFailure(it) }
        val pending =
            Oid4vciPrivateSessionState.PendingProofsLeg(
                prepared = proofSelection.prepared,
                holderKeyAliases = proofSelection.holderKeyAliases,
                credentialConfigurationId = credentialConfigurationId,
            )
        context.updateOid4vciState { it.copy(pendingProofs = pending) }
        return pending.approvalRequired(options)
    }

    private fun Oid4vciPrivateSessionState.PendingProofsLeg.approvalRequired(options: Oid4vciHolderIssuanceOptions): Oid4vciIssuanceExecutionResult {
        val first = prepared.proofs.first()
        return Oid4vciIssuanceExecutionResult.ProofApprovalRequired(
            operations =
                prepared.proofs.map { proof ->
                    WalletApprovalOperation(keyRef = proof.keyRef.keyRef ?: proof.keyRef.keyId, operationHash = proof.digestBinding)
                },
            walletAccountId = first.walletAccountId,
            operationBinding = options.operationBinding ?: first.operationBinding,
            audience = first.audience,
        )
    }

    /**
     * Wallet-initiated credential refresh: loads the existing record ->
     * looks up its stored OAuth2 refresh token -> re-resolves the authorization server (issuer
     * endpoints are never cached on the record) -> exchanges the refresh token for a fresh access
     * token -> re-requests the credential(s) with the EXISTING active-instance holder keys
     * (REUSED, never freshly minted) -> stores through the SAME [credentialReceiver] used for normal
     * issuance, so replacement and sibling-preservation semantics live in one place.
     *
     * Every failure path returns a typed [Oid4vciIssuanceExecutionResult.Failed]; nothing throws.
     */
    override suspend fun refreshCredential(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        credentialRecordId: String,
        credentialInstanceId: String?,
    ): Oid4vciIssuanceExecutionResult =
        refreshCredentialUnlogged(context, state, credentialRecordId, credentialInstanceId).logged(context, "refresh_credential")

    private suspend fun refreshCredentialUnlogged(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        credentialRecordId: String,
        credentialInstanceId: String?,
    ): Oid4vciIssuanceExecutionResult {
        val recordResult = credentialStore.getCredential(context.walletUnitId, credentialRecordId)
        if (recordResult.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_RECORD_LOOKUP_FAILED, "wallet.interaction.error.oid4vci_refresh_record_lookup_failed", recordResult.error, retryable = true)
        }
        val record =
            recordResult.value
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_RECORD_NOT_FOUND, "wallet.interaction.error.oid4vci_refresh_record_not_found")

        val refreshState =
            record.refreshState
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_STATE_MISSING, "wallet.interaction.error.oid4vci_refresh_state_missing")
        if (refreshState.refreshMethod != CredentialRefreshMethod.OID4VCI_REISSUANCE) {
            return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_METHOD_UNSUPPORTED, "wallet.interaction.error.oid4vci_refresh_method_unsupported")
        }
        val provenance =
            record.issuanceProvenance
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_PROVENANCE_MISSING, "wallet.interaction.error.oid4vci_refresh_provenance_missing")
        val credentialIssuer = provenance.credentialIssuerUrl
        val credentialConfigurationId = provenance.credentialConfigurationId

        val activeInstances = record.instances.filter { it.lifecycleState == CredentialLifecycleState.ACTIVE }
        val refreshInstances =
            if (credentialInstanceId != null) {
                val target = record.instances.singleOrNull { it.id == credentialInstanceId }
                    ?: return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_RECORD_NOT_FOUND, "wallet.interaction.error.oid4vci_refresh_record_not_found")
                if (target.lifecycleState != CredentialLifecycleState.ACTIVE) {
                    return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_HOLDER_KEY_MISSING, "wallet.interaction.error.oid4vci_refresh_holder_key_missing")
                }
                listOf(target)
            } else {
                // A record-level refresh is a true batch refresh: every active instance is
                // reissued in one request. This preserves the record's sibling pool while keeping
                // the one-key-per-instance mapping exact. A record with no active instance cannot
                // be refreshed safely because there is no current holder-key binding to present.
                activeInstances
            }
        if (refreshInstances.isEmpty()) {
            return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_HOLDER_KEY_MISSING, "wallet.interaction.error.oid4vci_refresh_holder_key_missing")
        }
        val holderKeyAliases = refreshInstances.mapNotNull { it.holderKeyRef?.alias }
        if (holderKeyAliases.size != refreshInstances.size || holderKeyAliases.distinct().size != holderKeyAliases.size) {
            return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_HOLDER_KEY_MISSING, "wallet.interaction.error.oid4vci_refresh_holder_key_missing")
        }

        val refreshTokenResult = issuanceSessionStore.getRefreshToken(context.walletUnitId, credentialRecordId)
        if (refreshTokenResult.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_TOKEN_LOOKUP_FAILED, "wallet.interaction.error.oid4vci_refresh_token_lookup_failed", refreshTokenResult.error, retryable = true)
        }
        val refreshToken =
            refreshTokenResult.value?.takeIf { it.isNotBlank() }
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_TOKEN_MISSING, "wallet.interaction.error.oid4vci_refresh_token_missing")

        val metadataResult = holder.resolveIssuerMetadata(credentialIssuer)
        if (metadataResult.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_ISSUER_METADATA_FAILED, "wallet.interaction.error.oid4vci_refresh_issuer_metadata_failed", metadataResult.error, retryable = true)
        }
        val metadata = metadataResult.value
        val credConfig =
            metadata.credentialConfigurationsSupported[credentialConfigurationId]
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_CREDENTIAL_CONFIGURATION_UNKNOWN, "wallet.interaction.error.oid4vci_refresh_credential_configuration_unknown")
        if (CredentialFormat.fromValueLenient(credConfig.format) == null) {
            return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_CREDENTIAL_FORMAT_UNSUPPORTED, "wallet.interaction.error.oid4vci_refresh_credential_format_unsupported")
        }

        // Do NOT persist AS endpoints on the record: re-resolve the authorization server fresh from
        // issuer metadata every refresh, exactly like the offer-based flow always re-derives it
        // rather than trusting a stale cached endpoint.
        val authorizationServer = holder.selectAuthorizationServer(metadata, null)
        if (authorizationServer.isErr) {
            return failed(
                WalletInteractionFailureCodes.OID4VCI_REFRESH_AUTHORIZATION_SERVER_RESOLVE_FAILED,
                "wallet.interaction.error.oid4vci_refresh_authorization_server_resolve_failed",
                authorizationServer.error,
                retryable = true,
            )
        }
        val tokenEndpoint = authorizationServer.value.tokenEndpoint

        // Effective credential/refresh endpoint: refreshState.refreshEndpoint overrides the issuer's
        // default credential_endpoint when the issuer advertises a distinct reissuance endpoint.
        val effectiveMetadata =
            refreshState.refreshEndpoint
                ?.takeIf { it.isNotBlank() }
                ?.let {
                    metadata.copy(
                        credentialEndpoint = it,
                    )
                }
                ?: metadata
        // Synthetic offer/resolved-offer: a wallet-initiated refresh has no CredentialOffer at all, but
        // every downstream helper (options provider, DPoP proof provider, requestCredentialWithDpopNonceRetry)
        // is shaped around ResolvedCredentialOffer. `offer` here is a placeholder carrying only the
        // issuer/config the refresh targets; nothing reads its (absent) grants.
        val syntheticOffer = CredentialOffer(credentialIssuer = credentialIssuer, credentialConfigurationIds = listOf(credentialConfigurationId), grants = null)
        val resolvedOfferForRefresh = ResolvedCredentialOffer(offer = syntheticOffer, issuerMetadata = effectiveMetadata)

        val baseOptions =
            try {
                optionsProvider.options(context, state, resolvedOfferForRefresh, existingHolderKeyAliases = holderKeyAliases)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (cause: Exception) {
                return optionsUnavailable(WalletInteractionFailureCodes.OID4VCI_REFRESH_OPTIONS_UNAVAILABLE, "wallet.interaction.error.oid4vci_refresh_options_unavailable", cause)
            }
        // The options provider may configure algorithms and client authentication, but it is not
        // allowed to mint replacement holder keys during reissuance. Existing aliases are an
        // immutable record-to-request mapping, and batch size follows the selected instances.
        val options =
            baseOptions.copy(
                credentialConfigurationId = credentialConfigurationId,
                signingKeyIds = holderKeyAliases,
                batchSize = holderKeyAliases.size,
            )

        context.updateOid4vciState {
            it.copy(
                refreshTargetCredentialRecordId = credentialRecordId,
                refreshTargetCredentialInstanceIds = refreshInstances.map { it.id },
                credentialConfigurationId = credentialConfigurationId,
                holderKeyAliases = holderKeyAliases,
            )
        }

        val tokenResult =
            exchangeRefreshTokenWithDpopNonceRetry(
                context = context,
                state = state,
                resolvedOffer = resolvedOfferForRefresh,
                options = options,
                tokenEndpoint = tokenEndpoint,
                authorizationServerIssuer = authorizationServer.value.issuer,
                refreshToken = refreshToken,
            )
        if (tokenResult.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_TOKEN_EXCHANGE_FAILED, "wallet.interaction.error.oid4vci_refresh_token_exchange_failed", tokenResult.error, retryable = true)
        }
        val token = tokenResult.value
        context.updateOid4vciState {
            it.copy(
                tokens =
                    Oid4vciPrivateSessionState.TokenLeg(
                        accessToken = token.accessToken,
                        // RFC 6749 Section 6: reuse the presented refresh token when the AS does not
                        // rotate it; the receiver persists whatever ends up here as the record's next
                        // refresh token.
                        refreshToken = token.refreshToken ?: refreshToken,
                        tokenEndpoint = tokenEndpoint,
                    ),
            )
        }

        val cNonce = resolveProofNonce(resolvedOfferForRefresh, token.cNonce)
        if (cNonce.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_NONCE_REQUEST_FAILED, "wallet.interaction.error.oid4vci_refresh_nonce_request_failed", cNonce.error)
        }
        val proofSelection =
            prepareCredentialRequestProofs(
                context = context,
                state = state,
                resolvedOffer = resolvedOfferForRefresh,
                credentialConfigurationId = credentialConfigurationId,
                cNonce = cNonce.value,
                options = options,
                clientId = options.clientId,
            ).getOrElse {
                return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_PROOF_CREATION_FAILED, "wallet.interaction.error.oid4vci_refresh_proof_creation_failed", it)
            }
        val refreshProofs =
            credentialRequestProofProvider.finalizeProofs(proofSelection.prepared).getOrElse {
                return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_PROOF_CREATION_FAILED, "wallet.interaction.error.oid4vci_refresh_proof_creation_failed", it)
            }

        val credentialDpopProof =
            credentialEndpointDpopProof(context, state, resolvedOfferForRefresh, options, token.accessToken).getOrElse {
                return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_CREDENTIAL_DPOP_PROOF_FAILED, "wallet.interaction.error.oid4vci_refresh_credential_dpop_proof_failed", it, retryable = true)
            }
        val credential =
            requestCredentialWithDpopNonceRetry(
                context = context,
                state = state,
                resolvedOffer = resolvedOfferForRefresh,
                options = options,
                accessToken = token.accessToken,
                dpopProofJwt = credentialDpopProof,
                credentialConfigurationId = credentialConfigurationId,
                proofs = refreshProofs.proofs,
                tokenAuthorizationDetails = token.authorizationDetails,
            )
        if (credential.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_CREDENTIAL_REQUEST_FAILED, "wallet.interaction.error.oid4vci_refresh_credential_request_failed", credential.error, retryable = true)
        }
        val credentialResponse = credential.value
        if (credentialResponse.transactionId != null) {
            // Deferred reissuance is not supported: a refresh must complete synchronously.
            return failed(WalletInteractionFailureCodes.OID4VCI_REFRESH_DEFERRED_UNSUPPORTED, "wallet.interaction.error.oid4vci_refresh_deferred_unsupported")
        }
        return handleCredentialResponse(context, state, resolvedOfferForRefresh, credentialResponse)
    }

    private suspend fun requestDeferredCredential(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        sessionState: Oid4vciPrivateSessionState,
    ): Oid4vciIssuanceExecutionResult {
        val deferred =
            sessionState.deferred
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_DEFERRED_ENDPOINT_MISSING, "wallet.interaction.error.oid4vci_deferred_endpoint_missing", retryable = true)
        val persistedDeferredAccessToken =
            try {
                issuanceSessionStore.getDeferredAccessToken(context.walletUnitId, context.sessionId.value)
            } catch (failure: Exception) {
                return failed(
                    WalletInteractionFailureCodes.OID4VCI_DEFERRED_REQUEST_FAILED,
                    "wallet.interaction.error.oid4vci_deferred_request_failed",
                    retryable = true,
                    arguments = mapOf("causeType" to (failure::class.simpleName ?: "Exception"), "cause" to failure.message.orEmpty()),
                )
            }
        if (persistedDeferredAccessToken.isErr) {
            return failed(
                WalletInteractionFailureCodes.OID4VCI_DEFERRED_REQUEST_FAILED,
                "wallet.interaction.error.oid4vci_deferred_request_failed",
                persistedDeferredAccessToken.error,
                retryable = true,
            )
        }
        val accessToken =
            persistedDeferredAccessToken.value?.takeIf { it.isNotBlank() }
                ?: return failed(
                    WalletInteractionFailureCodes.OID4VCI_DEFERRED_REQUEST_FAILED,
                    "wallet.interaction.error.oid4vci_deferred_request_failed",
                    retryable = true,
                )
        val rawOffer =
            sessionState.entryPointRaw?.takeIf { it.isNotBlank() }
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_CREDENTIAL_OFFER_MISSING, "wallet.interaction.error.oid4vci_credential_offer_missing", retryable = true)
        val offer = holder.parseCredentialOffer(rawOffer)
        if (offer.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_OFFER_PARSE_FAILED, "wallet.interaction.error.oid4vci_offer_parse_failed", offer.error)
        }
        val resolved = holder.resolveCredentialOffer(offer.value)
        if (resolved.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_OFFER_RESOLVE_FAILED, "wallet.interaction.error.oid4vci_offer_resolve_failed", resolved.error)
        }
        val options =
            try {
                optionsProvider.options(context, state, resolved.value)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (cause: Exception) {
                return optionsUnavailable(WalletInteractionFailureCodes.OID4VCI_OPTIONS_UNAVAILABLE, "wallet.interaction.error.oid4vci_options_unavailable", cause)
            }
        val encryptCredentialRequest =
            context.attributes[Oid4vciInteractionLaunchAttributes.ENCRYPT_CREDENTIAL_REQUEST]
                ?.trim()
                ?.takeIf(String::isNotEmpty)
                ?.lowercase()
                ?.let { value ->
                    when (value) {
                        "true" -> true
                        "false" -> false
                        else ->
                            return failed(
                                WalletInteractionFailureCodes.OID4VCI_OPTIONS_UNAVAILABLE,
                                "wallet.interaction.error.oid4vci_options_unavailable",
                                retryable = true,
                                arguments = mapOf("cause" to "oid4vci.launch_attribute_boolean_invalid:oid4vci.credential.request.encrypt"),
                            )
                    }
                } ?: false
        val requestEncryption = credentialRequestEncryption(resolved.value, encryptCredentialRequest)
        val deferredDpopProof =
            deferredEndpointDpopProof(
                context = context,
                state = state,
                resolvedOffer = resolved.value,
                options = options,
                deferredCredentialEndpoint = deferred.deferredCredentialEndpoint,
                accessToken = accessToken,
            ).getOrElse {
                return failed(WalletInteractionFailureCodes.OID4VCI_DEFERRED_DPOP_PROOF_FAILED, "wallet.interaction.error.oid4vci_deferred_dpop_proof_failed", it, retryable = true)
            }
        val credential =
            requestDeferredCredentialWithDpopNonceRetry(
                context = context,
                state = state,
                resolvedOffer = resolved.value,
                options = options,
                deferredCredentialEndpoint = deferred.deferredCredentialEndpoint,
                accessToken = accessToken,
                dpopProofJwt = deferredDpopProof,
                transactionId = deferred.transactionId,
                requestEncryptionJwk = requestEncryption?.jwk,
                requestEncryptionAlg = requestEncryption?.alg,
                requestEncryptionEnc = requestEncryption?.enc,
            )
        val answered =
            if (credential.isErr && credential.error.code == OAUTH_INVALID_TOKEN) {
                val refreshedToken =
                    refreshDeferredAccessToken(context, state, resolved.value, options, sessionState)
                        ?: return failed(
                            WalletInteractionFailureCodes.OID4VCI_OFFER_EXPIRED,
                            "wallet.interaction.error.oid4vci_offer_expired",
                        )
                if (refreshedToken.isErr) {
                    return failed(
                        WalletInteractionFailureCodes.OID4VCI_DEFERRED_REQUEST_FAILED,
                        "wallet.interaction.error.oid4vci_deferred_request_failed",
                        refreshedToken.error,
                        retryable = true,
                    )
                }
                val refreshedDpopProof =
                    deferredEndpointDpopProof(
                        context = context,
                        state = state,
                        resolvedOffer = resolved.value,
                        options = options,
                        deferredCredentialEndpoint = deferred.deferredCredentialEndpoint,
                        accessToken = refreshedToken.value,
                    ).getOrElse {
                        return failed(WalletInteractionFailureCodes.OID4VCI_DEFERRED_DPOP_PROOF_FAILED, "wallet.interaction.error.oid4vci_deferred_dpop_proof_failed", it, retryable = true)
                    }
                requestDeferredCredentialWithDpopNonceRetry(
                    context = context,
                    state = state,
                    resolvedOffer = resolved.value,
                    options = options,
                    deferredCredentialEndpoint = deferred.deferredCredentialEndpoint,
                    accessToken = refreshedToken.value,
                    dpopProofJwt = refreshedDpopProof,
                    transactionId = deferred.transactionId,
                    requestEncryptionJwk = requestEncryption?.jwk,
                    requestEncryptionAlg = requestEncryption?.alg,
                    requestEncryptionEnc = requestEncryption?.enc,
                )
            } else {
                credential
            }
        if (answered.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_DEFERRED_REQUEST_FAILED, "wallet.interaction.error.oid4vci_deferred_request_failed", answered.error, retryable = true)
        }
        return handleCredentialResponse(context, state, resolved.value, answered.value, options.isDpopBound())
    }

    /**
     * Exchanges the session's refresh token for a new access token after the deferred endpoint
     * answered `invalid_token`, and persists it as the deferred access token. Returns null when the
     * offer has to be restarted: there is no refresh token or token endpoint, or the authorization
     * server answered `invalid_grant`. Other failures are returned as errors and stay retryable.
     */
    private suspend fun refreshDeferredAccessToken(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        sessionState: Oid4vciPrivateSessionState,
    ): IdkResult<String, IdkError>? {
        val tokens = sessionState.tokens
        val refreshToken = tokens?.refreshToken?.takeIf { it.isNotBlank() } ?: return null
        val tokenEndpoint =
            (tokens.tokenEndpoint ?: sessionState.authorization?.tokenEndpoint)?.takeIf { it.isNotBlank() } ?: return null
        val exchanged =
            exchangeRefreshTokenWithDpopNonceRetry(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                tokenEndpoint = tokenEndpoint,
                authorizationServerIssuer = sessionState.authorization?.authorizationServerIssuer,
                refreshToken = refreshToken,
            )
        if (exchanged.isErr) {
            return if (exchanged.error.code == OAUTH_INVALID_GRANT) null else Err(exchanged.error)
        }
        val token = exchanged.value
        val stored =
            try {
                issuanceSessionStore.storeDeferredAccessToken(context.walletUnitId, context.sessionId.value, token.accessToken)
            } catch (failure: Exception) {
                return Err(IdkError.fromString(code = "oid4vci.deferred_token_store_failed", message = failure.message ?: "Deferred access token could not be stored"))
            }
        if (stored.isErr) return Err(stored.error)
        context.updateOid4vciState {
            it.copy(
                tokens =
                    Oid4vciPrivateSessionState.TokenLeg(
                        accessToken = token.accessToken,
                        // RFC 6749 Section 6: keep the presented refresh token when the AS does not rotate it.
                        refreshToken = token.refreshToken ?: refreshToken,
                        tokenEndpoint = tokenEndpoint,
                    ),
            )
        }
        return Ok(token.accessToken)
    }

    override suspend fun notifyCredentialAccepted(
        context: WalletInteractionContext,
        state: WalletInteractionState,
    ): Oid4vciIssuerNotificationResult = notifyIssuer(context, state, CredentialNotificationEvent.CREDENTIAL_ACCEPTED)

    override suspend fun notifyCredentialDeclined(
        context: WalletInteractionContext,
        state: WalletInteractionState,
    ): Oid4vciIssuerNotificationResult = notifyIssuer(context, state, CredentialNotificationEvent.CREDENTIAL_FAILURE, eventDescription = "credential_declined")

    private suspend fun buildAuthorizationRequest(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
    ): Oid4vciIssuanceExecutionResult {
        val authorizationGrant =
            resolvedOffer.offer.grants?.authorizationCode
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_UNSUPPORTED_GRANT, "wallet.interaction.error.oid4vci_unsupported_grant")
        val clientId = options.clientId ?: return failed(WalletInteractionFailureCodes.OID4VCI_CLIENT_ID_MISSING, "wallet.interaction.error.oid4vci_client_id_missing")
        val redirectUri = options.redirectUri ?: return failed(WalletInteractionFailureCodes.OID4VCI_REDIRECT_URI_MISSING, "wallet.interaction.error.oid4vci_redirect_uri_missing")
        val authorizationServer = holder.selectAuthorizationServer(resolvedOffer.issuerMetadata, authorizationGrant.authorizationServer)
        if (authorizationServer.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_SERVER_RESOLVE_FAILED, "wallet.interaction.error.oid4vci_authorization_server_resolve_failed", authorizationServer.error)
        }
        val challengedOptions = options.withAttestationChallenge(authorizationServer.value).getOrElse {
            return failed(WalletInteractionFailureCodes.OID4VCI_ATTESTATION_CHALLENGE_FAILED, "wallet.interaction.error.oid4vci_attestation_challenge_failed", it)
        }
        authorizationServer.value.interactiveAuthorizationEndpoint?.takeIf { it.isNotBlank() }?.let { iaeEndpoint ->
            return initiateInteractiveAuthorization(context, state, resolvedOffer, challengedOptions, authorizationServer.value, iaeEndpoint)
        }
        val authorizationEndpoint =
            authorizationServer.value.authorizationEndpoint
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_ENDPOINT_MISSING, "wallet.interaction.error.oid4vci_authorization_endpoint_missing")
        val usePar = challengedOptions.usePar || authorizationServer.value.metadata.requirePushedAuthorizationRequests == true
        val credentialConfigurationIds = state.effectiveOfferedCredentialConfigurationIds(resolvedOffer)
        val scope =
            credentialConfigurationIds
                .mapNotNull { resolvedOffer.issuerMetadata.credentialConfigurationsSupported[it]?.scope }
                .distinct()
                .joinToString(" ")
                .takeIf(String::isNotBlank)
        val authorizationRequest =
            if (usePar) {
                val parEndpoint =
                    authorizationServer.value.pushedAuthorizationRequestEndpoint
                        ?: return failed(WalletInteractionFailureCodes.OID4VCI_PAR_ENDPOINT_MISSING, "wallet.interaction.error.oid4vci_par_endpoint_missing")
                buildParAuthorizationRequestWithDpopNonceRetry(
                    context = context,
                    state = state,
                    resolvedOffer = resolvedOffer,
                    options = challengedOptions,
                    authorizationServer = authorizationServer.value,
                    authorizationEndpoint = authorizationEndpoint,
                    parEndpoint = parEndpoint,
                    clientId = clientId,
                    redirectUri = redirectUri,
                    credentialConfigurationIds = credentialConfigurationIds,
                    scope = scope,
                    issuerState = authorizationGrant.issuerState,
                )
            } else {
                holder.buildAuthorizationRequest(
                    authorizationEndpoint = authorizationEndpoint,
                    clientId = clientId,
                    redirectUri = redirectUri,
                    credentialConfigurationIds = credentialConfigurationIds,
                    scope = scope,
                    issuerState = authorizationGrant.issuerState,
                    locations = listOf(resolvedOffer.issuerMetadata.credentialIssuer),
                )
            }
        if (authorizationRequest.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_REQUEST_FAILED, "wallet.interaction.error.oid4vci_authorization_request_failed", authorizationRequest.error)
        }
        context.updateOid4vciState {
            it.copy(
                authorization =
                    Oid4vciPrivateSessionState.AuthorizationLeg(
                        authorizationServerIssuer = authorizationServer.value.issuer,
                        tokenEndpoint = authorizationServer.value.tokenEndpoint,
                        codeVerifier = authorizationRequest.value.codeVerifier,
                        state = authorizationRequest.value.state,
                        redirectUri = redirectUri,
                        clientId = clientId,
                        attestationChallenge = challengedOptions.haipTokenProofs?.attestationChallenge,
                    ),
            )
        }
        return Oid4vciIssuanceExecutionResult.AuthorizationRequired(authorizationRequest.value.authorizationUrl)
    }

    private suspend fun buildParAuthorizationRequestWithDpopNonceRetry(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        authorizationServer: ResolvedAuthorizationServer,
        authorizationEndpoint: String,
        parEndpoint: String,
        clientId: String,
        redirectUri: String,
        credentialConfigurationIds: List<String>,
        scope: String?,
        issuerState: String?,
    ): IdkResult<AuthorizationRequestResult, IdkError> {
        suspend fun attempt(nonce: String?): IdkResult<AuthorizationRequestResult, IdkError> {
            val proofs =
                tokenEndpointProofs(
                    context = context,
                    state = state,
                    resolvedOffer = resolvedOffer,
                    options = options,
                    tokenEndpoint = parEndpoint,
                    authorizationServerIssuer = authorizationServer.issuer,
                    nonce = nonce,
                )
            if (proofs.isErr) return Err(proofs.error)
            return holder.buildAuthorizationRequest(
                authorizationEndpoint = authorizationEndpoint,
                clientId = clientId,
                redirectUri = redirectUri,
                credentialConfigurationIds = credentialConfigurationIds,
                scope = scope,
                issuerState = issuerState,
                usePar = true,
                parEndpoint = parEndpoint,
                locations = listOf(resolvedOffer.issuerMetadata.credentialIssuer),
                clientAuthentication = proofs.value.clientAuthentication,
                dpopProofJwt = proofs.value.dpopProofJwt,
                clientAttestationJwt = proofs.value.clientAttestationJwt,
                clientAttestationPopJwt = proofs.value.clientAttestationPopJwt,
            )
        }

        val first = attempt(nonce = null)
        if (first.isOk) return first
        val nonce = first.error.meta["dpop_nonce"] as? String
        return if (first.error.code == "use_dpop_nonce" && !nonce.isNullOrBlank()) {
            attempt(nonce)
        } else {
            first
        }
    }

    private suspend fun initiateInteractiveAuthorization(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        authorizationServer: ResolvedAuthorizationServer,
        iaeEndpoint: String,
    ): Oid4vciIssuanceExecutionResult {
        val clientId = options.clientId ?: return failed(WalletInteractionFailureCodes.OID4VCI_CLIENT_ID_MISSING, "wallet.interaction.error.oid4vci_client_id_missing")
        val redirectUri = options.redirectUri ?: return failed(WalletInteractionFailureCodes.OID4VCI_REDIRECT_URI_MISSING, "wallet.interaction.error.oid4vci_redirect_uri_missing")
        val tokenEndpoint = authorizationServer.tokenEndpoint
        val result =
            holder.initiateIae(
                InitiateIaeArgs(
                    iaeEndpoint = iaeEndpoint,
                    clientId = clientId,
                    redirectUri = redirectUri,
                    interactionTypesSupported = listOf(IAE_OPENID4VP_PRESENTATION),
                    authorizationDetails = resolvedOffer.authorizationDetails(),
                    codeChallenge = options.iaeCodeChallenge,
                    codeChallengeMethod = options.iaeCodeChallengeMethod,
                ),
            )
        if (result.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_IAE_INITIATE_FAILED, "wallet.interaction.error.oid4vci_iae_initiate_failed", result.error)
        }
        context.updateOid4vciState {
            it.copy(
                iae =
                    Oid4vciPrivateSessionState.IaeLeg(
                        authorizationServerIssuer = authorizationServer.issuer,
                        tokenEndpoint = tokenEndpoint,
                        iaeEndpoint = iaeEndpoint,
                        redirectUri = redirectUri,
                        clientId = clientId,
                        codeVerifier = options.iaeCodeVerifier,
                        pending = false,
                    ),
            )
        }
        return handleIaeResult(context, state, resolvedOffer, options, result.value)
    }

    private suspend fun continueInteractiveAuthorization(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        sessionState: Oid4vciPrivateSessionState,
        action: WalletInteractionAction?,
    ): Oid4vciIssuanceExecutionResult {
        val iae =
            sessionState.iae
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_IAE_ENDPOINT_MISSING, "wallet.interaction.error.oid4vci_iae_endpoint_missing", retryable = true)
        val iaeEndpoint =
            iae.iaeEndpoint
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_IAE_ENDPOINT_MISSING, "wallet.interaction.error.oid4vci_iae_endpoint_missing", retryable = true)
        val authSession =
            iae.authSession
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_IAE_AUTH_SESSION_MISSING, "wallet.interaction.error.oid4vci_iae_auth_session_missing", retryable = true)
        val nestedResponse =
            when (
                val response =
                    nestedPresentationExecutor.createPresentationResponse(
                        context = context,
                        state = state,
                        action = action ?: WalletInteractionAction.continueFlow(),
                    )
            ) {
                is WalletNestedPresentationExecutionResult.Success -> {
                    response.value.response
                }

                is WalletNestedPresentationExecutionResult.Failed -> {
                    return failed(
                        code = response.code,
                        messageKey = response.messageKey,
                        retryable = response.retryable,
                        arguments = response.arguments,
                    )
                }
            }
        val result =
            holder.followUpIae(
                FollowUpIaeArgs(
                    iaeEndpoint = iaeEndpoint,
                    authSession = authSession,
                    openid4vpResponse = nestedResponse,
                    codeVerifier = iae.codeVerifier?.takeIf { it.isNotBlank() },
                ),
            )
        if (result.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_IAE_FOLLOW_UP_FAILED, "wallet.interaction.error.oid4vci_iae_follow_up_failed", result.error, retryable = true)
        }

        val rawOffer =
            sessionState.entryPointRaw?.takeIf { it.isNotBlank() }
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_CREDENTIAL_OFFER_MISSING, "wallet.interaction.error.oid4vci_credential_offer_missing", retryable = true)
        val offer = holder.parseCredentialOffer(rawOffer)
        if (offer.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_OFFER_PARSE_FAILED, "wallet.interaction.error.oid4vci_offer_parse_failed", offer.error)
        }
        val resolved = holder.resolveCredentialOffer(offer.value)
        if (resolved.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_OFFER_RESOLVE_FAILED, "wallet.interaction.error.oid4vci_offer_resolve_failed", resolved.error)
        }
        val options =
            try {
                optionsProvider.options(context, state, resolved.value)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (cause: Exception) {
                return optionsUnavailable(WalletInteractionFailureCodes.OID4VCI_OPTIONS_UNAVAILABLE, "wallet.interaction.error.oid4vci_options_unavailable", cause)
            }
        return handleIaeResult(context, state, resolved.value, options, result.value)
    }

    private suspend fun handleIaeResult(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        result: IaeHolderResult,
    ): Oid4vciIssuanceExecutionResult =
        when (result) {
            is IaeHolderResult.AuthorizationCode -> {
                exchangeIaeAuthorizationCodeAndRequestCredential(context, state, resolvedOffer, options, result.code)
            }

            is IaeHolderResult.Error -> {
                failed(
                    code = WalletInteractionFailureCodes.OID4VCI_IAE_ERROR,
                    messageKey = "wallet.interaction.error.oid4vci_iae_error",
                    arguments =
                        buildMap {
                            put("protocolError", result.error)
                            result.errorDescription?.let { put("protocolErrorDescription", it) }
                        },
                )
            }

            is IaeHolderResult.InteractionRequired -> {
                prepareNestedPresentation(context, state, result)
            }
        }

    private suspend fun prepareNestedPresentation(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        result: IaeHolderResult.InteractionRequired,
    ): Oid4vciIssuanceExecutionResult {
        if (result.type != IAE_OPENID4VP_PRESENTATION) {
            return failed(
                code = WalletInteractionFailureCodes.OID4VCI_IAE_INTERACTION_UNSUPPORTED,
                messageKey = "wallet.interaction.error.oid4vci_iae_interaction_unsupported",
                retryable = true,
                arguments = mapOf("interactionType" to result.type),
            )
        }
        context.updateOid4vciState {
            it.copy(
                iae =
                    (it.iae ?: Oid4vciPrivateSessionState.IaeLeg()).copy(
                        pending = true,
                        authSession = result.authSession,
                        requestUri = result.requestUri,
                    ),
            )
        }
        if (result.openid4vpRequest == null && result.requestUri.isNullOrBlank()) {
            return failed(
                code = WalletInteractionFailureCodes.OID4VCI_IAE_OPENID4VP_REQUEST_MISSING,
                messageKey = "wallet.interaction.error.oid4vci_iae_openid4vp_request_missing",
                retryable = true,
            )
        }
        val request =
            WalletNestedPresentationRequest(
                protocol = WalletProtocol.OID4VP,
                interactionType = result.type,
                requestObject = result.openid4vpRequest,
                requestUri = result.requestUri,
            )
        return when (val prepared = nestedPresentationExecutor.preparePresentation(context, state, request)) {
            is WalletNestedPresentationExecutionResult.Success -> {
                Oid4vciIssuanceExecutionResult.NestedPresentationRequired(
                    credentialSelection = prepared.value.credentialSelection,
                    disclosure = prepared.value.disclosure,
                    expiresInSeconds = result.expiresIn ?: prepared.value.expiresInSeconds,
                )
            }

            is WalletNestedPresentationExecutionResult.Failed -> {
                failed(
                    code = prepared.code,
                    messageKey = prepared.messageKey,
                    retryable = prepared.retryable,
                    arguments = prepared.arguments,
                )
            }
        }
    }

    private suspend fun exchangeIaeAuthorizationCodeAndRequestCredential(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        code: String,
    ): Oid4vciIssuanceExecutionResult {
        val sessionState = context.oid4vciState()
        val iae =
            sessionState.iae
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_TOKEN_ENDPOINT_MISSING, "wallet.interaction.error.oid4vci_token_endpoint_missing", retryable = true)
        val tokenEndpoint =
            iae.tokenEndpoint
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_TOKEN_ENDPOINT_MISSING, "wallet.interaction.error.oid4vci_token_endpoint_missing", retryable = true)
        val codeVerifier =
            iae.codeVerifier?.takeIf { it.isNotBlank() }
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_IAE_CODE_VERIFIER_MISSING, "wallet.interaction.error.oid4vci_iae_code_verifier_missing", retryable = true)
        val redirectUri =
            iae.redirectUri
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_REDIRECT_URI_MISSING, "wallet.interaction.error.oid4vci_redirect_uri_missing", retryable = true)
        val clientId = iae.clientId ?: options.clientId
        val tokenProofs =
            tokenEndpointProofs(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                tokenEndpoint = tokenEndpoint,
                authorizationServerIssuer = iae.authorizationServerIssuer,
            ).getOrElse {
            return failed(WalletInteractionFailureCodes.OID4VCI_TOKEN_PROOFS_FAILED, "wallet.interaction.error.oid4vci_token_proofs_failed", it, retryable = true)
        }
        val token =
            exchangeAuthorizationCodeWithDpopNonceRetry(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                tokenEndpoint = tokenEndpoint,
                authorizationServerIssuer = iae.authorizationServerIssuer,
                code = code,
                codeVerifier = codeVerifier,
                redirectUri = redirectUri,
                clientId = clientId,
                dpopProofJwt = tokenProofs.dpopProofJwt,
                clientAttestationJwt = tokenProofs.clientAttestationJwt,
                clientAttestationPopJwt = tokenProofs.clientAttestationPopJwt,
                clientAuthentication = tokenProofs.clientAuthentication,
            )
        if (token.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_CODE_EXCHANGE_FAILED, "wallet.interaction.error.oid4vci_authorization_code_exchange_failed", token.error)
        }
        val issuedToken =
            Oid4vciPrivateSessionState.TokenLeg(
                accessToken = token.value.accessToken,
                refreshToken = token.value.refreshToken,
                tokenEndpoint = tokenEndpoint,
                cNonce = token.value.cNonce,
                authorizationDetails = token.value.authorizationDetails,
            )
        context.updateOid4vciState { it.copy(tokens = issuedToken, iae = it.iae?.copy(pending = false)) }
        return requestCredentialWithIssuedToken(
            context = context,
            state = state,
            resolvedOffer = resolvedOffer,
            options = options,
            clientId = clientId,
            token = issuedToken,
            dpopProofFailureRetryable = true,
        )
    }

    private suspend fun prepareCredentialRequestProofs(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        credentialConfigurationId: String?,
        cNonce: String?,
        options: Oid4vciHolderIssuanceOptions,
        clientId: String?,
    ): IdkResult<Oid4vciPreparedProofSelection, IdkError> {
        val requestedBatchSize = options.batchSize
        if (requestedBatchSize <= 0) {
            return Err(
                IdkError.fromString(
                    code = "oid4vci.credential_batch_size_invalid",
                    message = "OID4VCI credential batch size must be greater than zero",
                ),
            )
        }
        if (requestedBatchSize > 1) {
            val advertisedBatchSize = resolvedOffer.issuerMetadata.batchCredentialIssuance?.batchSize
                ?: return Err(
                    IdkError.fromString(
                        code = "oid4vci.credential_batch_unsupported",
                        message = "The credential issuer does not advertise batch credential issuance",
                    ),
                )
            if (requestedBatchSize > advertisedBatchSize) {
                return Err(
                    IdkError.fromString(
                        code = "oid4vci.credential_batch_size_exceeded",
                        message = "Requested OID4VCI batch size $requestedBatchSize exceeds issuer maximum $advertisedBatchSize",
                    ),
                )
            }
        }

        val holderKeyAliases =
            if (options.signingKeyIds.isNotEmpty()) {
                options.signingKeyIds
            } else {
                try {
                    optionsProvider.holderKeys(context, state, options)
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (cause: Exception) {
                    return Err(
                        IdkError.fromString(
                            code = WalletInteractionFailureCodes.OID4VCI_HOLDER_KEY_PROVISIONING_FAILED,
                            message = "Holder proof key provisioning failed: ${cause::class.simpleName ?: "Exception"}: ${cause.message.orEmpty()}",
                            exception = cause,
                        ),
                    )
                }
            }
        if (holderKeyAliases.size != requestedBatchSize || holderKeyAliases.any(String::isBlank) || holderKeyAliases.distinct().size != holderKeyAliases.size) {
            return Err(
                IdkError.fromString(
                    code = "oid4vci.credential_holder_key_count_mismatch",
                    message = "OID4VCI requires one distinct provisioned holder key per requested credential",
                ),
            )
        }
        val proofRequests = mutableListOf<Oid4vciCredentialRequestProofRequest>()
        for (holderKeyAlias in holderKeyAliases) {
            val keyAttestationJwt =
                keyAttestationJwtIfRequired(
                    context,
                    resolvedOffer,
                    credentialConfigurationId,
                    holderKeyAlias,
                    options.signingAlgorithm,
                    cNonce,
                    options.operationBinding,
                    options.haipTokenProofs,
                ).getOrElse { error ->
                    return Err(
                        IdkError
                            .fromString(
                                code = WalletInteractionFailureCodes.OID4VCI_KEY_ATTESTATION_FAILED,
                                message = error.message.defaultMessage,
                            ).addCause(error),
                    )
                }
            val holderDidVerificationMethod =
                holderBindingDidVerificationMethod(context, resolvedOffer, credentialConfigurationId, holderKeyAlias)
                    .getOrElse { return Err(it) }
            proofRequests +=
                Oid4vciCredentialRequestProofRequest(
                    walletUnitId = context.walletUnitId,
                    operationBinding = options.operationBinding,
                    // OID4VCI 1.0 Final Appendix F.1 requires `aud` to be the exact
                    // Credential Issuer Identifier. The resolved metadata value is authoritative;
                    // the launch/discovery URL can be a different URL spelling (for example a
                    // trailing slash) and MUST NOT be copied into the proof.
                    issuerUrl = resolvedOffer.issuerMetadata.credentialIssuer,
                    cNonce = cNonce,
                    signingKeyId = holderKeyAlias,
                    signingAlgorithm = options.signingAlgorithm,
                    clientId = clientId,
                    keyAttestationJwt = keyAttestationJwt,
                    holderDidVerificationMethod = holderDidVerificationMethod,
                )
        }
        val prepared =
            credentialRequestProofProvider
                .prepareProofs(proofRequests, Clock.System.now().epochSeconds)
                .getOrElse { return Err(it) }
        if (prepared.proofs.size != requestedBatchSize) {
            return Err(
                IdkError.fromString(
                    code = "oid4vci.credential_batch_proof_count_mismatch",
                    message = "OID4VCI proof provider prepared ${prepared.proofs.size} proofs for batch size $requestedBatchSize",
                ),
            )
        }
        return Ok(
            Oid4vciPreparedProofSelection(
                prepared = prepared,
                holderKeyAliases = holderKeyAliases,
            ),
        )
    }

    /**
     * Chooses the key representation the issuer binds the credential to, from the configuration's
     * `cryptographic_binding_methods_supported` (OID4VCI 1.0 section 12.2.4): `did:jwk` when offered
     * and the holder key has a registered did:jwk verification method, otherwise `jwk` when offered
     * or when no binding method is advertised (binding not required). Anything else fails closed.
     */
    private suspend fun holderBindingDidVerificationMethod(
        context: WalletInteractionContext,
        resolvedOffer: ResolvedCredentialOffer,
        credentialConfigurationId: String?,
        holderKeyAlias: String,
    ): IdkResult<String?, IdkError> {
        val configuration =
            credentialConfigurationId
                ?.let { resolvedOffer.issuerMetadata.credentialConfigurationsSupported[it] }
        val methods = configuration?.cryptographicBindingMethodsSupported.orEmpty()
        return selectHolderDidVerificationMethod(methods, credentialFormat = configuration?.format) {
            holderVerificationMethodResolver?.resolve(context.walletUnitId, KeyRef(alias = holderKeyAlias))
        }
    }

    private fun credentialRequestProofFailure(error: IdkError): Oid4vciIssuanceExecutionResult =
        if (error.code == WalletInteractionFailureCodes.OID4VCI_KEY_ATTESTATION_FAILED) {
            failed(
                code = WalletInteractionFailureCodes.OID4VCI_KEY_ATTESTATION_FAILED,
                messageKey = "wallet.interaction.error.oid4vci_key_attestation_failed",
                error = error,
            )
        } else if (error.code == WalletInteractionFailureCodes.OID4VCI_HOLDER_KEY_PROVISIONING_FAILED) {
            failed(
                code = WalletInteractionFailureCodes.OID4VCI_HOLDER_KEY_PROVISIONING_FAILED,
                messageKey = "wallet.interaction.error.oid4vci_holder_key_provisioning_failed",
                error = error,
                retryable = true,
            )
        } else {
            failed(
                code = WalletInteractionFailureCodes.OID4VCI_PROOF_CREATION_FAILED,
                messageKey = "wallet.interaction.error.oid4vci_proof_creation_failed",
                error = error,
            )
        }

    private fun selectCredentialConfigurationId(
        options: Oid4vciHolderIssuanceOptions,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
    ): String? =
        options.credentialConfigurationId
            ?: preferredCredentialConfigurationId(state.effectiveOfferedCredentialConfigurationIds(resolvedOffer), resolvedOffer)
            ?: preferredCredentialConfigurationId(resolvedOffer.offer.credentialConfigurationIds, resolvedOffer)

    private fun preferredCredentialConfigurationId(
        credentialConfigurationIds: List<String>,
        resolvedOffer: ResolvedCredentialOffer,
    ): String? =
        credentialConfigurationIds
            .firstOrNull { id -> resolvedOffer.issuerMetadata.credentialConfigurationsSupported[id]?.format == HAIP_PREFERRED_CREDENTIAL_FORMAT }
            ?: credentialConfigurationIds.firstOrNull()

    private fun WalletInteractionState.effectiveOfferedCredentialConfigurationIds(
        resolvedOffer: ResolvedCredentialOffer,
    ): List<String> =
        selectedCredentialConfigurationIds.ifEmpty {
            credentialOffer?.credentialConfigurationIds.orEmpty().ifEmpty { resolvedOffer.offer.credentialConfigurationIds }
        }

    private fun ResolvedCredentialOffer.authorizationDetails(): List<JsonElement> =
        offer.credentialConfigurationIds.map { id ->
            buildJsonObject {
                put("type", JsonPrimitive("openid_credential"))
                put("credential_configuration_id", JsonPrimitive(id))
            }
        }

    private suspend fun requestCredentialWithDpopNonceRetry(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        accessToken: String,
        dpopProofJwt: String?,
        credentialConfigurationId: String?,
        proofs: CredentialRequestProofs?,
        tokenAuthorizationDetails: List<JsonElement>? = null,
    ): IdkResult<CredentialResponse, IdkError> {
        val requestTarget =
            selectCredentialRequestTarget(tokenAuthorizationDetails, credentialConfigurationId)
                .getOrElse { return Err(it) }
        // OID4VCI 1.0 final performs batch issuance at the ordinary Credential Endpoint.
        // The separate Batch Credential Endpoint existed only in older drafts.
        val credentialEndpoint = resolvedOffer.issuerMetadata.credentialEndpoint
        val requestEncryption = credentialRequestEncryption(resolvedOffer, options.encryptCredentialRequest)
        val initial =
            holder.requestCredential(
                credentialEndpoint = credentialEndpoint,
                accessToken = accessToken,
                dpopProofJwt = dpopProofJwt,
                credentialConfigurationId = requestTarget.credentialConfigurationId,
                credentialIdentifier = requestTarget.credentialIdentifier,
                proofs = proofs,
                requestEncryptionJwk = requestEncryption?.jwk,
                requestEncryptionAlg = requestEncryption?.alg,
                requestEncryptionEnc = requestEncryption?.enc,
            )
        val nonce = initial.errorDpopNonceOrNull() ?: return initial
        val retryDpop =
            credentialEndpointDpopProof(context, state, resolvedOffer, options, accessToken, nonce)
                .getOrElse { return Err(it) }
                ?: return initial
        return holder.requestCredential(
            credentialEndpoint = credentialEndpoint,
            accessToken = accessToken,
            dpopProofJwt = retryDpop,
            credentialConfigurationId = requestTarget.credentialConfigurationId,
            credentialIdentifier = requestTarget.credentialIdentifier,
            proofs = proofs,
            requestEncryptionJwk = requestEncryption?.jwk,
            requestEncryptionAlg = requestEncryption?.alg,
            requestEncryptionEnc = requestEncryption?.enc,
        )
    }

    private suspend fun requestDeferredCredentialWithDpopNonceRetry(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        deferredCredentialEndpoint: String,
        accessToken: String,
        dpopProofJwt: String?,
        transactionId: String,
        requestEncryptionJwk: JsonObject?,
        requestEncryptionAlg: String?,
        requestEncryptionEnc: String?,
    ): IdkResult<CredentialResponse, IdkError> {
        val initial =
            holder.requestDeferredCredential(
                deferredCredentialEndpoint = deferredCredentialEndpoint,
                accessToken = accessToken,
                dpopProofJwt = dpopProofJwt,
                transactionId = transactionId,
                requestEncryptionJwk = requestEncryptionJwk,
                requestEncryptionAlg = requestEncryptionAlg,
                requestEncryptionEnc = requestEncryptionEnc,
            )
        val nonce = initial.errorDpopNonceOrNull() ?: return initial
        val retryDpop =
            deferredEndpointDpopProof(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                deferredCredentialEndpoint = deferredCredentialEndpoint,
                accessToken = accessToken,
                nonce = nonce,
            ).getOrElse { return Err(it) }
                ?: return initial
        return holder.requestDeferredCredential(
            deferredCredentialEndpoint = deferredCredentialEndpoint,
            accessToken = accessToken,
            dpopProofJwt = retryDpop,
            transactionId = transactionId,
            requestEncryptionJwk = requestEncryptionJwk,
            requestEncryptionAlg = requestEncryptionAlg,
            requestEncryptionEnc = requestEncryptionEnc,
        )
    }

    private fun credentialRequestEncryption(
        resolvedOffer: ResolvedCredentialOffer,
        requested: Boolean,
    ): CredentialRequestEncryptionSelection? {
        val metadata = resolvedOffer.issuerMetadata.credentialRequestEncryption ?: return null
        if (!requested && !metadata.encryptionRequired) return null
        val jwk =
            (metadata.jwks["keys"] as? JsonArray)
                ?.firstOrNull()
                ?.let { it as? JsonObject }
                ?: throw IllegalArgumentException("oid4vci.credential_request_encryption_key_missing")
        val alg =
            (jwk["alg"] as? JsonPrimitive)?.contentOrNull
                ?: throw IllegalArgumentException("oid4vci.credential_request_encryption_alg_missing")
        val enc =
            metadata.encValuesSupported.firstOrNull()
                ?: throw IllegalArgumentException("oid4vci.credential_request_encryption_enc_missing")
        return CredentialRequestEncryptionSelection(jwk = jwk, alg = alg, enc = enc)
    }

    private suspend fun exchangeAuthorizationCodeAndRequestCredential(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        callback: String,
    ): Oid4vciIssuanceExecutionResult {
        val sessionState = context.oid4vciState()
        val authorization =
            sessionState.authorization
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_TOKEN_ENDPOINT_MISSING, "wallet.interaction.error.oid4vci_token_endpoint_missing")
        val expectedState = authorization.state?.takeIf(String::isNotBlank)
        val callbackState = runCatching { extractQueryParameters(callback)["state"] }
        if (expectedState != null && callbackState.isSuccess && callbackState.getOrNull() != expectedState) {
            // The redirect belongs to another receive. This one keeps its authorization and waits.
            context.updateOid4vciState { it.copy(authorizationCallback = null) }
            return failed(
                code = WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_STATE_MISMATCH,
                messageKey = "wallet.interaction.error.oid4vci_authorization_state_mismatch",
                retryable = true,
            )
        }
        val authorizationResponse =
            holder.parseAndValidateAuthorizationResponse(
                callbackUrl = callback,
                expectedState = expectedState,
                expectedIssuer = authorization.authorizationServerIssuer,
                requireIssuer = options.haipTokenProofs != null,
            )
        if (authorizationResponse.isErr) {
            return failed(
                WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_RESPONSE_INVALID,
                "wallet.interaction.error.oid4vci_authorization_response_invalid",
                authorizationResponse.error,
            )
        }
        val code = authorizationResponse.value.code
        val tokenEndpoint = authorization.tokenEndpoint
        val codeVerifier =
            authorization.codeVerifier
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_CODE_VERIFIER_MISSING, "wallet.interaction.error.oid4vci_code_verifier_missing")
        val redirectUri =
            authorization.redirectUri ?: options.redirectUri
                ?: return failed(WalletInteractionFailureCodes.OID4VCI_REDIRECT_URI_MISSING, "wallet.interaction.error.oid4vci_redirect_uri_missing")
        val clientId = authorization.clientId ?: options.clientId
        val challengedOptions =
            authorization.attestationChallenge?.let { challenge ->
                options.copy(haipTokenProofs = options.haipTokenProofs?.copy(attestationChallenge = challenge))
            } ?: options
        val tokenProofs =
            tokenEndpointProofs(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = challengedOptions,
                tokenEndpoint = tokenEndpoint,
                authorizationServerIssuer = authorization.authorizationServerIssuer,
            ).getOrElse {
            return failed(WalletInteractionFailureCodes.OID4VCI_TOKEN_PROOFS_FAILED, "wallet.interaction.error.oid4vci_token_proofs_failed", it)
        }
        val token =
            exchangeAuthorizationCodeWithDpopNonceRetry(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = challengedOptions,
                tokenEndpoint = tokenEndpoint,
                authorizationServerIssuer = authorization.authorizationServerIssuer,
                code = code,
                codeVerifier = codeVerifier,
                redirectUri = redirectUri,
                clientId = clientId,
                dpopProofJwt = tokenProofs.dpopProofJwt,
                clientAttestationJwt = tokenProofs.clientAttestationJwt,
                clientAttestationPopJwt = tokenProofs.clientAttestationPopJwt,
                clientAuthentication = tokenProofs.clientAuthentication,
            )
        if (token.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_CODE_EXCHANGE_FAILED, "wallet.interaction.error.oid4vci_authorization_code_exchange_failed", token.error)
        }
        val issuedToken =
            Oid4vciPrivateSessionState.TokenLeg(
                accessToken = token.value.accessToken,
                refreshToken = token.value.refreshToken,
                tokenEndpoint = tokenEndpoint,
                cNonce = token.value.cNonce,
                authorizationDetails = token.value.authorizationDetails,
            )
        context.updateOid4vciState { it.copy(tokens = issuedToken) }
        return requestCredentialWithIssuedToken(
            context = context,
            state = state,
            resolvedOffer = resolvedOffer,
            options = options,
            clientId = clientId,
            token = issuedToken,
            dpopProofFailureRetryable = false,
        )
    }

    private suspend fun exchangePreAuthorizedCodeWithDpopNonceRetry(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        tokenEndpoint: String,
        authorizationServerIssuer: String?,
        preAuthorizedCode: String,
        txCode: String?,
        clientId: String?,
        redirectUri: String?,
        dpopProofJwt: String?,
        clientAttestationJwt: String?,
        clientAttestationPopJwt: String?,
        clientAuthentication: ClientAuthenticationConfig?,
    ): IdkResult<TokenResponseWithContext, IdkError> {
        val initial =
            holder.exchangePreAuthorizedCode(
                tokenEndpoint = tokenEndpoint,
                preAuthorizedCode = preAuthorizedCode,
                txCode = txCode,
                clientId = clientId,
                redirectUri = redirectUri,
                dpopProofJwt = dpopProofJwt,
                clientAttestationJwt = clientAttestationJwt,
                clientAttestationPopJwt = clientAttestationPopJwt,
                clientAuthentication = clientAuthentication,
        )
        val nonce = initial.errorDpopNonceOrNull() ?: return initial
        val retryProofs =
            tokenEndpointProofs(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                tokenEndpoint = tokenEndpoint,
                authorizationServerIssuer = authorizationServerIssuer,
                nonce = nonce,
            ).getOrElse { return Err(it) }
        val retryDpop = retryProofs.dpopProofJwt ?: return initial
        return holder.exchangePreAuthorizedCode(
            tokenEndpoint = tokenEndpoint,
            preAuthorizedCode = preAuthorizedCode,
            txCode = txCode,
            clientId = clientId,
            redirectUri = redirectUri,
            dpopProofJwt = retryDpop,
            clientAttestationJwt = retryProofs.clientAttestationJwt,
            clientAttestationPopJwt = retryProofs.clientAttestationPopJwt,
            clientAuthentication = retryProofs.clientAuthentication,
        )
    }

    private suspend fun exchangeAuthorizationCodeWithDpopNonceRetry(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        tokenEndpoint: String,
        authorizationServerIssuer: String?,
        code: String,
        codeVerifier: String,
        redirectUri: String,
        clientId: String?,
        dpopProofJwt: String?,
        clientAttestationJwt: String?,
        clientAttestationPopJwt: String?,
        clientAuthentication: ClientAuthenticationConfig?,
    ): IdkResult<TokenResponseWithContext, IdkError> {
        val initial =
            holder.exchangeAuthorizationCode(
                tokenEndpoint = tokenEndpoint,
                code = code,
                codeVerifier = codeVerifier,
                redirectUri = redirectUri,
                clientId = clientId,
                dpopProofJwt = dpopProofJwt,
                clientAttestationJwt = clientAttestationJwt,
                clientAttestationPopJwt = clientAttestationPopJwt,
                clientAuthentication = clientAuthentication,
        )
        val nonce = initial.errorDpopNonceOrNull() ?: return initial
        val retryProofs =
            tokenEndpointProofs(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                tokenEndpoint = tokenEndpoint,
                authorizationServerIssuer = authorizationServerIssuer,
                nonce = nonce,
            ).getOrElse { return Err(it) }
        val retryDpop = retryProofs.dpopProofJwt ?: return initial
        return holder.exchangeAuthorizationCode(
            tokenEndpoint = tokenEndpoint,
            code = code,
            codeVerifier = codeVerifier,
            redirectUri = redirectUri,
            clientId = clientId,
            dpopProofJwt = retryDpop,
            clientAttestationJwt = retryProofs.clientAttestationJwt,
            clientAttestationPopJwt = retryProofs.clientAttestationPopJwt,
            clientAuthentication = retryProofs.clientAuthentication,
        )
    }

    /**
     * Mirrors [exchangeAuthorizationCodeWithDpopNonceRetry]'s shape exactly (initial attempt ->
     * `use_dpop_nonce` detection -> proof regeneration with the server-supplied nonce -> single
     * retry), but drives [refreshTokenGrantProvider] instead of a holder-service command, since no
     * OID4VCI holder command exposes the `refresh_token` grant.
     */
    private suspend fun exchangeRefreshTokenWithDpopNonceRetry(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        tokenEndpoint: String,
        authorizationServerIssuer: String?,
        refreshToken: String,
    ): IdkResult<TokenResponseWithContext, IdkError> {
        val initialProofs =
            tokenEndpointProofs(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                tokenEndpoint = tokenEndpoint,
                authorizationServerIssuer = authorizationServerIssuer,
            ).getOrElse { return Err(it) }
        val initial =
            refreshTokenGrantProvider.exchangeRefreshToken(
                Oid4vciRefreshTokenGrantRequest(
                    tokenEndpoint = tokenEndpoint,
                    refreshToken = refreshToken,
                    clientId = options.clientId,
                    dpopProofJwt = initialProofs.dpopProofJwt,
                    clientAttestationJwt = initialProofs.clientAttestationJwt,
                    clientAttestationPopJwt = initialProofs.clientAttestationPopJwt,
                    clientAuthentication = initialProofs.clientAuthentication,
                ),
            )
        val nonce = initial.errorDpopNonceOrNull() ?: return initial
        val retryProofs =
            tokenEndpointProofs(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                tokenEndpoint = tokenEndpoint,
                authorizationServerIssuer = authorizationServerIssuer,
                nonce = nonce,
            ).getOrElse { return Err(it) }
        val retryDpop = retryProofs.dpopProofJwt ?: return initial
        return refreshTokenGrantProvider.exchangeRefreshToken(
            Oid4vciRefreshTokenGrantRequest(
                tokenEndpoint = tokenEndpoint,
                refreshToken = refreshToken,
                clientId = options.clientId,
                dpopProofJwt = retryDpop,
                clientAttestationJwt = retryProofs.clientAttestationJwt,
                clientAttestationPopJwt = retryProofs.clientAttestationPopJwt,
                clientAuthentication = retryProofs.clientAuthentication,
            ),
        )
    }

    private suspend fun tokenEndpointDpopProof(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        tokenEndpoint: String,
        nonce: String,
    ): IdkResult<String?, IdkError> =
        tokenEndpointProofsProvider.dpopProof(
            Oid4vciDpopProofRequest(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                httpMethod = "POST",
                httpUrl = tokenEndpoint,
                nonce = nonce,
            ),
        )

    private fun IdkResult<*, IdkError>.errorDpopNonceOrNull(): String? {
        if (!isErr || error.code != "use_dpop_nonce") {
            return null
        }
        return error.meta["dpop_nonce"] as? String
    }

    private suspend fun resolveProofNonce(
        resolvedOffer: ResolvedCredentialOffer,
        fallback: String?,
    ): IdkResult<String?, IdkError> {
        val nonceEndpoint = resolvedOffer.issuerMetadata.nonceEndpoint
        if (nonceEndpoint == null) {
            return Ok(fallback)
        }
        val nonce = holder.requestNonce(nonceEndpoint)
        if (nonce.isErr) {
            return Err(nonce.error)
        }
        return Ok(nonce.value.cNonce)
    }

    private suspend fun tokenEndpointProofs(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        tokenEndpoint: String,
        authorizationServerIssuer: String?,
        nonce: String? = null,
    ): IdkResult<Oid4vciTokenEndpointProofs, IdkError> =
        tokenEndpointProofsProvider.proofs(
            Oid4vciTokenEndpointProofRequest(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                tokenEndpoint = tokenEndpoint,
                authorizationServerIssuer = authorizationServerIssuer,
                nonce = nonce,
            ),
        )

    private suspend fun Oid4vciHolderIssuanceOptions.withAttestationChallenge(
        authorizationServer: ResolvedAuthorizationServer,
    ): IdkResult<Oid4vciHolderIssuanceOptions, IdkError> {
        val haip = haipTokenProofs ?: return Ok(this)
        val endpoint = authorizationServer.metadata.challengeEndpoint?.takeIf(String::isNotBlank) ?: return Ok(this)
        val response = holder.requestAttestationChallenge(endpoint)
        return if (response.isErr) {
            Err(response.error)
        } else {
            Ok(copy(haipTokenProofs = haip.copy(attestationChallenge = response.value.attestationChallenge)))
        }
    }

    /**
     * KA-on-demand: when the resolved credential configuration's `jwt` proof type declares
     * `key_attestations_required`, obtains a key attestation for the credential-request signing
     * key via [keyAttestationProvider] and returns its compact JWT for attachment to the proof's
     * `key_attestation` header (OID4VCI 1.0 Section 7.2/11.2.3, TS 119 472-3). Returns `null` (no
     * attachment) when the configuration does not require one - the wallet never attaches a KA
     * uninvited.
     */
    private suspend fun keyAttestationJwtIfRequired(
        context: WalletInteractionContext,
        resolvedOffer: ResolvedCredentialOffer,
        credentialConfigurationId: String?,
        signingKeyId: String,
        signingAlgorithm: String,
        cNonce: String?,
        operationBinding: String?,
        haipOptions: Oid4vciHaipTokenProofOptions?,
    ): IdkResult<String?, IdkError> {
        val requirement =
            credentialConfigurationId
                ?.let { resolvedOffer.issuerMetadata.credentialConfigurationsSupported[it] }
                ?.proofTypesSupported
                ?.get(JWT_PROOF_TYPE)
                ?.keyAttestationsRequired
                ?: return Ok(null)
        val attendedOperationBinding =
            operationBinding?.takeIf { it.isNotBlank() }
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Credential configuration '$credentialConfigurationId' requires a key attestation, but the attended operation binding is missing",
                    ),
                )
        val nonce =
            cNonce
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Credential configuration '$credentialConfigurationId' requires a key attestation, but no proof nonce was issued for this credential request",
                    ),
                )
        val attestationJwt =
            keyAttestationProvider
                .attest(
                    Oid4vciKeyAttestationRequest(
                        walletUnitId = context.walletUnitId,
                        walletAccountId = haipOptions?.walletAccountId ?: context.walletUnitId,
                        operationBinding = attendedOperationBinding,
                        signingKeyId = signingKeyId,
                        signingAlgorithm = signingAlgorithm,
                        audience = resolvedOffer.issuerMetadata.credentialIssuer,
                        nonce = nonce,
                        signer = haipOptions?.signer,
                        evidence = haipOptions?.evidence.orEmpty(),
                        requirement = requirement,
                    ),
                ).getOrElse { return Err(it) }
        return Ok(attestationJwt)
    }

    private suspend fun credentialEndpointDpopProof(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        accessToken: String,
        nonce: String? = null,
    ): IdkResult<String?, IdkError> {
        // OID4VCI 1.0 final binds DPoP to the ordinary Credential Endpoint for both
        // single and multi-proof credential requests.
        val credentialEndpoint = resolvedOffer.issuerMetadata.credentialEndpoint
        return tokenEndpointProofsProvider.dpopProof(
            Oid4vciDpopProofRequest(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                httpMethod = "POST",
                httpUrl = credentialEndpoint,
                nonce = nonce,
                accessToken = accessToken,
            ),
        )
    }

    private suspend fun deferredEndpointDpopProof(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        deferredCredentialEndpoint: String,
        accessToken: String,
        nonce: String? = null,
    ): IdkResult<String?, IdkError> =
        tokenEndpointProofsProvider.dpopProof(
            Oid4vciDpopProofRequest(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                httpMethod = "POST",
                httpUrl = deferredCredentialEndpoint,
                nonce = nonce,
                accessToken = accessToken,
            ),
        )

    private suspend fun notificationEndpointDpopProof(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        options: Oid4vciHolderIssuanceOptions,
        notificationEndpoint: String,
        accessToken: String,
        nonce: String? = null,
    ): IdkResult<String?, IdkError> =
        tokenEndpointProofsProvider.dpopProof(
            Oid4vciDpopProofRequest(
                context = context,
                state = state,
                resolvedOffer = resolvedOffer,
                options = options,
                httpMethod = "POST",
                httpUrl = notificationEndpoint,
                nonce = nonce,
                accessToken = accessToken,
            ),
        )

    private suspend fun handleCredentialResponse(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        credentialResponse: CredentialResponse,
        /** Whether the access token is DPoP-bound; persisted on a deferral for unattended checks. */
        dpopBound: Boolean = false,
    ): Oid4vciIssuanceExecutionResult {
        val notificationId = credentialResponse.notificationId
        val notificationEndpoint = resolvedOffer.issuerMetadata.notificationEndpoint
        if (!notificationId.isNullOrBlank() && !notificationEndpoint.isNullOrBlank()) {
            context.updateOid4vciState {
                it.copy(
                    notification =
                        Oid4vciPrivateSessionState.NotificationLeg(
                            notificationEndpoint = notificationEndpoint,
                            notificationId = notificationId,
                        ),
                )
            }
        }
        val transactionId = credentialResponse.transactionId
        if (transactionId != null) {
            val deferredCredentialEndpoint = resolvedOffer.issuerMetadata.deferredCredentialEndpoint
            // A blank transaction_id must not produce a deferred leg: retrieval would send an empty
            // id to the issuer instead of failing fast at the wallet.
            if (!deferredCredentialEndpoint.isNullOrBlank() && transactionId.isNotBlank()) {
                val sessionState = context.oid4vciState()
                val accessToken =
                    credentialResponse.additionalParameters[DEFERRAL_ACCESS_TOKEN_PARAMETER]
                        ?.let { it as? JsonPrimitive }
                        ?.contentOrNull
                        ?.takeIf { it.isNotBlank() }
                        ?: sessionState.tokens?.accessToken
                        ?: return failed(
                            WalletInteractionFailureCodes.OID4VCI_ACCESS_TOKEN_MISSING,
                            "wallet.interaction.error.oid4vci_access_token_missing",
                            retryable = true,
                        )
                val accessTokenRef =
                    try {
                        issuanceSessionStore.storeDeferredAccessToken(context.walletUnitId, context.sessionId.value, accessToken)
                    } catch (failure: Exception) {
                        return failedDeferredPersistence(failure)
                    }
                if (accessTokenRef.isErr) return failedDeferredPersistence(accessTokenRef.error)

                val credentialConfigurationId =
                    sessionState.credentialConfigurationId?.takeIf { it.isNotBlank() }
                        ?: resolvedOffer.offer.credentialConfigurationIds.firstOrNull()?.takeIf { it.isNotBlank() }
                        ?: return failed(
                            WalletInteractionFailureCodes.OID4VCI_DEFERRED_REQUEST_FAILED,
                            "wallet.interaction.error.oid4vci_deferred_request_failed",
                            retryable = true,
                        )
                val now = Clock.System.now()
                val intervalSeconds = (credentialResponse.interval ?: DEFAULT_DEFERRED_INTERVAL_SECONDS).coerceAtLeast(0)
                val deferredSession =
                    IssuanceSession(
                        id = context.sessionId.value,
                        walletUnitId = context.walletUnitId,
                        issuerRef = resolvedOffer.offer.credentialIssuer.toIssuerRef(),
                        credentialIssuerUrl = resolvedOffer.offer.credentialIssuer,
                        credentialConfigurationId = credentialConfigurationId,
                        holderKeyRef = sessionState.holderKeyAliases.firstOrNull()?.let(::KeyRef),
                        holderKeyRefs = sessionState.holderKeyAliases.map(::KeyRef),
                        status = IssuanceSessionStatus.DEFERRED,
                        deferred =
                            DeferredIssuanceState(
                                transactionId = transactionId,
                                deferredCredentialEndpoint = deferredCredentialEndpoint,
                                accessTokenRef = accessTokenRef.value,
                                retryPolicy = RetryPolicy(initialDelaySeconds = intervalSeconds.toLong(), maxDelaySeconds = intervalSeconds.toLong()),
                                nextPollAt = now.plus(intervalSeconds.toLong().seconds),
                                dpopBound = dpopBound,
                            ),
                        createdAt = now,
                        updatedAt = now,
                    )
                val persistedSession =
                    try {
                        issuanceSessionStore.putSession(context.walletUnitId, deferredSession)
                    } catch (failure: Exception) {
                        return failedDeferredPersistence(failure)
                    }
                if (persistedSession.isErr) return failedDeferredPersistence(persistedSession.error)
                try {
                    context.updateOid4vciState {
                        it.copy(
                            deferred =
                                Oid4vciPrivateSessionState.DeferredLeg(
                                    deferredCredentialEndpoint = deferredCredentialEndpoint,
                                    transactionId = transactionId,
                                ),
                        )
                    }
                } catch (failure: Exception) {
                    return failedDeferredPersistence(failure)
                }
            }
            return Oid4vciIssuanceExecutionResult.Deferred(intervalSeconds = credentialResponse.interval)
        }
        if (credentialResponse.credentials.isNullOrEmpty()) {
            return failed(WalletInteractionFailureCodes.OID4VCI_EMPTY_CREDENTIAL_RESPONSE, "wallet.interaction.error.oid4vci_empty_credential_response")
        }
        val previews =
            try {
                credentialReceiver.receiveCredentialResponse(context, state, resolvedOffer, credentialResponse)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (expected: Exception) {
                return failed(
                    code = WalletInteractionFailureCodes.OID4VCI_CREDENTIAL_RECEIVER_FAILED,
                    messageKey = "wallet.interaction.error.oid4vci_credential_receiver_failed",
                    retryable = true,
                    arguments =
                        mapOf(
                            "causeType" to (expected::class.simpleName ?: "Exception"),
                            "stage" to "credential-receive",
                        ),
                )
            }
        return Oid4vciIssuanceExecutionResult.Received(credentialPreview = previews)
    }

    private suspend fun notifyIssuer(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        event: CredentialNotificationEvent,
        eventDescription: String? = null,
    ): Oid4vciIssuerNotificationResult {
        val sessionState = context.oid4vciState()
        val notificationEndpoint = sessionState.notification?.notificationEndpoint.orEmpty()
        val accessToken = sessionState.tokens?.accessToken.orEmpty()
        val notificationId = sessionState.notification?.notificationId.orEmpty()
        if (notificationEndpoint.isBlank() || accessToken.isBlank() || notificationId.isBlank()) {
            return Oid4vciIssuerNotificationResult.NotSupported
        }
        val rawOffer = sessionState.entryPointRaw?.takeIf { it.isNotBlank() } ?: return notificationFailed("credential_offer_missing")
        val offer = holder.parseCredentialOffer(rawOffer)
        if (offer.isErr) return notificationFailed(offer.error.code)
        val resolved = holder.resolveCredentialOffer(offer.value)
        if (resolved.isErr) return notificationFailed(resolved.error.code)
        val options =
            try {
                optionsProvider.options(context, state, resolved.value)
            } catch (_: Exception) {
                return notificationFailed("options_unavailable")
            }
        val initialDpop =
            notificationEndpointDpopProof(context, state, resolved.value, options, notificationEndpoint, accessToken)
                .getOrElse { return notificationFailed(it.code) }
        val initial =
            holder.sendNotification(
                notificationEndpoint = notificationEndpoint,
                accessToken = accessToken,
                dpopProofJwt = initialDpop,
                notificationId = notificationId,
                event = event,
                eventDescription = eventDescription,
            )
        val nonce = initial.errorDpopNonceOrNull()
        val result =
            if (nonce == null) {
                initial
            } else {
                val retryDpop =
                    notificationEndpointDpopProof(context, state, resolved.value, options, notificationEndpoint, accessToken, nonce)
                        .getOrElse { return notificationFailed(it.code) }
                        ?: return notificationFailed(initial.error.code)
                holder.sendNotification(
                    notificationEndpoint = notificationEndpoint,
                    accessToken = accessToken,
                    dpopProofJwt = retryDpop,
                    notificationId = notificationId,
                    event = event,
                    eventDescription = eventDescription,
                )
            }
        if (result.isErr) {
            return notificationFailed(result.error.code)
        }
        return Oid4vciIssuerNotificationResult.Sent
    }

    private fun notificationFailed(providerErrorCode: String): Oid4vciIssuerNotificationResult.Failed =
        Oid4vciIssuerNotificationResult.Failed(
            code = WalletInteractionFailureCodes.OID4VCI_NOTIFICATION_FAILED,
            messageKey = "wallet.interaction.error.oid4vci_notification_failed",
            arguments = mapOf("providerErrorCode" to providerErrorCode),
        )

    private fun failedDeferredPersistence(error: IdkError): Oid4vciIssuanceExecutionResult.Failed =
        failed(
            code = WalletInteractionFailureCodes.OID4VCI_DEFERRED_REQUEST_FAILED,
            messageKey = "wallet.interaction.error.oid4vci_deferred_request_failed",
            error = error,
            retryable = true,
        )

    private fun failedDeferredPersistence(failure: Exception): Oid4vciIssuanceExecutionResult.Failed =
        failed(
            code = WalletInteractionFailureCodes.OID4VCI_DEFERRED_REQUEST_FAILED,
            messageKey = "wallet.interaction.error.oid4vci_deferred_request_failed",
            retryable = true,
            arguments = mapOf("causeType" to (failure::class.simpleName ?: "Exception"), "cause" to failure.message.orEmpty()),
        )

    private companion object {
        /** RFC 6749 section 5.2; for a pre-authorized request with a tx_code it means a wrong code. */
        const val OAUTH_INVALID_GRANT = "invalid_grant"
        const val OID4VCI_INVALID_NONCE = "invalid_nonce"
        const val OAUTH_INVALID_TOKEN = "invalid_token"
    }

    private fun failed(
        code: String,
        messageKey: String,
        error: IdkError,
        retryable: Boolean = false,
    ): Oid4vciIssuanceExecutionResult.Failed =
        failed(
            code = code,
            messageKey = messageKey,
            retryable = retryable,
            arguments = mapOf("providerErrorCode" to error.code),
            diagnostics = error.toDiagnosticDetails("provider"),
        )

    private fun failed(
        code: String,
        messageKey: String,
        retryable: Boolean = false,
        arguments: Map<String, String> = emptyMap(),
        diagnostics: Map<String, String> = emptyMap(),
    ): Oid4vciIssuanceExecutionResult.Failed =
        Oid4vciIssuanceExecutionResult.Failed(
            code = code,
            messageKey = messageKey,
            retryable = retryable,
            arguments = arguments,
            diagnostics = diagnostics,
        )

    private fun optionsUnavailable(
        code: String,
        messageKey: String,
        cause: Exception,
    ): Oid4vciIssuanceExecutionResult.Failed =
        failed(
            code = code,
            messageKey = messageKey,
            retryable = true,
            arguments =
                mapOf(
                    "causeType" to (cause::class.simpleName ?: "Exception"),
                    "cause" to cause.message.orEmpty(),
                ),
            diagnostics = cause.toDiagnosticDetails("options"),
        )

    private fun Oid4vciIssuanceExecutionResult.logged(
        context: WalletInteractionContext,
        operation: String,
    ): Oid4vciIssuanceExecutionResult {
        if (this is Oid4vciIssuanceExecutionResult.Failed) {
            context.diagnostics.warn(
                event = "oid4vci.$operation.failed",
                sessionId = context.sessionId,
                details = mapOf("code" to code, "retryable" to retryable.toString()) + arguments + diagnostics,
            )
        }
        return this
    }

}

private const val IAE_OPENID4VP_PRESENTATION: String = "urn:openid:dcp:iae:openid4vp_presentation"
private const val HAIP_PREFERRED_CREDENTIAL_FORMAT: String = "dc+sd-jwt"
private const val JWT_PROOF_TYPE: String = "jwt"
private const val DEFERRAL_ACCESS_TOKEN_PARAMETER: String = "deferral_access_token"
private const val DEFAULT_DEFERRED_INTERVAL_SECONDS: Int = 5

/**
 * Resolves the Credential Request selector from the Token Response. OID4VCI 1.0 §8.2
 * requires `credential_identifier` whenever an `openid_credential` authorization detail
 * returned `credential_identifiers`; batch proofs still identify the same dataset and do not
 * switch the request back to `credential_configuration_id`.
 */
internal fun selectCredentialRequestTarget(
    tokenAuthorizationDetails: List<JsonElement>?,
    credentialConfigurationId: String?,
): IdkResult<Oid4vciCredentialRequestTarget, IdkError> {
    if (tokenAuthorizationDetails == null) {
        return credentialConfigurationTarget(credentialConfigurationId)
    }
    if (tokenAuthorizationDetails.isEmpty()) return invalidCredentialRequestTarget()

    val credentialDetails = mutableListOf<Pair<String, List<String>>>()
    for (element in tokenAuthorizationDetails) {
        val detail = element as? JsonObject ?: return invalidCredentialRequestTarget()
        val type = detail["type"].stringContentOrNull() ?: return invalidCredentialRequestTarget()
        if (type != "openid_credential") continue

        val detailConfigurationId =
            detail["credential_configuration_id"].stringContentOrNull()
                ?.takeIf(String::isNotBlank)
                ?: return invalidCredentialRequestTarget()
        val identifiers = detail["credential_identifiers"] as? JsonArray ?: return invalidCredentialRequestTarget()
        val parsedIdentifiers =
            identifiers.map { it.stringContentOrNull()?.takeIf(String::isNotBlank) ?: return invalidCredentialRequestTarget() }
        if (parsedIdentifiers.isEmpty() || parsedIdentifiers.distinct().size != parsedIdentifiers.size) {
            return invalidCredentialRequestTarget()
        }
        credentialDetails += detailConfigurationId to parsedIdentifiers
    }

    if (credentialDetails.isEmpty()) return credentialConfigurationTarget(credentialConfigurationId)
    val requestedConfigurationId = credentialConfigurationId?.takeIf(String::isNotBlank) ?: return invalidCredentialRequestTarget()
    val matchingDetails = credentialDetails.filter { (configurationId, _) -> configurationId == requestedConfigurationId }
    if (matchingDetails.size != 1) return invalidCredentialRequestTarget()

    return Ok(
        Oid4vciCredentialRequestTarget(
            credentialIdentifier = matchingDetails.single().second.first(),
        ),
    )
}

private fun credentialConfigurationTarget(credentialConfigurationId: String?): IdkResult<Oid4vciCredentialRequestTarget, IdkError> =
    credentialConfigurationId
        ?.takeIf(String::isNotBlank)
        ?.let { Ok(Oid4vciCredentialRequestTarget(credentialConfigurationId = it)) }
        ?: invalidCredentialRequestTarget()

private fun invalidCredentialRequestTarget(): IdkResult<Oid4vciCredentialRequestTarget, IdkError> =
    Err(
        IdkError.fromString(
            code = "oid4vci.credential_request_authorization_details_invalid",
            message = "Token authorization details do not unambiguously authorize the requested credential configuration",
        ),
    )

private fun JsonElement?.stringContentOrNull(): String? =
    (this as? JsonPrimitive)
        ?.takeIf { it.isString }
        ?.contentOrNull

private fun String.toIssuerRef(): IdentifierRef =
    IdentifierRef(
        type = if (startsWith("did:")) IdentifierType.DID else IdentifierType("https"),
        value = this,
    )

private fun signatureAlgorithm(joseAlgorithm: String): SignatureAlgorithm =
    when (joseAlgorithm.uppercase()) {
        "ES256" -> SignatureAlgorithm.ECDSA_SHA256
        "ES384" -> SignatureAlgorithm.ECDSA_SHA384
        "ES512" -> SignatureAlgorithm.ECDSA_SHA512
        "EDDSA" -> SignatureAlgorithm.ED25519
        else -> SignatureAlgorithm.ECDSA_SHA256
    }

/** A DPoP proof accompanies every request made with the access token these options produce. */
internal fun Oid4vciHolderIssuanceOptions.isDpopBound(): Boolean = dpopEnabled || haipTokenProofs != null

/**
 * The holder DID verification method for a credential request proof, or null for a JWK proof:
 * `did:jwk` when [methods] offers it and the key has a did:jwk verification method, otherwise JWK
 * when [methods] offers `jwk` or is empty (binding not required). Anything else fails closed.
 */
internal suspend fun selectHolderDidVerificationMethod(
    methods: List<String>,
    credentialFormat: String? = null,
    holderVerificationMethod: suspend () -> WalletHolderVerificationMethod?,
): IdkResult<String?, IdkError> {
    if (DID_JWK_BINDING_METHOD in methods) {
        val method = holderVerificationMethod()
        if (method?.kind == WalletHolderIdentifierKind.DID_VERIFICATION_METHOD && method.value.startsWith("$DID_JWK_BINDING_METHOD:")) {
            return Ok(method.value)
        }
    }
    if (methods.isEmpty() || JWK_BINDING_METHOD in methods) return Ok(null)
    // COSE_Key is the mdoc's DeviceKeyInfo representation. Its JWT proof still conveys the
    // same public key in the protected jwk header (OID4VCI 1.0 Appendix A.2 and F.1).
    if (credentialFormat == "mso_mdoc" && COSE_KEY_BINDING_METHOD in methods) return Ok(null)
    return Err(
        IdkError.fromString(
            code = "oid4vci.holder_binding_method_unsupported",
            message = "The wallet cannot satisfy the issuer's credential binding methods $methods for format $credentialFormat",
        ),
    )
}

/** OID4VCI 1.0 section 12.2.4 cryptographic binding method values the wallet can satisfy. */
private const val JWK_BINDING_METHOD = "jwk"
private const val DID_JWK_BINDING_METHOD = "did:jwk"
private const val COSE_KEY_BINDING_METHOD = "cose_key"
