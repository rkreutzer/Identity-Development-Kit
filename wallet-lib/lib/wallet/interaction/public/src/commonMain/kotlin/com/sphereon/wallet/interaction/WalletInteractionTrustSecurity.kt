/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.wallet.interaction

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

interface WalletCounterpartyTrustResolver {
    suspend fun resolve(input: WalletCounterpartyTrustRequest): WalletCounterpartyTrustSummary

    companion object {
        val unresolved: WalletCounterpartyTrustResolver =
            object : WalletCounterpartyTrustResolver {
                override suspend fun resolve(input: WalletCounterpartyTrustRequest): WalletCounterpartyTrustSummary =
                    WalletCounterpartyTrustSummary(
                        counterparty = input.counterparty,
                        status = WalletTrustStatus.UNKNOWN,
                        policyAction = WalletTrustPolicyAction.WARN,
                        sources = input.sources,
                    )
            }
    }
}

/**
 * The issuer-authentication material resolved for a concrete counterparty.  This is deliberately
 * separate from [WalletCounterpartyTrustSummary]: a trust decision is presentation/UI state,
 * while this immutable result is the cryptographic input used when an issued JWT VC is accepted.
 * Embedded `jwk`/`x5c` headers are never copied into this object by the wallet.
 */
@Serializable
data class WalletIssuerAuthenticationResult(
    val issuer: String,
    val trustedJwks: JsonObject,
    val provenance: List<WalletIssuerAuthenticationProvenance>,
) {
    init {
        require(issuer.isNotBlank()) { "wallet_issuer_authentication_issuer_blank" }
        val keys = trustedJwks["keys"]
        require(keys is JsonArray && keys.isNotEmpty() && keys.all { it is JsonObject }) {
            "wallet_issuer_authentication_trusted_jwks_empty_or_invalid"
        }
        require(provenance.isNotEmpty()) { "wallet_issuer_authentication_provenance_empty" }
    }
}

/** Provenance for the issuer key set used by [WalletIssuerAuthenticationResult]. */
@Serializable
data class WalletIssuerAuthenticationProvenance(
    val source: String,
    val reference: String,
) {
    init {
        require(source.isNotBlank()) { "wallet_issuer_authentication_provenance_source_blank" }
        require(reference.isNotBlank()) { "wallet_issuer_authentication_provenance_reference_blank" }
    }
}

/** Resolver SPI for binding an issuer identity to a trusted JWKS before credential storage. */
interface WalletIssuerAuthenticationResolver {
    suspend fun resolve(input: WalletIssuerAuthenticationRequest): WalletIssuerAuthenticationResult?

    companion object {
        val none: WalletIssuerAuthenticationResolver =
            object : WalletIssuerAuthenticationResolver {
                override suspend fun resolve(input: WalletIssuerAuthenticationRequest): WalletIssuerAuthenticationResult? = null
            }
    }
}

@Serializable
data class WalletIssuerAuthenticationRequest(
    val counterparty: WalletCounterpartySummary,
    val protocol: WalletProtocol,
)

interface WalletTrustPolicy {
    suspend fun evaluate(summary: WalletCounterpartyTrustSummary): WalletTrustPolicyDecision

    companion object {
        val warn: WalletTrustPolicy =
            object : WalletTrustPolicy {
                override suspend fun evaluate(summary: WalletCounterpartyTrustSummary): WalletTrustPolicyDecision =
                    when (summary.status) {
                        WalletTrustStatus.TRUSTED -> WalletTrustPolicyDecision(WalletTrustPolicyAction.ALLOW)
                        WalletTrustStatus.BLOCKED -> WalletTrustPolicyDecision(WalletTrustPolicyAction.BLOCK)
                        else -> WalletTrustPolicyDecision(WalletTrustPolicyAction.WARN)
                    }
            }

        /**
         * Always ALLOW, regardless of [WalletCounterpartyTrustSummary.status] (including BLOCKED).
         * For the conformance profile only: a conformance run deliberately trusts arbitrary suite
         * issuer/verifier endpoints so the headless runner can drive OIDF conformance non-interactively.
         * Production profiles never use this; they use [warn].
         */
        val allow: WalletTrustPolicy =
            object : WalletTrustPolicy {
                override suspend fun evaluate(summary: WalletCounterpartyTrustSummary): WalletTrustPolicyDecision =
                    WalletTrustPolicyDecision(WalletTrustPolicyAction.ALLOW)
            }
    }
}

interface WalletSecurityGate {
    suspend fun authorize(request: WalletSecurityGateRequest): WalletSecurityGateResult

    companion object {
        /** Fail-closed default for incomplete application graphs and direct context construction. */
        val deny: WalletSecurityGate =
            object : WalletSecurityGate {
                override suspend fun authorize(request: WalletSecurityGateRequest): WalletSecurityGateResult =
                    WalletSecurityGateResult.Denied("wallet.interaction.security.gate_not_configured")
            }

        /** Explicit test/conformance helper; production composition must install a real gate. */
        val allow: WalletSecurityGate =
            object : WalletSecurityGate {
                override suspend fun authorize(request: WalletSecurityGateRequest): WalletSecurityGateResult =
                    WalletSecurityGateResult.Authorized(
                        WalletSecurityGrant(
                            grantId = request.operationId,
                            assurance = WalletSecurityAssurance.NONE,
                        ),
                    )
            }
    }
}

@Serializable
data class WalletCounterpartyTrustRequest(
    val counterparty: WalletCounterpartySummary,
    val protocol: WalletProtocol,
    val sources: List<WalletTrustSource> = emptyList(),
    val hints: Map<String, String> = emptyMap(),
    /** The authenticated OID4VP client identifier of a verifier; null when the request carried no validated identity. */
    val clientAuthentication: WalletCounterpartyClientAuthentication? = null,
)

/**
 * How an OID4VP Verifier authenticated its client identifier, split into the OID4VP 1.0 client
 * identifier prefix and the bare identifier so a trust resolver can pick the matching evidence.
 */
@Serializable
data class WalletCounterpartyClientAuthentication(
    /** The client identifier prefix (for example `x509_san_dns`), or null for a pre-registered client without a prefix. */
    val scheme: String?,
    /** The client identifier without its prefix. */
    val identifier: String,
    /** The Request Object `x5c` chain (base64 DER, leaf first) for X.509 client identifier prefixes. */
    val certificateChain: List<String> = emptyList(),
) {
    companion object {
        const val SCHEME_DECENTRALIZED_IDENTIFIER: String = "decentralized_identifier"
        const val SCHEME_OPENID_FEDERATION: String = "openid_federation"
        const val SCHEME_X509_SAN_DNS: String = "x509_san_dns"
        const val SCHEME_X509_SAN_URI: String = "x509_san_uri"
        const val SCHEME_X509_HASH: String = "x509_hash"
    }
}

@Serializable
enum class WalletTrustChainLinks {
    VERIFIED,
    BROKEN,
}

@Serializable
enum class WalletTrustChainHopPosition {
    LEAF,
    INTERMEDIATE,
    ANCHOR,
}

@Serializable
data class WalletTrustChainHop(
    val identifier: String,
    val position: WalletTrustChainHopPosition,
    val displayName: String? = null,
    val assertedBy: String? = null,
    /** The organisation behind this hop, as the chain's signed statements describe it. */
    val organisation: WalletCounterpartyOrganisation? = null,
) {
    init {
        require(identifier.isNotBlank()) { "wallet_trust_chain_hop_identifier_blank" }
        require(displayName == null || displayName.isNotBlank()) { "wallet_trust_chain_hop_display_name_blank" }
        require(assertedBy == null || assertedBy.isNotBlank()) { "wallet_trust_chain_hop_asserted_by_blank" }
        if (position == WalletTrustChainHopPosition.ANCHOR) {
            require(assertedBy == null) { "wallet_trust_chain_anchor_must_not_name_an_attester" }
        }
    }
}

@Serializable
data class WalletTrustChain(
    val hops: List<WalletTrustChainHop>,
    val links: WalletTrustChainLinks,
    /** Verified trust mark types the counterparty holds under the chain's anchor. */
    val trustMarks: List<String> = emptyList(),
) {
    init {
        require(hops.isNotEmpty()) { "wallet_trust_chain_hops_empty" }
        require(trustMarks.none(String::isBlank)) { "wallet_trust_chain_trust_mark_blank" }
    }
}

/**
 * Organisation details a trust framework vouches for, such as the signed OpenID Federation
 * `federation_entity` metadata of the counterparty. Never the counterparty's self-declared display data.
 */
@Serializable
data class WalletCounterpartyOrganisation(
    val name: String? = null,
    val legalName: String? = null,
    /** Email addresses, phone numbers or URLs, as published. */
    val contacts: List<String> = emptyList(),
    val website: String? = null,
    val contactPage: String? = null,
    val privacyPolicy: String? = null,
    val logoUri: String? = null,
    /** Display name of the authority whose signed statement carries these details. */
    val attestedBy: String? = null,
)

@Serializable
enum class WalletTrustDomainPosture {
    FAIL_CLOSED,
    CUSTOM,
}

@Serializable
enum class WalletTrustDomainAdmissionOutcome {
    ADMITTED_NAMED_DOMAIN,
    NOT_ADMITTED,
    FAIL_CLOSED,
}

@Serializable
data class WalletTrustDomainAdmission(
    val posture: WalletTrustDomainPosture,
    val outcome: WalletTrustDomainAdmissionOutcome,
    val admittingDomain: String? = null,
) {
    init {
        require(admittingDomain == null || admittingDomain.isNotBlank()) { "wallet_trust_admitting_domain_blank" }
        when (outcome) {
            WalletTrustDomainAdmissionOutcome.ADMITTED_NAMED_DOMAIN -> {
                require(posture == WalletTrustDomainPosture.CUSTOM) { "wallet_trust_named_admission_requires_custom_posture" }
                require(!admittingDomain.isNullOrBlank()) { "wallet_trust_named_admission_requires_admitting_domain" }
            }
            WalletTrustDomainAdmissionOutcome.FAIL_CLOSED -> {
                require(posture == WalletTrustDomainPosture.FAIL_CLOSED) { "wallet_trust_fail_closed_outcome_requires_fail_closed_posture" }
                require(admittingDomain == null) { "wallet_trust_fail_closed_must_not_name_a_domain" }
            }
            WalletTrustDomainAdmissionOutcome.NOT_ADMITTED -> {
                require(posture == WalletTrustDomainPosture.CUSTOM) { "wallet_trust_not_admitted_requires_custom_posture" }
                require(admittingDomain == null) { "wallet_trust_not_admitted_must_not_name_a_domain" }
            }
        }
    }
}

@Serializable
enum class WalletAttestationAuthorisationOutcome {
    AUTHORISED,
    NOT_AUTHORISED,
    UNKNOWN,
}

@Serializable
data class WalletAttestationAuthorisation(
    val outcome: WalletAttestationAuthorisationOutcome,
    val scheme: String? = null,
) {
    init {
        require(scheme == null || scheme.isNotBlank()) { "wallet_attestation_authorisation_scheme_blank" }
    }
}

@Serializable
data class WalletCounterpartyTrustSummary(
    val counterparty: WalletCounterpartySummary,
    val status: WalletTrustStatus,
    val policyAction: WalletTrustPolicyAction = WalletTrustPolicyAction.WARN,
    val sources: List<WalletTrustSource> = emptyList(),
    val diagnostics: List<String> = emptyList(),
    val firstContactKey: String? = null,
    val rememberedDecision: Boolean = false,
    val trustChain: WalletTrustChain? = null,
    val domainAdmission: WalletTrustDomainAdmission? = null,
    val attestationAuthorisation: WalletAttestationAuthorisation? = null,
    /** Organisation details vouched for by the trust framework that recognised the counterparty. */
    val organisation: WalletCounterpartyOrganisation? = null,
    /** Immutable key-binding result used by receive-time JWT VC verification. */
    val issuerAuthentication: WalletIssuerAuthenticationResult? = null,
)

@Serializable
data class WalletTrustSource(
    val type: WalletTrustSourceType,
    val identifier: String,
    val labelKey: String? = null,
    /** Name under which this source recognises the counterparty, such as the name the holder gave a recognised organisation. */
    val displayName: String? = null,
) {
    init {
        requireWalletInteractionLocalizationKey("labelKey", labelKey)
    }
}

@Serializable
enum class WalletTrustSourceType {
    EUDI_TRUSTED_LIST,
    X509,
    VICAL,
    DID,
    OPENID_FEDERATION,
    DCQL_TRUSTED_AUTHORITY,
    REMEMBERED_USER_DECISION,

    /** Admitted by a trust domain of the organisation that runs this wallet. */
    TRUST_DOMAIN,

    /** Admitted by an anchor the holder keeps in this wallet profile. */
    WALLET_TRUST_ANCHOR,
}

@Serializable
enum class WalletTrustStatus {
    TRUSTED,
    UNKNOWN,
    WARNING,
    BLOCKED,
}

@Serializable
enum class WalletTrustPolicyMode {
    WARN,
    BLOCK,
    ASK_USER,
    FIRST_CONTACT_PROMPT,
    REMEMBERED_USER_DECISIONS,
}

@Serializable
data class WalletTrustPolicyDecision(
    val action: WalletTrustPolicyAction,
    val reasonCode: String? = null,
    val arguments: Map<String, String> = emptyMap(),
)

@Serializable
enum class WalletTrustPolicyAction {
    ALLOW,
    WARN,
    BLOCK,
    ASK_USER,
    FIRST_CONTACT_PROMPT,
}

@Serializable
data class WalletSecurityGateRequest(
    val operationId: String,
    val operation: WalletSecurityOperation,
    val audience: String? = null,
    val keyRef: String? = null,
    val walletUnitId: String? = null,
    val walletAccountId: String? = null,
    val activationDecisionId: String? = null,
    val operationType: String? = null,
    /** Binding for the exact attended operation; required whenever wallet-unit policy is used. */
    val operationBinding: String? = null,
    val operationHash: String? = null,
    val nonce: String? = null,
    val requiredAssurance: WalletSecurityAssurance = WalletSecurityAssurance.USER_PRESENT,
    /**
     * The holder-key signatures one approval authorizes, in signing order. When present, the
     * approval covers exactly these signatures and [keyRef] and [operationHash] are not used.
     */
    val operations: List<WalletApprovalOperation> = emptyList(),
)

/**
 * What a security challenge is authorizing. Names what is presented, never the OID4VP flow.
 *
 * [PRESENT_PROOF] is a holder-binding proof during issuance. [PRESENT_CREDENTIALS] is sharing
 * verifiable credentials (OID4VP or ISO 18013). A bare PRESENT is not a member: that word is
 * [WalletInteractionFlowKind.CredentialPresent] / the frontend InteractionFlow, the OID4VP flow
 * itself, and overloading it here is how a receive-side challenge was derived from the flow kind.
 */
@Serializable
enum class WalletSecurityOperation {
    PRESENT_PROOF,
    CREDENTIAL_STORAGE,
    PRESENT_CREDENTIALS,
    LOCAL_HSM_UNLOCK,
    REMOTE_KEY_AUTHORIZATION,
}

object WalletSecurityContextAttributes {
    const val KEY_REF: String = "wallet.key.ref"
    const val WALLET_UNIT_ID: String = "wallet.unit.id"
    const val WALLET_ACCOUNT_ID: String = "wallet.account.id"
    const val ACTIVATION_DECISION_ID: String = "wallet.activation.decision.id"
    const val OPERATION_TYPE: String = "wallet.operation.type"
    const val OPERATION_BINDING: String = "wallet.operation.binding"
    const val OPERATION_HASH: String = "wallet.operation.hash"
    const val NONCE: String = "wallet.operation.nonce"
}

@Serializable
sealed class WalletSecurityGateResult {
    @Serializable
    @SerialName("authorized")
    data class Authorized(
        val grant: WalletSecurityGrant,
    ) : WalletSecurityGateResult()

    @Serializable
    @SerialName("challenge_required")
    data class ChallengeRequired(
        val challenge: WalletSecurityChallenge,
    ) : WalletSecurityGateResult()

    @Serializable
    @SerialName("denied")
    data class Denied(
        val reasonKey: String,
        val arguments: Map<String, String> = emptyMap(),
    ) : WalletSecurityGateResult() {
        init {
            requireWalletInteractionLocalizationKey("reasonKey", reasonKey)
        }
    }
}
