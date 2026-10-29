/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.presenter.contracts

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
enum class WalletPartyRolePresentation { ISSUER, VERIFIER, MDOC_READER }

@Serializable
data class WalletPartyPresentation(
    val partyId: String,
    val role: WalletPartyRolePresentation,
    val displayName: String?,
    val legalName: String?,
    val domain: String?,
    val logoUri: String?,
    val purposeKey: String?,
    val purposeArguments: Map<String, String>,
    val retentionKey: String?,
    val retentionArguments: Map<String, String>,
) {
    init {
        require(partyId.isNotBlank()) { "wallet_party_id_blank" }
        requireScreenLocalizationKey("purposeKey", purposeKey)
        requireScreenLocalizationKey("retentionKey", retentionKey)
    }
}

/** One positive trust mechanism or no mechanism. ETSI and OpenID Federation never stack. */
@Serializable
enum class WalletTrustMechanismPresentation { ETSI_TRUSTED_LIST, OPENID_FEDERATION, TRUST_DOMAIN, WALLET_TRUST_ANCHOR, NONE }

/** Whether a trust domain admitted the counterparty. */
@Serializable
enum class WalletTrustAdmissionPresentation { NAMED_DOMAIN, NOT_ADMITTED, FAIL_CLOSED, ABSENT }

@Serializable
enum class WalletTrustStatusPresentation { TRUSTED, UNKNOWN, WARNING, BLOCKED }

@Serializable
enum class WalletTrustActionPresentation { ALLOW, WARN, BLOCK, ASK_USER, FIRST_CONTACT_PROMPT }

@Serializable
enum class WalletTrustSignalLevelPresentation { POSITIVE, WARNING, BLOCKING, INFORMATION }

@Serializable
data class WalletTrustSignalPresentation(
    val signalId: String,
    val level: WalletTrustSignalLevelPresentation,
    val labelKey: String?,
    val arguments: Map<String, String>,
) {
    init {
        require(signalId.isNotBlank()) { "wallet_trust_signal_id_blank" }
        requireScreenLocalizationKey("labelKey", labelKey)
    }
}

@Serializable
enum class WalletTrustChainLinksPresentation { VERIFIED, BROKEN }

@Serializable
enum class WalletTrustChainHopPositionPresentation { LEAF, INTERMEDIATE, ANCHOR }

/**
 * Organisation details a trust framework vouches for, such as signed OpenID Federation metadata.
 * Links are https only; contacts are shown as published.
 */
@Serializable
data class WalletOrganisationPresentation(
    val name: String? = null,
    val legalName: String? = null,
    val contacts: List<String> = emptyList(),
    val website: String? = null,
    val contactPage: String? = null,
    val privacyPolicy: String? = null,
    val logoUri: String? = null,
    /** Display name of the authority whose signed statement carries these details. */
    val attestedBy: String? = null,
) {
    init {
        listOf(website, contactPage, privacyPolicy).forEach { require(it == null || it.startsWith("https://")) { "wallet_organisation_link_not_https" } }
    }
}

@Serializable
data class WalletTrustChainHopPresentation(
    val identifier: String,
    val position: WalletTrustChainHopPositionPresentation,
    val displayName: String? = null,
    val assertedBy: String? = null,
    val organisation: WalletOrganisationPresentation? = null,
)

@Serializable
data class WalletTrustChainPresentation(
    val hops: List<WalletTrustChainHopPresentation>,
    val links: WalletTrustChainLinksPresentation,
    val trustMarks: List<String> = emptyList(),
)

@Serializable
data class WalletTrustPresentation(
    val status: WalletTrustStatusPresentation,
    val action: WalletTrustActionPresentation,
    val mechanism: WalletTrustMechanismPresentation,
    val signals: List<WalletTrustSignalPresentation>,
    val markedTrustedByUser: Boolean,
    val chain: WalletTrustChainPresentation? = null,
    val admission: WalletTrustAdmissionPresentation = WalletTrustAdmissionPresentation.ABSENT,
    /** The counterparty's organisation as the recognising trust framework describes it; null when self-declared only. */
    val organisation: WalletOrganisationPresentation? = null,
)

@Serializable
enum class WalletCredentialFaceStatusPresentation { PENDING, VALID, EXPIRED, REVOKED, SUSPENDED, SUPERSEDED, UNTRUSTED }

/** Shared full/mini credential face input. A null status is mandatory for unissued offer faces. */
@Serializable
data class WalletCredentialFacePresentation(
    val credentialId: String?,
    val configurationId: String?,
    val name: String?,
    val issuerName: String?,
    val description: String?,
    val logoUri: String?,
    val backgroundImageUri: String?,
    val backgroundColor: String?,
    val textColor: String?,
    val status: WalletCredentialFaceStatusPresentation?,
)

@Serializable
enum class WalletInfoVisibilityPresentation { HIDDEN, REVEALED }

@Serializable
data class WalletPrivacyPresentation(
    val scopeId: String,
    val visibility: WalletInfoVisibilityPresentation,
    val defaultVisibility: WalletInfoVisibilityPresentation,
    val policyForcesHiddenDefault: Boolean,
    val valuesWillBeDisclosedAfterApproval: Boolean,
) {
    init {
        require(scopeId.isNotBlank()) { "wallet_privacy_scope_id_blank" }
        require(!policyForcesHiddenDefault || defaultVisibility == WalletInfoVisibilityPresentation.HIDDEN) {
            "wallet_privacy_policy_default_invalid"
        }
    }
}

/** Values are absent while hidden. Renderers never receive a value merely to paint a mask over it. */
@Serializable
sealed interface WalletInfoNodePresentation {
    val nodeId: String
    val labelKey: String?
    val labelArguments: Map<String, String>

    @Serializable
    @SerialName("leaf")
    data class Leaf(
        override val nodeId: String,
        override val labelKey: String?,
        override val labelArguments: Map<String, String>,
        val value: WalletInfoValuePresentation?,
    ) : WalletInfoNodePresentation

    @Serializable
    @SerialName("object")
    data class ObjectNode(
        override val nodeId: String,
        override val labelKey: String?,
        override val labelArguments: Map<String, String>,
        val children: List<WalletInfoNodePresentation>,
    ) : WalletInfoNodePresentation

    @Serializable
    @SerialName("list")
    data class ListNode(
        override val nodeId: String,
        override val labelKey: String?,
        override val labelArguments: Map<String, String>,
        val items: List<WalletInfoNodePresentation>,
    ) : WalletInfoNodePresentation
}

@Serializable
sealed interface WalletInfoValuePresentation {
    @Serializable
    @SerialName("text")
    data class Text(val text: String) : WalletInfoValuePresentation

    /** A sanitized renderer-neutral rich-text AST, never arbitrary Markdown or HTML. */
    @Serializable
    @SerialName("rich-text")
    data class RichText(val blocks: List<WalletRichTextBlockPresentation>) : WalletInfoValuePresentation

    @Serializable
    @SerialName("inline-image")
    data class InlineImage(val dataUri: String, val alternativeText: String?) : WalletInfoValuePresentation

    /** External resources are link rows. Renderers must never fetch them as images. */
    @Serializable
    @SerialName("external-resource")
    data class ExternalResource(val uri: String, val label: String?) : WalletInfoValuePresentation
}

@Serializable
sealed interface WalletRichTextBlockPresentation {
    @Serializable
    @SerialName("paragraph")
    data class Paragraph(val runs: List<WalletRichTextRunPresentation>) : WalletRichTextBlockPresentation

    @Serializable
    @SerialName("heading")
    data class Heading(val level: Int, val runs: List<WalletRichTextRunPresentation>) : WalletRichTextBlockPresentation {
        init {
            require(level in 1..6) { "wallet_info_heading_level_invalid" }
        }
    }
}

@Serializable
data class WalletRichTextRunPresentation(
    val text: String,
    val bold: Boolean,
    val italic: Boolean,
    val underline: Boolean,
    val externalLink: String?,
)

@Serializable
enum class WalletAttendedAuthorizationMethodPresentation { PASSKEY, BIOMETRIC, PIN }

@Serializable
enum class WalletAttendedAuthorizationStagePresentation { READY, IN_PROGRESS, AUTHORIZED, CANCELLED, FAILED }

@Serializable
data class WalletAuthorizationOperationPresentation(
    val keyRef: String,
    val operationHash: String,
)

@Serializable
data class WalletAttendedAuthorizationPresentation(
    val operationRef: String,
    val challengeRef: String,
    val allowedMethods: List<WalletAttendedAuthorizationMethodPresentation>,
    val defaultMethod: WalletAttendedAuthorizationMethodPresentation,
    val stage: WalletAttendedAuthorizationStagePresentation,
    val reasonKey: String,
    val reasonArguments: Map<String, String>,
    val operations: List<WalletAuthorizationOperationPresentation> = emptyList(),
) {
    init {
        require(operationRef.isNotBlank()) { "wallet_authorization_operation_ref_blank" }
        require(challengeRef.isNotBlank()) { "wallet_authorization_challenge_ref_blank" }
        require(allowedMethods.isNotEmpty() && defaultMethod in allowedMethods) { "wallet_authorization_methods_invalid" }
        requireScreenLocalizationKey("reasonKey", reasonKey)
    }
}

@Serializable
enum class WalletSecureCeremonyPurpose { OPERATION_AUTHORIZATION, FACTOR_ENROLLMENT, DEVICE_ENROLLMENT, TRANSACTION_CODE }

/** Opaque references are deliberately redacted when accidentally interpolated into logs. */
@Serializable
data class WalletSecureCeremonyRef(val value: String) {
    init {
        require(value.isNotBlank()) { "wallet_secure_ceremony_ref_blank" }
    }

    override fun toString(): String = "WalletSecureCeremonyRef([redacted])"
}

@Serializable
data class WalletSecureCeremonyRequest(
    val ceremonyRef: WalletSecureCeremonyRef,
    val purpose: WalletSecureCeremonyPurpose,
    val method: WalletAttendedAuthorizationMethodPresentation,
    val operationRef: String,
    val challengeRef: String,
    val challengeArguments: Map<String, String>,
    val operations: List<WalletAuthorizationOperationPresentation> = emptyList(),
)

@Serializable
sealed interface WalletSecureCeremonyOutcome {
    @Serializable
    @SerialName("authorized")
    data class Authorized(val resultRef: WalletSecureCeremonyRef) : WalletSecureCeremonyOutcome

    @Serializable
    @SerialName("cancelled")
    data object Cancelled : WalletSecureCeremonyOutcome

    @Serializable
    @SerialName("failed")
    data class Failed(val code: String, val messageKey: String) : WalletSecureCeremonyOutcome {
        init {
            require(code.isNotBlank()) { "wallet_secure_ceremony_failure_code_blank" }
            requireScreenLocalizationKey("messageKey", messageKey)
        }
    }
}
