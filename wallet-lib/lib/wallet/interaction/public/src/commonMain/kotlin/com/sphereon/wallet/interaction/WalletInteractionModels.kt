/*
 * Copyright 2026 Sphereon International B.V.
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

package com.sphereon.wallet.interaction

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class WalletInteractionSessionId(
    val value: String,
) {
    init {
        require(value.isNotBlank()) { "wallet_interaction_session_id_blank" }
    }
}

/**
 * The wallet component that is the first semantic interpreter of captured interaction input and
 * owns the complete protocol exchange. Secure-component placement and credential storage are
 * deliberately independent from this decision.
 */
@Serializable
enum class ProtocolExecutionOwner {
    WALLET_APP,
    WALLET_BACKEND,
}

@Serializable
enum class WalletInteractionCaptureSource {
    MOBILE_QR,
    MOBILE_DEEPLINK,
    WEB_UI,
    API,
}

/** Non-secret protocol preferences that a policy-locked captured interaction may carry. */
object CapturedInteractionLaunchAttributes {
    const val OID4VCI_CLIENT_AUTHENTICATION_METHOD: String = "oid4vci.client.authentication.method"
    const val OID4VCI_DPOP_ENABLED: String = "oid4vci.dpop.enabled"
    const val OID4VCI_CREDENTIAL_BATCH_SIZE: String = "oid4vci.credential.batch.size"
    const val OID4VCI_USE_PAR: String = "oid4vci.use.par"
    const val OID4VCI_ENCRYPT_CREDENTIAL_REQUEST: String = "oid4vci.credential.request.encrypt"

    private val names: Set<String> = setOf(
        OID4VCI_CLIENT_AUTHENTICATION_METHOD,
        OID4VCI_DPOP_ENABLED,
        OID4VCI_CREDENTIAL_BATCH_SIZE,
        OID4VCI_USE_PAR,
        OID4VCI_ENCRYPT_CREDENTIAL_REQUEST,
    )
    val maximumAttributes: Int = names.size

    // Keep this list aligned with ClientAuthenticationMethod's serialized protocol values.
    private val clientAuthenticationMethods: Set<String> = setOf(
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt",
        "none",
        "attest_jwt_client_auth",
        "tls_client_auth",
        "self_signed_tls_client_auth",
    )

    fun allows(name: String): Boolean = name in names

    fun isValid(name: String, value: String): Boolean =
        allows(name) && value.isNotBlank() && value.length <= 256 && '\u0000' !in value &&
            when (name) {
                OID4VCI_DPOP_ENABLED,
                OID4VCI_USE_PAR,
                OID4VCI_ENCRYPT_CREDENTIAL_REQUEST ->
                    value.equals("true", ignoreCase = true) || value.equals("false", ignoreCase = true)

                OID4VCI_CREDENTIAL_BATCH_SIZE -> value.toIntOrNull()?.let { it > 0 } == true
                OID4VCI_CLIENT_AUTHENTICATION_METHOD -> value in clientAuthenticationMethods
                else -> false
            }
}

/**
 * Opaque handoff used when protocol ownership is resolved before any parsing or dereferencing.
 * The raw bytes are intentionally separate from [WalletEntryPoint], whose kind is already a
 * semantic classification made by a wallet protocol host.
 */
@Serializable
data class CapturedInteractionInput(
    val source: WalletInteractionCaptureSource,
    val walletProfileRef: String,
    val appRegistrationRef: String,
    val rawPayload: ByteArray,
    val payloadDigest: String,
    val captureBinding: String,
    val expectedPolicyRevision: Long,
    val idempotencyKey: String,
    /** Allowlisted non-secret protocol preferences; identity, key and secret overrides are excluded. */
    val launchAttributes: Map<String, String> = emptyMap(),
) {
    init {
        require(walletProfileRef.isNotBlank()) { "wallet_interaction_profile_ref_blank" }
        require(appRegistrationRef.isNotBlank()) { "wallet_interaction_app_registration_ref_blank" }
        require(rawPayload.isNotEmpty()) { "wallet_interaction_capture_payload_empty" }
        require(payloadDigest.isNotBlank()) { "wallet_interaction_capture_digest_blank" }
        require(captureBinding.isNotBlank()) { "wallet_interaction_capture_binding_blank" }
        require(expectedPolicyRevision > 0) { "wallet_interaction_policy_revision_invalid" }
        require(idempotencyKey.isNotBlank()) { "wallet_interaction_idempotency_key_blank" }
        require(launchAttributes.size <= CapturedInteractionLaunchAttributes.maximumAttributes) {
            "wallet_interaction_capture_launch_attributes_too_many"
        }
        require(launchAttributes.keys.all(CapturedInteractionLaunchAttributes::allows)) {
            "wallet_interaction_capture_launch_attribute_not_allowed"
        }
        require(launchAttributes.all { (name, value) -> CapturedInteractionLaunchAttributes.isValid(name, value) }) {
            "wallet_interaction_capture_launch_attribute_invalid"
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CapturedInteractionInput) return false
        return source == other.source &&
            walletProfileRef == other.walletProfileRef &&
            appRegistrationRef == other.appRegistrationRef &&
            rawPayload.contentEquals(other.rawPayload) &&
            payloadDigest == other.payloadDigest &&
            captureBinding == other.captureBinding &&
            expectedPolicyRevision == other.expectedPolicyRevision &&
            idempotencyKey == other.idempotencyKey &&
            launchAttributes == other.launchAttributes
    }

    override fun hashCode(): Int {
        var result = source.hashCode()
        result = 31 * result + walletProfileRef.hashCode()
        result = 31 * result + appRegistrationRef.hashCode()
        result = 31 * result + rawPayload.contentHashCode()
        result = 31 * result + payloadDigest.hashCode()
        result = 31 * result + captureBinding.hashCode()
        result = 31 * result + expectedPolicyRevision.hashCode()
        result = 31 * result + idempotencyKey.hashCode()
        result = 31 * result + launchAttributes.hashCode()
        return result
    }
}

/**
 * Policy result created without interpreting captured protocol bytes. The owner and policy
 * revision are immutable inputs to the later semantic interaction.
 */
@Serializable
data class LockedCapturedInteractionRuntimePlan(
    val walletUnitId: String,
    val executionOwner: ProtocolExecutionOwner,
    val policyRevision: Long,
    val permittedFlowKinds: Set<WalletInteractionFlowKind>,
    val providerRefs: Set<String>,
    val evidence: Map<String, String> = emptyMap(),
) {
    init {
        require(walletUnitId.isNotBlank()) { "wallet_interaction_locked_unit_id_blank" }
        require(policyRevision > 0) { "wallet_interaction_locked_policy_revision_invalid" }
        require(permittedFlowKinds.isNotEmpty()) { "wallet_interaction_locked_flow_kinds_empty" }
        require(providerRefs.isNotEmpty() && providerRefs.none(String::isBlank)) {
            "wallet_interaction_locked_provider_refs_empty"
        }
    }
}

@Serializable
enum class WalletInteractionFlowKind {
    CredentialReceive,
    CredentialPresent,
    AttendedPresent,
}

@Serializable
enum class WalletProtocol {
    OID4VCI,
    OID4VP,
    ISO18013,
    CUSTOM,
}

@Serializable
enum class WalletEntryPointKind {
    RAW_QR,
    DEEP_LINK,
    UNIVERSAL_LINK,
    HTTPS_LINK,
    NFC_HANDOVER,
    BLE_HANDOVER,
    WIFI_AWARE_HANDOVER,
    PARSED_OBJECT,
}

@Serializable
data class WalletInteractionInput(
    val walletUnitId: String,
    val entryPoint: WalletEntryPoint,
    val executionOwner: ProtocolExecutionOwner = ProtocolExecutionOwner.WALLET_APP,
    val requestedFlowKinds: List<WalletInteractionFlowKind> = emptyList(),
    val metadata: Map<String, String> = emptyMap(),
    /** Claimed local process context; only a host launch authority can admit it. */
    val processBinding: WalletInteractionProcessBinding? = null,
) {
    init {
        require(walletUnitId.isNotBlank()) { "wallet_interaction_wallet_unit_id_blank" }
    }
}

@Serializable
data class WalletEntryPoint(
    val kind: WalletEntryPointKind,
    val raw: String? = null,
    val bytes: ByteArray? = null,
    val parsedType: String? = null,
    val parsed: JsonElement? = null,
    val source: String? = null,
) {
    fun summary(): WalletEntryPointSummary =
        WalletEntryPointSummary(
            kind = kind,
            source = source,
            scheme = raw?.substringBefore(":", missingDelimiterValue = "")?.takeIf { it.isNotBlank() },
            fingerprint = stableFingerprint(raw ?: bytes?.decodeToString() ?: parsed?.toString() ?: parsedType.orEmpty()),
        )

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is WalletEntryPoint) return false
        return kind == other.kind &&
            raw == other.raw &&
            bytes.contentEquals(other.bytes) &&
            parsedType == other.parsedType &&
            parsed == other.parsed &&
            source == other.source
    }

    override fun hashCode(): Int {
        var result = kind.hashCode()
        result = 31 * result + (raw?.hashCode() ?: 0)
        result = 31 * result + (bytes?.contentHashCode() ?: 0)
        result = 31 * result + (parsedType?.hashCode() ?: 0)
        result = 31 * result + (parsed?.hashCode() ?: 0)
        result = 31 * result + (source?.hashCode() ?: 0)
        return result
    }

    companion object {
        fun rawQr(
            contents: String,
            source: String? = null
        ): WalletEntryPoint = WalletEntryPoint(kind = WalletEntryPointKind.RAW_QR, raw = contents, source = source)

        fun link(
            uri: String,
            source: String? = null
        ): WalletEntryPoint {
            val kind =
                when {
                    uri.startsWith("https://", ignoreCase = true) -> WalletEntryPointKind.HTTPS_LINK
                    uri.startsWith("http://", ignoreCase = true) -> WalletEntryPointKind.HTTPS_LINK
                    else -> WalletEntryPointKind.DEEP_LINK
                }
            return WalletEntryPoint(kind = kind, raw = uri, source = source)
        }

        fun nfc(
            payload: ByteArray,
            source: String? = null
        ): WalletEntryPoint = WalletEntryPoint(kind = WalletEntryPointKind.NFC_HANDOVER, bytes = payload, source = source)

        fun ble(
            payload: ByteArray,
            source: String? = null
        ): WalletEntryPoint = WalletEntryPoint(kind = WalletEntryPointKind.BLE_HANDOVER, bytes = payload, source = source)

        fun wifiAware(
            payload: ByteArray,
            source: String? = null
        ): WalletEntryPoint = WalletEntryPoint(kind = WalletEntryPointKind.WIFI_AWARE_HANDOVER, bytes = payload, source = source)

        fun parsed(
            type: String,
            value: JsonElement,
            source: String? = null
        ): WalletEntryPoint = WalletEntryPoint(kind = WalletEntryPointKind.PARSED_OBJECT, parsedType = type, parsed = value, source = source)
    }
}

@Serializable
data class WalletEntryPointSummary(
    val kind: WalletEntryPointKind,
    val source: String? = null,
    val scheme: String? = null,
    val fingerprint: String? = null,
)

@Serializable
data class WalletInteractionSession(
    val sessionId: WalletInteractionSessionId,
    val state: WalletInteractionState,
)

@Serializable
enum class WalletInteractionStatus {
    ResolvingEntryPoint,
    ImplementationChoiceRequired,
    UnsupportedEntryPoint,
    CounterpartyNotice,
    TrustReview,
    CredentialOfferReview,
    AuthorizationRequired,
    TxCodeRequired,
    CredentialPreview,
    CredentialSelection,
    DisclosureConsent,
    SecurityUnlockRequired,
    DeferredRetrievalPending,
    Sharing,
    Completed,
    Cancelled,
    Failed,
}

/** Nonsecret transport of the opaque completion value; the value remains private. */
@Serializable
enum class WalletInteractionCompletionTransport { BROWSER_REDIRECT, DIGITAL_CREDENTIALS_API }

@Serializable
data class WalletInteractionState(
    val sessionId: WalletInteractionSessionId,
    val walletUnitId: String,
    val status: WalletInteractionStatus,
    /** Locked before semantic interpretation and immutable for the lifetime of the interaction. */
    val executionOwner: ProtocolExecutionOwner = ProtocolExecutionOwner.WALLET_APP,
    val revision: Long = 0,
    val flowKind: WalletInteractionFlowKind? = null,
    val activity: WalletInteractionActivitySummary? = null,
    val protocol: WalletProtocol? = null,
    val adapterId: String? = null,
    val entryPoint: WalletEntryPointSummary? = null,
    val implementationChoices: List<WalletImplementationChoice> = emptyList(),
    val counterparty: WalletCounterpartySummary? = null,
    val counterpartyEncounter: WalletCounterpartyEncounterResult? = null,
    val trust: WalletCounterpartyTrustSummary? = null,
    /** Issuer-bound authentication result retained through the session for receive-time checks. */
    val issuerAuthentication: WalletIssuerAuthenticationResult? = null,
    val credentialOffer: WalletCredentialOfferSummary? = null,
    val selectedCredentialConfigurationIds: List<String> = emptyList(),
    val credentialPreview: List<WalletCredentialPreview> = emptyList(),
    /** Credentials actually returned and accepted during this interaction; never offer previews. */
    val receivedCredentialPreview: List<WalletCredentialPreview> = emptyList(),
    val credentialSelection: WalletCredentialSelectionRequest? = null,
    val disclosure: WalletDisclosureSummary? = null,
    val securityChallenge: WalletSecurityChallenge? = null,
    val authorizationHandoffRef: WalletInteractionSensitiveInputRef? = null,
    /** Optional post-completion user-agent handoff, kept opaque outside the private session store. */
    val completionHandoffRef: WalletInteractionSensitiveInputRef? = null,
    val completionHandoffTransport: WalletInteractionCompletionTransport? = null,
    val txCode: WalletTxCodeSpec? = null,
    val deferred: WalletDeferredRetrievalSummary? = null,
    val message: WalletDisplayMessage? = null,
    val error: WalletInteractionError? = null,
    val terminal: Boolean = false,
) {
    init {
        require(walletUnitId.isNotBlank()) { "wallet_interaction_wallet_unit_id_blank" }
    }

    fun next(
        status: WalletInteractionStatus = this.status,
        revision: Long = this.revision + 1,
        terminal: Boolean = false,
        message: WalletDisplayMessage? = this.message,
        error: WalletInteractionError? = null,
    ): WalletInteractionState = copy(status = status, revision = revision, terminal = terminal, message = message, error = error)

    companion object {
        fun resolving(
            sessionId: WalletInteractionSessionId,
            input: WalletInteractionInput,
        ): WalletInteractionState =
            WalletInteractionState(
                sessionId = sessionId,
                walletUnitId = input.walletUnitId,
                status = WalletInteractionStatus.ResolvingEntryPoint,
                executionOwner = input.executionOwner,
                entryPoint = input.entryPoint.summary(),
            )
    }
}

@Serializable
data class WalletInteractionActivitySummary(
    val type: WalletInteractionActivityType,
    val counterparty: WalletCounterpartySummary? = null,
    val metadata: Map<String, String> = emptyMap(),
    val authorizationDecision: WalletAuthorizationDecisionProjection? = null,
)

@Serializable
enum class WalletInteractionActivityType {
    CREDENTIAL_RECEIVE,
    CREDENTIAL_PRESENTATION,
    LOGIN,
    ATTENDED_PRESENTATION,
}

@Serializable
data class WalletDisplayMessage(
    val titleKey: String? = null,
    val textKey: String? = null,
    val arguments: Map<String, String> = emptyMap(),
) {
    init {
        requireWalletInteractionLocalizationKey("titleKey", titleKey)
        requireWalletInteractionLocalizationKey("textKey", textKey)
    }
}

/**
 * What can still be done with a failed interaction. Three genuinely different outcomes that a
 * boolean cannot express.
 *
 * [TERMINAL] means the exchange is over and the captured input is spent: offers, pre-authorized
 * codes and nonces are single-use, so re-uploading the same input would fail again for a new
 * reason. [REPEATABLE] means the failure was incidental to the exchange, a transport error or an
 * upstream timeout, and uploading the SAME captured input again is expected to work. [RESUMABLE]
 * means the interaction itself survived and can be picked up where it stopped, without re-uploading
 * anything. Consumers that do not recognise a value must treat it as [TERMINAL].
 *
 * [WalletInteractionState.terminal] and [TERMINAL] answer different questions (machine left live
 * statuses vs captured input is spent).
 */
@Serializable
enum class WalletFailureDisposition {
    TERMINAL,
    REPEATABLE,
    RESUMABLE,
}

@Serializable
data class WalletInteractionError(
    val code: String,
    val disposition: WalletFailureDisposition = WalletFailureDisposition.TERMINAL,
    val message: String? = null,
    val messageKey: String? = null,
    val arguments: Map<String, String> = emptyMap(),
) {
    init {
        require(code.isNotBlank()) { "wallet_interaction_error_code_blank" }
        requireWalletInteractionLocalizationKey("messageKey", messageKey)
    }
}

@Serializable
data class WalletImplementationChoice(
    val adapterId: String,
    val protocol: WalletProtocol,
    val flowKinds: List<WalletInteractionFlowKind>,
    val labelKey: String,
    val arguments: Map<String, String> = emptyMap(),
) {
    init {
        require(adapterId.isNotBlank()) { "wallet_interaction_adapter_id_blank" }
        requireWalletInteractionLocalizationKey("labelKey", labelKey)
    }
}

@Serializable
enum class WalletAttributeSourceKind {
    SELF_ASSERTED,
    SUPERIOR_ATTESTED,
    SUPERIOR_POLICY_PINNED,
    ACCESS_CERTIFICATE,
    REGISTRAR_REGISTERED,
    QUALIFIED_SUPERVISED,
}

/**
 * Provenance of one displayed fact. Non-[SELF_ASSERTED][WalletAttributeSourceKind.SELF_ASSERTED]
 * kinds require a named [authority]; an attested fact with no attester cannot be constructed.
 */
@Serializable
data class WalletAttributeSource(
    val kind: WalletAttributeSourceKind,
    val authority: String? = null,
    val authorityIdentifier: String? = null,
) {
    init {
        if (kind != WalletAttributeSourceKind.SELF_ASSERTED) {
            require(!authority.isNullOrBlank()) { "wallet_attribute_source_authority_required" }
        }
    }
}

@Serializable
data class WalletAttributedString(
    val value: String,
    val source: WalletAttributeSource,
)

@Serializable
data class WalletCounterpartyDetail(
    val legalName: WalletAttributedString? = null,
    val registeredAddress: WalletAttributedString? = null,
    val registrationNumber: WalletAttributedString? = null,
    val contactEmail: WalletAttributedString? = null,
    val contactPhone: WalletAttributedString? = null,
    val websiteUri: WalletAttributedString? = null,
    val privacyPolicyUri: WalletAttributedString? = null,
    val jurisdiction: WalletAttributedString? = null,
) {
    fun isBlank(): Boolean =
        legalName == null &&
            registeredAddress == null &&
            registrationNumber == null &&
            contactEmail == null &&
            contactPhone == null &&
            websiteUri == null &&
            privacyPolicyUri == null &&
            jurisdiction == null
}

/** Display-metadata name is the party's own claim. Blank or absent is not a source. */
fun selfAssertedDisplayNameSource(metadataName: String?): WalletAttributeSource? =
    metadataName?.takeUnless { it.isBlank() }?.let {
        WalletAttributeSource(kind = WalletAttributeSourceKind.SELF_ASSERTED)
    }

private val selfAssertedAttributeSource = WalletAttributeSource(kind = WalletAttributeSourceKind.SELF_ASSERTED)

fun selfAssertedAttributed(value: String?): WalletAttributedString? =
    value?.takeUnless { it.isBlank() }?.let { WalletAttributedString(value = it, source = selfAssertedAttributeSource) }

/**
 * One localised string, in the ETSI TS 119 602 JSON binding this codebase already uses for
 * trust-list content. Registered purposes are multilingual because the registrant must provide them
 * for every official language of the Member States the intended use is offered in; a wallet picks
 * the holder's language and never invents a translation.
 */
@Serializable
data class WalletMultiLangString(
    val lang: String,
    val value: String,
) {
    init {
        require(lang.isNotBlank()) { "wallet_multi_lang_string_lang_blank" }
        require(value.isNotBlank()) { "wallet_multi_lang_string_value_blank" }
    }
}

/** The purpose in [lang], or null when the registrar recorded no localisation for it. */
fun List<WalletMultiLangString>.forLang(lang: String): String? = firstOrNull { it.lang.equals(lang, ignoreCase = true) }?.value

/**
 * A relying party's registered intended use, as a registrar recorded it.
 *
 * Modelled on the IntendedUse class of the Commission's TS5, Common Formats and API for Relying
 * Party Registration Information: a registrar-assigned identifier together with one or more purposes
 * of the intended data processing under Article 5(1)(b), each localised. The certificate profiles
 * that carry it are ETSI TS 119 475 for relying party registration certificates and ETSI TS 119
 * 411-8 for access certificates; OpenID Federation entity metadata may carry it instead where that
 * is the trust mechanism in play.
 *
 * Registered is the whole point. A registrar has checked that this party may ask for these
 * attributes for this purpose, which is a different assurance from a sentence the verifier put in
 * its own request. OpenID4VP carries no purpose of its own, and nothing self-asserted may be
 * presented here, so [source] is
 * [ACCESS_CERTIFICATE][WalletAttributeSourceKind.ACCESS_CERTIFICATE] or
 * [REGISTRAR_REGISTERED][WalletAttributeSourceKind.REGISTRAR_REGISTERED] and the naming authority is
 * therefore always present.
 */
@Serializable
data class WalletRegisteredPurpose(
    /**
     * The registrar's unique identifier for this registered intended use. Stable across
     * presentations, so a holder and an auditor can recognise the same intended use again.
     */
    val intendedUseIdentifier: String,
    /** One or more purposes of the intended data processing, localised. */
    val purpose: List<WalletMultiLangString>,
    /** Which certificate or registry this came from, and the authority behind it. */
    val source: WalletAttributeSource,
) {
    init {
        require(intendedUseIdentifier.isNotBlank()) { "wallet_registered_purpose_intended_use_identifier_blank" }
        require(purpose.isNotEmpty()) { "wallet_registered_purpose_empty" }
        require(source.kind in registeredPurposeSourceKinds) { "wallet_registered_purpose_source_kind_invalid" }
    }
}

private val registeredPurposeSourceKinds =
    setOf(
        WalletAttributeSourceKind.ACCESS_CERTIFICATE,
        WalletAttributeSourceKind.REGISTRAR_REGISTERED,
    )

/**
 * RFC 7591 / OIDC Registration fields still present on raw `client_metadata` JSON.
 * Typed OID4VP ClientMetadata drops them; this projection does not promote `client_name`
 * into [WalletCounterpartyDetail.legalName].
 */
fun counterpartyDetailFromDcrMetadata(clientMetadata: JsonElement?): WalletCounterpartyDetail? {
    val obj = clientMetadata.asJsonObjectOrNull() ?: return null
    val contactEmail =
        obj["contacts"]
            ?.let { it as? JsonArray }
            ?.mapNotNull { (it as? JsonPrimitive)?.contentOrNull?.trim()?.takeUnless(String::isBlank) }
            ?.firstOrNull { contact -> contact.contains('@') && ' ' !in contact }
    val detail =
        WalletCounterpartyDetail(
            contactEmail = selfAssertedAttributed(contactEmail),
            websiteUri = selfAssertedAttributed(obj.stringField("client_uri")),
            privacyPolicyUri = selfAssertedAttributed(obj.stringField("policy_uri")),
        )
    return detail.takeUnless { it.isBlank() }
}

fun WalletCounterpartySummary.emittedAttributeSources(): List<WalletAttributeSource> =
    buildList {
        displayNameSource?.let(::add)
        detail?.legalName?.source?.let(::add)
        detail?.registeredAddress?.source?.let(::add)
        detail?.registrationNumber?.source?.let(::add)
        detail?.contactEmail?.source?.let(::add)
        detail?.contactPhone?.source?.let(::add)
        detail?.websiteUri?.source?.let(::add)
        detail?.privacyPolicyUri?.source?.let(::add)
        detail?.jurisdiction?.source?.let(::add)
    }

private fun JsonElement?.asJsonObjectOrNull(): JsonObject? =
    when (this) {
        is JsonObject -> this
        is JsonPrimitive ->
            contentOrNull?.trim()?.takeUnless { it.isBlank() }?.let { raw ->
                runCatching { Json.parseToJsonElement(raw) as? JsonObject }.getOrNull()
            }
        else -> null
    }

private fun JsonObject.stringField(name: String): String? = (this[name] as? JsonPrimitive)?.contentOrNull?.trim()?.takeUnless { it.isBlank() }

@Serializable
data class WalletCounterpartySummary(
    val role: WalletCounterpartyRole,
    val identifier: String,
    val displayName: String? = null,
    val logoUri: String? = null,
    /** Complete protocol-supplied display metadata. [displayName]/[logoUri] are the resolved active-locale face. */
    val localizedBranding: List<WalletCounterpartyLocalizedBranding> = emptyList(),
    val metadata: Map<String, String> = emptyMap(),
    /** Stable Party identifier assigned by the wallet Party registry after resolution. */
    val partyId: String? = null,
    /** Who stands behind [displayName]. Absent when displayName is the identifier fallback or unset. */
    val displayNameSource: WalletAttributeSource? = null,
    /** Expandable attributed facts. Absence is the common case. */
    val detail: WalletCounterpartyDetail? = null,
) {
    init {
        require(identifier.isNotBlank()) { "wallet_counterparty_identifier_blank" }
        require(partyId == null || partyId.isNotBlank()) { "wallet_counterparty_party_id_blank" }
    }
}

/** Provider-neutral localized issuer/RP branding retained with the wallet Party contact. */
@Serializable
data class WalletCounterpartyLocalizedBranding(
    val locale: String? = null,
    val name: String,
    val logoUri: String? = null,
    val logoAltText: String? = null,
    val description: String? = null,
    val backgroundImageUri: String? = null,
    val backgroundColor: String? = null,
    val textColor: String? = null,
) {
    init {
        require(name.isNotBlank()) { "wallet_counterparty_branding_name_blank" }
        require(locale == null || locale.isNotBlank()) { "wallet_counterparty_branding_locale_blank" }
    }
}

@Serializable
enum class WalletCounterpartyRole {
    ISSUER,
    VERIFIER,
    MDOC_READER,
}

@Serializable
data class WalletCredentialOfferSummary(
    val issuer: WalletCounterpartySummary,
    val credentialConfigurationIds: List<String>,
    val preAuthorizedCodeAvailable: Boolean = false,
    val authorizationCodeAvailable: Boolean = false,
    val txCodeRequired: Boolean = false,
    val branding: List<WalletCredentialBranding> = emptyList(),
)

@Serializable
data class WalletCredentialBranding(
    val credentialConfigurationId: String,
    val name: String? = null,
    val locale: String? = null,
    val description: String? = null,
    val logoUri: String? = null,
    val backgroundImageUri: String? = null,
    val backgroundColor: String? = null,
    val textColor: String? = null,
    /** Pre-issuance display names only. Credential values never belong in an offer summary. */
    val info: List<WalletCredentialOfferInfoDescriptor> = emptyList(),
)

@Serializable
data class WalletCredentialOfferInfoDescriptor(
    val path: List<String>,
    /** The issuer's first display name, or the last path segment when it gave none. */
    val displayName: String,
    /**
     * Every display name the issuer gave, keyed by its BCP 47 locale. The renderer picks the entry
     * for the holder's language; the engine carries no locale of its own.
     */
    val localizedDisplayNames: Map<String, String> = emptyMap(),
) {
    init {
        require(path.isNotEmpty() && path.none(String::isBlank)) { "wallet_credential_offer_info_path_invalid" }
        require(displayName.isNotBlank()) { "wallet_credential_offer_info_name_blank" }
    }
}

@Serializable
data class WalletTxCodeSpec(
    val inputMode: String? = null,
    val length: Int? = null,
    val descriptionKey: String? = null,
    val arguments: Map<String, String> = emptyMap(),
    /** The issuer rejected the last code submitted for this offer; the holder may try again. */
    val rejected: Boolean = false,
    /** The issuer rejected two or more codes in a row; the offer may have expired. */
    val possiblyExpired: Boolean = false,
) {
    init {
        requireWalletInteractionLocalizationKey("descriptionKey", descriptionKey)
    }
}

@Serializable
data class WalletCredentialPreview(
    val id: String,
    val name: String? = null,
    val format: String? = null,
    val issuer: WalletCounterpartySummary? = null,
    val claims: List<WalletClaimDescriptor> = emptyList(),
    /** Domain-resolved face from the accepted credential record, not renderer fallback data. */
    val branding: WalletCredentialBranding? = null,
)

@Serializable
data class WalletCredentialSelectionRequest(
    val requirements: List<WalletCredentialRequirement>,
    val satisfiable: Boolean,
    /**
     * The registered intended use the request as a whole is made under, when one covers every
     * requirement in it. Null otherwise; see [WalletCredentialRequirement.purpose].
     */
    val purpose: WalletRegisteredPurpose? = null,
    val credentialSets: List<WalletCredentialSetRequirement> = emptyList(),
)

@Serializable
data class WalletRequestedClaim(
    val path: List<JsonElement>,
    val label: String? = null,
    val description: String? = null,
)

@Serializable
data class WalletCandidateDisclosure(
    val credentialId: String,
    val disclosedClaims: List<WalletRequestedClaim> = emptyList(),
    val satisfiesFully: Boolean = true,
)

@Serializable
data class WalletCredentialRequirement(
    val id: String,
    val format: String? = null,
    val multipleAllowed: Boolean = false,
    val requiredClaimPaths: List<List<JsonElement>> = emptyList(),
    val candidateCredentialIds: List<String> = emptyList(),
    /** Parallel labelled form of [requiredClaimPaths]. Empty means that form was not produced. */
    val requestedClaims: List<WalletRequestedClaim> = emptyList(),
    /**
     * The registered intended use this requirement is asked under. One relying party may register
     * several, each with its own attribute set, which is why this sits per requirement as well as on
     * the request. Null when the relying party's certificate registers none for it, and a wallet
     * must not present a missing purpose as an empty or assumed one.
     */
    val purpose: WalletRegisteredPurpose? = null,
    /** Per-candidate cost, keyed to [candidateCredentialIds]. Empty means cost was not computed. */
    val candidateDisclosures: List<WalletCandidateDisclosure> = emptyList(),
)

@Serializable
data class WalletCredentialSetRequirement(
    val id: String,
    val required: Boolean,
    val options: List<WalletCredentialSetOption>,
)

@Serializable
data class WalletCredentialSetOption(
    val requirementIds: List<String>,
    val satisfiable: Boolean,
)

@Serializable
data class WalletCredentialSelection(
    val selectedCredentialIdsByRequirement: Map<String, List<String>>,
)

@Serializable
data class WalletDisclosureSummary(
    val verifier: WalletCounterpartySummary? = null,
    val requestedClaims: List<WalletClaimDescriptor> = emptyList(),
    val selectedCredentialIds: List<String> = emptyList(),
    val claimValuesRevealed: Boolean = false,
)

@Serializable
data class WalletClaimDescriptor(
    val path: List<JsonElement>,
    val labelKey: String? = null,
    val intentToRetain: Boolean? = null,
    val valueAvailable: Boolean = false,
) {
    init {
        requireWalletInteractionLocalizationKey("labelKey", labelKey)
    }
}

@Serializable
data class WalletDeferredRetrievalSummary(
    val intervalSeconds: Int? = null,
    val attempt: Int? = null,
    val resumable: Boolean = true,
)

@Serializable
data class WalletSecurityChallenge(
    val challengeId: String,
    val kind: WalletSecurityChallengeKind,
    val reasonKey: String,
    val arguments: Map<String, String> = emptyMap(),
    val requiredAssurance: WalletSecurityAssurance = WalletSecurityAssurance.USER_PRESENT,
    /**
     * Every holder-key signature this approval authorizes, in signing order. Empty for an approval
     * of a single operation, which the [arguments] describe.
     */
    val operations: List<WalletApprovalOperation> = emptyList(),
) {
    init {
        require(challengeId.isNotBlank()) { "wallet_interaction_security_challenge_id_blank" }
        requireWalletInteractionLocalizationKey("reasonKey", reasonKey)
    }
}

@Serializable
enum class WalletSecurityChallengeKind {
    PASSKEY,
    PIN,
    BIOMETRIC,
    LOCAL_HSM_UNLOCK,
    LOCAL_TEE_UNLOCK,
    REMOTE_HSM_UNLOCK,
    REMOTE_KEY_AUTHORIZATION,
    WALLET_UNIT_POLICY,
}

@Serializable
data class WalletSecurityGrant(
    val grantId: String,
    val assurance: WalletSecurityAssurance,
    val expiresAtEpochSeconds: Long? = null,
    val evidence: Map<String, String> = emptyMap(),
)

/**
 * One holder-key signature a holder approves: the key that signs and the hash of the exact bytes it
 * signs.
 *
 * A holder approves an interaction on a wallet unit once. That approval lists every holder-key
 * signature of the interaction on that unit, for instance one proof per credential received, so
 * the holder authenticates once however many credentials are received or presented.
 */
@Serializable
data class WalletApprovalOperation(
    val keyRef: String,
    val operationHash: String,
) {
    init {
        require(keyRef.isNotBlank()) { "wallet_interaction_approval_operation_key_ref_blank" }
        require(operationHash.isNotBlank()) { "wallet_interaction_approval_operation_hash_blank" }
    }
}

object WalletApprovalOperations {
    /** Grant evidence entry that carries the approved operations of a listed approval. */
    const val EVIDENCE_KEY: String = "approval_operations"

    private val json = Json { ignoreUnknownKeys = false }

    fun encode(operations: List<WalletApprovalOperation>): String =
        json.encodeToString(kotlinx.serialization.builtins.ListSerializer(WalletApprovalOperation.serializer()), operations)

    /** The approved operations of [evidence], or null when it is not a listed approval or is malformed. */
    fun decode(evidence: Map<String, String>): List<WalletApprovalOperation>? =
        evidence[EVIDENCE_KEY]?.let { encoded ->
            runCatching {
                json.decodeFromString(kotlinx.serialization.builtins.ListSerializer(WalletApprovalOperation.serializer()), encoded)
            }.getOrNull()?.takeIf { it.isNotEmpty() }
        }
}

/** Typed result for one-time attended grant validation at the protocol boundary. */
sealed interface WalletSecurityGrantValidation {
    data object Valid : WalletSecurityGrantValidation

    data class Invalid(val reasonKey: String) : WalletSecurityGrantValidation
}

/**
 * Validates the consumed grant against the exact outstanding challenge before protocol state can
 * advance. Consumption provides one-time use; this function adds challenge, expiry, assurance,
 * Wallet Unit, audience and operation binding checks.
 */
fun WalletSecurityGrant.validateFor(
    challenge: WalletSecurityChallenge?,
    walletUnitId: String,
    audience: String?,
    nowEpochSeconds: Long,
): WalletSecurityGrantValidation {
    challenge ?: return WalletSecurityGrantValidation.Invalid("wallet.interaction.security.challenge_missing")
    if (grantId != challenge.challengeId || evidence["challenge_id"] != challenge.challengeId) {
        return WalletSecurityGrantValidation.Invalid("wallet.interaction.security.challenge_binding_invalid")
    }
    val expiry = expiresAtEpochSeconds
        ?: return WalletSecurityGrantValidation.Invalid("wallet.interaction.security.grant_expiry_missing")
    if (expiry <= nowEpochSeconds) return WalletSecurityGrantValidation.Invalid("wallet.interaction.security.grant_expired")
    if (!assurance.satisfies(challenge.requiredAssurance)) {
        return WalletSecurityGrantValidation.Invalid("wallet.interaction.security.grant_assurance_insufficient")
    }
    challenge.arguments["wallet_unit_id"]?.let { expected ->
        if (expected != walletUnitId || evidence["wallet_unit_id"] != expected) {
            return WalletSecurityGrantValidation.Invalid("wallet.interaction.security.grant_wallet_unit_invalid")
        }
    }
    challenge.arguments["audience"]?.let { expected ->
        if (expected != audience || evidence["audience"] != expected) {
            return WalletSecurityGrantValidation.Invalid("wallet.interaction.security.grant_audience_invalid")
        }
    }
    challenge.arguments["operation_binding"]?.let { expected ->
        if (evidence["operation_binding"] != expected) {
            return WalletSecurityGrantValidation.Invalid("wallet.interaction.security.grant_operation_binding_invalid")
        }
    }
    return WalletSecurityGrantValidation.Valid
}

private fun WalletSecurityAssurance.satisfies(required: WalletSecurityAssurance): Boolean =
    when (required) {
        WalletSecurityAssurance.NONE -> true
        WalletSecurityAssurance.USER_PRESENT -> this != WalletSecurityAssurance.NONE
        WalletSecurityAssurance.PASSKEY -> this == WalletSecurityAssurance.PASSKEY
        WalletSecurityAssurance.PIN -> this == WalletSecurityAssurance.PASSKEY || this == WalletSecurityAssurance.PIN || this == WalletSecurityAssurance.BIOMETRIC
        WalletSecurityAssurance.BIOMETRIC -> this == WalletSecurityAssurance.PASSKEY || this == WalletSecurityAssurance.BIOMETRIC
        WalletSecurityAssurance.HARDWARE_BACKED -> this == WalletSecurityAssurance.HARDWARE_BACKED || this == WalletSecurityAssurance.REMOTE_AUTHORIZED
        WalletSecurityAssurance.REMOTE_AUTHORIZED -> this == WalletSecurityAssurance.REMOTE_AUTHORIZED
    }

@Serializable
enum class WalletSecurityAssurance {
    NONE,
    USER_PRESENT,
    PASSKEY,
    PIN,
    BIOMETRIC,
    HARDWARE_BACKED,
    REMOTE_AUTHORIZED,
}

@Serializable
data class WalletInteractionAction(
    val type: WalletInteractionActionType,
    val implementationId: String? = null,
    val selection: WalletCredentialSelection? = null,
    val sensitiveInputRef: WalletInteractionSensitiveInputRef? = null,
    val rememberDecision: Boolean = false,
    val counterpartyAssociation: WalletCounterpartyAssociationDecision? = null,
) {
    init {
        when (type) {
            WalletInteractionActionType.SUBMIT_TX_CODE -> {
                require(sensitiveInputRef != null) { "wallet_interaction_action_tx_code_ref_missing" }
            }

            WalletInteractionActionType.AUTH_CALLBACK -> {
                require(sensitiveInputRef != null) { "wallet_interaction_action_auth_callback_ref_missing" }
            }

            WalletInteractionActionType.CHOOSE_IMPLEMENTATION -> {
                require(!implementationId.isNullOrBlank()) { "wallet_interaction_action_implementation_id_missing" }
            }

            WalletInteractionActionType.SELECT_CREDENTIALS -> {
                require(selection != null) { "wallet_interaction_action_selection_missing" }
            }

            WalletInteractionActionType.APPROVE_SECURITY_CHALLENGE -> {
                require(sensitiveInputRef != null) { "wallet_interaction_action_security_grant_ref_missing" }
            }

            WalletInteractionActionType.RESOLVE_COUNTERPARTY_CONTACT -> {
                require(counterpartyAssociation != null) { "wallet_interaction_action_counterparty_association_missing" }
            }

            else -> {
                Unit
            }
        }
    }

    companion object {
        fun continueFlow(): WalletInteractionAction = WalletInteractionAction(WalletInteractionActionType.CONTINUE)

        fun resolveCounterpartyContact(decision: WalletCounterpartyAssociationDecision): WalletInteractionAction =
            WalletInteractionAction(WalletInteractionActionType.RESOLVE_COUNTERPARTY_CONTACT, counterpartyAssociation = decision)

        fun decline(): WalletInteractionAction = WalletInteractionAction(WalletInteractionActionType.DECLINE)

        fun submitTxCode(ref: WalletInteractionSensitiveInputRef): WalletInteractionAction =
            WalletInteractionAction(WalletInteractionActionType.SUBMIT_TX_CODE, sensitiveInputRef = ref)

        fun authCallback(ref: WalletInteractionSensitiveInputRef): WalletInteractionAction =
            WalletInteractionAction(WalletInteractionActionType.AUTH_CALLBACK, sensitiveInputRef = ref)

        fun chooseImplementation(adapterId: String): WalletInteractionAction = WalletInteractionAction(WalletInteractionActionType.CHOOSE_IMPLEMENTATION, implementationId = adapterId)

        fun selectCredentials(selection: WalletCredentialSelection): WalletInteractionAction = WalletInteractionAction(WalletInteractionActionType.SELECT_CREDENTIALS, selection = selection)

        fun revealClaimValues(): WalletInteractionAction = WalletInteractionAction(WalletInteractionActionType.REVEAL_CLAIM_VALUES)

        fun approveSecurityChallenge(ref: WalletInteractionSensitiveInputRef): WalletInteractionAction =
            WalletInteractionAction(WalletInteractionActionType.APPROVE_SECURITY_CHALLENGE, sensitiveInputRef = ref)

        fun retryDeferredRetrieval(): WalletInteractionAction = WalletInteractionAction(WalletInteractionActionType.RETRY_DEFERRED_RETRIEVAL)

        fun resumeDeferredRetrieval(): WalletInteractionAction = WalletInteractionAction(WalletInteractionActionType.RESUME_DEFERRED_RETRIEVAL)

        fun cancel(): WalletInteractionAction = WalletInteractionAction(WalletInteractionActionType.CANCEL)
    }
}

@Serializable
enum class WalletInteractionActionType {
    @SerialName("resolve_counterparty_contact")
    RESOLVE_COUNTERPARTY_CONTACT,

    @SerialName("continue")
    CONTINUE,

    @SerialName("decline")
    DECLINE,

    @SerialName("submit_tx_code")
    SUBMIT_TX_CODE,

    @SerialName("auth_callback")
    AUTH_CALLBACK,

    @SerialName("choose_implementation")
    CHOOSE_IMPLEMENTATION,

    @SerialName("select_credentials")
    SELECT_CREDENTIALS,

    @SerialName("reveal_claim_values")
    REVEAL_CLAIM_VALUES,

    @SerialName("approve_security_challenge")
    APPROVE_SECURITY_CHALLENGE,

    @SerialName("retry_deferred_retrieval")
    RETRY_DEFERRED_RETRIEVAL,

    @SerialName("resume_deferred_retrieval")
    RESUME_DEFERRED_RETRIEVAL,

    @SerialName("cancel")
    CANCEL,
}

private fun stableFingerprint(value: String): String? {
    if (value.isBlank()) return null
    var hash = 1125899906842597L
    value.forEach { hash = 31 * hash + it.code }
    return hash.toString(16)
}

internal fun requireWalletInteractionLocalizationKey(
    fieldName: String,
    value: String?,
) {
    if (value == null) return
    require(walletInteractionLocalizationKeyPattern.matches(value)) {
        "wallet_interaction_localization_key_invalid"
    }
}

private val walletInteractionLocalizationKeyPattern = Regex("""[a-z][a-z0-9_-]*(\.[a-z0-9_-]+)+""")
