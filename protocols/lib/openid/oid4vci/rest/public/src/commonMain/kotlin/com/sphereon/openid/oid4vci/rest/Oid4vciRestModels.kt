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

package com.sphereon.openid.oid4vci.rest

import com.sphereon.core.api.http.callback.CallbackSigningAlgorithm
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.core.compat.JsExportIgnoreCompat
import com.sphereon.openid.oid4vc.common.QrCodeOptions
import com.sphereon.openid.oid4vc.common.SessionError
import com.sphereon.openid.oid4vci.issuer.command.OfferRateLimit
import com.sphereon.openid.oid4vci.issuer.command.OfferUriLifecycle
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Request body for POST /api/oid4vci/v1/backend/credential/offers.
 *
 * Creates a new OID4VCI credential offer session. The caller specifies which
 * credential configurations to offer and optionally supplies subject data.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateCredentialOfferInput", exact = true)
@JsExportCompat
@Serializable
data class CreateCredentialOfferInput(
    /**
     * Identifiers for the offered credential configurations. Required.
     */
    @SerialName("credential_configuration_ids")
    val credentialConfigurationIds: List<String>,
    /**
     * Pre-seeded attributes for the credential subject.
     * Keys are attribute names, values are JSON elements.
     */
    @SerialName("credential_subject_data")
    @JsExportIgnoreCompat
    val credentialSubjectData: Map<String, JsonElement>? = null,
    /**
     * Opaque initial connector fields for lifecycle extensions. IDK does not interpret these
     * fields as credential subject data; EDK connector pipelines consume them as start-phase input.
     */
    @SerialName("initial_connector_fields")
    @JsExportIgnoreCompat
    val initialConnectorFields: Map<String, JsonElement> = emptyMap(),
    /**
     * Business key for later status queries. If omitted, the server generates one and the call never replays.
     *
     * A supplied value also makes the call idempotent. Repeating the same intent under it returns the original offer
     * without creating another one, a different intent under it is refused, and a repeat while an earlier attempt's
     * outcome is unknown is refused as in doubt until that attempt's offer has expired.
     *
     * A repeat returns the original offer and a status URI computed again. A transaction code is shown once and never
     * stored, so only the first answer carries it and a repeat of a request that required one cannot recover it. A QR
     * code is rendered again from the repeat's own QR options.
     */
    @SerialName("correlation_id")
    val correlationId: String? = null,
    /**
     * Which configured issuer to use. Resolved from context if omitted. Not part of the published contract: the issuer
     * instance in the route owns its identifier, and this is read only on the route without an instance.
     */
    @SerialName("issuer_id")
    val issuerId: String? = null,
    /**
     * Canonical UUID of the issuer instance the offer belongs to. An HTTP caller selects the instance through the
     * `instanceId` of the route and omits it, a caller outside HTTP supplies it, and so does a caller of the route without
     * an instance. When the route and this field both name an instance they must be equal.
     */
    @SerialName("issuer_instance_id")
    val issuerInstanceId: String? = null,
    /**
     * Authorization grant configuration for the credential offer.
     */
    val grants: CredentialOfferGrantsInput? = null,
    /**
     * URI scheme for the offer deeplink. Default: "openid-credential-offer://".
     */
    val scheme: String? = null,
    /**
     * QR code generation options.
     */
    @SerialName("qr_code")
    val qrCodeOptions: QrCodeOptions? = null,
    /**
     * Webhook callback configuration for status notifications.
     */
    val callback: IssuanceCallbackConfig? = null,
    /**
     * Caller-provided opaque state for correlation.
     */
    val state: String? = null,
    /**
     * Session TTL in seconds.
     */
    @SerialName("ttl_seconds")
    val ttlSeconds: Long? = null,
    /**
     * Controls whether the offer URI is single-use (default) or stays alive across multiple
     * wallet fetches, minting a fresh offer on each GET.
     */
    @SerialName("uri_lifecycle")
    val uriLifecycle: OfferUriLifecycle = OfferUriLifecycle.SINGLE_USE,
    /**
     * Rate-limit applied to a reusable offer URI. Mandatory when
     * [uriLifecycle] is [OfferUriLifecycle.REUSABLE_FRESH_PER_FETCH].
     */
    @SerialName("rate_limit")
    val rateLimit: OfferRateLimit? = null,
    /**
     * Internal attribution for offers created by an issuance template. This is deliberately not
     * part of the public JSON request contract: the template execution adapter sets it after
     * decoding so callers cannot forge another template's session-history association.
     */
    @kotlinx.serialization.Transient
    val templateId: String? = null,
    /** Template-owned UUID selector. Never accepted from the public create-offer request body. */
    @kotlinx.serialization.Transient
    val templateAuthorizationServerId: String? = null,
    @kotlinx.serialization.Transient
    val templateAuthorizationServerAllowedGrants: Set<com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationGrant>? = null,
)

/**
 * Authorization grant configuration for a credential offer.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CredentialOfferGrantsInput", exact = true)
@JsExportCompat
@Serializable
data class CredentialOfferGrantsInput(
    /**
     * Pre-authorized code grant configuration.
     */
    @SerialName("pre_authorized_code")
    val preAuthorizedCode: PreAuthorizedCodeGrantInput? = null,
    /**
     * Authorization code grant configuration.
     */
    @SerialName("authorization_code")
    val authorizationCode: AuthorizationCodeGrantInput? = null,
)

/**
 * Pre-authorized code grant configuration.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("PreAuthorizedCodeGrantInput", exact = true)
@JsExportCompat
@Serializable
data class PreAuthorizedCodeGrantInput(
    /**
     * Transaction code configuration (PIN entry).
     */
    @SerialName("tx_code")
    val txCode: TxCodeInput? = null,
)

/**
 * Transaction code (PIN) configuration.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("TxCodeInput", exact = true)
@JsExportCompat
@Serializable
data class TxCodeInput(
    /**
     * Input mode: "numeric" or "text".
     */
    @SerialName("input_mode")
    val inputMode: String? = null,
    /**
     * Length of the transaction code.
     */
    val length: Int? = null,
    /**
     * Guidance for the holder. Max 300 characters.
     */
    val description: String? = null,
)

/**
 * Authorization code grant configuration.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("AuthorizationCodeGrantInput", exact = true)
@JsExportCompat
@Serializable
data class AuthorizationCodeGrantInput(
    /**
     * Opaque OAuth2 issuer_state for the wallet.
     */
    @SerialName("issuer_state")
    val issuerState: String? = null,
)

/**
 * Webhook callback configuration for OID4VCI issuance sessions.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("IssuanceCallbackConfig", exact = true)
@JsExportCompat
@Serializable
data class IssuanceCallbackConfig(
    /**
     * Webhook URL to POST status updates to.
     */
    val url: String,
    /**
     * Filter callbacks to only these statuses. Empty list means all statuses.
     */
    val statuses: List<CredentialOfferSessionStatus> = emptyList(),
    /**
     * Include issuance data in callback payload when credential is issued.
     */
    @SerialName("include_issuance_data")
    val includeIssuanceData: Boolean = false,
    /**
     * Per-session override of the webhook registry: reference of the secret used to sign this
     * session's callbacks. Absent means the matching registered endpoint secret is used, or the
     * callback is sent unsigned when there is none.
     */
    @SerialName("secret_ref")
    val secretRef: String? = null,
    /**
     * Signature scheme for this session's callbacks.
     */
    val signing: CallbackSigningAlgorithm? = null,
)

/**
 * Response body for POST /api/oid4vci/v1/backend/credential/offers.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateCredentialOfferOutput", exact = true)
@JsExportCompat
@Serializable
data class CreateCredentialOfferOutput(
    /**
     * Business/caller correlation identifier for status polling and callbacks. Distinct from the
     * protocol session id.
     */
    @SerialName("correlation_id")
    val correlationId: String,
    /**
     * Immutable protocol-session identifier for the durable session APIs.
     */
    @SerialName("session_id")
    val sessionId: String,
    /**
     * Credential offer URI (e.g., openid-credential-offer://...).
     */
    @SerialName("offer_uri")
    val offerUri: String,
    /**
     * Endpoint URL for checking session status.
     */
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    @SerialName("status_uri")
    val statusUri: String? = null,
    /**
     * QR code as data URI. Only provided when qr_code options were included.
     */
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    @SerialName("qr_uri")
    val qrUri: String? = null,
    /**
     * Transaction code (PIN) if tx_code was requested.
     */
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    @SerialName("tx_code")
    val txCode: String? = null,
)

/**
 * Response body for GET /api/oid4vci/v1/backend/credential/offers/{correlation_id}.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("GetCredentialOfferStatusOutput", exact = true)
@JsExportCompat
@Serializable
data class GetCredentialOfferStatusOutput(
    /**
     * Session/correlation identifier.
     */
    @SerialName("correlation_id")
    val correlationId: String,
    /**
     * Current session status.
     */
    val status: CredentialOfferSessionStatus,
    /**
     * Unix timestamp in milliseconds of the last update.
     */
    @SerialName("last_updated")
    val lastUpdated: Long,
    /** Optional non-sensitive session metadata for developer/test integrations. */
    @SerialName("session_id")
    val sessionId: String? = null,
    @SerialName("offer_id")
    val offerId: String? = null,
    @SerialName("issuance_session_id")
    val issuanceSessionId: String? = null,
    @SerialName("created_at")
    val createdAt: Long? = null,
    @SerialName("expires_at")
    val expiresAt: Long? = null,
    /**
     * Error details when status is ERROR.
     */
    val error: SessionError? = null,
    /**
     * Issuance result data. Populated when status is CREDENTIAL_ISSUED.
     */
    @SerialName("issuance_data")
    val issuanceData: IssuanceData? = null,
)

/**
 * Session status for the OID4VCI backend REST API.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CredentialOfferSessionStatus", exact = true)
@JsExportCompat
@Serializable
enum class CredentialOfferSessionStatus {
    @SerialName("credential_offer_created")
    CREDENTIAL_OFFER_CREATED,

    @SerialName("credential_offer_retrieved")
    CREDENTIAL_OFFER_RETRIEVED,

    @SerialName("token_requested")
    TOKEN_REQUESTED,

    @SerialName("credential_requested")
    CREDENTIAL_REQUESTED,

    @SerialName("credential_issued")
    CREDENTIAL_ISSUED,

    @SerialName("error")
    ERROR,
}

/**
 * Issuance result data, included when credentials have been issued.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("IssuanceData", exact = true)
@JsExportCompat
@Serializable
data class IssuanceData(
    /**
     * Credential configuration IDs that were issued.
     */
    @SerialName("credential_configuration_ids")
    val credentialConfigurationIds: List<String>,
    /**
     * Credential identifiers assigned during issuance.
     */
    @SerialName("credential_identifiers")
    val credentialIdentifiers: List<String>? = null,
)

/**
 * Callback payload POSTed to the webhook URL on status changes.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CredentialOfferSessionStatusUpdate", exact = true)
@JsExportCompat
@Serializable
data class CredentialOfferSessionStatusUpdate(
    @SerialName("correlation_id")
    val correlationId: String,
    val status: CredentialOfferSessionStatus,
    @SerialName("updated_at")
    val updatedAt: Long,
    @SerialName("error_code")
    val errorCode: String? = null,
    @SerialName("error_message")
    val errorMessage: String? = null,
)

/**
 * Error response body for OID4VCI REST API errors.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("Oid4vciRestErrorResponse", exact = true)
@JsExportCompat
@Serializable
data class Oid4vciRestErrorResponse(
    /**
     * HTTP status code.
     */
    val status: Int,
    /**
     * Human-readable error message.
     */
    val message: String,
    /**
     * Optional additional error details.
     */
    @SerialName("error_details")
    val errorDetails: String? = null,
)
