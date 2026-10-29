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

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.core.compat.JsExportIgnoreCompat
import com.sphereon.openid.oid4vci.issuer.command.OfferRateLimit
import com.sphereon.openid.oid4vci.issuer.command.OfferUriLifecycle
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationPolicySnapshot
import com.sphereon.openid.oid4vci.issuer.store.Oid4vciSessionIdentity
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Session entity for the OID4VCI backend REST API.
 *
 * Maps a correlationId to the internal OID4VCI offer/session,
 * storing callback config and session metadata.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CredentialOfferSession", exact = true)
@JsExportCompat
@Serializable
data class CredentialOfferSession(
    @SerialName("correlation_id")
    val correlationId: String,
    @SerialName("instance_id")
    val instanceId: String,
    @SerialName("offer_id")
    val offerId: String,
    @SerialName("issuance_session_id")
    val issuanceSessionId: String,
    val status: CredentialOfferSessionStatus,
    @SerialName("callback_config")
    val callbackConfig: IssuanceCallbackConfig? = null,
    val state: String? = null,
    @SerialName("created_at")
    val createdAt: Long,
    @SerialName("last_updated_at")
    val lastUpdatedAt: Long,
    @SerialName("expires_at")
    val expiresAt: Long? = null,
    /**
     * Controls whether the offer URI is single-use (default) or stays alive across multiple
     * wallet fetches. Stored so the GET handler can apply the correct fetch semantics.
     */
    @SerialName("uri_lifecycle")
    val uriLifecycle: OfferUriLifecycle = OfferUriLifecycle.SINGLE_USE,
    /**
     * Rate-limit for reusable offer URIs. Present when [uriLifecycle] is
     * [OfferUriLifecycle.REUSABLE_FRESH_PER_FETCH].
     */
    @SerialName("rate_limit")
    val rateLimit: OfferRateLimit? = null,
    /**
     * Replayable offer-creation inputs. Present so the GET handler can rebuild a
     * [com.sphereon.openid.oid4vci.issuer.command.CreateCredentialOfferArgs] and mint a fresh
     * inner offer on each fetch of a [OfferUriLifecycle.REUSABLE_FRESH_PER_FETCH] URI, while the
     * stable offer URI / offer id and this session row stay put. It is optional because
     * single-use sessions do not require replay inputs.
     */
    @SerialName("offer_template")
    @JsExportIgnoreCompat
    val offerTemplate: CredentialOfferTemplate? = null,
    /** Immutable policy decision used for every continuation or reusable-offer remint. */
    @SerialName("authorization_policy_snapshot")
    @JsExportIgnoreCompat
    val authorizationPolicySnapshot: Oid4vciAuthorizationPolicySnapshot? = null,
) {
    init {
        Oid4vciSessionIdentity.requireCanonical("instanceId", instanceId)
        Oid4vciSessionIdentity.requireCanonical("protocolSessionId", issuanceSessionId)
    }
}

/**
 * Minimal replayable snapshot of the inputs that produced this offer's inner protocol content.
 *
 * Holds exactly the fields a fresh mint needs to rebuild
 * [com.sphereon.openid.oid4vci.issuer.command.CreateCredentialOfferArgs]. The reusable-URI fields
 * ([OfferUriLifecycle], [OfferRateLimit]) already live on [CredentialOfferSession],
 * so they are not duplicated here.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CredentialOfferTemplate", exact = true)
@JsExportCompat
@Serializable
data class CredentialOfferTemplate(
    @SerialName("issuer_id")
    val issuerId: String,
    @SerialName("credential_configuration_ids")
    val credentialConfigurationIds: List<String>,
    @SerialName("pre_authorized_code_grant")
    val preAuthorizedCodeGrant: Boolean = false,
    @SerialName("authorization_code_grant")
    val authorizationCodeGrant: Boolean = false,
    @SerialName("tx_code_required")
    val txCodeRequired: Boolean = false,
    @SerialName("tx_code_length")
    val txCodeLength: Int? = null,
    @SerialName("tx_code_input_mode")
    val txCodeInputMode: String? = null,
    @SerialName("pre_seeded_attributes")
    @JsExportIgnoreCompat
    val preSeededAttributes: Map<String, JsonElement>? = null,
    @SerialName("initial_connector_fields")
    @JsExportIgnoreCompat
    val initialConnectorFields: Map<String, JsonElement> = emptyMap(),
    @SerialName("offer_ttl_seconds")
    val offerTtlSeconds: Long = 600,
    val scheme: String? = null,
)

/**
 * Where a correlation id stands.
 */
@JsExportCompat
@Serializable
enum class OfferRequestState {
    /** A caller holds the key and is creating the offer. Its outcome is unknown until it completes or the claim expires. */
    ACTIVE,

    /** The offer exists and [OfferRequestReservation.outcome] describes it. */
    COMPLETED,

    /** The attempt definitely created nothing and gave the key back, so the next caller may take it. */
    RELEASED,

    /** The offer was deleted. The key is not used for another offer. */
    WITHDRAWN,
    ;

    companion object {
        fun fromValue(value: String): OfferRequestState =
            entries.find { it.name.equals(value, ignoreCase = true) }
                ?: throw IllegalArgumentException("Unknown OfferRequestState: $value")
    }
}

/**
 * The offer a correlation id produced, kept with the claim so a repeat is answered from it.
 *
 * @property offerUri the offer URI handed to the wallet.
 * @property issuanceSessionId the protocol session the offer belongs to.
 * @property instanceId the issuer instance the offer was created for.
 * @property offerExpiresAt epoch milliseconds after which the offer can no longer be redeemed.
 */
@JsExportCompat
@Serializable
data class OfferRequestOutcome(
    val offerUri: String,
    val issuanceSessionId: String,
    val instanceId: String,
    val offerExpiresAt: Long,
)

/**
 * A claim on a correlation id, made before the offer it covers exists so that no second offer can follow a lost
 * response.
 *
 * @property intentDigest digest of what the request asked for, including the issuer instance it was bound to.
 * @property expiresAt epoch milliseconds after which an [OfferRequestState.ACTIVE] claim no longer protects the key,
 *   because the offer it covers would have expired by then.
 * @property state where the key stands.
 * @property outcome the offer, present exactly when [state] is [OfferRequestState.COMPLETED].
 */
@JsExportCompat
@Serializable
data class OfferRequestReservation(
    val key: String,
    val intentDigest: String,
    val createdAt: Long,
    val expiresAt: Long,
    val state: OfferRequestState = OfferRequestState.ACTIVE,
    val outcome: OfferRequestOutcome? = null,
)

/**
 * The answer to a claim: this caller holds the key, or somebody already did.
 *
 * @property reservation the reservation that holds the key now, this caller's own when [claimed] is true.
 * @property version an opaque token naming the claim as the store saw it. Handing the whole claim back to
 *   [CredentialOfferSessionStore.reclaimRequest], [CredentialOfferSessionStore.completeRequest] or
 *   [CredentialOfferSessionStore.releaseRequest] acts on that claim only, so a caller that read a claim which has
 *   changed since can neither take over, complete nor free somebody else's.
 */
@JsExportCompat
data class OfferRequestClaim(
    val claimed: Boolean,
    val reservation: OfferRequestReservation,
    val version: String? = null,
)

/**
 * Store for OID4VCI backend REST API sessions.
 */
@JsExportCompat
interface CredentialOfferSessionStore {
    companion object {
        const val DEFAULT_TTL_SECONDS: Long = 600
    }

    suspend fun create(session: CredentialOfferSession): IdkResult<CredentialOfferSession, IdkError>

    suspend fun get(correlationId: String): IdkResult<CredentialOfferSession?, IdkError>

    /**
     * Looks up a session by its [offerId]. Returns the session when found, or `Ok(null)` when
     * no session with that offer ID exists.
     */
    suspend fun getByOfferId(offerId: String): IdkResult<CredentialOfferSession?, IdkError>

    suspend fun update(session: CredentialOfferSession): IdkResult<CredentialOfferSession, IdkError>

    /**
     * Deletes the session. A correlation id claimed under the same id is withdrawn, so a repeat of that request is told the
     * offer was deleted instead of creating another one.
     */
    suspend fun delete(correlationId: String): IdkResult<Boolean, IdkError>

    /**
     * Atomically claims [reservation]'s key unless a claim exists. A claim that is still [OfferRequestState.ACTIVE]
     * after its expiry answers as the claim on the key, because only the caller can tell whether it left an offer
     * behind, and it takes the key over through [reclaimRequest]. A store that cannot claim atomically refuses, so an
     * idempotent request is never admitted without the guarantee.
     */
    suspend fun claimRequest(reservation: OfferRequestReservation): IdkResult<OfferRequestClaim, IdkError> =
        Err(IdkError.UNSUPPORTED_OPERATION_ERROR(operation = "claimRequest", reason = "The session store has no atomic request claim"))

    /**
     * Replaces [observed], the claim a caller read, with [replacement], only while [observed] still is the claim on
     * the key. Of several callers that read the same expired claim exactly one is told it holds the key, and the others
     * are shown the claim that won.
     */
    suspend fun reclaimRequest(observed: OfferRequestClaim, replacement: OfferRequestReservation): IdkResult<OfferRequestClaim, IdkError> =
        Err(IdkError.UNSUPPORTED_OPERATION_ERROR(operation = "reclaimRequest", reason = "The session store has no atomic request reclaim"))

    /**
     * Records [outcome] on [claim], only while [claim] still is the claim on its key. The answer is claimed when the
     * outcome was recorded. Otherwise it shows the claim that holds the key now, and the caller must not hand out the
     * offer it created: somebody took the key over while it was creating it.
     */
    suspend fun completeRequest(claim: OfferRequestClaim, outcome: OfferRequestOutcome): IdkResult<OfferRequestClaim, IdkError> =
        Err(IdkError.UNSUPPORTED_OPERATION_ERROR(operation = "completeRequest", reason = "The session store has no atomic request completion"))

    /**
     * Gives [claim], one whose request definitely created nothing, back for the caller's next attempt. Answers false
     * when the key is no longer held by [claim], because somebody else holds it by now and it is not this caller's to
     * free.
     */
    suspend fun releaseRequest(claim: OfferRequestClaim): IdkResult<Boolean, IdkError> =
        Err(IdkError.UNSUPPORTED_OPERATION_ERROR(operation = "releaseRequest", reason = "The session store has no atomic request release"))
}
