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

package com.sphereon.openid.oid4vp.verifier.model

import com.sphereon.core.api.http.callback.CallbackSigningAlgorithm
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.universal.VerifiedDataOpts
import com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse
import com.sphereon.openid.oid4vp.verifier.ValidationResult
import com.sphereon.statuslist.CredentialStatusPolicy
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Authorization session status aligned with Universal OID4VP.
 *
 * The `@SerialName` annotations map each constant to its snake_case wire format
 * (e.g. `"authorization_request_created"`). This is required because the wallet agent
 * (Node.js) returns status values in snake_case JSON, and without explicit serial names
 * kotlinx-serialization defaults to the uppercase enum constant names which causes
 * deserialization failures.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("AuthorizationSessionStatus", exact = true)
@JsExportCompat
@Serializable
enum class AuthorizationSessionStatus {
    @SerialName("authorization_request_created")
    AUTHORIZATION_REQUEST_CREATED,

    @SerialName("authorization_request_retrieved")
    AUTHORIZATION_REQUEST_RETRIEVED,

    @SerialName("authorization_response_received")
    AUTHORIZATION_RESPONSE_RECEIVED,

    @SerialName("authorization_response_verified")
    AUTHORIZATION_RESPONSE_VERIFIED,

    @SerialName("error")
    ERROR,
}

/**
 * Callback configuration for status updates (webhook).
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("AuthorizationSessionCallbackConfig", exact = true)
@JsExportCompat
data class AuthorizationSessionCallbackConfig(
    val url: String,
    /**
     * If empty, all status transitions may be emitted.
     */
    val statuses: List<AuthorizationSessionStatus> = emptyList(),
    /**
     * The verified data representations the callback carries once the session is verified. Absent or
     * empty modes carry none.
     */
    val verifiedData: VerifiedDataOpts? = null,
    /**
     * Secret reference and algorithm requested for signing this session's callbacks. They are stored
     * with the session, but callbacks are currently posted unsigned.
     */
    val secretRef: String? = null,
    val signing: CallbackSigningAlgorithm? = null,
)

/**
 * Additional error information for a failed session.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("AuthorizationSessionError", exact = true)
@JsExportCompat
data class AuthorizationSessionError(
    val code: String,
    val message: String,
)

/**
 * Inputs for creating an authorization session.
 *
 * This is intentionally minimal in Phase 1; it will be extended in later phases
 * (configuration stores, request_uri handling, verified data, etc).
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("AuthorizationSessionCreateArgs", exact = true)
@JsExportCompat
data class AuthorizationSessionCreateArgs(
    val instanceId: String,
    /**
     * Optional reference to a pre-configured query (configuration mode).
     */
    val queryId: String? = null,
    /**
     * Inline DCQL query (direct mode).
     */
    val dcqlQuery: DcqlQuery? = null,
    val clientId: String,
    val responseMode: ResponseMode = ResponseMode.DIRECT_POST,
    val responseUri: String? = null,
    val redirectUri: String? = null,
    val nonce: String,
    val state: String? = null,
    val verifierId: String? = null,
    val callback: AuthorizationSessionCallbackConfig? = null,
) {
    init {
        Oid4vpSessionIdentity.requireCanonical("instanceId", instanceId)
    }
}

/** Canonical identity constraints shared by OID4VP session producers and history events. */
object Oid4vpSessionIdentity {
    const val MAX_IDENTIFIER_LENGTH: Int = 190

    fun normalize(
        fieldName: String,
        value: String,
    ): String {
        val normalized = value.trim()
        require(normalized.isNotEmpty()) { "$fieldName must not be blank" }
        require(normalized.length <= MAX_IDENTIFIER_LENGTH) {
            "$fieldName must not exceed $MAX_IDENTIFIER_LENGTH characters"
        }
        return normalized
    }

    fun requireCanonical(
        fieldName: String,
        value: String,
    ) {
        require(value == normalize(fieldName, value)) { "$fieldName must not contain surrounding whitespace" }
    }
}

/**
 * Stored authorization session state.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("AuthorizationSession", exact = true)
@JsExportCompat
data class AuthorizationSession(
    /** Immutable verifier-instance identity captured before session creation. */
    val instanceId: String,
    val sessionId: String,
    /**
     * Business key / correlation id.
     */
    val correlationId: String,
    val queryId: String? = null,
    val dcqlQuery: DcqlQuery,
    /**
     * Version snapshot of the DCQL query this session was created against, when the query came
     * from a version-history store. The session resolves this exact `(dcqlQueryId,
     * dcqlQueryVersion)` for its full lifetime, so a later edit of the query header does not
     * change what an in-flight session validates against. Both null for inline DCQL queries or
     * stores without versioning.
     */
    val dcqlQueryId: String? = null,
    val dcqlQueryVersion: Int? = null,
    /**
     * Optional business identifier of the verifier instance this session was created for.
     */
    val verifierId: String? = null,
    /**
     * Optional identifier of the verification template this session's authorization request was
     * created from (see `createAuthorizationRequestFromVerificationTemplate`). Threaded into
     * response-side credential trust validation so TEMPLATE-scoped trust-domain defaults apply
     * for the lifetime of this session, without the wallet or caller needing to resend it.
     */
    val templateId: String? = null,
    val authorizationRequest: AuthorizationRequest,
    val status: AuthorizationSessionStatus,
    val error: AuthorizationSessionError? = null,
    val parsedResponse: ParsedAuthorizationResponse? = null,
    val validationResult: ValidationResult? = null,
    val callback: AuthorizationSessionCallbackConfig? = null,
    /**
     * Where the wallet sends the user after a `direct_post` / `direct_post.jwt` response: the
     * OID4VP §7.2 `redirect_uri` the verifier returns in the response body, with the
     * `response_code` appended. HAIP 1.0 requires it to be present in that response.
     *
     * Response-endpoint state, pinned on the session rather than read off
     * [authorizationRequest]: the authorization request omits `redirect_uri` for the direct_post
     * modes — `redirect_uri` and `response_uri` are mutually exclusive on the wire — so a
     * post-completion destination has nowhere else to live.
     */
    val directPostResponseRedirectUri: String? = null,
    /**
     * Optional one-time invitation token bound to this verifier session at create
     * time. Carried forward into [com.sphereon.openid.oid4vp.verifier.hook.PostPresentationHookArgs.boundInvitationToken]
     * so a downstream subscriber (e.g. VDX's `VerifierPresentationConsumeHookCommand`)
     * can correlate a successful presentation back to the originating invitation
     * and call `invitationService.redeem(...)`. Mirrors
     * `IssuanceSession.boundUsageToken` on the OID4VCI side.
     */
    val boundInvitationToken: String? = null,
    /**
     * Optional per-session allow list of post-presentation hook command IDs. The
     * dispatcher intersects the deployment-resolved hook set with this list before
     * invocation; null means "all deployment-registered hooks may fire". Mirrors
     * `IssuanceSession.postIssuanceHookAllowList` on the OID4VCI side.
     */
    val postPresentationHookAllowList: List<String>? = null,
    /**
     * Per-DCQL-credential-query credential status policy, keyed by the DCQL credential query `id`,
     * pinned for this session's lifetime. Read at response validation to decide whether a received
     * credential's resolved status is acceptable. Null / missing entry → the strict default
     * ([com.sphereon.statuslist.CredentialStatusPolicy] defaults). Only enforced when a non-empty set
     * of `CredentialStatusVerifier` implementations is on the verifier's classpath.
     */
    val credentialStatusPolicies: Map<String, CredentialStatusPolicy>? = null,
    val createdAt: Long,
    val updatedAt: Long,
    val expiresAt: Long,
    val templateRevision: String? = null,
) {
    init {
        Oid4vpSessionIdentity.requireCanonical("instanceId", instanceId)
        Oid4vpSessionIdentity.requireCanonical("protocolSessionId", sessionId)
    }
}
