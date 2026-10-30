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

package com.sphereon.openid.oid4vp.universal

import com.sphereon.core.compat.JsExportCompat
import com.sphereon.core.compat.JsExportIgnoreCompat
import com.sphereon.openid.oid4vc.common.SessionError
import com.sphereon.openid.oid4vp.common.CredentialFormat
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejection
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Response body for GET /backend/auth/requests/{correlation_id} per the Universal OID4VP spec.
 *
 * @see <a href="https://github.com/FIDEScommunity/universal-oid4vp">Universal OID4VP spec</a>
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("GetAuthorizationRequestStatusOutput", exact = true)
@JsExportCompat
@Serializable
data class GetAuthorizationRequestStatusOutput(
    /**
     * Session/correlation identifier. Required by spec.
     */
    @SerialName("correlation_id")
    val correlationId: String,
    /**
     * Presentation definition identifier. Required by spec.
     */
    @SerialName("query_id")
    val queryId: String? = null,
    /**
     * Current session status. Required by spec.
     */
    val status: AuthorizationSessionStatus,
    /**
     * Unix timestamp in milliseconds of the last update. Required by spec.
     */
    @SerialName("last_updated")
    val lastUpdated: Long,
    /** Optional non-sensitive session metadata for developer/test integrations. */
    @SerialName("session_id")
    val sessionId: String? = null,
    @SerialName("verifier_id")
    val verifierId: String? = null,
    @SerialName("created_at")
    val createdAt: Long? = null,
    @SerialName("expires_at")
    val expiresAt: Long? = null,
    @SerialName("verification_binding")
    val verificationBinding: VerificationSessionBinding? = null,
    /**
     * Error details when status is "error".
     */
    val error: SessionError? = null,
    /**
     * Verified credential data. Only included when status is "authorization_response_verified".
     */
    @SerialName("verified_data")
    val verifiedData: VerifiedData? = null,
    /**
     * Outcome of the response validation. Present whenever a validation has run, valid or not.
     */
    @SerialName("validation")
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    val validation: AuthorizationValidationSummary? = null,
)

/**
 * Outcome of validating an authorization response, as exposed on the session status.
 *
 * Present whenever a validation has run - valid or not - so that a relying party can tell a session
 * that was rejected apart from one that has not been validated yet. It deliberately carries no
 * claims, presentation or issuer: a rejected verification records no credential content, and the
 * verified content of a successful one travels on [VerifiedData] instead.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("AuthorizationValidationSummary", exact = true)
@JsExportCompat
@Serializable
data class AuthorizationValidationSummary(
    val valid: Boolean,
    /**
     * Credentials the verifier discarded on credential-status grounds. Empty on a valid session, and
     * empty on an invalid one whose failure had nothing to do with credential status.
     */
    val rejections: List<CredentialValidationRejection> = emptyList(),
)

/**
 * Verified credential data from a successful OID4VP verification,
 * per the FIDES Universal OID4VP spec.
 *
 * @see <a href="https://github.com/FIDEScommunity/universal-oid4vp">Universal OID4VP spec</a>
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifiedData", exact = true)
@JsExportCompat
@Serializable
data class VerifiedData(
    /**
     * Deserialized credential claims per the FIDES Universal OID4VP spec.
     */
    @SerialName("credential_claims")
    val credentialClaims: List<VerifiedClaimsValue>? = null,
    /**
     * Full authorization response per the FIDES Universal OID4VP spec.
     */
    @JsExportIgnoreCompat
    @SerialName("authorization_response")
    val authorizationResponse: JsonObject? = null,
) {
    /**
     * Returns credential claims as [VerifiedCredential] list for convenient claim extraction.
     */
    val credentials: List<VerifiedCredential>
        get() = credentialClaims?.map { it.toVerifiedCredential() } ?: emptyList()
}

/**
 * Deserialized credential claims per the FIDES Universal OID4VP spec.
 *
 * @see <a href="https://github.com/FIDEScommunity/universal-oid4vp">Universal OID4VP spec</a>
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifiedClaimsValue", exact = true)
@JsExportCompat
@Serializable
data class VerifiedClaimsValue(
    /**
     * The id of the query. Can be a presentation exchange id, a DCQL query or query set Id.
     */
    val id: String,
    /**
     * The digital credential type: a vct value, an mdoc doctype or a json-ld type. It is never the
     * credential format, which is carried by [format]. A credential that has no type of its own gets
     * its format value here as a fallback, so do not read [type] to learn the format.
     */
    val type: String,
    /**
     * Claims returned and deserialized in the form of a map.
     */
    @JsExportIgnoreCompat
    val claims: Map<String, JsonElement>? = null,
    /**
     * The raw VP token presentation string (JWT, SD-JWT, etc.) for this credential.
     * Available when the status is AUTHORIZATION_RESPONSE_VERIFIED.
     * Can be used to extract the holder binding key (kid/x5c) from the JWT header.
     */
    val presentation: String? = null,
    /** Verifier-owned evidence; never populated from disclosed credential claims. */
    val verificationEvidence: com.sphereon.openid.oid4vp.verifier.VerifiedCredentialEvidence? = null,
    /**
     * The credential format the verifier detected for the matched credential, such as `dc+sd-jwt`,
     * independent of [type]. `null` when the verifier did not report it. It is never inferred from
     * [type] or from the format a query requested.
     */
    val format: CredentialFormat? = null,
) {
    /**
     * Convert to [VerifiedCredential] for unified handling.
     *
     * [VerifiedCredential.type] is the credential [type] and [VerifiedCredential.format] is the
     * detected [format], so a real vct is kept as the type and never parsed as a format. When the
     * verifier reported no format, the format is the empty string, which means unavailable.
     */
    fun toVerifiedCredential(): VerifiedCredential =
        VerifiedCredential(
            id = id,
            format = format?.value ?: "",
            type = type,
            claims = claims ?: emptyMap(),
        )
}

/**
 * A single verified credential with its claims.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifiedCredential", exact = true)
@JsExportCompat
@Serializable
data class VerifiedCredential(
    /**
     * Credential query ID from the DCQL query.
     */
    val id: String,
    /**
     * Credential format (e.g., dc+sd-jwt, mso_mdoc).
     */
    val format: String,
    /**
     * Credential type (e.g., vct value for SD-JWT, doctype for mDoc).
     */
    val type: String? = null,
    /**
     * Disclosed claims as key-value pairs.
     */
    @JsExportIgnoreCompat
    val claims: Map<String, JsonElement> = emptyMap(),
)
