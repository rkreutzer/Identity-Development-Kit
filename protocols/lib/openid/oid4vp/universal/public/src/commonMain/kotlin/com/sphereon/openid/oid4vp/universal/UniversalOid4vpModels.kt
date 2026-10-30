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

import com.sphereon.core.api.http.callback.CallbackSigningAlgorithm
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.openid.oid4vc.common.QrCodeOptions
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.statuslist.CredentialStatusPolicy
import kotlinx.serialization.EncodeDefault
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * How the verifier delivers the authorization request to the wallet.
 *
 * [URL_QUERY] emits the authorization parameters directly on the wallet-facing
 * URI. [REQUEST_URI] emits a request_uri reference whose contents are served by
 * the verifier. This is separate from `request_uri_method`, which selects GET or
 * POST only after [REQUEST_URI] has been chosen.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("AuthorizationRequestMethod", exact = true)
@Serializable
@JsExportCompat
enum class AuthorizationRequestMethod {
    @SerialName("url_query")
    URL_QUERY,

    @SerialName("request_uri")
    REQUEST_URI,

    /** Return a signed Request Object for browser/native Digital Credentials API invocation. */
    @SerialName("dc_api")
    DC_API,
}

/**
 * Request body for POST /backend/auth/requests per the Universal OID4VP spec.
 *
 * Creates a new OID4VP authorization session. [queryId] references a pre-configured
 * DCQL or Presentation Exchange query. Alternatively [dcqlQuery] can provide an inline query.
 *
 * @see <a href="https://github.com/FIDEScommunity/universal-oid4vp">Universal OID4VP spec</a>
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateAuthorizationRequestInput", exact = true)
@JsExportCompat
@Serializable
data class CreateAuthorizationRequestInput(
    /**
     * Identifier for the query (DCQL or PE). Required by spec.
     * Either this or [dcqlQuery] must be provided.
     */
    @SerialName("query_id")
    val queryId: String? = null,
    /**
     * Inline DCQL query (extension, not in base spec).
     * Either this or [queryId] must be provided.
     */
    @SerialName("dcql_query")
    val dcqlQuery: DcqlQuery? = null,
    /**
     * Business key or UUID for later status queries.
     * If omitted, the server randomly assigns one.
     */
    @SerialName("correlation_id")
    val correlationId: String? = null,
    /**
     * Client ID and schema per RFC6749 and OID4VP.
     */
    @SerialName("client_id")
    val clientId: String? = null,
    /**
     * Client ID scheme per OID4VP spec. Determines how the wallet resolves the verifier's identity.
     * Defaults to [ClientIdScheme.PRE_REGISTERED] for server-side usage.
     */
    @SerialName("client_id_scheme")
    val clientIdScheme: ClientIdScheme? = null,
    /**
     * HTTPS base URL for the inner OID4VP §5.10 `request_uri` parameter — the URL the wallet
     * GETs/POSTs to fetch the signed JAR. MUST be `https://` (or `http://` for localhost).
     * Defaults to the verifier's `oid4vp.universal.external-base-url` config value.
     *
     * NOT the outer wallet-deeplink scheme — that's [walletUriScheme].
     */
    @SerialName("request_uri_base")
    val requestUriBase: String? = null,
    /**
     * HTTPS endpoint where the wallet posts the Authorization Response for `direct_post` and
     * `direct_post.jwt`. Defaults to the verifier deployment configuration.
     */
    @SerialName("response_uri")
    val responseUri: String? = null,
    /**
     * URI scheme of the outer wallet deeplink (the part before `://?`), per OID4VP §5.10.
     * Examples: `openid4vp` (default, spec-canonical), `haip-vp` (HAIP 1.0 Final presentation),
     * `oid4vp` (Sphereon mobile-wallet custom), `openid` (legacy).
     *
     * Sent without the trailing `://`. The verifier emits
     * `<scheme>://?client_id=...&request_uri=https://.../...`.
     */
    @SerialName("wallet_uri_scheme")
    val walletUriScheme: String? = null,
    /**
     * How the wallet accesses the request URI: "get" or "post". Default: "get".
     */
    @SerialName("request_uri_method")
    val requestUriMethod: String? = null,
    /**
     * Whether authorization parameters are carried inline or through request_uri.
     * Defaults to request_uri, the normal signed-request-object deployment mode.
     */
    @SerialName("authorization_request_method")
    val authorizationRequestMethod: AuthorizationRequestMethod = AuthorizationRequestMethod.REQUEST_URI,
    /**
     * Response type. This verifier currently supports only "vp_token", which is also the default.
     * Values containing "id_token" are rejected because no ID Token response handling is implemented.
     * End-to-end `vp_token id_token` support is tracked by
     * [VDX-203](https://4sure.atlassian.net/browse/VDX-203).
     */
    @SerialName("response_type")
    val responseType: String? = null,
    /**
     * Response mode: "direct_post", "direct_post.jwt", or "dc_api.jwt". Default: "direct_post".
     */
    @SerialName("response_mode")
    val responseMode: String? = null,
    /** Verifier browser origins in a signed DC API Request Object (OID4VP Appendix A.2). */
    @SerialName("expected_origins")
    val expectedOrigins: List<String>? = null,
    /**
     * Base64url-encoded JSON objects with transaction details.
     */
    @SerialName("transaction_data")
    val transactionData: List<String>? = null,
    /**
     * Post-completion redirect destination.
     */
    @SerialName("direct_post_response_redirect_uri")
    val directPostResponseRedirectUri: String? = null,
    /**
     * QR code generation options.
     */
    @SerialName("qr_code")
    val qrCodeOptions: QrCodeOptions? = null,
    /**
     * Webhook callback configuration for status notifications.
     */
    val callback: CallbackConfig? = null,
    /**
     * Optional client metadata ID reference (extension).
     */
    @SerialName("client_metadata_id")
    val clientMetadataId: String? = null,
    /**
     * Caller-provided state for correlation (extension).
     */
    val state: String? = null,
    /**
     * Session TTL in seconds (extension).
     */
    @SerialName("ttl_seconds")
    val ttlSeconds: Long? = null,
    /**
     * Identifier of the verifier this request is for. Opaque to IDK/EDK — passed to the
     * [com.sphereon.openid.oid4vp.dcql.store.DcqlQueryResolver] so a higher layer can
     * resolve the DCQL query through a verifier→binding→pinned-version chain.
     */
    @SerialName("verifier_id")
    val verifierId: String? = null,
    /**
     * Identifier of the verification template this request was created from (extension). Set by
     * `createAuthorizationRequestFromVerificationTemplate` so EDK can resolve TEMPLATE-scoped
     * trust-domain defaults at response validation time; opaque to IDK otherwise.
     */
    @SerialName("template_id")
    val templateId: String? = null,
    /**
     * Optional per-DCQL-credential-query credential status policy, keyed by the DCQL credential query
     * `id`. Decides how the verifier treats a received credential's resolved status (accept revoked /
     * suspended, require a status list, fail-closed on unresolvable). A verifier-internal extension:
     * OpenID4VP DCQL has no status concept, so this stays out of the signed `dcql_query` and is only
     * enforced when the verifier has credential-status implementations on its classpath.
     */
    @SerialName("credential_status_policies")
    val credentialStatusPolicies: Map<String, CredentialStatusPolicy>? = null,
    /** Stable operation identity for durable, idempotent creation. Requires a persistent tenant store. */
    @SerialName("operation_id")
    val operationId: String? = null,
    @SerialName("template_revision")
    val templateRevision: String? = null,
)

/**
 * Webhook callback configuration.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CallbackConfig", exact = true)
@JsExportCompat
@Serializable
data class CallbackConfig(
    /**
     * Webhook URL to POST status updates to.
     */
    val url: String,
    /**
     * Filter callbacks to only these statuses. Empty list means all statuses. The wire name is the
     * singular `status` the Universal OID4VP spec defines for this array.
     */
    @SerialName("status")
    val statuses: List<AuthorizationSessionStatus> = emptyList(),
    /**
     * Which verified credential data representations the callback carries when the status is
     * verified.
     */
    @SerialName("verified_data")
    val verifiedData: VerifiedDataOpts? = null,
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
 * Response body for POST /backend/auth/requests per the Universal OID4VP spec.
 *
 * @see <a href="https://github.com/FIDEScommunity/universal-oid4vp">Universal OID4VP spec</a>
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateAuthorizationRequestOutput", exact = true)
@JsExportCompat
@Serializable
data class CreateAuthorizationRequestOutput(
    /**
     * Immutable protocol-session identifier. Use this identifier for durable session-history
     * detail and event APIs. It is deliberately distinct from [correlationId], which remains the
     * business/status-polling key echoed by the wallet.
     */
    @SerialName("session_id")
    val sessionId: String,
    /**
     * Business/status-polling correlation identifier. Required by spec.
     */
    @SerialName("correlation_id")
    val correlationId: String,
    /**
     * DCQL/PE query identifier. Required by spec.
     */
    @SerialName("query_id")
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    val queryId: String? = null,
    /**
     * Inline authorization request object. At least one of this value or [requestUri] is required.
     */
    @SerialName("request")
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    val request: String? = null,
    /**
     * Deeplink URI initiating the authentication flow (e.g., openid4vp://...). At least one of
     * this value or [request] is required.
     */
    @SerialName("request_uri")
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    val requestUri: String? = null,
    /**
     * Endpoint URL for checking authentication status. Required by spec.
     */
    @SerialName("status_uri")
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    val statusUri: String? = null,
    /**
     * QR code as data URI. Only provided when qr_code options were included in the request.
     */
    @SerialName("qr_uri")
    @EncodeDefault(EncodeDefault.Mode.NEVER)
    val qrUri: String? = null,
    @SerialName("verification_binding")
    val verificationBinding: VerificationSessionBinding? = null,
) {
    init {
        require(!request.isNullOrBlank() || !requestUri.isNullOrBlank()) {
            "Either request or request_uri should be present"
        }
    }
}

/**
 * Error response body for API errors.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("UniversalOid4vpErrorResponse", exact = true)
@JsExportCompat
@Serializable
data class UniversalOid4vpErrorResponse(
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
