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

package com.sphereon.openid.oid4vp.holder

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.ServiceCommand
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.resolution.managed.ManagedIdentifierOptsOrResult
import com.sphereon.crypto.jose.jwe.JweHeader
import com.sphereon.oauth2.common.jarm.JarmConfig
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.oauth2.common.model.AuthorizationResponse
import com.sphereon.oauth2.common.model.AuthorizationErrorResponse
import com.sphereon.openid.oid4vp.common.ResponseMode
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Symbolic Request Object audience required by OpenID4VP 1.0 Final section 5.8
 * when the Verifier uses static discovery metadata.
 */
const val OID4VP_STATIC_DISCOVERY_REQUEST_OBJECT_AUDIENCE: String = "https://self-issued.me/v2"

// ============================================================================
// Command Interfaces
// ============================================================================

/**
 * Arguments for parsing an OpenID4VP authorization request
 *
 * Exactly one of [requestUri] and [digitalCredentialsRequest] must be supplied.
 *
 * @property requestUri The authorization request URI (for example openid4vp:// or HAIP 1.0 Final's haip-vp://)
 * @property walletConfig Optional wallet configuration for JWT validation
 * @property digitalCredentialsRequest Request delivered by the browser Digital Credentials API
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("ParseAuthorizationRequestArgs", exact = true)
@JsExportCompat
data class ParseAuthorizationRequestArgs(
    val requestUri: String? = null,
    val walletConfig: WalletConfig? = null,
    val digitalCredentialsRequest: DigitalCredentialsAuthorizationRequest? = null,
) {
    init {
        require((requestUri != null) xor (digitalCredentialsRequest != null)) {
            "Exactly one authorization request transport must be supplied"
        }
    }
}

/**
 * Wallet configuration for request object validation
 *
 * Per OpenID4VP 1.0 Final and RFC 9101:
 * - audience: The expected Request Object JWT `aud` claim. For static discovery this is
 *   [OID4VP_STATIC_DISCOVERY_REQUEST_OBJECT_AUDIENCE]; dynamic discovery uses the Verifier `iss`.
 * - decryptionKey: Optional key for decrypting encrypted request objects (JWE)
 *
 * @property audience Exact audience expected in a signed Request Object
 * @property decryptionKey Optional private key for decrypting encrypted request objects
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("WalletConfig", exact = true)
@JsExportCompat
data class WalletConfig(
    val audience: String? = null,
    val decryptionKey: KeyInfoType<*>? = null,
)

/**
 * Command for parsing an OpenID4VP authorization request URI
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("ParseAuthorizationRequestCommand", exact = true)
@JsExportCompat
interface ParseAuthorizationRequestCommand : ServiceCommand<ParseAuthorizationRequestArgs, AuthorizationRequest, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oid4vp.holder.parserequest"
    }
}

/**
 * Command service interface for parsing authorization requests
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("ParseAuthorizationRequestCommandService", exact = true)
interface ParseAuthorizationRequestCommandService {
    suspend fun parseAuthorizationRequest(
        requestUri: String,
        walletConfig: WalletConfig? = null,
    ): IdkResult<AuthorizationRequest, IdkError>

    suspend fun parseDigitalCredentialsAuthorizationRequest(
        request: DigitalCredentialsAuthorizationRequest,
        walletConfig: WalletConfig? = null,
    ): IdkResult<AuthorizationRequest, IdkError>
}

/**
 * Command for resolving an authorization request (fetching client metadata, validating)
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("ResolveAuthorizationRequestCommand", exact = true)
@JsExportCompat
interface ResolveAuthorizationRequestCommand : ServiceCommand<AuthorizationRequest, ResolvedOid4vpRequest, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oid4vp.holder.resolverequest"
    }
}

/**
 * Command service interface for resolving authorization requests
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("ResolveAuthorizationRequestCommandService", exact = true)
interface ResolveAuthorizationRequestCommandService {
    suspend fun resolveAuthorizationRequest(request: AuthorizationRequest): IdkResult<ResolvedOid4vpRequest, IdkError>
}

/**
 * Arguments for creating an authorization response
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateAuthorizationResponseArgs", exact = true)
@JsExportCompat
data class CreateAuthorizationResponseArgs(
    val request: ResolvedOid4vpRequest,
    val selectedCredentials: List<SelectedCredential>,
    val preparedPresentations: List<PreparedPresentation> = emptyList(),
    val preparedJwtVp: HolderPreparedJwtVpResponse? = null,
    val preparedJwtVpSignatures: List<HolderJwtVpSigningResult> = emptyList(),
    val preparedMdocSignings: List<PreparedMdocCredentialSigning> = emptyList(),
    val preparedMdocSignatures: List<MdocCredentialSigningSignature> = emptyList(),
)

/**
 * Command for creating an authorization response with VP tokens
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateAuthorizationResponseCommand", exact = true)
@JsExportCompat
interface CreateAuthorizationResponseCommand : ServiceCommand<CreateAuthorizationResponseArgs, AuthorizationResponse, IdkError> {
    override val commandId: String get() = COMMAND_ID

    suspend fun prepareMdocDeviceAuthenticationSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
    ): IdkResult<List<PreparedMdocCredentialSigning>, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc DeviceAuth signing is not configured"))

    suspend fun createAuthorizationResponseWithPreparedMdocDeviceAuthenticationSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedMdocSignings: List<PreparedMdocCredentialSigning>,
        signatures: List<MdocCredentialSigningSignature>,
    ): IdkResult<AuthorizationResponse, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc DeviceAuth signing is not configured"))

    suspend fun createAuthorizationResponseWithPreparedSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedJwtVp: HolderPreparedJwtVpResponse?,
        jwtSignatures: List<HolderJwtVpSigningResult>,
        preparedMdocSignings: List<PreparedMdocCredentialSigning>,
        mdocSignatures: List<MdocCredentialSigningSignature>,
    ): IdkResult<AuthorizationResponse, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared holder signing is not configured"))

    companion object {
        const val COMMAND_ID = "oid4vp.holder.createresponse"
    }
}

/**
 * Command service interface for creating authorization responses
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("CreateAuthorizationResponseCommandService", exact = true)
interface CreateAuthorizationResponseCommandService {
    suspend fun createAuthorizationResponse(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation> = emptyList(),
    ): IdkResult<AuthorizationResponse, IdkError>

    suspend fun prepareMdocDeviceAuthenticationSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
    ): IdkResult<List<PreparedMdocCredentialSigning>, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc DeviceAuth signing is not configured"))

    suspend fun createAuthorizationResponseWithPreparedMdocDeviceAuthenticationSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedMdocSignings: List<PreparedMdocCredentialSigning>,
        signatures: List<MdocCredentialSigningSignature>,
    ): IdkResult<AuthorizationResponse, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc DeviceAuth signing is not configured"))

    suspend fun createAuthorizationResponseWithPreparedSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedJwtVp: HolderPreparedJwtVpResponse?,
        jwtSignatures: List<HolderJwtVpSigningResult>,
        preparedMdocSignings: List<PreparedMdocCredentialSigning>,
        mdocSignatures: List<MdocCredentialSigningSignature>,
    ): IdkResult<AuthorizationResponse, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared holder signing is not configured"))
}

/**
 * JARM (JWT Secured Authorization Response Mode) options for submitting authorization responses.
 *
 * Required when response_mode is "direct_post.jwt" per OpenID4VP 1.0 Section 8.4.
 *
 * @property signingKey The wallet's signing key for JARM JWS (required for SIGNED or SIGNED_ENCRYPTED mode)
 * @property issuer The wallet's identifier (becomes JWT "iss" claim)
 * @property jarmConfig Optional explicit JARM configuration. If not provided, will be derived from client_metadata.
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("JarmOptions", exact = true)
@JsExportCompat
data class JarmOptions(
    @kotlinx.serialization.Transient
    val signingKey: ManagedIdentifierOptsOrResult? = null,
    val issuer: String,
    val jarmConfig: JarmConfig? = null,
    /** Optional profile-specific protected JWE headers; null preserves regular OID4VP behavior. */
    @kotlinx.serialization.Transient
    val protectedHeaderOverrides: JweHeader? = null,
)

/**
 * Arguments for submitting an authorization response
 *
 * @property resolvedRequest The resolved authorization request (contains response_uri/redirect_uri)
 * @property response The authorization response containing vp_token
 * @property responseMode The response mode to use (defaults to request's response_mode or DIRECT_POST)
 * @property jarmOptions JARM options for direct_post.jwt mode (required when using JARM)
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("SubmitAuthorizationResponseArgs", exact = true)
@JsExportCompat
data class SubmitAuthorizationResponseArgs(
    val resolvedRequest: ResolvedOid4vpRequest,
    val response: AuthorizationResponse? = null,
    val responseMode: ResponseMode? = null,
    val jarmOptions: JarmOptions? = null,
    /** Holder-private binding to the verifier JWK used by prepared mdoc DeviceAuthentication. */
    val preparedOid4vpJweRecipientBinding: PreparedOid4vpJweRecipientBinding? = null,
    val errorResponse: AuthorizationErrorResponse? = null,
) {
    init {
        require((response == null) != (errorResponse == null)) { "Exactly one authorization response is required" }
        require(errorResponse == null || preparedOid4vpJweRecipientBinding == null) { "An error cannot carry prepared credential signing material" }
    }
}

/**
 * Command for submitting an authorization response to the verifier
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("SubmitAuthorizationResponseCommand", exact = true)
@JsExportCompat
interface SubmitAuthorizationResponseCommand : ServiceCommand<SubmitAuthorizationResponseArgs, SubmissionResult, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oid4vp.holder.submit"
    }
}

/**
 * Command service interface for submitting authorization responses
 */
@OptIn(ExperimentalObjCName::class)
@ObjCName("SubmitAuthorizationResponseCommandService", exact = true)
interface SubmitAuthorizationResponseCommandService {
    suspend fun submitAuthorizationResponse(
        resolvedRequest: ResolvedOid4vpRequest,
        response: AuthorizationResponse,
        responseMode: ResponseMode? = null,
        jarmOptions: JarmOptions? = null,
    ): IdkResult<SubmissionResult, IdkError>

    /**
     * Binding-aware overload. Legacy command-service implementations remain source-compatible,
     * but fail closed when asked to submit a response that requires a prepared recipient binding.
     */
    suspend fun submitAuthorizationResponse(
        resolvedRequest: ResolvedOid4vpRequest,
        response: AuthorizationResponse,
        responseMode: ResponseMode?,
        jarmOptions: JarmOptions?,
        preparedOid4vpJweRecipientBinding: PreparedOid4vpJweRecipientBinding,
    ): IdkResult<SubmissionResult, IdkError> =
        com.sphereon.core.api.Err(
            IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared OID4VP JWE recipient binding is not supported by this holder service"),
        )
}
