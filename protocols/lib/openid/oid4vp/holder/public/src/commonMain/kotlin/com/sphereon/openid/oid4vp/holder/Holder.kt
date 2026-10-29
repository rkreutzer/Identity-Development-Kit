/*
 * Copyright 2023-2026 Sphereon International B.V.
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
import com.sphereon.core.compat.JsExportCompat
import kotlin.js.JsName
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.oauth2.common.model.AuthorizationResponse
import com.sphereon.oauth2.common.model.AuthorizationErrorResponse
import com.sphereon.openid.oid4vp.common.ResponseMode
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

/**
 * Service interface for OID4VP Holder (Wallet) operations.
 *
 * This is the command-free surface that exposes holder actions only as services,
 * keeping command objects internal to implementations.
 */
@JsExportCompat
@Suppress("NON_EXPORTABLE_TYPE")
@OptIn(ExperimentalObjCName::class)
@ObjCName("Oid4vpHolderService", exact = true)
interface Oid4vpHolderService {
    suspend fun parseAuthorizationRequest(
        requestUri: String,
        walletConfig: WalletConfig? = null,
    ): IdkResult<AuthorizationRequest, IdkError>

    suspend fun parseDigitalCredentialsAuthorizationRequest(
        request: DigitalCredentialsAuthorizationRequest,
        walletConfig: WalletConfig? = null,
    ): IdkResult<AuthorizationRequest, IdkError>

    suspend fun resolveAuthorizationRequest(request: AuthorizationRequest): IdkResult<ResolvedOid4vpRequest, IdkError>

    suspend fun createAuthorizationResponse(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation> = emptyList(),
    ): IdkResult<AuthorizationResponse, IdkError>

    /** Prepare exact mdoc DeviceAuth signing operations without performing a private-key signature. */
    suspend fun prepareMdocDeviceAuthenticationSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
    ): IdkResult<List<PreparedMdocCredentialSigning>, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc DeviceAuth signing is not configured"))

    /** Compose the response from the exact prepared mdoc operations and their external signatures. */
    suspend fun createAuthorizationResponseWithPreparedMdocDeviceAuthenticationSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedMdocSignings: List<PreparedMdocCredentialSigning>,
        signatures: List<MdocCredentialSigningSignature>,
    ): IdkResult<AuthorizationResponse, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared mdoc DeviceAuth signing is not configured"))

    /** Compose one response using the externally signed JWT-VP and mdoc DeviceAuth operations. */
    suspend fun createAuthorizationResponseWithPreparedSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedJwtVp: HolderPreparedJwtVpResponse? = null,
        jwtSignatures: List<HolderJwtVpSigningResult> = emptyList(),
        preparedMdocSignings: List<PreparedMdocCredentialSigning> = emptyList(),
        mdocSignatures: List<MdocCredentialSigningSignature> = emptyList(),
    ): IdkResult<AuthorizationResponse, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared holder signing is not configured"))

    /** Combines finalized JWT VPs with the other selected formats in the canonical response builder. */
    suspend fun createAuthorizationResponseWithPreparedJwtVp(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedJwtVp: HolderPreparedJwtVpResponse,
        signatures: List<HolderJwtVpSigningResult>,
    ): IdkResult<AuthorizationResponse, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Prepared JWT VP response composition is not configured"))

    suspend fun prepareJwtVpResponse(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
    ): IdkResult<HolderPreparedJwtVpResponse, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Holder JWT VP preparation is not configured"))

    suspend fun finalizeJwtVpResponse(
        prepared: HolderPreparedJwtVpResponse,
        signatures: List<HolderJwtVpSigningResult>,
    ): IdkResult<AuthorizationResponse, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Holder JWT VP finalization is not configured"))

    /** Sends an error through the authenticated response route, without credential material. */
    suspend fun submitAuthorizationErrorResponse(
        resolvedRequest: ResolvedOid4vpRequest,
        error: AuthorizationErrorResponse,
        responseMode: ResponseMode? = null,
        jarmOptions: JarmOptions? = null,
    ): IdkResult<SubmissionResult, IdkError> =
        com.sphereon.core.api.Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Authorization error submission is not configured"))

    suspend fun submitAuthorizationResponse(
        resolvedRequest: ResolvedOid4vpRequest,
        response: AuthorizationResponse,
        responseMode: ResponseMode? = null,
        jarmOptions: JarmOptions? = null,
    ): IdkResult<SubmissionResult, IdkError>

    /**
     * Binding-aware overload. Legacy adapters remain source-compatible and refuse non-null
     * bindings rather than silently dropping the prepared-recipient constraint.
     */
    // JavaScript has no overloads; overrides inherit this name.
    @JsName("submitAuthorizationResponseWithRecipientBinding")
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

/**
 * Adapter interface for OID4VP Holder (Wallet) operations without command exposure.
 *
 * This keeps a lightweight surface for integrations that only need the holder
 * operations and do not require access to the command objects.
 */
@JsExportCompat
@Suppress("NON_EXPORTABLE_TYPE")
@OptIn(ExperimentalObjCName::class)
@ObjCName("Oid4vpHolderAdapter", exact = true)
interface Oid4vpHolderAdapter : Oid4vpHolderService

/**
 * Main interface for OID4VP Holder (Wallet) operations.
 *
 * A Holder is responsible for:
 * 1. Parsing authorization requests from verifiers
 * 2. Resolving requests (fetching metadata, validating client identity)
 * 3. Creating authorization responses with selected credentials
 * 4. Submitting responses to the verifier
 *
 * Reference: OpenID4VP 1.0 - Wallet/Holder flow
 * - Section 5: Authorization Request
 * - Section 6: Authorization Response
 * - Section 8: Response Modes
 *
 * @see ResolvedOid4vpRequest
 * @see SelectedCredential
 * @see SubmissionResult
 */
@Suppress("NON_EXPORTABLE_TYPE")
@OptIn(ExperimentalObjCName::class)
@ObjCName("Oid4vpHolder", exact = true)
interface Oid4vpHolder : Oid4vpHolderAdapter {
    val commands: Commands

    interface Commands {
        val parseAuthorizationRequest: ParseAuthorizationRequestCommand
        val resolveAuthorizationRequest: ResolveAuthorizationRequestCommand
        val createAuthorizationResponse: CreateAuthorizationResponseCommand
        val submitAuthorizationResponse: SubmitAuthorizationResponseCommand
    }

    /**
     * Parses an authorization request from a URI.
     *
     * Handles multiple request formats:
     * - Direct request parameters (inline query string)
     * - Request by reference (request_uri)
     * - Request Object (signed JWT)
     *
     * Reference: OpenID4VP 1.0 Section 5.1 - Authorization Request
     *
     * @param requestUri The authorization request URI (e.g., "openid4vp://?client_id=...&request_uri=...")
     * @param walletConfig Optional wallet configuration for JWT validation (audience, decryption key)
     * @return Parsed authorization request or error
     */
    override suspend fun parseAuthorizationRequest(
        requestUri: String,
        walletConfig: WalletConfig?,
    ): IdkResult<AuthorizationRequest, IdkError>

    /**
     * Parses a request delivered by the W3C Digital Credentials API. The caller supplies the
     * browser [DigitalCredentialsAuthorizationRequest.origin] as trusted transport context.
     */
    override suspend fun parseDigitalCredentialsAuthorizationRequest(
        request: DigitalCredentialsAuthorizationRequest,
        walletConfig: WalletConfig?,
    ): IdkResult<AuthorizationRequest, IdkError>

    /**
     * Resolves an authorization request by fetching metadata and validating client identity.
     *
     * Resolution includes:
     * - Parsing DCQL query (if present)
     * - Fetching client metadata (if client_metadata_uri provided)
     * - Resolving client identity based on client_id_scheme
     * - Validating request parameters
     *
     * Reference: OpenID4VP 1.0
     * - Section 5.3: Client Metadata
     * - Section 10: Client Identifier Schemes
     *
     * @param request The parsed authorization request
     * @return Resolved request with metadata and client info or error
     */
    override suspend fun resolveAuthorizationRequest(request: AuthorizationRequest): IdkResult<ResolvedOid4vpRequest, IdkError>

    /**
     * Creates an authorization response with selected credentials.
     *
     * Response includes:
     * - VP Token(s) for selected credentials
     * - Presentation Submission mapping
     * - State/nonce from original request
     *
     * Reference: OpenID4VP 1.0 Section 6 - Authorization Response
     *
     * @param request The resolved authorization request
     * @param selectedCredentials List of credentials to present
     * @return Authorization response ready to submit or error
     */
    override suspend fun createAuthorizationResponse(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
    ): IdkResult<AuthorizationResponse, IdkError>

    /**
     * Submits an authorization response to the verifier.
     *
     * Submission method depends on response_mode:
     * - `direct_post`: HTTP POST to response_uri
     * - `direct_post.jwt`: HTTP POST with signed JWT
     * - `fragment`: URL redirect with fragment parameters
     * - `query`: URL redirect with query parameters
     *
     * Reference: OpenID4VP 1.0 Section 8 - Response Modes
     *
     * @param resolvedRequest The resolved authorization request (contains response_uri/redirect_uri)
     * @param response The authorization response to submit
     * @param responseMode Optional override for response mode (defaults to request's response_mode or DIRECT_POST)
     * @param jarmOptions Optional JARM options for `direct_post.jwt`
     * @return Result of the submission or error
     */
    override suspend fun submitAuthorizationResponse(
        resolvedRequest: ResolvedOid4vpRequest,
        response: AuthorizationResponse,
        responseMode: ResponseMode?,
        jarmOptions: JarmOptions?,
    ): IdkResult<SubmissionResult, IdkError>
}
