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

package com.sphereon.openid.oid4vp.holder.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.oauth2.common.model.AuthorizationResponse
import com.sphereon.oauth2.common.model.AuthorizationErrorResponse
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.holder.CreateAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.holder.CreateAuthorizationResponseCommand
import com.sphereon.openid.oid4vp.holder.DigitalCredentialsAuthorizationRequest
import com.sphereon.openid.oid4vp.holder.FinalizeJwtVpResponseArgs
import com.sphereon.openid.oid4vp.holder.FinalizeJwtVpResponseCommand
import com.sphereon.openid.oid4vp.holder.HolderJwtVpPreparationCredential
import com.sphereon.openid.oid4vp.holder.HolderJwtVpSigningResult
import com.sphereon.openid.oid4vp.holder.HolderPreparedJwtVpResponse
import com.sphereon.openid.oid4vp.holder.PreparedMdocCredentialSigning
import com.sphereon.openid.oid4vp.holder.PreparedOid4vpJweRecipientBinding
import com.sphereon.openid.oid4vp.holder.MdocCredentialSigningSignature
import com.sphereon.openid.oid4vp.holder.JarmOptions
import com.sphereon.openid.oid4vp.holder.Oid4vpHolder
import com.sphereon.openid.oid4vp.holder.Oid4vpHolder.Commands
import com.sphereon.openid.oid4vp.holder.Oid4vpHolderAdapter
import com.sphereon.openid.oid4vp.holder.Oid4vpHolderService
import com.sphereon.openid.oid4vp.holder.ParseAuthorizationRequestArgs
import com.sphereon.openid.oid4vp.holder.ParseAuthorizationRequestCommand
import com.sphereon.openid.oid4vp.holder.PrepareJwtVpResponseArgs
import com.sphereon.openid.oid4vp.holder.PrepareJwtVpResponseCommand
import com.sphereon.openid.oid4vp.holder.PreparedPresentation
import com.sphereon.openid.oid4vp.holder.ResolveAuthorizationRequestCommand
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.SelectedCredential
import com.sphereon.openid.oid4vp.holder.SubmissionResult
import com.sphereon.openid.oid4vp.holder.SubmitAuthorizationResponseArgs
import com.sphereon.openid.oid4vp.holder.SubmitAuthorizationResponseCommand
import com.sphereon.openid.oid4vp.holder.WalletConfig
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

/**
 * Implementation of the OID4VP Holder service.
 *
 * This service handles wallet/holder operations for OpenID4VP:
 * - Parsing and resolving authorization requests
 * - Creating authorization responses with VP tokens
 * - Submitting responses to verifiers
 *
 * Reference: OpenID4VP 1.0
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<Oid4vpHolder>())
@ContributesBinding(SessionScope::class, binding = binding<Oid4vpHolderService>())
@ContributesBinding(SessionScope::class, binding = binding<Oid4vpHolderAdapter>())
class Oid4vpHolderServiceImpl(
    private val parseAuthorizationRequestCommand: ParseAuthorizationRequestCommand,
    private val resolveAuthorizationRequestCommand: ResolveAuthorizationRequestCommand,
    private val createAuthorizationResponseCommand: CreateAuthorizationResponseCommand,
    private val submitAuthorizationResponseCommand: SubmitAuthorizationResponseCommand,
    private val prepareJwtVpResponseCommand: PrepareJwtVpResponseCommand,
    private val finalizeJwtVpResponseCommand: FinalizeJwtVpResponseCommand,
) : Oid4vpHolder {
    inner class CommandsImpl : Commands {
        override val parseAuthorizationRequest: ParseAuthorizationRequestCommand = this@Oid4vpHolderServiceImpl.parseAuthorizationRequestCommand
        override val resolveAuthorizationRequest: ResolveAuthorizationRequestCommand = this@Oid4vpHolderServiceImpl.resolveAuthorizationRequestCommand
        override val createAuthorizationResponse: CreateAuthorizationResponseCommand = this@Oid4vpHolderServiceImpl.createAuthorizationResponseCommand
        override val submitAuthorizationResponse: SubmitAuthorizationResponseCommand = this@Oid4vpHolderServiceImpl.submitAuthorizationResponseCommand
    }

    override val commands: Commands = CommandsImpl()

    override suspend fun parseAuthorizationRequest(
        requestUri: String,
        walletConfig: WalletConfig?,
    ): IdkResult<AuthorizationRequest, IdkError> = parseAuthorizationRequestCommand.execute(ParseAuthorizationRequestArgs(requestUri, walletConfig))

    override suspend fun parseDigitalCredentialsAuthorizationRequest(
        request: DigitalCredentialsAuthorizationRequest,
        walletConfig: WalletConfig?,
    ): IdkResult<AuthorizationRequest, IdkError> =
        parseAuthorizationRequestCommand.execute(
            ParseAuthorizationRequestArgs(walletConfig = walletConfig, digitalCredentialsRequest = request),
        )

    override suspend fun resolveAuthorizationRequest(request: AuthorizationRequest): IdkResult<ResolvedOid4vpRequest, IdkError> = resolveAuthorizationRequestCommand.execute(request)

    override suspend fun createAuthorizationResponse(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
    ): IdkResult<AuthorizationResponse, IdkError> = createAuthorizationResponseCommand.execute(CreateAuthorizationResponseArgs(request, selectedCredentials, preparedPresentations))

    override suspend fun createAuthorizationResponseWithPreparedJwtVp(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedJwtVp: HolderPreparedJwtVpResponse,
        signatures: List<com.sphereon.openid.oid4vp.holder.HolderJwtVpSigningResult>,
    ): IdkResult<AuthorizationResponse, IdkError> = createAuthorizationResponseCommand.execute(
        CreateAuthorizationResponseArgs(request, selectedCredentials, preparedPresentations, preparedJwtVp, signatures),
    )

    override suspend fun prepareMdocDeviceAuthenticationSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
    ): IdkResult<List<PreparedMdocCredentialSigning>, IdkError> =
        createAuthorizationResponseCommand.prepareMdocDeviceAuthenticationSignatures(request, selectedCredentials)

    override suspend fun createAuthorizationResponseWithPreparedMdocDeviceAuthenticationSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedMdocSignings: List<PreparedMdocCredentialSigning>,
        signatures: List<MdocCredentialSigningSignature>,
    ): IdkResult<AuthorizationResponse, IdkError> =
        createAuthorizationResponseCommand.createAuthorizationResponseWithPreparedMdocDeviceAuthenticationSignatures(
            request,
            selectedCredentials,
            preparedPresentations,
            preparedMdocSignings,
            signatures,
        )

    override suspend fun createAuthorizationResponseWithPreparedSignatures(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
        preparedPresentations: List<PreparedPresentation>,
        preparedJwtVp: HolderPreparedJwtVpResponse?,
        jwtSignatures: List<HolderJwtVpSigningResult>,
        preparedMdocSignings: List<PreparedMdocCredentialSigning>,
        mdocSignatures: List<MdocCredentialSigningSignature>,
    ): IdkResult<AuthorizationResponse, IdkError> =
        createAuthorizationResponseCommand.createAuthorizationResponseWithPreparedSignatures(
            request,
            selectedCredentials,
            preparedPresentations,
            preparedJwtVp,
            jwtSignatures,
            preparedMdocSignings,
            mdocSignatures,
        )

    override suspend fun prepareJwtVpResponse(
        request: ResolvedOid4vpRequest,
        selectedCredentials: List<SelectedCredential>,
    ): IdkResult<HolderPreparedJwtVpResponse, IdkError> {
        val selected = selectedCredentials.map { credential ->
            val identifier = credential.holderJwtVpSigningIdentifier
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JWT VP signing identifier is missing"))
            val algorithm = credential.holderSigningAlgorithm
                ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JWT VP signing algorithm is missing"))
            HolderJwtVpPreparationCredential(credential, identifier, algorithm)
        }
        return prepareJwtVpResponseCommand.execute(PrepareJwtVpResponseArgs(request, selected))
    }

    override suspend fun finalizeJwtVpResponse(
        prepared: HolderPreparedJwtVpResponse,
        signatures: List<HolderJwtVpSigningResult>,
    ): IdkResult<AuthorizationResponse, IdkError> =
        finalizeJwtVpResponseCommand.execute(FinalizeJwtVpResponseArgs(prepared, signatures))

    override suspend fun submitAuthorizationErrorResponse(
        resolvedRequest: ResolvedOid4vpRequest,
        error: AuthorizationErrorResponse,
        responseMode: ResponseMode?,
        jarmOptions: JarmOptions?,
    ): IdkResult<SubmissionResult, IdkError> = submitAuthorizationResponseCommand.execute(
        SubmitAuthorizationResponseArgs(
            resolvedRequest = resolvedRequest,
            errorResponse = error,
            responseMode = responseMode,
            jarmOptions = jarmOptions,
        ),
    )

    override suspend fun submitAuthorizationResponse(
        resolvedRequest: ResolvedOid4vpRequest,
        response: AuthorizationResponse,
        responseMode: ResponseMode?,
        jarmOptions: JarmOptions?,
    ): IdkResult<SubmissionResult, IdkError> = submitAuthorizationResponseCommand.execute(
        SubmitAuthorizationResponseArgs(resolvedRequest, response, responseMode, jarmOptions, null),
    )

    override suspend fun submitAuthorizationResponse(
        resolvedRequest: ResolvedOid4vpRequest,
        response: AuthorizationResponse,
        responseMode: ResponseMode?,
        jarmOptions: JarmOptions?,
        preparedOid4vpJweRecipientBinding: PreparedOid4vpJweRecipientBinding,
    ): IdkResult<SubmissionResult, IdkError> =
        submitAuthorizationResponseCommand.execute(
            SubmitAuthorizationResponseArgs(
                resolvedRequest,
                response,
                responseMode,
                jarmOptions,
                preparedOid4vpJweRecipientBinding,
            ),
        )
}
