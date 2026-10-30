/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import kotlin.time.Clock
import com.sphereon.core.api.Ok
import com.sphereon.core.api.IdkResult
import com.sphereon.oauth2.common.model.AuthorizationResponse
import com.sphereon.openid.oid4vp.common.CredentialFormat
import com.sphereon.openid.oid4vp.holder.HolderJwtVpSigningResult
import com.sphereon.wallet.interaction.ProtocolExecutionOwner
import com.sphereon.wallet.interaction.WalletInteractionPrivateSessionData
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import com.sphereon.core.api.error.IdkError
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.holder.JarmOptions
import com.sphereon.openid.oid4vp.holder.Oid4vpHolderService
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.SelectedCredential
import com.sphereon.openid.oid4vp.holder.SubmissionResult
import com.sphereon.openid.oid4vp.holder.WalletConfig
import com.sphereon.wallet.interaction.WalletInteractionContext
import com.sphereon.wallet.interaction.WalletInteractionFailureCodes
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.toDiagnosticDetails
import kotlinx.serialization.decodeFromString

interface Oid4vpSelectedCredentialResolver {
    suspend fun resolveSelectedCredentials(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedRequest: ResolvedOid4vpRequest,
        selectedCredentialIdsByRequirement: Map<String, List<String>>,
    ): List<SelectedCredential>

    suspend fun recordPresentationSubmitted(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedRequest: ResolvedOid4vpRequest,
        selectedCredentialIdsByRequirement: Map<String, List<String>>,
        selectedCredentials: List<SelectedCredential>,
    ) {
    }
}

interface Oid4vpWalletConfigProvider {
    suspend fun walletConfig(
        context: WalletInteractionContext,
        state: WalletInteractionState,
    ): WalletConfig?

    companion object {
        val none: Oid4vpWalletConfigProvider =
            object : Oid4vpWalletConfigProvider {
                override suspend fun walletConfig(
                    context: WalletInteractionContext,
                    state: WalletInteractionState,
                ): WalletConfig? = null
            }
    }
}

interface Oid4vpJarmOptionsProvider {
    suspend fun jarmOptions(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedRequest: ResolvedOid4vpRequest,
    ): JarmOptions?

    companion object {
        val none: Oid4vpJarmOptionsProvider =
            object : Oid4vpJarmOptionsProvider {
                override suspend fun jarmOptions(
                    context: WalletInteractionContext,
                    state: WalletInteractionState,
                    resolvedRequest: ResolvedOid4vpRequest,
                ): JarmOptions? = null
            }

        /**
         * Default holder-side JARM options enabling encrypted `direct_post.jwt` responses (OpenID4VP
         * 1.0 section 8.3: unsigned encrypted JWTs). The JWE configuration is derived downstream from
         * the verifier's client_metadata; the wallet unit id becomes the JARM payload issuer. No
         * signing key is provided, so a verifier demanding signed JARM fails with the explicit
         * signing-key error instead of silently degrading.
         */
        val walletUnitIssuer: Oid4vpJarmOptionsProvider =
            object : Oid4vpJarmOptionsProvider {
                override suspend fun jarmOptions(
                    context: WalletInteractionContext,
                    state: WalletInteractionState,
                    resolvedRequest: ResolvedOid4vpRequest,
                ): JarmOptions = JarmOptions(issuer = context.walletUnitId)
            }
    }
}

class Oid4vpHolderPresentationExecutor(
    private val holder: Oid4vpHolderService,
    private val selectedCredentialResolver: Oid4vpSelectedCredentialResolver,
    private val sdJwtHolderBindingProvider: Oid4vpSdJwtHolderBindingProvider,
    private val dataIntegrityHolderBindingProvider: Oid4vpDataIntegrityHolderBindingProvider = Oid4vpDataIntegrityHolderBindingProvider.none,
    private val walletConfigProvider: Oid4vpWalletConfigProvider = Oid4vpWalletConfigProvider.none,
    private val jarmOptionsProvider: Oid4vpJarmOptionsProvider = Oid4vpJarmOptionsProvider.none,
    private val responseMode: ResponseMode? = null,
    private val preparedJwtSigningProvider: Oid4vpPreparedJwtSigningProvider? = null,
    private val mdocHolderSigningProvider: Oid4vpMdocHolderSigningProvider? = null,
    private val nowEpochSeconds: () -> Long = { Clock.System.now().epochSeconds },
) : Oid4vpPresentationExecutor {
    override suspend fun preparePresentation(
        context: WalletInteractionContext,
        state: WalletInteractionState,
    ): Oid4vpPresentationPreparation {
        var stagedJwt = false
        return try {
            preparePresentationChecked(context, state) { stagedJwt = true }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            context.diagnostics.warn("oid4vp.prepare_presentation_failed", context.sessionId, failure.toDiagnosticDetails())
            // Preserve non-staged exception propagation; its caller retains the existing retry policy.
            if (!stagedJwt) throw failure
            prepareFailed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", null, retryable = false)
        }
    }

    private suspend fun preparePresentationChecked(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        markStagedJwt: () -> Unit,
    ): Oid4vpPresentationPreparation {
        val privateValues =
            context.privateSessionStore
                .get(context.sessionId, Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID)
                ?.values
                .orEmpty()
        if (listOf(JWT_INTENT, JWT_PREPARED, JWT_SIGNING_STARTED, JWT_FINAL_RESPONSE, JWT_DISPATCH_STARTED).any { it in privateValues }) {
            markStagedJwt()
        }
        requireResumablePrivateState(privateValues)
        val rawRequest =
            privateValues["entry_point.raw"]
                ?: return prepareFailed(WalletInteractionFailureCodes.OID4VP_AUTHORIZATION_REQUEST_MISSING, "wallet.interaction.error.oid4vp_authorization_request_missing", null, retryable = true)
        val request =
            cachedAuthorizationRequest(privateValues)
                ?: holder.parseAuthorizationRequest(rawRequest, walletConfigProvider.walletConfig(context, state)).getOrElse {
                    return prepareFailed(WalletInteractionFailureCodes.OID4VP_REQUEST_PARSE_FAILED, "wallet.interaction.error.oid4vp_request_parse_failed", it)
                }
        val resolved = holder.resolveAuthorizationRequest(request).getOrElse {
            return prepareFailed(WalletInteractionFailureCodes.OID4VP_REQUEST_RESOLVE_FAILED, "wallet.interaction.error.oid4vp_request_resolve_failed", it)
        }
        val selectedCredentials =
            try {
                selectedCredentialResolver.resolveSelectedCredentials(
                    context = context,
                    state = state,
                    resolvedRequest = resolved,
                    selectedCredentialIdsByRequirement = selectedIdsByRequirement(privateValues, state),
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                context.diagnostics.warn("oid4vp.resolve_selected_credentials_failed", context.sessionId, failure.toDiagnosticDetails())
                return prepareFailed(WalletInteractionFailureCodes.OID4VP_CREDENTIAL_RESOLUTION_FAILED, "wallet.interaction.error.oid4vp_credential_resolution_failed", null, retryable = true)
            }
        val binding = operationBinding(context, state)
        val boundSelection = selectedCredentials.map {
            it.copy(holderJwtVpOperationBinding = binding, holderJwtVpWalletUnitId = context.walletUnitId)
        }
        val jwtCredentials = boundSelection.filter { it.isJwtVpCredential() }
        val stagedJwt = context.executionOwner == ProtocolExecutionOwner.WALLET_BACKEND && jwtCredentials.isNotEmpty()
        val stagedMdoc = context.executionOwner == ProtocolExecutionOwner.WALLET_BACKEND &&
            mdocHolderSigningProvider != null && boundSelection.any { it.credentialFormat?.isMdoc == true }
        val stagedPreparedPresentation = stagedJwt || stagedMdoc
        if (stagedPreparedPresentation) markStagedJwt()
        if (privateValues[JWT_INTENT] != null) {
            check(stagedPreparedPresentation && privateValues[JWT_SIGNING_STARTED] == null && privateValues[JWT_DISPATCH_STARTED] == null)
            val saved = readPrepared(privateValues)
            saved.requireUsable(context, resolved, boundSelection, selectedIdsByRequirement(privateValues, state), binding, nowEpochSeconds(), responseMode)
            return saved.approvalRequired() ?: prepareFailed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", null)
        }
        if (stagedPreparedPresentation) {
            if (stagedJwt) checkNotNull(preparedJwtSigningProvider) { "Prepared JWT signer is required for backend JWT presentation" }
            check(!binding.isNullOrBlank())
            // Write and read back intent before key preparation. An incomplete preparation cannot regenerate on reentry.
            putPrivate(context, mapOf(JWT_INTENT to "true"))
        }
        val issuedAt = nowEpochSeconds()
        val operations =
            sdJwtHolderBindingProvider
                .prepareHolderBinding(
                    Oid4vpSdJwtHolderBindingRequest(
                        walletUnitId = context.walletUnitId,
                        operationBinding = operationBinding(context, state),
                        request = resolved,
                        selectedCredentials = selectedCredentials,
                        issuedAtEpochSeconds = issuedAt,
                    ),
                ).getOrElse {
                    return prepareFailed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", it)
                }
        if (stagedPreparedPresentation) {
            val prepared = if (stagedJwt) holder.prepareJwtVpResponse(resolved, jwtCredentials).getOrElse {
                return prepareFailed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", it)
            } else null
            val signing = prepared?.presentations.orEmpty().map { item ->
                preparedJwtSigningProvider!!.prepare(item.signingRequest).getOrElse {
                    return prepareFailed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", it)
                }
            }
            val mdocSigning = if (stagedMdoc) {
                mdocHolderSigningProvider!!.prepare(
                    Oid4vpMdocHolderSigningRequest(context.walletUnitId, binding, resolved, boundSelection),
                ).getOrElse {
                    return prepareFailed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", it)
                }
            } else emptyList()
            if (stagedMdoc && mdocSigning.isEmpty()) {
                return prepareFailed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", null)
            }
            val expiry = (listOf(issuedAt + 120) + listOfNotNull(
                (resolved.request.additionalParameters["exp"] as? JsonPrimitive)?.longOrNull,
            ) + prepared?.presentations.orEmpty().mapNotNull { (it.signingRequest.payload["exp"] as? JsonPrimitive)?.longOrNull }).min()
            val saved = Oid4vpPreparedJwtPresentation(
                context.sessionId, context.walletUnitId, checkNotNull(binding), resolved,
                Oid4vpPreparedJwtPresentation.selectionFingerprint(boundSelection), selectedIdsByRequirement(privateValues, state),
                issuedAt, expiry, prepared, signing, mdocSigning, operations.size,
                operations + mdocSigning.map { it.operation } + signing.map { it.approvalOperation() },
            ).sealed()
            saved.requireUsable(context, resolved, boundSelection, selectedIdsByRequirement(privateValues, state), binding, nowEpochSeconds(), responseMode)
            putPrivate(context, mapOf(JWT_PREPARED to Oid4vpWalletInteractionProtocolAdapter.json.encodeToString(saved), KEY_BINDING_ISSUED_AT_PRIVATE_KEY to issuedAt.toString()))
            return saved.approvalRequired() ?: prepareFailed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", null)
        }
        if (operations.isEmpty()) return Oid4vpPresentationPreparation.Ready
        context.privateSessionStore.put(
            context.sessionId,
            com.sphereon.wallet.interaction.WalletInteractionPrivateSessionData(
                namespace = Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID,
                values = privateValues + (KEY_BINDING_ISSUED_AT_PRIVATE_KEY to issuedAt.toString()),
            ),
        )
        return Oid4vpPresentationPreparation.ApprovalRequired(operations)
    }

    private fun requireResumablePrivateState(values: Map<String, String>) {
        check(values[JWT_INTENT] == null || values[JWT_PREPARED] != null) {
            "Prepared presentation intent has no completed snapshot"
        }
        check(values[JWT_SIGNING_STARTED] == null || values[JWT_FINAL_RESPONSE] != null) {
            "Prepared presentation signing was interrupted before its final response was saved"
        }
        check(values[JWT_DISPATCH_STARTED] == null) {
            "Prepared presentation dispatch was already claimed"
        }
    }

    private suspend fun operationBinding(
        context: WalletInteractionContext,
        state: WalletInteractionState,
    ): String? =
        state.adapterId?.let { namespace ->
            context.privateSessionStore
                .get(context.sessionId, namespace)
                ?.values
                ?.get(Oid4vpWalletInteractionProtocolAdapter.SECURITY_OPERATION_BINDING_PRIVATE_KEY)
        }

    private fun prepareFailed(
        code: String,
        messageKey: String,
        error: IdkError?,
        retryable: Boolean = false,
    ): Oid4vpPresentationPreparation.Failed =
        Oid4vpPresentationPreparation.Failed(
            code = code,
            messageKey = messageKey,
            retryable = retryable,
            arguments =
                error?.let {
                    buildMap {
                        put("providerErrorCode", it.code)
                        it.message.defaultMessage.takeIf(String::isNotBlank)?.let { message -> put("providerErrorMessage", message) }
                    }
                }.orEmpty(),
        )

    override suspend fun submitPresentation(
        context: WalletInteractionContext,
        state: WalletInteractionState,
    ): Oid4vpPresentationExecutionResult {
        var stagedJwt = false
        return try {
            submitPresentationChecked(context, state) { stagedJwt = true }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            context.diagnostics.warn("oid4vp.submit_presentation_failed", context.sessionId, failure.toDiagnosticDetails())
            // Preserve non-staged exception propagation; its caller retains the existing retry policy.
            if (!stagedJwt) throw failure
            failed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", retryable = false)
        }
    }

    private suspend fun submitPresentationChecked(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        markStagedJwt: () -> Unit,
    ): Oid4vpPresentationExecutionResult {
        val privateValues =
            context.privateSessionStore
                .get(context.sessionId, Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID)
                ?.values
                .orEmpty()
        if (listOf(JWT_INTENT, JWT_PREPARED, JWT_SIGNING_STARTED, JWT_FINAL_RESPONSE, JWT_DISPATCH_STARTED).any { it in privateValues }) {
            markStagedJwt()
        }
        requireResumablePrivateState(privateValues)
        val rawRequest =
            privateValues["entry_point.raw"]
                ?: return failed(
                    code = WalletInteractionFailureCodes.OID4VP_AUTHORIZATION_REQUEST_MISSING,
                    messageKey = "wallet.interaction.error.oid4vp_authorization_request_missing",
                    retryable = true,
                )

        val request =
            cachedAuthorizationRequest(privateValues)
                ?: run {
                    val parsed = holder.parseAuthorizationRequest(rawRequest, walletConfigProvider.walletConfig(context, state))
                    if (parsed.isErr) {
                        return failed(WalletInteractionFailureCodes.OID4VP_REQUEST_PARSE_FAILED, "wallet.interaction.error.oid4vp_request_parse_failed", parsed.error)
                    }
                    parsed.value
                }

        val resolved = holder.resolveAuthorizationRequest(request)
        if (resolved.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VP_REQUEST_RESOLVE_FAILED, "wallet.interaction.error.oid4vp_request_resolve_failed", resolved.error)
        }

        val selectedCredentials =
            try {
                selectedCredentialResolver.resolveSelectedCredentials(
                    context = context,
                    state = state,
                    resolvedRequest = resolved.value,
                    selectedCredentialIdsByRequirement = selectedIdsByRequirement(privateValues, state),
                )
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                context.diagnostics.warn("oid4vp.resolve_selected_credentials_failed", context.sessionId, failure.toDiagnosticDetails())
                return failed(
                    code = WalletInteractionFailureCodes.OID4VP_CREDENTIAL_RESOLUTION_FAILED,
                    messageKey = "wallet.interaction.error.oid4vp_credential_resolution_failed",
                    retryable = true,
                )
            }

        val operationBinding = operationBinding(context, state)
        val selectedCredentialsWithBinding =
            selectedCredentials.map {
                it.copy(
                    holderJwtVpOperationBinding = operationBinding,
                    holderJwtVpWalletUnitId = context.walletUnitId,
                )
            }
        val stagedJwt = context.executionOwner == ProtocolExecutionOwner.WALLET_BACKEND && selectedCredentialsWithBinding.any { it.isJwtVpCredential() }
        val stagedMdoc = context.executionOwner == ProtocolExecutionOwner.WALLET_BACKEND &&
            mdocHolderSigningProvider != null && selectedCredentialsWithBinding.any { it.credentialFormat?.isMdoc == true }
        val stagedPreparedPresentation = privateValues[JWT_INTENT] != null || stagedJwt || stagedMdoc
        if (stagedPreparedPresentation) markStagedJwt()
        val preparedPresentation = if (stagedPreparedPresentation) {
            check(privateValues[JWT_INTENT] == "true")
            check(privateValues[JWT_DISPATCH_STARTED] == null) { "Prepared presentation was already dispatched" }
            readPrepared(privateValues).also {
                it.requireUsable(context, resolved.value, selectedCredentialsWithBinding, selectedIdsByRequirement(privateValues, state), operationBinding, nowEpochSeconds(), responseMode)
                check(privateValues[KEY_BINDING_ISSUED_AT_PRIVATE_KEY]?.toLongOrNull() == it.issuedAt)
            }
        } else null
        val savedResponse = privateValues[JWT_FINAL_RESPONSE]?.let {
            checkNotNull(preparedPresentation)
            Oid4vpWalletInteractionProtocolAdapter.json.decodeFromString<AuthorizationResponse>(it)
        }
        val response: IdkResult<AuthorizationResponse, IdkError> = if (savedResponse != null) Ok(savedResponse) else {
        if (preparedPresentation != null) {
            if (preparedPresentation.signing.isNotEmpty()) checkNotNull(preparedJwtSigningProvider)
            check(privateValues[JWT_SIGNING_STARTED] == null) { "Prepared presentation signing was already attempted" }
            putPrivate(context, mapOf(JWT_SIGNING_STARTED to "true"))
        }
        val mdocValidation = if (preparedPresentation?.mdocSigning?.isNotEmpty() == true) {
            mdocHolderSigningProvider?.validate(
                Oid4vpMdocHolderSigningRequest(context.walletUnitId, operationBinding, resolved.value, selectedCredentialsWithBinding),
                preparedPresentation.mdocSigning,
            )?.getOrElse {
                return failed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", it)
            } ?: return failed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", retryable = false)
        } else null
        // The mdoc SessionTranscript commits to the verifier key the response is encrypted to; a
        // recipient binding that no longer names that key must never reach an mdoc signature.
        if (preparedPresentation?.mdocSigning?.any { it.signing.recipientBinding?.matchesVerifierEncryptionKey(resolved.value) == false } == true) {
            return failed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", retryable = false)
        }
        val dataIntegrityBinding =
            dataIntegrityHolderBindingProvider
                .applyHolderBinding(
                    Oid4vpDataIntegrityHolderBindingRequest(
                        walletUnitId = context.walletUnitId,
                        operationBinding = operationBinding,
                        request = resolved.value,
                        selectedCredentials = selectedCredentialsWithBinding,
                    ),
                ).getOrElse {
                    return failed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", it)
                }
        val boundCredentials =
            sdJwtHolderBindingProvider
                .applyHolderBinding(
                    Oid4vpSdJwtHolderBindingRequest(
                        walletUnitId = context.walletUnitId,
                        operationBinding = operationBinding,
                        request = resolved.value,
                        selectedCredentials = dataIntegrityBinding.selectedCredentials,
                        issuedAtEpochSeconds = privateValues[KEY_BINDING_ISSUED_AT_PRIVATE_KEY]?.toLongOrNull(),
                    ),
                ).getOrElse {
                    return failed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", it)
                }

        if (preparedPresentation == null) holder.createAuthorizationResponse(
            resolved.value, boundCredentials, dataIntegrityBinding.preparedPresentations,
        ) else {
            val jwtSignatures = preparedPresentation.signing.map { snapshot ->
                preparedJwtSigningProvider!!.finalize(snapshot).getOrElse {
                    return failed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", it)
                }
            }
            val mdocSignatures = if (preparedPresentation.mdocSigning.isNotEmpty()) {
                mdocHolderSigningProvider?.finalize(
                    Oid4vpMdocHolderSigningRequest(context.walletUnitId, operationBinding, resolved.value, selectedCredentialsWithBinding),
                    preparedPresentation.mdocSigning,
                    checkNotNull(mdocValidation),
                )?.getOrElse {
                    return failed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", it)
                } ?: return failed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", retryable = false)
            } else emptyList()
            if (preparedPresentation.mdocSigning.isEmpty()) {
                val preparedJwtVp = preparedPresentation.prepared
                    ?: return failed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", retryable = false)
                holder.createAuthorizationResponseWithPreparedJwtVp(
                    resolved.value, boundCredentials, dataIntegrityBinding.preparedPresentations, preparedJwtVp, jwtSignatures,
                )
            } else {
                holder.createAuthorizationResponseWithPreparedSignatures(
                    request = resolved.value,
                    selectedCredentials = boundCredentials,
                    preparedPresentations = dataIntegrityBinding.preparedPresentations,
                    preparedJwtVp = preparedPresentation.prepared,
                    jwtSignatures = jwtSignatures,
                    preparedMdocSignings = preparedPresentation.mdocSigning.map { it.signing },
                    mdocSignatures = mdocSignatures,
                )
            }
        }
        }
        if (response.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED, "wallet.interaction.error.oid4vp_response_creation_failed", response.error)
        }

        if (preparedPresentation != null) {
            if (savedResponse == null) putPrivate(context, mapOf(JWT_FINAL_RESPONSE to Oid4vpWalletInteractionProtocolAdapter.json.encodeToString(response.value)))
            // The controller owns the durable dispatch claim. Private KV does not claim atomicity.
            // An ambiguous POST may not sign again or silently repeat a non-idempotent submission.
            putPrivate(context, mapOf(JWT_DISPATCH_STARTED to "true"))
        }
        val preparedJweRecipientBinding =
            if (responseMode == ResponseMode.DIRECT_POST_JWT || responseMode == ResponseMode.DC_API_JWT ||
                (responseMode == null && (resolved.value.request.responseMode == ResponseMode.DIRECT_POST_JWT.value ||
                    resolved.value.request.responseMode == ResponseMode.DC_API_JWT.value))) {
                preparedPresentation?.mdocSigning?.firstOrNull()?.signing?.recipientBinding
            } else {
                null
            }
        val jarmOptions = jarmOptionsProvider.jarmOptions(context, state, resolved.value)
        val submission =
            if (preparedJweRecipientBinding != null) {
                holder.submitAuthorizationResponse(
                    resolvedRequest = resolved.value,
                    response = response.value,
                    responseMode = responseMode,
                    jarmOptions = jarmOptions,
                    preparedOid4vpJweRecipientBinding = preparedJweRecipientBinding,
                )
            } else {
                holder.submitAuthorizationResponse(
                    resolvedRequest = resolved.value,
                    response = response.value,
                    responseMode = responseMode,
                    jarmOptions = jarmOptions,
                )
            }
        if (submission.isErr) {
            return failed(WalletInteractionFailureCodes.OID4VP_RESPONSE_SUBMISSION_FAILED, "wallet.interaction.error.oid4vp_response_submission_failed", submission.error)
        }

        suspend fun recordPresentationSubmitted(): Oid4vpPresentationExecutionResult.Failed? =
            try {
                selectedCredentialResolver.recordPresentationSubmitted(
                    context = context,
                    state = state,
                    resolvedRequest = resolved.value,
                    selectedCredentialIdsByRequirement = selectedIdsByRequirement(privateValues, state),
                    selectedCredentials = selectedCredentials,
                )
                null
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                context.diagnostics.warn("oid4vp.record_presentation_failed", context.sessionId, failure.toDiagnosticDetails())
                failed(
                    code = WalletInteractionFailureCodes.OID4VP_PRESENTATION_HISTORY_UPDATE_FAILED,
                    messageKey = "wallet.interaction.error.oid4vp_presentation_history_update_failed",
                    retryable = false,
                )
            }

        return when (val result = submission.value) {
            is SubmissionResult.Success -> {
                recordPresentationSubmitted()
                    ?: (
                        result.redirectUri?.let { Oid4vpPresentationExecutionResult.RedirectRequired(it) }
                            ?: Oid4vpPresentationExecutionResult.Submitted()
                    )
            }

            is SubmissionResult.Redirect -> {
                recordPresentationSubmitted()
                    ?: Oid4vpPresentationExecutionResult.RedirectRequired(result.redirectUri)
            }

            is SubmissionResult.DigitalCredential -> {
                recordPresentationSubmitted()
                    ?: Oid4vpPresentationExecutionResult.DigitalCredentialResponse(result.data)
            }

            is SubmissionResult.Error -> {
                Oid4vpPresentationExecutionResult.Failed(
                    code = WalletInteractionFailureCodes.OID4VP_VERIFIER_ERROR,
                    messageKey = "wallet.interaction.error.oid4vp_verifier_error",
                    arguments = mapOf("protocolError" to result.error),
                )
            }
        }
    }

    private fun SelectedCredential.isJwtVpCredential(): Boolean =
        credentialFormat == CredentialFormat.JWT_VC_JSON || credentialFormat == CredentialFormat.JWT_VC_JSON_LD

    private fun readPrepared(values: Map<String, String>): Oid4vpPreparedJwtPresentation =
        Oid4vpWalletInteractionProtocolAdapter.json.decodeFromString(checkNotNull(values[JWT_PREPARED]))

    private suspend fun putPrivate(context: WalletInteractionContext, added: Map<String, String>) {
        val namespace = Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID
        val existing = context.privateSessionStore.get(context.sessionId, namespace)?.values.orEmpty()
        context.privateSessionStore.put(context.sessionId, WalletInteractionPrivateSessionData(namespace, existing + added))
        val persisted = context.privateSessionStore.get(context.sessionId, namespace)?.values.orEmpty()
        check(added.all { (key, value) -> persisted[key] == value }) { "Prepared presentation persistence failed" }
    }

    private fun selectedIdsByRequirement(
        privateValues: Map<String, String>,
        state: WalletInteractionState,
    ): Map<String, List<String>> {
        privateValues["selected_credential_ids_by_requirement"]?.let { serialized ->
            return Oid4vpWalletInteractionProtocolAdapter.json.decodeFromString(serialized)
        }
        val selectedIds = state.disclosure?.selectedCredentialIds.orEmpty()
        val requirements = state.credentialSelection?.requirements.orEmpty()
        return if (selectedIds.isNotEmpty() && requirements.size == 1) {
            mapOf(requirements.single().id to selectedIds)
        } else {
            emptyMap()
        }
    }

    private fun cachedAuthorizationRequest(privateValues: Map<String, String>): AuthorizationRequest? =
        privateValues["authorization_request"]?.let { serialized ->
            runCatching {
                Oid4vpWalletInteractionProtocolAdapter.json.decodeFromString(AuthorizationRequest.serializer(), serialized)
            }.getOrNull()
        }

    private fun failed(
        code: String,
        messageKey: String,
        error: IdkError,
        retryable: Boolean = false,
    ): Oid4vpPresentationExecutionResult.Failed =
        failed(
            code = code,
            messageKey = messageKey,
            retryable = retryable,
            arguments =
                buildMap {
                    put("providerErrorCode", error.code)
                    error.message.defaultMessage
                        .takeIf { it.isNotBlank() }
                        ?.let { put("providerErrorMessage", it) }
                },
        )

    private fun failed(
        code: String,
        messageKey: String,
        retryable: Boolean = false,
        arguments: Map<String, String> = emptyMap(),
    ): Oid4vpPresentationExecutionResult.Failed =
        Oid4vpPresentationExecutionResult.Failed(
            code = code,
            messageKey = messageKey,
            retryable = retryable,
            arguments = arguments,
        )

    private companion object {
        const val JWT_INTENT = "jwt_vp.intent"
        const val JWT_PREPARED = "jwt_vp.prepared"
        const val JWT_SIGNING_STARTED = "jwt_vp.signing_started"
        const val JWT_FINAL_RESPONSE = "jwt_vp.final_response"
        const val JWT_DISPATCH_STARTED = "jwt_vp.dispatch_started"
        /** The Key Binding JWTs' `iat` of the presentation the holder is approving. */
        const val KEY_BINDING_ISSUED_AT_PRIVATE_KEY = "key_binding_issued_at"
    }
}
