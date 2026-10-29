/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import com.sphereon.wallet.interaction.WalletApprovalOperation
import com.sphereon.wallet.interaction.WalletInteractionContext
import com.sphereon.wallet.interaction.WalletInteractionFailureCodes
import com.sphereon.wallet.interaction.WalletInteractionState
import kotlinx.serialization.json.JsonObject

interface Oid4vpPresentationExecutor {
    /**
     * Prepares the selected presentation without signing it, and states the holder-key signatures
     * it needs so the holder approves exactly those before [submitPresentation] signs them.
     */
    suspend fun preparePresentation(
        context: WalletInteractionContext,
        state: WalletInteractionState,
    ): Oid4vpPresentationPreparation = Oid4vpPresentationPreparation.Ready

    suspend fun submitPresentation(
        context: WalletInteractionContext,
        state: WalletInteractionState,
    ): Oid4vpPresentationExecutionResult

    companion object {
        val notConfigured: Oid4vpPresentationExecutor =
            object : Oid4vpPresentationExecutor {
                override suspend fun submitPresentation(
                    context: WalletInteractionContext,
                    state: WalletInteractionState,
                ): Oid4vpPresentationExecutionResult =
                    Oid4vpPresentationExecutionResult.Failed(
                        code = WalletInteractionFailureCodes.OID4VP_EXECUTION_NOT_CONFIGURED,
                        messageKey = "wallet.interaction.error.oid4vp_execution_not_configured",
                        retryable = true,
                    )
            }
    }
}

sealed class Oid4vpPresentationPreparation {
    /** The presentation signs nothing the holder has to approve. */
    data object Ready : Oid4vpPresentationPreparation()

    /** One approval of these holder-key signatures, on this wallet unit, before anything is signed. */
    data class ApprovalRequired(
        val operations: List<WalletApprovalOperation>,
        /** The wallet account owning the prepared holder keys, when the prepared signings name it. */
        val walletAccountId: String? = null,
    ) : Oid4vpPresentationPreparation() {
        init {
            require(operations.isNotEmpty()) { "oid4vp_presentation_approval_operations_empty" }
        }
    }

    data class Failed(
        val code: String,
        val messageKey: String,
        val retryable: Boolean = false,
        val arguments: Map<String, String> = emptyMap(),
    ) : Oid4vpPresentationPreparation()
}

sealed class Oid4vpPresentationExecutionResult {
    data class Submitted(
        val titleKey: String = "wallet.interaction.status.presentation_shared",
    ) : Oid4vpPresentationExecutionResult()

    data class Sharing(
        val titleKey: String = "wallet.interaction.status.sharing",
    ) : Oid4vpPresentationExecutionResult()

    data class RedirectRequired(
        val redirectUri: String,
    ) : Oid4vpPresentationExecutionResult()

    data class DigitalCredentialResponse(
        val data: JsonObject,
    ) : Oid4vpPresentationExecutionResult()

    data class Failed(
        val code: String,
        val messageKey: String,
        val retryable: Boolean = false,
        val arguments: Map<String, String> = emptyMap(),
    ) : Oid4vpPresentationExecutionResult()
}
