/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

package com.sphereon.wallet.interaction.holder.wiring

import com.sphereon.wallet.interaction.WalletSecurityAssurance
import com.sphereon.wallet.interaction.WalletSecurityChallenge
import com.sphereon.wallet.interaction.WalletSecurityChallengeKind
import com.sphereon.wallet.interaction.WalletSecurityGate
import com.sphereon.wallet.interaction.WalletSecurityGateRequest
import com.sphereon.wallet.interaction.WalletSecurityGateResult
import com.sphereon.wallet.interaction.WalletSecurityOperation
import com.sphereon.wallet.wsca.Wsca
import com.sphereon.wallet.wsca.WscaUserAuthenticationFactor
import com.sphereon.wallet.wscd.WscdProfile

/**
 * Production interaction gate. It declares the exact attended challenge required by WSCA;
 * the presenter/platform ceremony captures the factor and returns a one-use operation-bound grant.
 * This gate never captures secrets and never starts a second, hidden authentication ceremony.
 */
class WscaWalletSecurityGate(
    private val wscaProvider: () -> Wsca,
) : WalletSecurityGate {
    constructor(wsca: Wsca) : this({ wsca })

    private val wsca: Wsca by lazy { wscaProvider() }

    override suspend fun authorize(request: WalletSecurityGateRequest): WalletSecurityGateResult {
        val walletUnitId =
            request.walletUnitId
                ?: return denied("wallet.interaction.security.wallet_unit_missing")
        val operationBinding = request.operationBinding
            ?: return denied("wallet.interaction.security.operation_binding_missing")
        val primaryFactor = wsca.userAuthentication.primaryFactor(walletUnitId).getOrElse {
            return denied("wallet.interaction.security.enrollment_unavailable")
        } ?: return WalletSecurityGateResult.ChallengeRequired(
            WalletSecurityChallenge(
                challengeId = request.operationId,
                kind = WalletSecurityChallengeKind.PASSKEY,
                reasonKey = "wallet.interaction.security.enrollment_required",
                arguments = challengeArguments(request, walletUnitId, operationBinding),
                requiredAssurance = request.requiredAssurance,
            ),
        )
        val kind =
            when (request.requiredAssurance) {
                WalletSecurityAssurance.NONE,
                WalletSecurityAssurance.USER_PRESENT,
                WalletSecurityAssurance.PASSKEY,
                WalletSecurityAssurance.PIN,
                WalletSecurityAssurance.BIOMETRIC,
                -> when (primaryFactor) {
                    WscaUserAuthenticationFactor.PASSKEY -> WalletSecurityChallengeKind.PASSKEY
                    WscaUserAuthenticationFactor.PIN ->
                        if (
                            request.requiredAssurance == WalletSecurityAssurance.BIOMETRIC &&
                            wsca.userAuthentication.enrollmentCapabilities.value.biometric.available
                        ) {
                            WalletSecurityChallengeKind.BIOMETRIC
                        } else {
                            WalletSecurityChallengeKind.PIN
                        }
                    WscaUserAuthenticationFactor.BIOMETRIC ->
                        return denied("wallet.interaction.security.primary_factor_invalid")
                }
                WalletSecurityAssurance.HARDWARE_BACKED ->
                    if (wsca.wscdProfile == WscdProfile.LocalNative) {
                        WalletSecurityChallengeKind.LOCAL_TEE_UNLOCK
                    } else {
                        return denied("wallet.interaction.security.hardware_assurance_unavailable")
                    }
                WalletSecurityAssurance.REMOTE_AUTHORIZED ->
                    return denied("wallet.interaction.security.remote_authorization_required")
            }
        val arguments = challengeArguments(request, walletUnitId, operationBinding)
        return WalletSecurityGateResult.ChallengeRequired(
            WalletSecurityChallenge(
                challengeId = request.operationId,
                kind = kind,
                reasonKey = "wallet.interaction.security.authorization_required",
                arguments = arguments,
                requiredAssurance = request.requiredAssurance,
            ),
        )
    }

    private fun denied(reasonKey: String): WalletSecurityGateResult = WalletSecurityGateResult.Denied(reasonKey)

    /**
     * The holder ceremony reads `operationType` / `operationHash` / `nonce` / `audience` off these
     * arguments and refuses an unlock that omits them. Both the enrollment-required and the
     * already-enrolled challenge must therefore publish the same operation binding the gate was
     * asked to authorize -- otherwise Confirm cannot mint a grant that `validateFor` will accept.
     */
    private fun challengeArguments(
        request: WalletSecurityGateRequest,
        walletUnitId: String,
        operationBinding: String,
    ): Map<String, String> =
        buildMap {
            put("operation", request.operation.name)
            put("operation_binding", operationBinding)
            put("wallet_unit_id", walletUnitId)
            request.keyRef?.let { put("operationKeyRef", it) }
            request.audience?.let { put("audience", it) }
            put("operationType", request.operationType ?: namedOperationType(request.operation))
            request.operationHash?.let { put("operationHash", it) }
            request.nonce?.let { put("nonce", it) }
        }

    private fun namedOperationType(operation: WalletSecurityOperation): String =
        when (operation) {
            WalletSecurityOperation.PRESENT_PROOF -> "wallet.holder-proof"
            WalletSecurityOperation.PRESENT_CREDENTIALS -> "wallet.presentation-sharing"
            WalletSecurityOperation.CREDENTIAL_STORAGE -> "wallet.credential-storage"
            WalletSecurityOperation.LOCAL_HSM_UNLOCK -> "wallet.local-hsm-unlock"
            WalletSecurityOperation.REMOTE_KEY_AUTHORIZATION -> "wallet.remote-key-authorization"
        }
}
