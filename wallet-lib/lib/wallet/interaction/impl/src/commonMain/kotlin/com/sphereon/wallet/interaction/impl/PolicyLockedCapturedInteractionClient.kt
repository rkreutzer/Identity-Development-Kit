/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.wallet.interaction.impl

import com.sphereon.core.api.encodeToHex
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.wallet.interaction.CapturedInteractionClient
import com.sphereon.wallet.interaction.CapturedInteractionInput
import com.sphereon.wallet.interaction.CapturedInteractionRuntimePlanResolver
import com.sphereon.wallet.interaction.ProtocolExecutionOwner
import com.sphereon.wallet.interaction.WalletEntryPoint
import com.sphereon.wallet.interaction.WalletInteractionAction
import com.sphereon.wallet.interaction.WalletInteractionClient
import com.sphereon.wallet.interaction.WalletInteractionInput
import com.sphereon.wallet.interaction.WalletInteractionSession
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionCaptureSource
import kotlinx.coroutines.flow.StateFlow

/**
 * Adds policy-locked opaque capture only when a product assembly supplies an authoritative runtime
 * plan resolver. Ordinary local wallet graphs expose [WalletInteractionClient] without this
 * backend-only capability.
 */
class PolicyLockedCapturedInteractionClient(
    private val delegate: WalletInteractionClient,
    private val runtimePlanResolver: CapturedInteractionRuntimePlanResolver,
) : CapturedInteractionClient {
    override suspend fun start(input: WalletInteractionInput): WalletInteractionSession = delegate.start(input)

    override suspend fun startCaptured(input: CapturedInteractionInput): WalletInteractionSession {
        // This is deliberately the first operation. The resolver is forbidden from inspecting the
        // raw payload and locks the execution owner before this process performs semantic work.
        val lockedPlan = runtimePlanResolver.resolve(input).getOrThrow()
        require(lockedPlan.executionOwner == ProtocolExecutionOwner.WALLET_BACKEND) {
            "wallet_interaction_captured_owner_not_backend"
        }
        require(lockedPlan.policyRevision == input.expectedPolicyRevision) {
            "wallet_interaction_capture_policy_revision_mismatch"
        }
        require(input.rawPayload.size <= MAX_CAPTURE_BYTES) {
            "wallet_interaction_capture_payload_too_large"
        }
        val actualDigest = "sha256:${hash(input.rawPayload, DigestAlg.SHA256).encodeToHex()}"
        require(constantTimeEquals(actualDigest, input.payloadDigest.lowercase())) {
            "wallet_interaction_capture_digest_mismatch"
        }

        // Semantic classification begins only after the authoritative owner and exact payload have
        // been locked. Captured online ingress never introduces BLE, NFC, or offline mdoc paths.
        val value = input.rawPayload.decodeToString()
        require(value.encodeToByteArray().contentEquals(input.rawPayload)) {
            "wallet_interaction_capture_payload_not_utf8"
        }
        val entryPoint =
            when (input.source) {
                WalletInteractionCaptureSource.MOBILE_QR -> WalletEntryPoint.rawQr(value, input.source.name)
                WalletInteractionCaptureSource.MOBILE_DEEPLINK -> WalletEntryPoint.link(value, input.source.name)
                WalletInteractionCaptureSource.WEB_UI,
                WalletInteractionCaptureSource.API,
                -> if (looksLikeUri(value)) WalletEntryPoint.link(value, input.source.name) else WalletEntryPoint.rawQr(value, input.source.name)
            }
        return delegate.start(
            WalletInteractionInput(
                walletUnitId = lockedPlan.walletUnitId,
                entryPoint = entryPoint,
                executionOwner = lockedPlan.executionOwner,
                requestedFlowKinds = lockedPlan.permittedFlowKinds.toList(),
                metadata =
                    input.launchAttributes + lockedPlan.evidence +
                        mapOf(
                            "captureSource" to input.source.name,
                            "walletProfileRef" to input.walletProfileRef,
                            "appRegistrationRef" to input.appRegistrationRef,
                            "payloadDigest" to actualDigest,
                            "policyRevision" to lockedPlan.policyRevision.toString(),
                            "idempotencyKey" to input.idempotencyKey,
                            "executionOwnerLocked" to lockedPlan.executionOwner.name,
                        ),
            ),
        )
    }

    override suspend fun load(sessionId: WalletInteractionSessionId): WalletInteractionSession = delegate.load(sessionId)

    override suspend fun resume(sessionId: WalletInteractionSessionId): WalletInteractionSession = delegate.resume(sessionId)

    override suspend fun dispatch(sessionId: WalletInteractionSessionId, action: WalletInteractionAction) =
        delegate.dispatch(sessionId, action)

    override suspend fun cancel(sessionId: WalletInteractionSessionId) = delegate.cancel(sessionId)

    override fun observe(sessionId: WalletInteractionSessionId): StateFlow<WalletInteractionState> = delegate.observe(sessionId)
}

private const val MAX_CAPTURE_BYTES: Int = 65_536

private fun looksLikeUri(value: String): Boolean {
    val separator = value.indexOf(':')
    if (separator !in 1..32) return false
    return value.substring(0, separator).all { it.isLetterOrDigit() || it == '+' || it == '-' || it == '.' }
}

private fun constantTimeEquals(expected: String, actual: String): Boolean {
    if (expected.length != actual.length) return false
    var difference = 0
    expected.indices.forEach { index -> difference = difference or (expected[index].code xor actual[index].code) }
    return difference == 0
}
