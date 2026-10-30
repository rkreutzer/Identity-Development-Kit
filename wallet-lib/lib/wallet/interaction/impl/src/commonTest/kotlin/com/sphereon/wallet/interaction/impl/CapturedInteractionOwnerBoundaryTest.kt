/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.wallet.interaction.impl

import com.sphereon.core.api.Ok
import com.sphereon.core.api.encodeToHex
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.wallet.interaction.CapturedInteractionInput
import com.sphereon.wallet.interaction.CapturedInteractionLaunchAttributes
import com.sphereon.wallet.interaction.CapturedInteractionRuntimePlanResolver
import com.sphereon.wallet.interaction.LockedCapturedInteractionRuntimePlan
import com.sphereon.wallet.interaction.ProtocolExecutionOwner
import com.sphereon.wallet.interaction.WalletEntryPoint
import com.sphereon.wallet.interaction.WalletEntryPointKind
import com.sphereon.wallet.interaction.WalletInteractionCaptureSource
import com.sphereon.wallet.interaction.WalletInteractionContext
import com.sphereon.wallet.interaction.WalletInteractionFlowKind
import com.sphereon.wallet.interaction.WalletInteractionProtocolAdapter
import com.sphereon.wallet.interaction.WalletInteractionSession
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.interaction.WalletProtocol
import com.sphereon.wallet.interaction.WalletProtocolCapability
import com.sphereon.wallet.interaction.WalletProtocolMatch
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CapturedInteractionOwnerBoundaryTest {
    @Test
    fun locksBackendOwnerBeforeFirstSemanticInterpretation() = runTest {
        var ownerLocked = false
        val adapter = RecordingAdapter { check(ownerLocked) { "semantic_interpretation_before_owner_lock" } }
        val engine =
            PolicyLockedCapturedInteractionClient(
                delegate =
                    testWalletInteractionEngine(
                        adapters = listOf(adapter),
                        sessionIdGenerator = FixedWalletInteractionSessionIdGenerator(),
                    ),
                runtimePlanResolver =
                    CapturedInteractionRuntimePlanResolver {
                        ownerLocked = true
                        Ok(lockedPlan())
                    },
            )

        val session = engine.startCaptured(capturedInput())

        assertEquals(WalletInteractionStatus.CounterpartyNotice, session.state.status)
        assertEquals(ProtocolExecutionOwner.WALLET_BACKEND, adapter.lastExecutionOwner)
        assertEquals(WalletEntryPointKind.RAW_QR, adapter.lastEntryPoint?.kind)
        assertEquals(2, adapter.semanticCalls)
    }

    @Test
    fun ownerOrDigestFailureNeverInvokesProtocolAdapters() = runTest {
        val adapter = RecordingAdapter()
        val appOwned =
            PolicyLockedCapturedInteractionClient(
                testWalletInteractionEngine(adapters = listOf(adapter)),
                CapturedInteractionRuntimePlanResolver { Ok(lockedPlan(ProtocolExecutionOwner.WALLET_APP)) },
            )
        assertFailsWith<IllegalArgumentException> { appOwned.startCaptured(capturedInput()) }

        val wrongDigest =
            PolicyLockedCapturedInteractionClient(
                testWalletInteractionEngine(adapters = listOf(adapter)),
                CapturedInteractionRuntimePlanResolver { Ok(lockedPlan()) },
            )
        assertFailsWith<IllegalArgumentException> { wrongDigest.startCaptured(capturedInput().copy(payloadDigest = "sha256:00")) }

        assertEquals(0, adapter.semanticCalls)
    }

    @Test
    fun onlineCapturedIngressCannotBecomeBleOrNfc() = runTest {
        val adapter = RecordingAdapter()
        val engine =
            PolicyLockedCapturedInteractionClient(
                testWalletInteractionEngine(adapters = listOf(adapter)),
                CapturedInteractionRuntimePlanResolver { Ok(lockedPlan()) },
            )

        engine.startCaptured(capturedInput(source = WalletInteractionCaptureSource.MOBILE_DEEPLINK))

        assertEquals(WalletEntryPointKind.DEEP_LINK, adapter.lastEntryPoint?.kind)
    }

    @Test
    fun allowlistedLaunchPreferencesSurviveOwnerLockWithoutReplacingCaptureEvidence() = runTest {
        val adapter = RecordingAdapter()
        val engine =
            PolicyLockedCapturedInteractionClient(
                testWalletInteractionEngine(adapters = listOf(adapter)),
                CapturedInteractionRuntimePlanResolver {
                    Ok(
                        lockedPlan().copy(
                            evidence =
                                mapOf(
                                    CapturedInteractionLaunchAttributes.OID4VCI_DPOP_ENABLED to "false",
                                    "lockedEvidence" to "recorded",
                                ),
                        ),
                    )
                },
            )

        engine.startCaptured(
            capturedInput().copy(
                launchAttributes = mapOf(
                    CapturedInteractionLaunchAttributes.OID4VCI_CLIENT_AUTHENTICATION_METHOD to "private_key_jwt",
                    CapturedInteractionLaunchAttributes.OID4VCI_DPOP_ENABLED to "true",
                    CapturedInteractionLaunchAttributes.OID4VCI_CREDENTIAL_BATCH_SIZE to "10",
                ),
            ),
        )

        assertEquals("private_key_jwt", adapter.lastAttributes[CapturedInteractionLaunchAttributes.OID4VCI_CLIENT_AUTHENTICATION_METHOD])
        assertEquals("false", adapter.lastAttributes[CapturedInteractionLaunchAttributes.OID4VCI_DPOP_ENABLED])
        assertEquals("10", adapter.lastAttributes[CapturedInteractionLaunchAttributes.OID4VCI_CREDENTIAL_BATCH_SIZE])
        assertEquals("recorded", adapter.lastAttributes["lockedEvidence"])
        assertEquals("profile-a", adapter.lastAttributes["walletProfileRef"])
    }

    @Test
    fun capturedLaunchAttributesRejectClientIdentityAndSecretOverrides() {
        val identityOverride = assertFailsWith<IllegalArgumentException> {
            capturedInput().copy(launchAttributes = mapOf("oid4vci.client.id" to "unregistered-client"))
        }
        assertEquals("wallet_interaction_capture_launch_attribute_not_allowed", identityOverride.message)

        val secretOverride = assertFailsWith<IllegalArgumentException> {
            capturedInput().copy(launchAttributes = mapOf("oid4vci.iae.code.verifier" to "secret-verifier"))
        }
        assertEquals("wallet_interaction_capture_launch_attribute_not_allowed", secretOverride.message)
    }

    private fun lockedPlan(owner: ProtocolExecutionOwner = ProtocolExecutionOwner.WALLET_BACKEND) =
        LockedCapturedInteractionRuntimePlan(
            walletUnitId = "wallet-unit-a",
            executionOwner = owner,
            policyRevision = 7,
            permittedFlowKinds = setOf(WalletInteractionFlowKind.CredentialReceive, WalletInteractionFlowKind.CredentialPresent),
            providerRefs = setOf("enterprise-holder"),
            evidence = mapOf("manifestSignatureRef" to "signature-a"),
        )

    private fun capturedInput(source: WalletInteractionCaptureSource = WalletInteractionCaptureSource.MOBILE_QR): CapturedInteractionInput {
        val payload = "openid-credential-offer://issuer.example/offer".encodeToByteArray()
        return CapturedInteractionInput(
            source = source,
            walletProfileRef = "profile-a",
            appRegistrationRef = "app-a",
            rawPayload = payload,
            payloadDigest = "sha256:${hash(payload, DigestAlg.SHA256).encodeToHex()}",
            captureBinding = "activation:app-a",
            expectedPolicyRevision = 7,
            idempotencyKey = "capture-a",
        )
    }
}

private class RecordingAdapter(
    private val beforeSemanticCall: () -> Unit = {},
) : WalletInteractionProtocolAdapter {
    var semanticCalls: Int = 0
    var lastEntryPoint: WalletEntryPoint? = null
    var lastExecutionOwner: ProtocolExecutionOwner? = null
    var lastAttributes: Map<String, String> = emptyMap()

    override val capability: WalletProtocolCapability =
        WalletProtocolCapability(
            adapterId = "recording-oid4vc",
            protocol = WalletProtocol.OID4VCI,
            flowKinds = listOf(WalletInteractionFlowKind.CredentialReceive),
        )

    override suspend fun canHandle(entryPoint: WalletEntryPoint): WalletProtocolMatch {
        beforeSemanticCall()
        semanticCalls += 1
        lastEntryPoint = entryPoint
        return WalletProtocolMatch.strong()
    }

    override suspend fun start(
        context: WalletInteractionContext,
        entryPoint: WalletEntryPoint,
    ): WalletInteractionSession {
        beforeSemanticCall()
        semanticCalls += 1
        lastEntryPoint = entryPoint
        lastExecutionOwner = context.executionOwner
        lastAttributes = context.attributes
        return WalletInteractionSession(
            context.sessionId,
            WalletInteractionState(
                sessionId = context.sessionId,
                walletUnitId = context.walletUnitId,
                status = WalletInteractionStatus.CounterpartyNotice,
                protocol = WalletProtocol.OID4VCI,
            ),
        )
    }

    override suspend fun handle(
        context: WalletInteractionContext,
        sessionState: WalletInteractionState,
        action: com.sphereon.wallet.interaction.WalletInteractionAction,
    ): WalletInteractionState = sessionState
}
