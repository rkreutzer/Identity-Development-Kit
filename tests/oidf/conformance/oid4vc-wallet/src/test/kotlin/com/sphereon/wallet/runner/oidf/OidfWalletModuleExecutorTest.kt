/*
 * (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package com.sphereon.wallet.runner.oidf

import com.sphereon.wallet.interaction.WalletInteractionError
import com.sphereon.wallet.interaction.WalletInteractionFailureCodes
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.runner.HeadlessRunOutcome
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class OidfWalletModuleExecutorTest {
    private val invalidSignature = "oid4vp-1final-wallet-negative-test-invalid-request-object-signature"

    @Test
    fun pinnedVpRequestNegativeModulesRequireProtocolRejection() {
        listOf(
            "response-uri-not-client-id",
            "invalid-request-object-signature",
            "invalid-request-object-typ",
            "missing-request-object-typ",
            "mismatched-client-id",
            "redirect-uri-with-direct-post",
            "missing-nonce",
            "wrong-expected-origins",
            "invalid-client-id-prefix",
            "unknown-transaction-data-type",
        ).forEach { suffix ->
            val module = "oid4vp-1final-wallet-negative-test-$suffix"
            assertTrue(OidfWalletModuleOutcomePolicy.expectsRejection(module), module)
            assertTrue(matches(module, WalletInteractionFailureCodes.OID4VP_REQUEST_PARSE_FAILED), module)
            assertTrue(matches(module, WalletInteractionFailureCodes.OID4VP_REQUEST_RESOLVE_FAILED), module)
            assertFalse(OidfWalletModuleOutcomePolicy.matches(module, "Completed", true, true, null), module)
        }
    }

    @Test
    fun nonMatchingCredentialAndClaimsRequireSelectionRefusal() {
        listOf("required-non-matching-credential", "claim-not-in-credential").forEach { suffix ->
            val module = "oid4vp-1final-wallet-negative-test-$suffix"
            assertTrue(matches(module, WalletInteractionFailureCodes.OID4VP_SELECTION_UNSATISFIABLE), module)
            assertFalse(matches(module, WalletInteractionFailureCodes.OID4VP_REQUEST_URI_FETCH_FAILED), module)
        }
    }

    @Test
    fun unrelatedFailuresTimeoutsAndMissingOutcomesNeverSatisfyVpRefusal() {
        listOf(
            WalletInteractionFailureCodes.OID4VP_REQUEST_URI_FETCH_FAILED,
            WalletInteractionFailureCodes.OID4VP_EXECUTION_NOT_CONFIGURED,
            WalletInteractionFailureCodes.OID4VP_RESPONSE_CREATION_FAILED,
            "unexpected.crash",
            "",
        ).forEach { code -> assertFalse(matches(invalidSignature, code), code) }
        assertFalse(OidfWalletModuleOutcomePolicy.matches(invalidSignature, "Failed", false, false, WalletInteractionFailureCodes.OID4VP_REQUEST_PARSE_FAILED))
        assertFalse(OidfWalletModuleOutcomePolicy.matches(invalidSignature, null, null, null, null))
    }

    @Test
    fun oneInvalidMultisignatureStillRequiresCompletion() {
        val module = "oid4vp-1final-wallet-multisigned-one-invalid-signature"
        assertFalse(OidfWalletModuleOutcomePolicy.expectsRejection(module))
        assertTrue(OidfWalletModuleOutcomePolicy.matches(module, "Completed", true, true, null))
        assertFalse(matches(module, WalletInteractionFailureCodes.OID4VP_REQUEST_PARSE_FAILED))
    }

    @Test
    fun unknownNegativeLookingNameDoesNotAuthorizeRefusal() {
        val module = "oid4vp-1final-wallet-negative-test-future-module"
        assertFalse(OidfWalletModuleOutcomePolicy.expectsRejection(module))
        assertFalse(matches(module, WalletInteractionFailureCodes.OID4VP_REQUEST_PARSE_FAILED))
    }

    @Test
    fun stateMismatchMayRefuseOnlyTheCallbackWithoutTerminatingReceive() {
        val module = "fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-state-fails"
        assertTrue(OidfWalletModuleOutcomePolicy.matches(module, WalletInteractionStatus.AuthorizationRequired.name, false, false, WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_STATE_MISMATCH))
        assertFalse(OidfWalletModuleOutcomePolicy.matches(module, WalletInteractionStatus.AuthorizationRequired.name, false, false, WalletInteractionFailureCodes.OID4VCI_TOKEN_EXCHANGE_FAILED))
    }

    @Test
    fun pendingOfficialUiReviewRemainsUnpassedAndActionable() {
        val diagnostic = OidfWalletModuleOutcomePolicy.pendingReviewDiagnostic(invalidSignature, "WAITING", true)
        assertTrue(checkNotNull(diagnostic).contains("genuine wallet error-screen screenshot"))
        assertTrue(diagnostic.contains("remains unpassed"))
        assertNull(OidfWalletModuleOutcomePolicy.pendingReviewDiagnostic(invalidSignature, "FINISHED", true))
        assertNull(OidfWalletModuleOutcomePolicy.pendingReviewDiagnostic(invalidSignature, "WAITING", false))
        assertNull(OidfWalletModuleOutcomePolicy.pendingReviewDiagnostic("oid4vp-1final-wallet-happy-flow", "WAITING", true))
    }

    @Test
    fun suiteTimeoutAfterTypedRefusalPreservesOutcomeAndOriginalFailure() {
        val outcome =
            HeadlessRunOutcome(
                sessionId = WalletInteractionSessionId("observed-vp-refusal"),
                status = WalletInteractionStatus.Failed,
                terminal = true,
                error = WalletInteractionError(WalletInteractionFailureCodes.OID4VP_REQUEST_PARSE_FAILED),
            )
        val timeout = java.net.http.HttpTimeoutException("official wait-state request timed out")
        val failure =
            assertFailsWith<OidfWalletSuiteCompletionException> {
                oidfWithObservedWalletOutcome(outcome) { throw timeout }
            }
        assertSame(outcome, failure.walletOutcome)
        assertSame(timeout, failure.cause)
        val observed = failure.walletOutcome
        val matched =
            OidfWalletModuleOutcomePolicy.matches(
                invalidSignature,
                observed.status.name,
                observed.terminal,
                observed.succeeded,
                observed.error?.code,
            )
        assertTrue(matched)
        val diagnostic = checkNotNull(OidfWalletModuleOutcomePolicy.executionDiagnostic(invalidSignature, "WAITING", matched, failure.stackTraceToString()))
        assertTrue(diagnostic.contains("official wait-state request timed out"))
        assertTrue(diagnostic.contains("genuine wallet error-screen screenshot"))
        assertFalse(OidfWalletModuleOutcomePolicy.passed("WAITING", "REVIEW", matched, diagnostic))
        // A later status read must never erase the failed completion exchange.
        assertFalse(OidfWalletModuleOutcomePolicy.passed("FINISHED", "PASSED", matched, diagnostic))
    }

    @Test
    fun unexpectedFailureAfterObservedWalletCrashIsNotRejectionEvidence() {
        val outcome =
            HeadlessRunOutcome(
                sessionId = WalletInteractionSessionId("unexpected-failure"),
                status = WalletInteractionStatus.Failed,
                terminal = true,
                error = WalletInteractionError("unexpected.crash"),
            )
        val failure =
            assertFailsWith<OidfWalletSuiteCompletionException> {
                oidfWithObservedWalletOutcome(outcome) { error("unexpected suite failure") }
            }
        val observed = failure.walletOutcome
        val matched =
            OidfWalletModuleOutcomePolicy.matches(
                invalidSignature,
                observed.status.name,
                observed.terminal,
                observed.succeeded,
                observed.error?.code,
            )
        assertFalse(matched)
        val diagnostic = checkNotNull(OidfWalletModuleOutcomePolicy.executionDiagnostic(invalidSignature, null, matched, failure.stackTraceToString()))
        assertFalse(diagnostic.contains("genuine wallet error-screen screenshot"))
        assertFalse(OidfWalletModuleOutcomePolicy.passed("FINISHED", "PASSED", matched, diagnostic))
    }

    private fun matches(
        module: String,
        errorCode: String,
    ): Boolean = OidfWalletModuleOutcomePolicy.matches(module, WalletInteractionStatus.Failed.name, true, false, errorCode)
}
