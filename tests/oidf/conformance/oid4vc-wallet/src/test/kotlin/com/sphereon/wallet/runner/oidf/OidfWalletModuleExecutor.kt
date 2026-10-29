/*
 * (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package com.sphereon.wallet.runner.oidf

import com.sphereon.oidf.conformance.OidfConformanceSuiteClient
import com.sphereon.oidf.conformance.OidfPlan
import com.sphereon.oidf.conformance.OidfPlanModule
import com.sphereon.oidf.conformance.OidfPlanScenario
import com.sphereon.oidf.conformance.OidfSuiteConfigPreprocessor
import com.sphereon.wallet.interaction.WalletInteractionFailureCodes
import com.sphereon.wallet.interaction.WalletInteractionStatus
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.nio.file.Files
import java.nio.file.Path

@Serializable
internal data class OidfWalletModuleExecution(
    val scenarioId: String,
    val scenarioKey: String,
    val planId: String,
    val moduleName: String,
    val moduleVariant: Map<String, String>,
    val testId: String? = null,
    val status: String? = null,
    val result: String? = null,
    val walletStatus: String? = null,
    val walletTerminal: Boolean? = null,
    val walletSucceeded: Boolean? = null,
    val walletErrorCode: String? = null,
    val walletErrorArguments: Map<String, String> = emptyMap(),
    val expectedWalletOutcome: String,
    val walletOutcomeMatched: Boolean,
    val startedAtEpochMs: Long,
    val durationMs: Long,
    val passed: Boolean,
    val error: String? = null,
)

/** Executes one discovered wallet module and always leaves a machine-readable result. */
internal class OidfWalletModuleExecutor(
    private val suite: OidfConformanceSuiteClient,
    private val configPreprocessor: OidfSuiteConfigPreprocessor,
    private val haip: Boolean,
    private val haipAttestationFixture: OidfHaipWalletAttestationFixture? = null,
) {
    private val json = Json { prettyPrint = true }
    private val harness =
        OidfWalletConformanceHarness(
            suite = suite,
            configPreprocessor = configPreprocessor,
            profileId = "default",
            haipAttestationFixture = haipAttestationFixture,
        )

    suspend fun execute(
        scenario: OidfPlanScenario,
        plan: OidfPlan,
        module: OidfPlanModule,
        evidenceDirectory: Path,
    ): OidfWalletModuleExecution {
        Files.createDirectories(evidenceDirectory)
        val startedAt = System.currentTimeMillis()
        val scenarioKey = module.scenarioKey(plan.name, plan.selectionVariant)
        var testId: String? = null
        var status: String? = null
        var result: String? = null
        var walletStatus: String? = null
        var walletTerminal: Boolean? = null
        var walletSucceeded: Boolean? = null
        var walletErrorCode: String? = null
        var walletErrorArguments: Map<String, String> = emptyMap()
        var executionError: String? = null
        val expectsRejection = OidfWalletModuleOutcomePolicy.expectsRejection(module.testModule)

        try {
            val harnessResult =
                harness.runModule(
                    plan = plan,
                    module = module,
                    haip = haip,
                    evidenceDirectory = evidenceDirectory,
                ) { startedId -> testId = startedId }
            testId = harnessResult.testId
            status = harnessResult.suiteStatus
            result = harnessResult.suiteResult
            walletStatus = harnessResult.walletOutcome.status.name
            walletTerminal = harnessResult.walletOutcome.terminal
            walletSucceeded = harnessResult.walletOutcome.succeeded
            walletErrorCode = harnessResult.walletOutcome.error?.code
            walletErrorArguments =
                harnessResult.walletOutcome.error
                    ?.arguments
                    .orEmpty()
        } catch (error: Throwable) {
            executionError = error.stackTraceToString()
            if (error is OidfWalletSuiteCompletionException) {
                walletStatus = error.walletOutcome.status.name
                walletTerminal = error.walletOutcome.terminal
                walletSucceeded = error.walletOutcome.succeeded
                walletErrorCode = error.walletOutcome.error?.code
                walletErrorArguments =
                    error.walletOutcome.error
                        ?.arguments
                        .orEmpty()
            }
            testId?.let { id ->
                runCatching { suite.info(id) }
                    .getOrNull()
                    ?.let { info ->
                        status = info.status
                        result = info.result
                    }
            }
        }

        val walletOutcomeMatched =
            OidfWalletModuleOutcomePolicy.matches(
                module.testModule,
                walletStatus,
                walletTerminal,
                walletSucceeded,
                walletErrorCode,
            )
        executionError =
            OidfWalletModuleOutcomePolicy.executionDiagnostic(module.testModule, status, walletOutcomeMatched, executionError)
        val execution =
            OidfWalletModuleExecution(
                scenarioId = scenario.id,
                scenarioKey = scenarioKey,
                planId = plan.id,
                moduleName = module.testModule,
                moduleVariant = module.variant.toSortedMap(),
                testId = testId,
                status = status,
                result = result,
                walletStatus = walletStatus,
                walletTerminal = walletTerminal,
                walletSucceeded = walletSucceeded,
                walletErrorCode = walletErrorCode,
                walletErrorArguments = walletErrorArguments,
                expectedWalletOutcome = if (expectsRejection) "REJECTED" else "COMPLETED",
                walletOutcomeMatched = walletOutcomeMatched,
                startedAtEpochMs = startedAt,
                durationMs = System.currentTimeMillis() - startedAt,
                passed =
                    OidfWalletModuleOutcomePolicy.passed(status, result, walletOutcomeMatched, executionError),
                error = executionError,
            )
        Files.writeString(
            evidenceDirectory.resolve("result.json"),
            json.encodeToString(OidfWalletModuleExecution.serializer(), execution),
        )
        return execution
    }

    fun close() = harness.close()
}

/** Explicit pinned suite behavior: a negative-looking name alone never changes acceptance. */
internal object OidfWalletModuleOutcomePolicy {
    private val stateRejections =
        setOf(
            "fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-missing-state-fails",
            "fapi2-security-profile-final-client-test-ensure-authorization-response-with-invalid-state-fails",
        )
    private val fapiRejections =
        stateRejections +
            setOf(
                "fapi2-security-profile-final-client-test-discovery-issuer-mismatch",
                "fapi2-security-profile-final-client-test-invalid-authorization-response-iss",
                "fapi2-security-profile-final-client-test-remove-authorization-response-iss",
            )

    // VP1FinalWalletTestPlan and the modules' rejection/error-response contracts. In particular,
    // multisigned-one-invalid-signature retains another valid signature and MUST complete.
    private val vpRequestRejections =
        setOf(
            "oid4vp-1final-wallet-negative-test-response-uri-not-client-id",
            "oid4vp-1final-wallet-negative-test-invalid-request-object-signature",
            "oid4vp-1final-wallet-negative-test-invalid-request-object-typ",
            "oid4vp-1final-wallet-negative-test-missing-request-object-typ",
            "oid4vp-1final-wallet-negative-test-mismatched-client-id",
            "oid4vp-1final-wallet-negative-test-redirect-uri-with-direct-post",
            "oid4vp-1final-wallet-negative-test-missing-nonce",
            "oid4vp-1final-wallet-negative-test-wrong-expected-origins",
            "oid4vp-1final-wallet-negative-test-invalid-client-id-prefix",
            "oid4vp-1final-wallet-negative-test-unknown-transaction-data-type",
        )
    private val vpSelectionRejections =
        setOf(
            "oid4vp-1final-wallet-negative-test-required-non-matching-credential",
            "oid4vp-1final-wallet-negative-test-claim-not-in-credential",
        )
    private val vpRejections = vpRequestRejections + vpSelectionRejections

    fun expectsRejection(moduleName: String): Boolean = moduleName in fapiRejections || moduleName in vpRejections

    fun matches(
        moduleName: String,
        walletStatus: String?,
        terminal: Boolean?,
        succeeded: Boolean?,
        errorCode: String?,
    ): Boolean {
        if (!expectsRejection(moduleName)) return succeeded == true
        if (moduleName in stateRejections &&
            walletStatus == WalletInteractionStatus.AuthorizationRequired.name &&
            terminal == false && succeeded == false &&
            errorCode == WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_STATE_MISMATCH
        ) {
            return true
        }
        if (terminal != true || succeeded != false || errorCode.isNullOrBlank()) return false
        return when (moduleName) {
            in vpRequestRejections -> {
                errorCode == WalletInteractionFailureCodes.OID4VP_REQUEST_PARSE_FAILED ||
                    errorCode == WalletInteractionFailureCodes.OID4VP_REQUEST_RESOLVE_FAILED
            }

            in vpSelectionRejections -> {
                errorCode == WalletInteractionFailureCodes.OID4VP_SELECTION_UNSATISFIABLE
            }

            else -> {
                true
            }
        }
    }

    fun passed(
        suiteStatus: String?,
        suiteResult: String?,
        walletOutcomeMatched: Boolean,
        executionError: String?,
    ): Boolean = executionError == null && suiteStatus == "FINISHED" && suiteResult == "PASSED" && walletOutcomeMatched

    fun executionDiagnostic(
        moduleName: String,
        suiteStatus: String?,
        walletOutcomeMatched: Boolean,
        originalError: String?,
    ): String? {
        val review = pendingReviewDiagnostic(moduleName, suiteStatus, walletOutcomeMatched)
        return listOfNotNull(originalError, review).takeIf { it.isNotEmpty() }?.joinToString("\n\n")
    }

    fun pendingReviewDiagnostic(
        moduleName: String,
        suiteStatus: String?,
        walletOutcomeMatched: Boolean,
    ): String? =
        if (moduleName in vpRejections && walletOutcomeMatched && suiteStatus != "FINISHED") {
            "Wallet rejected the VP request, but the official suite is still $suiteStatus. " +
                "Inspect the test's outstanding requirements: rejection without a protocol error response can require " +
                "a genuine wallet error-screen screenshot and official upload/review. A headless result cannot supply " +
                "that UI evidence; this module remains unpassed."
        } else {
            null
        }
}

internal fun OidfPlanModule.displayName(): String =
    buildString {
        append(testModule)
        if (variant.isNotEmpty()) {
            append(" [")
            append(variant.toSortedMap().entries.joinToString(",") { "${it.key}=${it.value}" })
            append(']')
        }
    }
