/*
 * (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package com.sphereon.wallet.runner.oidf

import com.sphereon.core.api.conf.DefaultPrincipalMapPropertySource
import com.sphereon.oidf.conformance.JvmTrustStoreScope
import com.sphereon.oidf.conformance.OidfConformanceSuiteClient
import com.sphereon.oidf.conformance.OidfPlan
import com.sphereon.oidf.conformance.OidfPlanScenario
import com.sphereon.oidf.conformance.OidfPlanScenarioManifest
import com.sphereon.oidf.conformance.OidfSuiteConfigPreprocessor
import com.sphereon.oidf.conformance.OidfSuiteEnvironment
import com.sphereon.oidf.conformance.OidfSuiteLock
import com.sphereon.oidf.conformance.evidenceDirectoryName
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.DynamicContainer
import org.junit.jupiter.api.DynamicNode
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory
import org.junit.jupiter.api.TestInstance
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.Path
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class OidfWalletPlanConformanceTest {
    private val json =
        Json {
            prettyPrint = true
            encodeDefaults = true
        }
    private val executions = mutableListOf<OidfWalletModuleExecution>()
    private val scenarioErrors = mutableListOf<String>()
    private val plans = linkedMapOf<OidfPlanScenario, OidfPlan>()
    private var enabled = false
    private var planName = ""
    private lateinit var evidenceDirectory: Path
    private lateinit var lock: OidfSuiteLock
    private var environment: OidfSuiteEnvironment? = null
    private var trustScope: JvmTrustStoreScope? = null
    private var suite: OidfConformanceSuiteClient? = null
    private var preprocessor: OidfSuiteConfigPreprocessor? = null
    private var executor: OidfWalletModuleExecutor? = null
    private var haipAttestationFixture: OidfHaipWalletAttestationFixture? = null
    private var startedAtEpochMs: Long = 0
    private var previousVerifierTrustAnchors: String? = null
    private var verifierTrustConfigured = false

    @BeforeAll
    fun startPlanRow() {
        enabled = System.getProperty("oidf.suite.mode") == MODE
        if (!enabled) return

        startedAtEpochMs = System.currentTimeMillis()
        planName = checkNotNull(System.getProperty("oidf.plan")) { "Pass -Poidf.plan=<wallet-plan>" }
        require(planName in SUPPORTED_PLANS) {
            "Wallet runner supports ${SUPPORTED_PLANS.sorted()}, got '$planName'"
        }
        evidenceDirectory =
            Path(checkNotNull(System.getProperty("oidf.evidence.dir")))
                .resolve(planName)
        Files.createDirectories(evidenceDirectory)
        lock = OidfSuiteLock.load()
        val existingSuite = existingOidfWalletSuite()
        if (existingSuite != null) {
            suite = existingSuite.client
            preprocessor = existingSuite.preprocessor
        } else {
            val runningEnvironment =
                OidfSuiteEnvironment.start(
                    lock = lock,
                    startupEvidenceDirectory = evidenceDirectory.resolve("containers-startup"),
                )
            environment = runningEnvironment
            trustScope = runningEnvironment.installJvmTrustStore()
            val runningSuite = runningEnvironment.client()
            suite = runningSuite
            val runningPreprocessor =
                OidfSuiteConfigPreprocessor(
                    suiteDir = runningEnvironment.suiteSourceDirectory,
                    baseUrl = runningEnvironment.advertisedBaseUrl,
                    localBaseUrl = runningEnvironment.apiBaseUrl,
                    mtlsBaseUrl = runningEnvironment.advertisedMtlsBaseUrl,
                )
            preprocessor = runningPreprocessor
        }
        val runningSuite = checkNotNull(suite)
        val runningPreprocessor = checkNotNull(preprocessor)
        // Request-object trust is separate from HTTPS transport trust. Anchor only the
        // locked suite's dedicated verifier CA, never the x5c leaf from a request.
        previousVerifierTrustAnchors = DefaultPrincipalMapPropertySource.getPropertyAsString(VERIFIER_TRUST_ANCHORS)
        DefaultPrincipalMapPropertySource.addProperty(
            VERIFIER_TRUST_ANCHORS,
            runningPreprocessor.sourceText("scripts/certs-keys/vp-signing-ca.crt"),
        )
        verifierTrustConfigured = true
        haipAttestationFixture =
            if (planName == VCI_HAIP_PLAN) OidfHaipWalletAttestationFixture() else null

        val selectedScenario = System.getProperty("oidf.scenario")?.takeIf(String::isNotBlank)
        OidfPlanScenarioManifest
            .forPlan(planName)
            .filter { selectedScenario == null || it.id == selectedScenario }
            .also { selected ->
                require(selected.isNotEmpty()) { "No wallet scenario matched oidf.scenario='$selectedScenario'" }
            }.forEach { scenario ->
                try {
                    val plan =
                        runningSuite.createPlan(
                            planName = scenario.planName,
                            configJson =
                                runningPreprocessor.config(
                                    scenario.configTemplate,
                                    haipAttestationFixture?.let { fixture ->
                                        buildJsonObject {
                                            scenario.configOverrides.forEach { (key, value) -> put(key, value) }
                                            put(
                                                "client_attestation",
                                                buildJsonObject {
                                                    put("trust_anchor", fixture.trustAnchorPem)
                                                    put("key_attestation_trust_anchor_pem", fixture.trustAnchorPem)
                                                },
                                            )
                                        }
                                    } ?: scenario.configOverrides,
                                ),
                            variant = scenario.variantJson(),
                        )
                    require(plan.modules.isNotEmpty()) { "Scenario ${scenario.id} discovered no modules" }
                    plans[scenario] = plan
                } catch (error: Throwable) {
                    scenarioErrors += "${scenario.id}: ${error.stackTraceToString()}"
                }
            }

        val keys = plans.values.flatMap(OidfPlan::scenarioKeys)
        val duplicates = keys.groupingBy { it }.eachCount().filterValues { it > 1 }
        require(duplicates.isEmpty()) { "Duplicate wallet scenario keys: $duplicates" }
    }

    @TestFactory
    fun `every discovered wallet module passes`(): List<DynamicNode> {
        if (!enabled) return emptyList()
        val runningSuite = checkNotNull(suite)
        val runningExecutor =
            OidfWalletModuleExecutor(
                suite = runningSuite,
                configPreprocessor = checkNotNull(preprocessor),
                haip = planName in HAIP_PLANS,
                haipAttestationFixture = haipAttestationFixture,
            )
        executor = runningExecutor
        val selectedModule = System.getProperty("oidf.module")?.takeIf(String::isNotBlank)
        return plans.map { (scenario, plan) ->
            val selectedModules = plan.modules.filter { selectedModule == null || it.testModule == selectedModule }
            require(selectedModules.isNotEmpty()) {
                "Scenario ${scenario.id} has no module matching oidf.module='$selectedModule'"
            }
            DynamicContainer.dynamicContainer(
                scenario.id,
                selectedModules.map { module ->
                    DynamicTest.dynamicTest(module.displayName()) {
                        val execution =
                            runBlocking {
                                runningExecutor.execute(
                                    scenario = scenario,
                                    plan = plan,
                                    module = module,
                                    evidenceDirectory =
                                        evidenceDirectory
                                            .resolve(scenario.id)
                                            .resolve(module.evidenceDirectoryName()),
                                )
                            }
                        executions += execution
                        assertNull(execution.error, execution.error)
                        assertEquals("FINISHED", execution.status, execution.toString())
                        assertEquals("PASSED", execution.result, execution.toString())
                        assertTrue(execution.passed, execution.toString())
                    }
                },
            )
        }
    }

    @AfterAll
    fun finishPlanRow() {
        if (!enabled) return
        val cleanupErrors = mutableListOf<String>()
        val runningSuite = suite
        val runningEnvironment = environment
        try {
            runCatching { executor?.close() }
                .onFailure { cleanupErrors += "wallet runtime close: ${it.stackTraceToString()}" }
            if (runningSuite != null) {
                plans.forEach { (scenario, plan) ->
                    runCatching {
                        runningSuite.exportPlanHtml(
                            plan.id,
                            evidenceDirectory.resolve(scenario.id).resolve("plan-${plan.id}.zip"),
                        )
                    }.onFailure { cleanupErrors += "${scenario.id} export: ${it.stackTraceToString()}" }
                    runCatching { runningSuite.deletePlan(plan.id) }
                        .onFailure { cleanupErrors += "${scenario.id} delete: ${it.stackTraceToString()}" }
                }
            }
        } finally {
            if (verifierTrustConfigured) {
                previousVerifierTrustAnchors?.let {
                    DefaultPrincipalMapPropertySource.addProperty(VERIFIER_TRUST_ANCHORS, it)
                } ?: DefaultPrincipalMapPropertySource.deleteProperty(VERIFIER_TRUST_ANCHORS)
            }
            runCatching { runningEnvironment?.exportContainerLogs(evidenceDirectory.resolve("containers")) }
                .onFailure { cleanupErrors += "container logs: ${it.stackTraceToString()}" }
            runCatching { trustScope?.close() }
                .onFailure { cleanupErrors += "trust-store restore: ${it.stackTraceToString()}" }
            runCatching { runningEnvironment?.close() }
                .onFailure { cleanupErrors += "suite close: ${it.stackTraceToString()}" }
            scenarioErrors += cleanupErrors
            writeCoverage()
        }
        assertTrue(scenarioErrors.isEmpty(), scenarioErrors.joinToString("\n"))
    }

    private fun writeCoverage() {
        val expectedScenarioIds = OidfPlanScenarioManifest.forPlan(planName).map(OidfPlanScenario::id)
        val discovered = plans.values.flatMap(OidfPlan::scenarioKeys).sorted()
        val executed = executions.filter { it.testId != null }.map(OidfWalletModuleExecution::scenarioKey).sorted()
        val passed = executions.filter(OidfWalletModuleExecution::passed).map(OidfWalletModuleExecution::scenarioKey).sorted()
        val report =
            OidfWalletCoverageReport(
                generatedAtEpochMs = System.currentTimeMillis(),
                durationMs = System.currentTimeMillis() - startedAtEpochMs,
                vdxCommit = gitCommit(),
                vdxWorktreeDirty = gitWorktreeDirty(),
                suiteCommit = lock.upstreamCommit,
                patchSet = lock.patchSet,
                images =
                    mapOf(
                        "server" to lock.serverImage,
                        "nginx" to lock.nginxImage,
                        "mongo" to lock.mongoImage,
                    ),
                imageIds = environment?.imageIds.orEmpty(),
                planName = planName,
                profile = profile(planName),
                expectedScenarioIds = expectedScenarioIds,
                discoveredModuleKeys = discovered,
                executedModuleKeys = executed,
                passedModuleKeys = passed,
                missingModuleKeys = (discovered - executed.toSet()).sorted(),
                failedModuleKeys = (executed.toSet() - passed.toSet()).sorted(),
                scenarioErrors = scenarioErrors,
                executions = executions.sortedBy(OidfWalletModuleExecution::scenarioKey),
            )
        Files.writeString(
            evidenceDirectory.resolve("oidf-coverage.json"),
            json.encodeToString(OidfWalletCoverageReport.serializer(), report),
        )
    }

    private fun gitCommit(): String =
        git("rev-parse", "HEAD")
            .takeIf { it.matches(Regex("[0-9a-f]{40}")) }
            ?: System.getenv("GITHUB_SHA")
            ?: "unknown"

    private fun gitWorktreeDirty(): Boolean = git("status", "--porcelain").isNotBlank()

    private fun git(vararg args: String): String {
        val workspace = System.getProperty("oidf.sut.workspace") ?: Path.of("").toAbsolutePath().toString()
        return runCatching {
            val process = ProcessBuilder(listOf("git", "-C", workspace) + args).redirectErrorStream(true).start()
            val output =
                process.inputStream
                    .bufferedReader()
                    .use { it.readText() }
                    .trim()
            if (process.waitFor() == 0) output else ""
        }.getOrDefault("")
    }

    private companion object {
        const val VERIFIER_TRUST_ANCHORS = "oid4vp.request.trust-anchors"
        const val MODE = "wallet-plan"
        const val VCI_FINAL_PLAN = "oid4vci-1_0-wallet-test-plan"
        const val VCI_HAIP_PLAN = "oid4vci-1_0-wallet-haip-test-plan"
        const val VP_FINAL_PLAN = "oid4vp-1final-wallet-test-plan"
        const val VP_HAIP_PLAN = "oid4vp-1final-wallet-haip-test-plan"
        val SUPPORTED_PLANS = setOf(VCI_FINAL_PLAN, VCI_HAIP_PLAN, VP_FINAL_PLAN, VP_HAIP_PLAN)
        val HAIP_PLANS = setOf(VCI_HAIP_PLAN, VP_HAIP_PLAN)

        fun profile(planName: String): String =
            when (planName) {
                VCI_FINAL_PLAN -> "OID4VCI_1_0_FINAL"
                VCI_HAIP_PLAN -> "OID4VCI_HAIP_1_0"
                VP_FINAL_PLAN -> "OID4VP_1_0_FINAL"
                VP_HAIP_PLAN -> "OID4VP_HAIP_1_0"
                else -> error("Unsupported wallet plan: $planName")
            }
    }
}

@Serializable
private data class OidfWalletCoverageReport(
    val schemaVersion: Int = 1,
    val generatedAtEpochMs: Long,
    val durationMs: Long,
    val vdxCommit: String,
    val vdxWorktreeDirty: Boolean,
    val suiteCommit: String,
    val patchSet: String,
    val images: Map<String, String>,
    val imageIds: Map<String, String>,
    val role: String = "wallet",
    val planName: String,
    val profile: String,
    val expectedScenarioIds: List<String>,
    val discoveredModuleKeys: List<String>,
    val executedModuleKeys: List<String>,
    val passedModuleKeys: List<String>,
    val missingModuleKeys: List<String>,
    val failedModuleKeys: List<String>,
    val scenarioErrors: List<String>,
    val executions: List<OidfWalletModuleExecution>,
)
