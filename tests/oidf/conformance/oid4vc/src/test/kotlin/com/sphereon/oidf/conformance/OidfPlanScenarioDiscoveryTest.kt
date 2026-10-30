/*
 * (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package com.sphereon.oidf.conformance

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.file.Files
import kotlin.io.path.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OidfPlanScenarioDiscoveryTest {
    @Test
    fun haipWalletPresentationTrustAnchorsMatchCredentialFormat() {
        val scenarios = OidfPlanScenarioManifest.forPlan("oid4vp-1final-wallet-haip-test-plan")
        assertEquals(4, scenarios.size)
        scenarios.forEach { scenario ->
            val expected =
                when (scenario.variant.getValue("credential_format")) {
                    "iso_mdl" -> "{mdoc-iaca-root.crt}"
                    "sd_jwt_vc" -> "{vp-signing-ca.crt}"
                    else -> error("Unexpected credential format")
                }
            val credential = scenario.configOverrides.getValue("credential").jsonObject
            assertEquals(expected, credential.getValue("trust_anchor_pem").jsonPrimitive.content, scenario.id)
            val expectedStatus = if (scenario.variant.getValue("credential_format") == "iso_mdl") "{mdoc-iaca-root.crt}" else "{vci-test-root.crt}"
            assertEquals(expectedStatus, credential.getValue("status_list_trust_anchor_pem").jsonPrimitive.content, scenario.id)
        }
        assertTrue(OidfPlanScenarioManifest.forPlan("oid4vci-1_0-wallet-haip-test-plan").all { it.configOverrides.isEmpty() })
    }

    @Test
    fun `pinned suite accepts every required scenario and returns unique modules`() {
        if (System.getProperty("oidf.suite.mode") != "discover") {
            println("Skipping OIDF plan discovery; pass -Doidf.suite.mode=discover to run it.")
            return
        }

        val evidenceDirectory = Path(checkNotNull(System.getProperty("oidf.evidence.dir"))).resolve("plan-discovery")
        val results = mutableListOf<ScenarioDiscoveryResult>()
        OidfSuiteEnvironment
            .start(startupEvidenceDirectory = evidenceDirectory.resolve("containers"))
            .use { environment ->
                try {
                    val preprocessor =
                        OidfSuiteConfigPreprocessor(
                            suiteDir = environment.suiteSourceDirectory,
                            baseUrl = environment.advertisedBaseUrl,
                            localBaseUrl = environment.apiBaseUrl,
                            mtlsBaseUrl = environment.advertisedMtlsBaseUrl,
                        )
                    OidfPlanScenarioManifest.scenarios.forEach { scenario ->
                        var planId: String? = null
                        try {
                            val plan =
                                environment.client().createPlan(
                                    planName = scenario.planName,
                                    configJson = preprocessor.config(scenario.configTemplate, scenario.configOverrides),
                                    variant = scenario.variantJson(),
                                )
                            planId = plan.id
                            results +=
                                ScenarioDiscoveryResult(
                                    scenario = scenario,
                                    planId = plan.id,
                                    moduleKeys = plan.scenarioKeys,
                                )
                        } catch (error: Throwable) {
                            results += ScenarioDiscoveryResult(scenario = scenario, error = error.message ?: error.toString())
                        } finally {
                            planId?.let { id -> runCatching { environment.client().deletePlan(id) } }
                        }
                    }
                } finally {
                    writeEvidence(evidenceDirectory, environment.lock, results)
                    environment.exportContainerLogs(evidenceDirectory.resolve("containers"))
                }
            }

        val errors = results.filter { it.error != null }
        assertTrue(errors.isEmpty(), errors.joinToString("\n") { "${it.scenario.id}: ${it.error}" })
        assertTrue(results.all { it.moduleKeys.isNotEmpty() }, "Every scenario must expand to at least one suite module")
        val moduleKeys = results.flatMap { it.moduleKeys }
        val duplicateKeys = moduleKeys.groupingBy { it }.eachCount().filterValues { it > 1 }
        assertTrue(duplicateKeys.isEmpty(), "Duplicate suite module coverage: $duplicateKeys")
    }

    private fun writeEvidence(
        evidenceDirectory: java.nio.file.Path,
        lock: OidfSuiteLock,
        results: List<ScenarioDiscoveryResult>,
    ) {
        Files.createDirectories(evidenceDirectory)
        val evidence =
            buildJsonObject {
                put("upstreamCommit", lock.upstreamCommit)
                put("patchSet", lock.patchSet)
                put("scenarioCount", results.size)
                put("moduleCount", results.sumOf { it.moduleKeys.size })
                put(
                    "scenarios",
                    buildJsonArray {
                        results.forEach { result ->
                            add(
                                buildJsonObject {
                                    put("id", result.scenario.id)
                                    put("planName", result.scenario.planName)
                                    put("configTemplate", result.scenario.configTemplate)
                                    put("variant", result.scenario.variantJson())
                                    result.planId?.let { put("planId", it) }
                                    result.error?.let { put("error", it) }
                                    put(
                                        "moduleKeys",
                                        buildJsonArray { result.moduleKeys.forEach { add(JsonPrimitive(it)) } },
                                    )
                                },
                            )
                        }
                    },
                )
            }
        Files.writeString(
            evidenceDirectory.resolve("scenario-discovery.json"),
            Json { prettyPrint = true }.encodeToString(
                kotlinx.serialization.json.JsonElement
                    .serializer(),
                evidence
            ),
        )
    }
}

private data class ScenarioDiscoveryResult(
    val scenario: OidfPlanScenario,
    val planId: String? = null,
    val moduleKeys: List<String> = emptyList(),
    val error: String? = null,
)
