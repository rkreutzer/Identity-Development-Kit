/*
 * (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package com.sphereon.wallet.runner.oidf

import com.sphereon.oidf.conformance.OidfConformanceSuiteClient
import com.sphereon.oidf.conformance.OidfPlan
import com.sphereon.oidf.conformance.OidfPlanScenarioManifest
import com.sphereon.oidf.conformance.OidfSuiteConfigPreprocessor
import com.sphereon.oidf.conformance.OidfSuiteEnvironment
import com.sphereon.wallet.runner.di.RunnerTokenClientAssertionRequest
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.file.Files
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64
import kotlin.io.path.Path
import kotlin.io.path.exists
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.minutes

class OidfWalletConformanceHarnessTest {
    @Test
    fun issuerInitiatedFapiModulesUseTheCredentialOfferInsteadOfDroppingIssuerState() {
        val fapiOptions = mapOf("fapi_profile" to "vci_haip", "vci_grant_type" to "authorization_code")
        assertFalse(
            oidfWalletInitiatedIssuance(
                mapOf("vci_authorization_code_flow_variant" to "issuer_initiated"),
                fapiOptions,
            ),
        )
        assertTrue(
            oidfWalletInitiatedIssuance(
                mapOf("vci_authorization_code_flow_variant" to "wallet_initiated"),
                fapiOptions,
            ),
        )
        assertFalse(
            oidfWalletInitiatedIssuance(
                mapOf("vci_authorization_code_flow_variant" to "wallet_initiated"),
                fapiOptions + ("vci_authorization_code_flow_variant" to "issuer_initiated"),
            ),
        )
        assertTrue(
            oidfWalletInitiatedIssuance(
                mapOf("vci_authorization_code_flow_variant" to "issuer_initiated"),
                fapiOptions + ("vci_authorization_code_flow_variant" to "wallet_initiated"),
            ),
        )
        assertFalse(oidfWalletInitiatedIssuance(emptyMap(), emptyMap()))
        assertTrue(
            oidfWalletInitiatedIssuance(
                emptyMap(),
                emptyMap(),
                "fapi2-security-profile-final-client-test-happy-path",
            ),
        )
        assertFalse(
            oidfWalletInitiatedIssuance(
                mapOf("vci_authorization_code_flow_variant" to "issuer_initiated"),
                fapiOptions,
                "fapi2-security-profile-final-client-test-happy-path",
            ),
        )
    }

    @Test
    fun encryptionUsesTheSelectedPlanVariantWhenTheModuleOnlyAddsFapiOptions() {
        assertTrue(
            oidfCredentialRequestEncryption(
                mapOf("vci_credential_encryption" to "encrypted"),
                mapOf("fapi_client_type" to "plain_oauth", "fapi_response_mode" to "plain_response"),
            ),
        )
        assertFalse(
            oidfCredentialRequestEncryption(
                mapOf("vci_credential_encryption" to "encrypted"),
                mapOf("vci_credential_encryption" to "plain"),
            ),
        )
        assertFalse(oidfCredentialRequestEncryption(emptyMap(), emptyMap()))
    }

    @Test
    fun preprocessorProducesValidHeadlessWalletConfigWhenSuiteCheckoutExists() {
        val suiteDir = configuredOidfSuiteDir()
        if (suiteDir == null || !suiteDir.exists()) {
            println("Skipping OIDF config preprocessing smoke; set -Doidf.suite.dir to a locked suite source directory.")
            return
        }

        val config =
            OidfSuiteConfigPreprocessor(
                suiteDir = suiteDir,
                baseUrl = "https://localhost.emobix.co.uk:8443/",
            ).walletConfig("scripts/test-configs-rp-against-op/vci-wallet-test-config-plain.json")

        val obj = Json.parseToJsonElement(config).jsonObject
        assertFalse(obj.containsKey("browser"), config)
        assertEquals(
            "https://localhost.emobix.co.uk:8443/test/a/oidf-vci-issuer-test/credential_offer",
            obj
                .getValue("vci")
                .jsonObject
                .getValue("credential_offer_endpoint")
                .jsonPrimitive.content,
        )
        assertNotNull(obj.getValue("server").jsonObject.getValue("jwks"))
    }

    @Test
    fun privateKeyJwtProviderSignsSuiteClientAssertionWhenSuiteCheckoutExists() =
        runTest {
            val suiteDir = configuredOidfSuiteDir()
            if (suiteDir == null || !suiteDir.exists()) {
                println("Skipping OIDF private_key_jwt smoke; set -Doidf.suite.dir to a locked suite source directory.")
                return@runTest
            }

            val provider =
                oidfSuitePrivateKeyJwtClientAssertionProvider(
                    suiteDir = suiteDir,
                    clock = Clock.fixed(Instant.ofEpochSecond(1_800_000_000), ZoneOffset.UTC),
                )
            val assertion =
                provider.assertion(
                    RunnerTokenClientAssertionRequest(
                        clientId = "52480754053",
                        tokenEndpoint = "https://localhost.emobix.co.uk:8443/test/a/oidf-vci-issuer-test/token",
                        audience = "https://localhost.emobix.co.uk:8443/test/a/oidf-vci-issuer-test/",
                    ),
                )

            assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", assertion.assertionType)
            val parts = assertion.assertion.split(".")
            assertEquals(3, parts.size, assertion.assertion)
            val header = Json.parseToJsonElement(base64UrlDecodeToString(parts[0])).jsonObject
            val claims = Json.parseToJsonElement(base64UrlDecodeToString(parts[1])).jsonObject
            assertEquals("ES256", header.getValue("alg").jsonPrimitive.content)
            assertEquals("vci-example-key-1", header.getValue("kid").jsonPrimitive.content)
            assertEquals("52480754053", claims.getValue("iss").jsonPrimitive.content)
            assertEquals("52480754053", claims.getValue("sub").jsonPrimitive.content)
            assertEquals("https://localhost.emobix.co.uk:8443/test/a/oidf-vci-issuer-test/", claims.getValue("aud").jsonPrimitive.content)
        }

    @Test
    fun localOidfSuiteVciPreAuthorizedCredentialIssuanceWhenConfigured() =
        runTest(timeout = 3.minutes) {
            val baseUrl = System.getProperty("oidf.suite.baseUrl")
            if (baseUrl.isNullOrBlank()) {
                println("Skipping live OIDF wallet conformance smoke; pass -Doidf.suite.baseUrl=https://localhost.emobix.co.uk:8443 to run it.")
                return@runTest
            }

            val suiteDir = configuredOidfSuiteDir() ?: error("-Doidf.suite.dir is required with -Doidf.suite.baseUrl")
            val suite = OidfConformanceSuiteClient(baseUrl = baseUrl)
            assertTrue(suite.healthCheck(), "OIDF conformance suite is not reachable at $baseUrl")

            val result =
                OidfWalletConformanceHarness(
                    suite = suite,
                    configPreprocessor = OidfSuiteConfigPreprocessor(suiteDir = suiteDir, baseUrl = baseUrl),
                ).runVciPreAuthorizedCredentialIssuance()

            assertTrue(result.walletInput.contains("credential_offer"), result.toString())
            assertTrue(result.walletOutcome.terminal, result.toString())
            assertEquals("FINISHED", result.suiteStatus, result.toString())
            assertEquals("PASSED", result.suiteResult, result.toString())
            println("OIDF wallet conformance result: $result")
        }

    @Test
    fun pinnedContainerSuiteVciPreAuthorizedCredentialIssuanceWhenConfigured() =
        runTest(timeout = 5.minutes) {
            if (System.getProperty("oidf.suite.mode") != "containers") {
                println("Skipping containerized OIDF wallet conformance; pass -Doidf.suite.mode=containers to run it.")
                return@runTest
            }

            val evidenceDirectory =
                Path(checkNotNull(System.getProperty("oidf.evidence.dir")))
                    .resolve("wallet-vci-pre-authorized")
            OidfSuiteEnvironment
                .start(startupEvidenceDirectory = evidenceDirectory.resolve("containers"))
                .use { environment ->
                    try {
                        environment.installJvmTrustStore().use {
                            val result =
                                OidfWalletConformanceHarness(
                                    suite = environment.client(),
                                    configPreprocessor =
                                        OidfSuiteConfigPreprocessor(
                                            suiteDir = environment.suiteSourceDirectory,
                                            baseUrl = environment.advertisedBaseUrl,
                                            localBaseUrl = environment.apiBaseUrl,
                                            mtlsBaseUrl = environment.advertisedMtlsBaseUrl,
                                        ),
                                ).runVciPreAuthorizedCredentialIssuance()

                            Files.createDirectories(evidenceDirectory)
                            environment.client().exportPlanHtml(
                                result.planId,
                                evidenceDirectory.resolve("plan-${result.planId}.zip"),
                            )
                            Files.writeString(
                                evidenceDirectory.resolve("result.json"),
                                buildJsonObject {
                                    put("planId", result.planId)
                                    put("testId", result.testId)
                                    put("suiteStatus", result.suiteStatus)
                                    put("suiteResult", result.suiteResult)
                                    put("walletTerminal", result.walletOutcome.terminal)
                                    put("walletOutcome", result.walletOutcome.toString())
                                }.toString(),
                            )

                            assertTrue(result.walletInput.contains("credential_offer"), result.toString())
                            assertTrue(result.walletOutcome.terminal, result.toString())
                            assertEquals("FINISHED", result.suiteStatus, result.toString())
                            assertEquals("PASSED", result.suiteResult, result.toString())
                            println("Pinned OIDF wallet conformance result: $result")
                        }
                    } finally {
                        environment.exportContainerLogs(evidenceDirectory.resolve("containers"))
                    }
                }
        }

    @Test
    fun pinnedContainerSuiteVpDigitalCredentialsHappyFlowWhenConfigured() =
        runTest(timeout = 10.minutes) {
            if (System.getProperty("oidf.suite.mode") != "wallet-vp-smoke") {
                println("Skipping containerized OIDF wallet VP smoke; pass -Doidf.suite.mode=wallet-vp-smoke to run it.")
                return@runTest
            }

            val evidenceDirectory =
                Path(checkNotNull(System.getProperty("oidf.evidence.dir")))
                    .resolve("wallet-vp-dc-api-happy-flow")
            OidfSuiteEnvironment
                .start(startupEvidenceDirectory = evidenceDirectory.resolve("containers"))
                .use { environment ->
                    val suite = environment.client()
                    var plan: OidfPlan? = null
                    var harness: OidfWalletConformanceHarness? = null
                    try {
                        environment.installJvmTrustStore().use {
                            val scenario =
                                OidfPlanScenarioManifest.scenarios.single {
                                    it.id == "wallet-vp-final-sd-jwt-vc-request-uri-unsigned-dc-api"
                                }
                            val configPreprocessor =
                                OidfSuiteConfigPreprocessor(
                                    suiteDir = environment.suiteSourceDirectory,
                                    baseUrl = environment.advertisedBaseUrl,
                                    localBaseUrl = environment.apiBaseUrl,
                                    mtlsBaseUrl = environment.advertisedMtlsBaseUrl,
                                )
                            val createdPlan =
                                suite.createPlan(
                                    planName = scenario.planName,
                                    configJson = configPreprocessor.config(scenario.configTemplate, scenario.configOverrides),
                                    variant = scenario.variantJson(),
                                )
                            plan = createdPlan
                            val module =
                                createdPlan.modules.single {
                                    it.testModule == "oid4vp-1final-wallet-happy-flow"
                                }
                            harness =
                                OidfWalletConformanceHarness(
                                    suite = suite,
                                    configPreprocessor = configPreprocessor,
                                )
                            val result =
                                harness.runModule(
                                    plan = createdPlan,
                                    module = module,
                                    haip = false,
                                    evidenceDirectory = evidenceDirectory.resolve("module"),
                                )

                            Files.createDirectories(evidenceDirectory)
                            suite.exportPlanHtml(
                                result.planId,
                                evidenceDirectory.resolve("plan-${result.planId}.zip"),
                            )
                            Files.writeString(
                                evidenceDirectory.resolve("result.json"),
                                buildJsonObject {
                                    put("scenarioId", scenario.id)
                                    put("planId", result.planId)
                                    put("testId", result.testId)
                                    put("suiteStatus", result.suiteStatus)
                                    put("suiteResult", result.suiteResult)
                                    put("walletTerminal", result.walletOutcome.terminal)
                                    put("walletOutcome", result.walletOutcome.toString())
                                }.toString(),
                            )

                            assertTrue(result.walletInput.contains("openid4vp-v1-unsigned"), result.toString())
                            assertTrue(result.walletOutcome.terminal, result.toString())
                            assertEquals("FINISHED", result.suiteStatus, result.toString())
                            assertEquals("PASSED", result.suiteResult, result.toString())
                            println("Pinned OIDF wallet VP conformance result: $result")
                        }
                    } finally {
                        runCatching { harness?.close() }
                        runCatching { plan?.let { suite.deletePlan(it.id) } }
                        environment.exportContainerLogs(evidenceDirectory.resolve("containers"))
                    }
                }
        }
}

private fun base64UrlDecodeToString(value: String): String = Base64.getUrlDecoder().decode(value).decodeToString()
