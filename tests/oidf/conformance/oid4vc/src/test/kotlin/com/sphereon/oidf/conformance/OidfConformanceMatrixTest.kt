/*
 * (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package com.sphereon.oidf.conformance

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class OidfConformanceMatrixTest {
    @Test
    fun `matrix covers final and HAIP plans for issuer verifier and both wallet protocols`() {
        assertEquals(8, OidfConformanceMatrix.requiredPlans.size)
        assertEquals(
            8,
            OidfConformanceMatrix.requiredPlans
                .map { it.planName }
                .toSet()
                .size
        )

        assertEquals(
            setOf(OidfProfile.FINAL_1_0, OidfProfile.HAIP_1_0),
            OidfConformanceMatrix.requiredPlans
                .filter { it.role == OidfRole.ISSUER && it.protocol == OidfProtocol.OID4VCI }
                .map { it.profile }
                .toSet(),
        )
        assertEquals(
            setOf(OidfProfile.FINAL_1_0, OidfProfile.HAIP_1_0),
            OidfConformanceMatrix.requiredPlans
                .filter { it.role == OidfRole.VERIFIER && it.protocol == OidfProtocol.OID4VP }
                .map { it.profile }
                .toSet(),
        )
        assertEquals(
            setOf(
                OidfProtocol.OID4VCI to OidfProfile.FINAL_1_0,
                OidfProtocol.OID4VCI to OidfProfile.HAIP_1_0,
                OidfProtocol.OID4VP to OidfProfile.FINAL_1_0,
                OidfProtocol.OID4VP to OidfProfile.HAIP_1_0,
            ),
            OidfConformanceMatrix.requiredPlans
                .filter { it.role == OidfRole.WALLET }
                .map { it.protocol to it.profile }
                .toSet(),
        )
    }

    @Test
    fun `availability guard fails closed when a required plan disappears`() {
        val available = OidfConformanceMatrix.requiredPlans.map { it.planName }.toMutableSet()
        available.remove("oid4vp-1final-wallet-haip-test-plan")

        assertFailsWith<IllegalArgumentException> {
            OidfConformanceMatrix.requireAvailablePlans(available)
        }
    }

    @Test
    fun suiteLockPinsUnmodifiedOfficialImages() {
        val lock = OidfSuiteLock.load()

        assertEquals(40, lock.upstreamCommit.length)
        assertEquals("upstream-unmodified", lock.patchSet)
        listOf(
            lock.gitImage,
            lock.mavenImage,
            lock.serverRuntimeImage,
            lock.upstreamNginxImage,
            lock.mongoImage,
        ).forEach { image -> assertTrue(image.matches(Regex(".+@sha256:[0-9a-f]{64}")), image) }
        assertTrue(lock.serverImage.matches(Regex("registry\\.gitlab\\.com/openid/conformance-suite@sha256:[0-9a-f]{64}")))
        assertTrue(lock.nginxImage.matches(Regex("registry\\.gitlab\\.com/openid/conformance-suite/nginx@sha256:[0-9a-f]{64}")))
        assertTrue(
            OidfSuiteConfigPreprocessor.VCI_WALLET_CLIENT_AUTH_CONFIG in OidfSuiteConfigPreprocessor.requiredSourceFiles,
            "The hermetic suite source manifest must include the wallet's private-key client-auth config",
        )
    }

    @Test
    fun `scenario keys include plan module and canonical variant`() {
        val module =
            OidfPlanModule(
                testModule = "oid4vci-1_0-wallet-test-credential-issuance",
                variant = linkedMapOf("zeta" to "last", "alpha" to "first"),
            )

        assertEquals(
            "oid4vci-1_0-wallet-test-plan|planVariant:format=sd_jwt_vc|oid4vci-1_0-wallet-test-credential-issuance|moduleVariant:alpha=first|moduleVariant:zeta=last",
            module.scenarioKey(
                "oid4vci-1_0-wallet-test-plan",
                mapOf("format" to "sd_jwt_vc"),
            ),
        )
    }

    @Test
    fun `scenario manifest covers every required plan and protocol dimension`() {
        val scenarios = OidfPlanScenarioManifest.scenarios

        assertEquals(51, scenarios.size)
        assertEquals(scenarios.size, scenarios.map { it.id }.toSet().size)
        assertEquals(
            OidfConformanceMatrix.requiredPlans.map { it.planName }.toSet(),
            scenarios.map { it.planName }.toSet(),
        )
        OidfConformanceMatrix.requiredPlans.forEach { plan ->
            assertTrue(OidfPlanScenarioManifest.forPlan(plan.planName).isNotEmpty(), plan.planName)
        }

        assertEquals(setOf("sd_jwt_vc", "mdoc"), valuesForRole(OidfRole.ISSUER, "credential_format"))
        assertEquals(setOf("sd_jwt_vc", "iso_mdl"), valuesForRole(OidfRole.VERIFIER, "credential_format"))
        assertEquals(
            setOf("sd_jwt_vc", "mdoc", "iso_mdl"),
            valuesForRole(OidfRole.WALLET, "credential_format"),
        )
        assertEquals(
            setOf("direct_post", "direct_post.jwt", "dc_api", "dc_api.jwt"),
            valuesForRole(OidfRole.WALLET, "response_mode"),
        )
        assertEquals(
            setOf("plain", "encrypted"),
            scenarios.mapNotNull { it.variant["vci_credential_encryption"] }.toSet(),
        )
        assertTrue(scenarios.all { scenario -> scenario.variant.all { (key, value) -> key.isNotBlank() && value.isNotBlank() } })
    }

    @Test
    fun `wallet VP scenarios use format-specific wallet configs and HAIP trust anchors`() {
        val walletVpScenarios =
            OidfPlanScenarioManifest.scenarios.filter {
                it.requiredPlan.role == OidfRole.WALLET && it.requiredPlan.protocol == OidfProtocol.OID4VP
            }

        walletVpScenarios.forEach { scenario ->
            val expectedConfig =
                when (scenario.variant.getValue("credential_format")) {
                    "sd_jwt_vc" -> "scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-sdjwt.json"
                    "iso_mdl" -> "scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-mdoc-mdl.json"
                    else -> error("Unexpected wallet VP format: ${scenario.variant}")
                }
            assertEquals(expectedConfig, scenario.configTemplate, scenario.id)
        }

        walletVpScenarios
            .filter { it.requiredPlan.profile == OidfProfile.HAIP_1_0 }
            .forEach { scenario ->
                val credential = scenario.configOverrides.getValue("credential").jsonObject
                val isMdoc = scenario.variant.getValue("credential_format") == "iso_mdl"
                val credentialTrustAnchor = if (isMdoc) "{mdoc-iaca-root.crt}" else "{vp-signing-ca.crt}"
                val statusTrustAnchor = if (isMdoc) "{mdoc-iaca-root.crt}" else "{vci-test-root.crt}"
                assertEquals(credentialTrustAnchor, credential.getValue("trust_anchor_pem").jsonPrimitive.content, scenario.id)
                assertEquals(statusTrustAnchor, credential.getValue("status_list_trust_anchor_pem").jsonPrimitive.content, scenario.id)
            }
    }

    @Test
    fun `wallet VCI mdoc pre-authorized scenario uses format-aware authorization details`() {
        val scenarios = OidfPlanScenarioManifest.forPlan("oid4vci-1_0-wallet-test-plan")
        val mdocPreAuthorized =
            scenarios.single {
                it.variant["credential_format"] == "mdoc" &&
                    it.variant["vci_grant_type"] == "pre_authorization_code"
            }
        val sdJwtPreAuthorized =
            scenarios.single {
                it.variant["credential_format"] == "sd_jwt_vc" &&
                    it.variant["vci_grant_type"] == "pre_authorization_code"
            }

        assertEquals("rar", mdocPreAuthorized.variant["authorization_request_type"])
        assertEquals("simple", sdJwtPreAuthorized.variant["authorization_request_type"])
    }

    @Test
    fun `config preprocessor expands certificate placeholders supplied by overrides`() {
        val suiteDir = Files.createTempDirectory("oidf-config-preprocessor-")
        try {
            val certDirectory = Files.createDirectories(suiteDir.resolve("scripts/certs-keys"))
            val certificate = "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n"
            Files.writeString(suiteDir.resolve("config.json"), "{}")
            Files.writeString(certDirectory.resolve("vp-signing-ca.crt"), certificate)

            val config =
                OidfSuiteConfigPreprocessor(suiteDir, "https://suite.example")
                    .config(
                        relativePath = "config.json",
                        overrides =
                            buildJsonObject {
                                put(
                                    "credential",
                                    buildJsonObject {
                                        put("trust_anchor_pem", "{vp-signing-ca.crt}")
                                        put("status_list_trust_anchor_pem", "{vp-signing-ca.crt}")
                                    },
                                )
                            },
                    )
            val credential =
                Json
                    .parseToJsonElement(config)
                    .jsonObject
                    .getValue("credential")
                    .jsonObject

            assertEquals(certificate, credential.getValue("trust_anchor_pem").jsonPrimitive.content)
            assertEquals(certificate, credential.getValue("status_list_trust_anchor_pem").jsonPrimitive.content)
        } finally {
            suiteDir.toFile().deleteRecursively()
        }
    }

    private fun valuesForRole(
        role: OidfRole,
        variantName: String,
    ): Set<String> =
        OidfPlanScenarioManifest.scenarios
            .filter { it.requiredPlan.role == role }
            .mapNotNull { it.variant[variantName] }
            .toSet()
}
