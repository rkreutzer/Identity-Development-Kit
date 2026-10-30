/*
 * (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package com.sphereon.oidf.conformance

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

data class OidfPlanScenario(
    val id: String,
    val planName: String,
    val configTemplate: String,
    val variant: Map<String, String>,
    val configOverrides: JsonObject = JsonObject(emptyMap()),
) {
    val requiredPlan: OidfRequiredPlan
        get() = OidfConformanceMatrix.requiredPlans.single { it.planName == planName }

    fun variantJson(): JsonObject =
        buildJsonObject {
            variant.toSortedMap().forEach { (name, value) -> put(name, value) }
        }
}

/**
 * Explicit, reviewable plan-selection manifest for the VDX OID4VC lane.
 *
 * A scenario creates one live OIDF plan. The runner must then execute every
 * module returned by that plan; it may not filter module names. HAIP plans fix
 * several variants in their ModuleListEntry definitions, so only the remaining
 * user-selectable values appear here. Final plans expose more values at plan
 * creation and therefore spell them out below.
 *
 * This is deliberately coverage-oriented rather than a blind cartesian
 * product: every protocol value VDX claims is represented, while combinations
 * the pinned suite declares invalid are absent.
 */
object OidfPlanScenarioManifest {
    val scenarios: List<OidfPlanScenario> =
        issuerFinal() +
            issuerHaip() +
            verifierFinal() +
            verifierHaip() +
            walletVciFinal() +
            walletVciHaip() +
            walletVpFinal() +
            walletVpHaip()

    init {
        require(scenarios.map { it.id }.distinct().size == scenarios.size) {
            "OIDF scenario ids must be unique"
        }
        val unknownPlans = scenarios.map { it.planName }.toSet() - OidfConformanceMatrix.requiredPlans.map { it.planName }.toSet()
        require(unknownPlans.isEmpty()) { "OIDF scenarios reference plans outside the required matrix: $unknownPlans" }
    }

    fun forPlan(planName: String): List<OidfPlanScenario> = scenarios.filter { it.planName == planName }

    private fun issuerFinal(): List<OidfPlanScenario> {
        val plan = "oid4vci-1_0-issuer-test-plan"
        val config = "scripts/test-configs-rp-against-op/vci-issuer-test-config-no-mtls.json"
        val base =
            mapOf(
                "sender_constrain" to "dpop",
                "fapi_profile" to "vci",
                "fapi_request_method" to "unsigned",
                "client_auth_type" to "private_key_jwt",
                "authorization_request_type" to "simple",
                "openid" to "plain_oauth",
                "fapi_response_mode" to "plain_response",
            )

        fun scenario(
            id: String,
            format: String,
            grant: String,
            flow: String,
            encryption: String,
        ) = OidfPlanScenario(
            id = id,
            planName = plan,
            configTemplate = config,
            variant =
                base +
                    mapOf(
                        "credential_format" to format,
                        "vci_grant_type" to grant,
                        "vci_authorization_code_flow_variant" to flow,
                        "vci_credential_encryption" to encryption,
                    ),
            configOverrides = JsonObject(emptyMap()),
        )

        return listOf(
            scenario("issuer-final-sdjwt-wallet-auth-plain", "sd_jwt_vc", "authorization_code", "wallet_initiated", "plain"),
            scenario("issuer-final-sdjwt-issuer-auth-encrypted", "sd_jwt_vc", "authorization_code", "issuer_initiated", "encrypted"),
            scenario("issuer-final-mdoc-wallet-auth-encrypted", "mdoc", "authorization_code", "wallet_initiated", "encrypted"),
            scenario("issuer-final-mdoc-issuer-auth-plain", "mdoc", "authorization_code", "issuer_initiated", "plain"),
            scenario("issuer-final-sdjwt-issuer-preauth-plain", "sd_jwt_vc", "pre_authorization_code", "issuer_initiated", "plain"),
            scenario("issuer-final-mdoc-issuer-preauth-encrypted", "mdoc", "pre_authorization_code", "issuer_initiated", "encrypted"),
        )
    }

    private fun issuerHaip(): List<OidfPlanScenario> {
        val plan = "oid4vci-1_0-issuer-haip-test-plan"
        val config = "scripts/test-configs-rp-against-op/vci-issuer-test-config-client_attestation-client-auth-dpop.json"
        return listOf("sd_jwt_vc", "mdoc").flatMap { format ->
            listOf("wallet_initiated", "issuer_initiated").map { flow ->
                OidfPlanScenario(
                    id = "issuer-haip-${format.idPart()}-${flow.idPart()}",
                    planName = plan,
                    configTemplate = config,
                    variant =
                        mapOf(
                            "credential_format" to format,
                            "vci_authorization_code_flow_variant" to flow,
                        ),
                )
            }
        }
    }

    private fun verifierFinal(): List<OidfPlanScenario> {
        val plan = "oid4vp-1final-verifier-test-plan"
        val requestModes =
            listOf(
                "redirect_uri" to "url_query",
                "x509_san_dns" to "request_uri_signed",
                "x509_hash" to "request_uri_signed",
            )
        return listOf("sd_jwt_vc", "iso_mdl").flatMap { format ->
            requestModes.flatMap { (clientIdPrefix, requestMethod) ->
                listOf("direct_post", "direct_post.jwt").map { responseMode ->
                    OidfPlanScenario(
                        id = "verifier-final-${format.idPart()}-${clientIdPrefix.idPart()}-${responseMode.idPart()}",
                        planName = plan,
                        configTemplate = vpWalletConfig(format),
                        variant =
                            mapOf(
                                "vp_profile" to "plain_vp",
                                "credential_format" to format,
                                "client_id_prefix" to clientIdPrefix,
                                "response_mode" to responseMode,
                                "request_method" to requestMethod,
                            ),
                    )
                }
            }
        }
    }

    private fun verifierHaip(): List<OidfPlanScenario> =
        listOf("sd_jwt_vc", "iso_mdl").map { format ->
            OidfPlanScenario(
                id = "verifier-haip-${format.idPart()}",
                planName = "oid4vp-1final-verifier-haip-test-plan",
                configTemplate = vpWalletConfig(format),
                variant =
                    mapOf(
                        "credential_format" to format,
                        "response_mode" to "direct_post.jwt",
                    ),
            )
        }

    private fun walletVciFinal(): List<OidfPlanScenario> {
        val plan = "oid4vci-1_0-wallet-test-plan"
        val config = "scripts/test-configs-rp-against-op/vci-wallet-test-config-plain.json"
        val base =
            mapOf(
                "fapi_request_method" to "unsigned",
                "sender_constrain" to "dpop",
                "fapi_profile" to "vci",
                "client_auth_type" to "private_key_jwt",
                "authorization_request_type" to "simple",
            )

        fun scenario(
            id: String,
            format: String,
            grant: String,
            flow: String,
            offer: String?,
            issuanceMode: String,
            encryption: String,
            authorizationRequestType: String = "simple",
        ): OidfPlanScenario =
            OidfPlanScenario(
                id = id,
                planName = plan,
                configTemplate = config,
                variant =
                    base +
                        mapOf(
                            "authorization_request_type" to authorizationRequestType,
                            "credential_format" to format,
                            "vci_grant_type" to grant,
                            "vci_authorization_code_flow_variant" to flow,
                            "vci_credential_issuance_mode" to issuanceMode,
                            "vci_credential_encryption" to encryption,
                        ) +
                        (offer?.let { mapOf("vci_credential_offer_variant" to it) } ?: emptyMap()),
            )

        return listOf(
            scenario("wallet-vci-final-sdjwt-preauth-value-immediate-plain", "sd_jwt_vc", "pre_authorization_code", "issuer_initiated", "by_value", "immediate", "plain"),
            scenario(
                "wallet-vci-final-mdoc-preauth-reference-deferred-encrypted",
                "mdoc",
                "pre_authorization_code",
                "issuer_initiated",
                "by_reference",
                "deferred",
                "encrypted",
                authorizationRequestType = "rar",
            ),
            scenario("wallet-vci-final-sdjwt-auth-reference-deferred-plain", "sd_jwt_vc", "authorization_code", "issuer_initiated", "by_reference", "deferred", "plain"),
            scenario("wallet-vci-final-mdoc-auth-value-immediate-encrypted", "mdoc", "authorization_code", "issuer_initiated", "by_value", "immediate", "encrypted"),
            scenario("wallet-vci-final-sdjwt-wallet-auth-immediate-plain", "sd_jwt_vc", "authorization_code", "wallet_initiated", null, "immediate", "plain"),
            scenario("wallet-vci-final-mdoc-wallet-auth-deferred-encrypted", "mdoc", "authorization_code", "wallet_initiated", null, "deferred", "encrypted"),
            scenario("wallet-vci-final-sdjwt-dc-api-immediate-plain", "sd_jwt_vc", "authorization_code", "issuer_initiated_dc_api", null, "immediate", "plain"),
        )
    }

    private fun walletVciHaip(): List<OidfPlanScenario> {
        val plan = "oid4vci-1_0-wallet-haip-test-plan"
        val config = "scripts/test-configs-rp-against-op/vci-wallet-test-config-haip.json"
        return listOf("sd_jwt_vc", "mdoc").flatMap { format ->
            listOf(
                Triple("wallet_initiated", null, "wallet"),
                Triple("issuer_initiated", "by_value", "issuer-value"),
                Triple("issuer_initiated", "by_reference", "issuer-reference"),
            ).map { (flow, offer, suffix) ->
                OidfPlanScenario(
                    id = "wallet-vci-haip-${format.idPart()}-$suffix",
                    planName = plan,
                    configTemplate = config,
                    variant =
                        mapOf(
                            "credential_format" to format,
                            "vci_authorization_code_flow_variant" to flow,
                        ) +
                            (offer?.let { mapOf("vci_credential_offer_variant" to it) } ?: emptyMap()),
                )
            }
        }
    }

    private fun walletVpFinal(): List<OidfPlanScenario> {
        val plan = "oid4vp-1final-wallet-test-plan"
        val modes =
            listOf(
                Triple("redirect_uri", "url_query", "direct_post"),
                Triple("x509_hash", "request_uri_signed", "direct_post.jwt"),
                Triple("web-origin", "request_uri_unsigned", "dc_api"),
                Triple("x509_hash", "request_uri_signed", "dc_api.jwt"),
                Triple("x509_hash", "request_uri_multisigned", "dc_api.jwt"),
            )
        return listOf("sd_jwt_vc", "iso_mdl").flatMap { format ->
            modes.map { (clientIdPrefix, requestMethod, responseMode) ->
                OidfPlanScenario(
                    id = "wallet-vp-final-${format.idPart()}-${requestMethod.idPart()}-${responseMode.idPart()}",
                    planName = plan,
                    configTemplate = vpWalletConfig(format),
                    variant =
                        mapOf(
                            "vp_profile" to "plain_vp",
                            "credential_format" to format,
                            "client_id_prefix" to clientIdPrefix,
                            "response_mode" to responseMode,
                            "request_method" to requestMethod,
                        ),
                )
            }
        }
    }

    private fun walletVpHaip(): List<OidfPlanScenario> {
        val plan = "oid4vp-1final-wallet-haip-test-plan"
        return listOf("sd_jwt_vc", "iso_mdl").flatMap { format ->
            listOf("direct_post.jwt", "dc_api.jwt").map { responseMode ->
                OidfPlanScenario(
                    id = "wallet-vp-haip-${format.idPart()}-${responseMode.idPart()}",
                    planName = plan,
                    configTemplate = vpWalletConfig(format),
                    variant =
                        mapOf(
                            "credential_format" to format,
                            "response_mode" to responseMode,
                        ),
                    configOverrides =
                        buildJsonObject {
                            put(
                                "credential",
                                buildJsonObject {
                                    val trustAnchor = if (format == "iso_mdl") "{mdoc-iaca-root.crt}" else "{vp-signing-ca.crt}"
                                    put("trust_anchor_pem", trustAnchor)
                                    val statusTrustAnchor = if (format == "iso_mdl") "{mdoc-iaca-root.crt}" else "{vci-test-root.crt}"
                                    put("status_list_trust_anchor_pem", statusTrustAnchor)
                                },
                            )
                        },
                )
            }
        }
    }

    private fun vpWalletConfig(format: String): String =
        when (format) {
            "sd_jwt_vc" -> "scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-sdjwt.json"
            "iso_mdl" -> "scripts/test-configs-rp-against-op/vp-wallet-test-config-dcql-mdoc-mdl.json"
            else -> error("Unsupported VP credential format: $format")
        }
}

private fun String.idPart(): String = lowercase().replace("_", "-").replace(".", "-")
