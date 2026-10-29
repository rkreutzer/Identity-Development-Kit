/*
 * (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package com.sphereon.wallet.runner.oidf

import com.sphereon.oidf.conformance.OidfBrowserApiRequest
import com.sphereon.oidf.conformance.OidfConformanceSuiteClient
import com.sphereon.oidf.conformance.OidfPlan
import com.sphereon.oidf.conformance.OidfPlanModule
import com.sphereon.oidf.conformance.OidfSuiteConfigPreprocessor
import com.sphereon.wallet.interaction.WalletEntryPoint
import com.sphereon.wallet.interaction.WalletInteractionAction
import com.sphereon.wallet.interaction.WalletInteractionFailureCodes
import com.sphereon.wallet.interaction.WalletInteractionFlowKind
import com.sphereon.wallet.interaction.WalletInteractionInput
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciInteractionLaunchAttributes
import com.sphereon.wallet.interaction.protocol.oid4vci.Oid4vciWalletInteractionProtocolAdapter
import com.sphereon.wallet.interaction.protocol.oid4vp.Oid4vpWalletInteractionProtocolAdapter
import com.sphereon.wallet.runner.HeadlessRunOutcome
import com.sphereon.wallet.runner.HeadlessWalletRunner
import com.sphereon.wallet.runner.HeadlessWalletRunnerBootstrap
import kotlinx.coroutines.delay
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.Path
import kotlin.time.Clock

internal data class OidfWalletHarnessResult(
    val planId: String,
    val testId: String,
    val walletInput: String,
    val walletOutcome: HeadlessRunOutcome,
    val suiteStatus: String?,
    val suiteResult: String?,
)

/** Retains an observed wallet result when the subsequent official-suite exchange fails. */
internal class OidfWalletSuiteCompletionException(
    val walletOutcome: HeadlessRunOutcome,
    cause: Throwable,
) : RuntimeException("Official suite completion failed after observing the wallet outcome", cause)

internal inline fun <T> oidfWithObservedWalletOutcome(
    walletOutcome: HeadlessRunOutcome,
    awaitSuiteCompletion: () -> T,
): T =
    try {
        awaitSuiteCompletion()
    } catch (error: Throwable) {
        throw OidfWalletSuiteCompletionException(walletOutcome, error)
    }

private data class OidfWalletExecution(
    val outcome: HeadlessRunOutcome,
    val completionHandoff: JsonObject? = null,
)

private sealed interface OidfWalletInput {
    data class Uri(
        val value: String,
    ) : OidfWalletInput

    data class WalletInitiated(
        val credentialIssuer: String,
        val credentialConfigurationId: String,
    ) : OidfWalletInput

    data class BrowserApi(
        val protocol: String,
        val data: kotlinx.serialization.json.JsonElement,
        val callback: OidfBrowserApiRequest,
    ) : OidfWalletInput
}

internal class OidfWalletConformanceHarness(
    private val suite: OidfConformanceSuiteClient,
    private val configPreprocessor: OidfSuiteConfigPreprocessor,
    private val profileId: String = "default",
    private val haipAttestationFixture: OidfHaipWalletAttestationFixture? = null,
) {
    private lateinit var walletUnitId: String
    private var vpBootstrap: HeadlessWalletRunnerBootstrap? = null
    private var vpRunner: HeadlessWalletRunner? = null
    private val provisionedPresentationFormats = mutableSetOf<String>()

    suspend fun runVciPreAuthorizedCredentialIssuance(): OidfWalletHarnessResult {
        val config =
            configPreprocessor.walletConfig(
                "scripts/test-configs-rp-against-op/vci-wallet-test-config-plain.json",
            )
        val plan =
            suite.createPlan(
                planName = "oid4vci-1_0-wallet-test-plan",
                configJson = config,
                variant = oidfVciPreAuthorizedSmokeVariant(),
            )
        val module = plan.modules.single { it.testModule == "oid4vci-1_0-wallet-test-credential-issuance" }
        return runModule(plan, module, haip = false)
    }

    suspend fun runModule(
        plan: OidfPlan,
        module: OidfPlanModule,
        haip: Boolean,
        evidenceDirectory: Path? = null,
        onStarted: (String) -> Unit = {},
    ): OidfWalletHarnessResult {
        val presentationFormat =
            plan.selectionVariant["credential_format"]
                ?.takeIf { plan.name.startsWith("oid4vp-") }
        if (presentationFormat != null) {
            ensurePresentationCredential(
                format = presentationFormat,
                evidenceDirectory = evidenceDirectory?.resolve("credential-provisioning"),
            )
            checkNotNull(vpBootstrap).setHaipEnabled(haip, profileId)
        }
        val test = suite.startModule(module.testModule, plan.id, module.variant.toJsonObject())
        onStarted(test.id)
        suite.waitForState(test.id, listOf("WAITING", "FINISHED", "INTERRUPTED"), timeoutMs = 30_000)
        val testInfo = suite.info(test.id)
        val walletClientId =
            if (presentationFormat == null) {
                testInfo.clientId
                    ?: error("OIDF suite issuance test ${test.id} did not expose config.client.client_id")
            } else {
                null
            }
        val redirectUri =
            if (presentationFormat == null) {
                testInfo.redirectUri
                    ?: error("OIDF suite issuance test ${test.id} did not expose config.client.redirect_uri")
            } else {
                null
            }
        val encryptCredentialRequest = oidfCredentialRequestEncryption(plan.selectionVariant, module.variant)
        val credentialBatchSize = if (module.testModule == VCI_BATCH_MODULE) 2 else 1
        val walletInput =
            if (oidfWalletInitiatedIssuance(plan.selectionVariant, module.variant, module.testModule)) {
                awaitWalletInitiatedInput(
                    testId = test.id,
                    testModule = module.testModule,
                    credentialFormat = plan.selectionVariant["credential_format"],
                )
            } else {
                awaitWalletInput(test.id)
            }
        val walletExecution =
            if (presentationFormat != null) {
                runWallet(walletInput, checkNotNull(vpRunner), null, false, 1)
            } else {
                runWalletEphemeral(
                    walletInput,
                    checkNotNull(walletClientId),
                    checkNotNull(redirectUri),
                    encryptCredentialRequest,
                    haip,
                    credentialBatchSize,
                )
            }
        val walletOutcome = walletExecution.outcome
        return oidfWithObservedWalletOutcome(walletOutcome) {
            when (walletInput) {
                is OidfWalletInput.Uri -> {
                    suite.markVisited(test.id, walletInput.value)
                }

                is OidfWalletInput.WalletInitiated -> {
                    Unit
                }

                is OidfWalletInput.BrowserApi -> {
                    if (walletInput.callback.submitUrl.isBlank()) {
                        require(walletInput.protocol == "openid4vci-v1") {
                            "Only the OID4VCI Digital Credentials API create flow may omit a submit URL"
                        }
                        require(walletOutcome.succeeded) {
                            "VDX wallet did not complete OID4VCI Digital Credentials API issuance: " +
                                (walletOutcome.error?.code ?: walletOutcome.status)
                        }
                    } else {
                        val response =
                            walletExecution.completionHandoff
                                ?: buildJsonObject {
                                    put(
                                        "exception",
                                        walletOutcome.error?.code
                                            ?: "wallet interaction ended with ${walletOutcome.status}",
                                    )
                                }
                        suite.submitBrowserApiResponse(
                            submitUrl = walletInput.callback.submitUrl,
                            responseJson = response,
                        )
                    }
                }
            }
            suite.waitForState(test.id, listOf("FINISHED", "INTERRUPTED"), timeoutMs = 180_000)
            val info = suite.info(test.id)
            OidfWalletHarnessResult(
                planId = plan.id,
                testId = test.id,
                walletInput = walletInput.toString(),
                walletOutcome = walletOutcome,
                suiteStatus = info.status,
                suiteResult = info.result,
            )
        }
    }

    private suspend fun runWalletEphemeral(
        walletInput: OidfWalletInput,
        walletClientId: String,
        redirectUri: String,
        encryptCredentialRequest: Boolean,
        haip: Boolean,
        credentialBatchSize: Int,
    ): OidfWalletExecution {
        val bootstrap =
            HeadlessWalletRunnerBootstrap.create(
                hostRequirements = createOidfWalletHostRequirements(),
                profile = profileId,
                conformance = true,
                haip = haip,
                walletClientId = walletClientId,
                tokenClientAssertionProvider = oidfSuitePrivateKeyJwtClientAssertionProvider(configPreprocessor.suiteDir),
                tokenDpopEnabled = true,
            )
        return try {
            val runner = bootstrap.runner(profileId = profileId)
            bindProfileWalletUnit(bootstrap)
            if (haip) {
                checkNotNull(haipAttestationFixture) { "HAIP OID4VCI requires x5c wallet-attestation material" }
                    .provision(bootstrap, walletUnitId, profileId)
            }
            runWallet(walletInput, runner, redirectUri, encryptCredentialRequest, credentialBatchSize)
        } finally {
            bootstrap.destroy()
        }
    }

    private suspend fun bindProfileWalletUnit(bootstrap: HeadlessWalletRunnerBootstrap) {
        val profile = bootstrap.profileRegistry.get(profileId).getOrElse { error(it.toString()) }
        walletUnitId =
            checkNotNull(profile.providerBinding?.descriptor?.walletUnitId) {
                "OIDF fixture requires the selected profile's wallet-unit binding"
            }
    }

    private suspend fun runWallet(
        walletInput: OidfWalletInput,
        runner: HeadlessWalletRunner,
        redirectUri: String?,
        encryptCredentialRequest: Boolean,
        credentialBatchSize: Int,
    ): OidfWalletExecution {
        var outcome =
            when (walletInput) {
                is OidfWalletInput.Uri -> {
                    runner.run(
                        WalletInteractionInput(
                            walletUnitId = walletUnitId,
                            entryPoint = WalletEntryPoint.link(walletInput.value, source = "oidf-conformance"),
                            requestedFlowKinds = listOf(WalletInteractionFlowKind.CredentialReceive),
                            metadata = oid4vciLaunchMetadata(redirectUri, encryptCredentialRequest, credentialBatchSize),
                        ),
                    )
                }

                is OidfWalletInput.WalletInitiated -> {
                    runner.run(
                        WalletInteractionInput(
                            walletUnitId = walletUnitId,
                            entryPoint =
                                WalletEntryPoint.parsed(
                                    type = Oid4vciWalletInteractionProtocolAdapter.ISSUE_PARSED_TYPE,
                                    value =
                                        buildJsonObject {
                                            put("credentialIssuer", walletInput.credentialIssuer)
                                            put(
                                                "credentialConfigurationIds",
                                                buildJsonArray { add(JsonPrimitive(walletInput.credentialConfigurationId)) },
                                            )
                                        },
                                    source = "oidf-wallet-initiated",
                                ),
                            requestedFlowKinds = listOf(WalletInteractionFlowKind.CredentialReceive),
                            metadata =
                                oid4vciLaunchMetadata(redirectUri, encryptCredentialRequest, credentialBatchSize) +
                                    (
                                        Oid4vciInteractionLaunchAttributes.CREDENTIAL_CONFIGURATION_ID to
                                            walletInput.credentialConfigurationId
                                    ),
                        ),
                    )
                }

                is OidfWalletInput.BrowserApi -> {
                    runner.run(
                        WalletInteractionInput(
                            walletUnitId = walletUnitId,
                            entryPoint =
                                WalletEntryPoint.parsed(
                                    type = walletInput.protocol,
                                    value = walletInput.data,
                                    source = "oidf-digital-credentials-api",
                                ),
                            requestedFlowKinds =
                                listOf(
                                    if (walletInput.protocol.startsWith("openid4vci")) {
                                        WalletInteractionFlowKind.CredentialReceive
                                    } else {
                                        WalletInteractionFlowKind.CredentialPresent
                                    },
                                ),
                            metadata =
                                if (walletInput.protocol.startsWith("openid4vp-v1-")) {
                                    mapOf(
                                        Oid4vpWalletInteractionProtocolAdapter.DIGITAL_CREDENTIAL_ORIGIN_METADATA_KEY to
                                            suite.browserOrigin,
                                    )
                                } else if (walletInput.protocol.startsWith("openid4vci")) {
                                    oid4vciLaunchMetadata(redirectUri, encryptCredentialRequest, credentialBatchSize)
                                } else {
                                    emptyMap()
                                },
                        ),
                    )
                }
            }
        if (outcome.status == WalletInteractionStatus.TxCodeRequired) {
            val txRef = runner.registerTransactionCode(outcome.sessionId, "123456")
            runner.dispatch(outcome.sessionId, WalletInteractionAction.submitTxCode(txRef))
            outcome = runner.driveToTerminal(outcome.sessionId)
        }
        for (handoffAttempt in 0 until MAX_EXTERNAL_HANDOFFS) {
            when (outcome.status) {
                WalletInteractionStatus.AuthorizationRequired -> {
                    val handoffRef =
                        runner.observe(outcome.sessionId).value.authorizationHandoffRef
                            ?: error("OID4VCI authorization handoff is unavailable")
                    val authorizationUrl =
                        runner.consumeAuthorizationHandoff(outcome.sessionId, handoffRef)
                            ?: error(
                                "OID4VCI authorization handoff is invalid or expired " +
                                    "(status=${outcome.status}, errorCode=${outcome.error?.code})",
                            )
                    val callbackUri = suite.visitFollowingRedirects(authorizationUrl, terminalRedirectUri = redirectUri)
                    val callbackRef = runner.registerAuthorizationCallback(outcome.sessionId, callbackUri)
                    runner.dispatch(outcome.sessionId, WalletInteractionAction.authCallback(callbackRef))
                    outcome = runner.driveToTerminal(outcome.sessionId)
                    if (
                        outcome.status == WalletInteractionStatus.AuthorizationRequired &&
                        outcome.error?.code == WalletInteractionFailureCodes.OID4VCI_AUTHORIZATION_STATE_MISMATCH
                    ) {
                        // The callback was rejected; the pending receive still waits for its own response.
                        // The browser handoff is one-use. Preserve the real typed outcome and let the
                        // official suite independently observe that no token request follows this callback.
                        break
                    }
                }

                WalletInteractionStatus.DeferredRetrievalPending -> {
                    val intervalSeconds =
                        runner
                            .observe(outcome.sessionId)
                            .value.deferred
                            ?.intervalSeconds ?: 1
                    delay(intervalSeconds.coerceIn(1, MAX_DEFERRED_INTERVAL_SECONDS).toLong() * 1_000)
                    runner.dispatch(outcome.sessionId, WalletInteractionAction.retryDeferredRetrieval())
                    outcome = runner.driveToTerminal(outcome.sessionId)
                }

                else -> {
                    break
                }
            }
        }
        val completionHandoff =
            if (outcome.succeeded) {
                val state = runner.observe(outcome.sessionId).value
                state.completionHandoffRef?.let { ref ->
                    consumeOidfCompletionHandoff(
                        transport = state.completionHandoffTransport,
                        consume = {
                            checkNotNull(runner.consumeCompletionHandoff(outcome.sessionId, ref)) {
                                "OIDF completion handoff is invalid or expired"
                            }
                        },
                    )
                }
            } else {
                null
            }
        return OidfWalletExecution(outcome, completionHandoff)
    }

    private fun oid4vciLaunchMetadata(
        redirectUri: String?,
        encryptCredentialRequest: Boolean,
        credentialBatchSize: Int,
    ): Map<String, String> =
        buildMap {
            redirectUri?.let { put(Oid4vciInteractionLaunchAttributes.REDIRECT_URI, it) }
            put(Oid4vciInteractionLaunchAttributes.ENCRYPT_CREDENTIAL_REQUEST, encryptCredentialRequest.toString())
            put(Oid4vciInteractionLaunchAttributes.CREDENTIAL_BATCH_SIZE, credentialBatchSize.toString())
        }

    /**
     * Obtains the presentation credential through the real Tier 1 OID4VCI interaction before the
     * VP row starts. The same bootstrap, profile, session, WSCA keys, acceptance checks, and wallet
     * store are then used for presentation; no test code writes a credential record directly.
     */
    private suspend fun ensurePresentationCredential(
        format: String,
        evidenceDirectory: Path?,
    ) {
        if (format in provisionedPresentationFormats) return
        val bootstrap =
            vpBootstrap
                ?: HeadlessWalletRunnerBootstrap
                    .create(
                        hostRequirements = createOidfWalletHostRequirements(),
                        profile = profileId,
                        conformance = true,
                        haip = false,
                        walletClientId = VCI_WALLET_CLIENT_ID,
                        tokenClientAssertionProvider = oidfSuitePrivateKeyJwtClientAssertionProvider(configPreprocessor.suiteDir),
                        tokenDpopEnabled = true,
                    ).also { created ->
                        vpBootstrap = created
                        vpRunner = created.runner(profileId = profileId)
                        bindProfileWalletUnit(created)
                    }
        bootstrap.setHaipEnabled(false, profileId)
        val runner = checkNotNull(vpRunner)
        val signingJwk = configPreprocessor.sourceJson("scripts/certs-keys/vp-signing-jwk.json")
        val setupPlan =
            suite.createPlan(
                planName = VCI_SETUP_PLAN,
                configJson =
                    configPreprocessor.config(
                        relativePath = VCI_SETUP_CONFIG,
                        overrides =
                            buildJsonObject {
                                put("credential", buildJsonObject { put("signing_jwk", signingJwk) })
                                if (format == "iso_mdl") {
                                    put("vci", buildJsonObject { put("credential_configuration_id", "org.iso.18013.5.1.mDL") })
                                }
                            },
                    ),
                variant = oidfVciPresentationCredentialVariant(format),
            )
        val setupModule =
            setupPlan.modules.singleOrNull { it.testModule == VCI_SETUP_MODULE }
                ?: error("OIDF credential setup plan did not expose exactly one $VCI_SETUP_MODULE module")
        var setupTestId: String? = null
        var setupInfo: com.sphereon.oidf.conformance.OidfTestInfo? = null
        try {
            val setupTest = suite.startModule(setupModule.testModule, setupPlan.id, setupModule.variant.toJsonObject())
            setupTestId = setupTest.id
            suite.waitForState(setupTest.id, listOf("WAITING", "FINISHED", "INTERRUPTED"), timeoutMs = 30_000)
            val setupInput = awaitWalletInput(setupTest.id)
            val setupRedirectUri =
                suite.info(setupTest.id).redirectUri
                    ?: error("OIDF credential setup test ${setupTest.id} did not expose config.client.redirect_uri")
            val setupExecution = runWallet(setupInput, runner, setupRedirectUri, false, 1)
            when (setupInput) {
                is OidfWalletInput.Uri -> {
                    suite.markVisited(setupTest.id, setupInput.value)
                }

                is OidfWalletInput.WalletInitiated -> {
                    error("VP credential provisioning expects an issuer-initiated credential offer")
                }

                is OidfWalletInput.BrowserApi -> {
                    error("VP credential provisioning expects an OID4VCI credential-offer URI, not Browser API input")
                }
            }
            require(setupExecution.outcome.succeeded) {
                val providerCode =
                    setupExecution.outcome.error
                        ?.arguments
                        ?.get("providerErrorCode")
                "OIDF credential setup wallet flow failed: ${setupExecution.outcome.error?.code ?: setupExecution.outcome.status}" +
                    (providerCode?.let { "; providerErrorCode=${it.toString().take(160)}" } ?: "")
            }
            suite.waitForState(setupTest.id, listOf("FINISHED", "INTERRUPTED"), timeoutMs = 180_000)
            setupInfo = suite.info(setupTest.id)
            require(setupInfo.status == "FINISHED" && setupInfo.result == "PASSED") {
                "OIDF credential setup did not pass: $setupInfo"
            }
            val stored =
                bootstrap
                    .holder(profileId)
                    .credentials
                    .list()
                    .getOrElse { error(it.toString()) }
            val matching =
                stored.filter { credential ->
                    when (format) {
                        "sd_jwt_vc" -> credential.format.isSdJwt
                        "iso_mdl" -> credential.format.isMdoc
                        else -> false
                    }
                }
            require(matching.isNotEmpty()) {
                "OIDF credential setup completed without storing a presentable $format credential"
            }
            if (format == "sd_jwt_vc") {
                val records =
                    matching.map { metadata ->
                        bootstrap
                            .holder(profileId)
                            .credentials
                            .get(metadata.credentialRecordId)
                            .getOrElse { error(it.toString()) }
                    }
                require(
                    records.any { record ->
                        record
                            .presentableInstance(Clock.System.now())
                            ?.holderKeyRef
                            ?.alias
                            ?.isNotBlank() == true
                    },
                ) {
                    val instanceSummary =
                        records.joinToString { record ->
                            "${record.id}=[${record.instances.joinToString { instance ->
                                "${instance.id}:${instance.lifecycleState}:holderKey=${!instance.holderKeyRef?.alias.isNullOrBlank()}"
                            }}]"
                        }
                    "OIDF credential setup stored SD-JWT VC records without a holder-bound presentable instance: $instanceSummary"
                }
            }
            provisionedPresentationFormats += format
        } finally {
            evidenceDirectory?.let { directory ->
                Files.createDirectories(directory)
                runCatching { suite.exportPlanHtml(setupPlan.id, directory.resolve("plan-${setupPlan.id}.zip")) }
                Files.writeString(
                    directory.resolve("result.json"),
                    buildJsonObject {
                        put("format", format)
                        put("planId", setupPlan.id)
                        setupTestId?.let { put("testId", it) }
                        setupInfo?.status?.let { put("status", it) }
                        setupInfo?.result?.let { put("result", it) }
                    }.toString(),
                )
            }
            runCatching { suite.deletePlan(setupPlan.id) }
        }
    }

    fun close() {
        vpBootstrap?.destroy()
        vpBootstrap = null
        vpRunner = null
        provisionedPresentationFormats.clear()
    }

    private suspend fun awaitWalletInput(testId: String): OidfWalletInput {
        repeat(60) {
            val browser = suite.browser(testId)
            require(browser.error == null) { "OIDF suite test $testId failed before wallet handoff: ${browser.error}" }
            require(browser.urls.size + browser.browserApiRequests.size <= 1) {
                "OIDF suite test $testId exposed multiple simultaneous wallet inputs: $browser"
            }
            browser.urls.singleOrNull()?.let { return OidfWalletInput.Uri(it) }
            browser.browserApiRequests.singleOrNull()?.let { callback ->
                val requests =
                    callback.request["digital"]
                        ?.jsonObject
                        ?.get("requests")
                        ?.jsonArray
                        ?: error("OIDF Browser API request is missing digital.requests: ${callback.request}")
                require(requests.size == 1) { "VDX conformance wallet accepts exactly one Digital Credentials API request: $requests" }
                val request = requests.single().jsonObject
                val protocol = request.getValue("protocol").jsonPrimitive.content
                val data = request.getValue("data")
                return OidfWalletInput.BrowserApi(protocol, data, callback)
            }
            delay(1_000)
        }
        error("OIDF suite test $testId did not expose a wallet input within 60 seconds")
    }

    private suspend fun awaitWalletInitiatedInput(
        testId: String,
        testModule: String,
        credentialFormat: String?,
    ): OidfWalletInput.WalletInitiated {
        var lastExposed = emptyMap<String, String>()
        val fapiCredentialConfigurationId =
            if (testModule.startsWith(FAPI2_CLIENT_MODULE_PREFIX)) {
                when (credentialFormat) {
                    "sd_jwt_vc" -> "eu.europa.ec.eudi.pid.1"
                    "mdoc" -> "eu.europa.ec.eudi.pid.mdoc.1"
                    else -> error("Unsupported OIDF HAIP FAPI2 wallet credential format '$credentialFormat'")
                }
            } else {
                null
            }
        repeat(20) {
            val exposed = suite.exposed(testId)
            lastExposed = exposed
            val credentialIssuer = exposed["credential_issuer"]?.takeIf(String::isNotBlank)
            val credentialConfigurationId =
                exposed["credential_configuration_id_hint"]?.takeIf(String::isNotBlank)
                    ?: fapiCredentialConfigurationId
            if (credentialIssuer != null && credentialConfigurationId != null) {
                return OidfWalletInput.WalletInitiated(credentialIssuer, credentialConfigurationId)
            }
            delay(250)
        }
        error(
            "OIDF suite test $testId did not expose wallet-initiated issuer and credential configuration " +
                "within 5 seconds; exposed=$lastExposed",
        )
    }
}

internal fun configuredOidfSuiteDir(): Path? = System.getProperty("oidf.suite.dir")?.takeIf(String::isNotBlank)?.let(::Path)

internal fun localOidfSuiteConfigured(): Boolean =
    System.getProperty("oidf.suite.baseUrl").isNullOrBlank().not() &&
        configuredOidfSuiteDir()?.let(Files::isDirectory) == true

private fun oidfVciPreAuthorizedSmokeVariant(): JsonObject =
    buildJsonObject {
        put("credential_format", "sd_jwt_vc")
        put("fapi_request_method", "unsigned")
        put("sender_constrain", "dpop")
        put("fapi_profile", "vci")
        put("client_auth_type", "private_key_jwt")
        put("authorization_request_type", "simple")
        put("vci_grant_type", "pre_authorization_code")
        put("vci_authorization_code_flow_variant", "issuer_initiated")
        put("vci_credential_offer_variant", "by_value")
        put("vci_credential_issuance_mode", "immediate")
        put("vci_credential_encryption", "plain")
    }

private fun oidfVciPresentationCredentialVariant(format: String): JsonObject =
    oidfVciPreAuthorizedSmokeVariant().let { base ->
        JsonObject(
            base +
                mapOf(
                    "credential_format" to JsonPrimitive(if (format == "iso_mdl") "mdoc" else format),
                    "authorization_request_type" to JsonPrimitive("rar"),
                ),
        )
    }

private const val VCI_SETUP_PLAN = "oid4vci-1_0-wallet-test-plan"
private const val VCI_SETUP_MODULE = "oid4vci-1_0-wallet-test-credential-issuance"

internal fun oidfCredentialRequestEncryption(
    planVariant: Map<String, String>,
    moduleVariant: Map<String, String>,
): Boolean = (planVariant + moduleVariant)["vci_credential_encryption"] == "encrypted"

internal fun oidfWalletInitiatedIssuance(
    planVariant: Map<String, String>,
    moduleVariant: Map<String, String>,
    testModule: String = "",
): Boolean =
    when ((planVariant + moduleVariant)["vci_authorization_code_flow_variant"]) {
        null -> testModule.startsWith(FAPI2_CLIENT_MODULE_PREFIX)
        "wallet_initiated" -> true
        else -> false
    }

private const val VCI_BATCH_MODULE = "oid4vci-1_0-wallet-test-batch-credential-issuance"
private const val FAPI2_CLIENT_MODULE_PREFIX = "fapi2-security-profile-final-client-test-"
private const val VCI_SETUP_CONFIG = "scripts/test-configs-rp-against-op/vci-wallet-test-config-plain.json"
private const val VCI_WALLET_CLIENT_ID = "52480754053"
private const val MAX_EXTERNAL_HANDOFFS = 10
private const val MAX_DEFERRED_INTERVAL_SECONDS = 10

private fun Map<String, String>.toJsonObject(): JsonObject = JsonObject(mapValues { (_, value) -> JsonPrimitive(value) })
