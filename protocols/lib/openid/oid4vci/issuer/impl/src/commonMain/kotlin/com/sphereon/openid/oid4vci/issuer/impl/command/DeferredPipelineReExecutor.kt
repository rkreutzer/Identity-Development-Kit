/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.sphereon.openid.oid4vci.issuer.impl.command

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.Err
import com.sphereon.data.store.credential.design.CredentialDesignService
import com.sphereon.data.store.credential.design.impl.mapper.Oid4vciDesignMapper
import com.sphereon.data.store.credential.design.model.ClaimPresentation
import com.sphereon.data.store.credential.design.model.DesignBindingKey
import com.sphereon.data.store.credential.design.model.ResolveCredentialDesignInput
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.common.model.CredentialResponse
import com.sphereon.openid.oid4vci.common.model.CredentialResponseItem
import com.sphereon.openid.oid4vci.issuer.attribute.CredentialAttributeContributor
import com.sphereon.openid.oid4vci.issuer.bridge.ValidatedTokenContext
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider
import com.sphereon.openid.oid4vci.issuer.format.CredentialFormatHandler
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import com.sphereon.openid.oid4vci.issuer.format.SdPolicy
import com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciCompletenessLifecycleArgs
import com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuanceLifecycleHook
import com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuancePhase
import com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciPhaseLifecycleArgs
import com.sphereon.openid.oid4vci.issuer.spi.IssuerFederationEntityResolver
import com.sphereon.openid.oid4vci.issuer.store.CredentialIssuanceSessionStore
import com.sphereon.openid.oid4vci.issuer.store.DeferredCredentialEntry
import com.sphereon.openid.oid4vci.issuer.store.DeferredCredentialStatus
import com.sphereon.openid.oid4vci.issuer.store.DeferredCredentialStore
import com.sphereon.openid.oid4vci.issuer.store.IssuanceSession
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * File-private helper that owns the pipeline re-execution flow on
 * `/deferred_credential`. Pulled out of [HandleDeferredCredentialRequestCommandImpl] so the
 * command class stays at a single concern (status routing + access-token validation + entry
 * lifecycle) while the multi-step re-execution machinery sits in its own testable unit.
 *
 * Instantiated only when an OID4VCI lifecycle hook is wired in; EDK binds the connector-backed
 * implementation while pure-IDK sessions without a lifecycle correlation id fall through.
 */
class DeferredPipelineReExecutor(
    private val deferredStore: DeferredCredentialStore,
    private val sessionStore: CredentialIssuanceSessionStore,
    private val attributeContributor: CredentialAttributeContributor,
    private val lifecycleHook: Oid4vciIssuanceLifecycleHook,
    private val issuerConfigProvider: Oid4vciIssuerConfigProvider,
    private val formatHandlers: Set<CredentialFormatHandler>,
    private val credentialDesignService: CredentialDesignService?,
    private val tenantIdProvider: () -> String?,
    private val businessModeProvider: () -> String? = { null },
    private val federationEntityResolver: IssuerFederationEntityResolver? = null,
) {
    /**
     * Run the DEFERRED pipeline phase, re-check completeness, and if every binding is complete
     * and not awaiting approval dispatch the matching [CredentialFormatHandler]. Returns:
     * - `null` when the session has no pipeline binding, or any pipeline step / format-handler
     *   step short-circuits; the caller falls back to the 202 response
     * - `Ok(CredentialResponse)` carrying the credential when re-execution succeeds
     *
     * Re-execution failures (ContributeAttributesCommand returning Err, format handler erroring,
     * the format handler signalling `deferred = true` again) are intentionally swallowed so a
     * transient source-side issue keeps the deferred poll alive.
     */
    suspend fun attempt(
        entry: DeferredCredentialEntry,
        tokenContext: ValidatedTokenContext,
    ): IdkResult<CredentialResponse, IdkError>? {
        val session = sessionStore.get(entry.issuanceSessionId).getOrElse { null }
        val correlationId = session?.lifecycleCorrelationId
        return when {
            session == null || correlationId == null -> null
            !runDeferredPhaseAndPipelineIsReady(correlationId, session.sessionId) -> null
            else -> issueCredential(entry, tokenContext, session)
        }
    }

    private suspend fun runDeferredPhaseAndPipelineIsReady(
        correlationId: String,
        protocolSessionId: String,
    ): Boolean {
        val contributeResult =
            lifecycleHook.recordPhase(
                Oid4vciPhaseLifecycleArgs(
                    correlationId = correlationId,
                    protocolSessionId = protocolSessionId,
                    phase = Oid4vciIssuancePhase.DEFERRED,
                ),
            )
        if (contributeResult.isErr) {
            return false
        }
        val verdictsResult =
            lifecycleHook.evaluateCompleteness(
                Oid4vciCompletenessLifecycleArgs(correlationId = correlationId),
            )
        if (verdictsResult.isErr) {
            return false
        }
        val verdict = verdictsResult.value
        return !verdict.shouldDefer && !verdict.awaitingApproval && verdict.missingRequiredClaims.isEmpty()
    }

    private suspend fun issueCredential(
        entry: DeferredCredentialEntry,
        tokenContext: ValidatedTokenContext,
        session: IssuanceSession,
    ): IdkResult<CredentialResponse, IdkError>? {
        val correlationId = session.lifecycleCorrelationId ?: return null
        issuerConfigProvider.prepare()
        val inputs = prepareDispatchInputs(entry, tokenContext, session) ?: return null
        val issuanceContext = buildIssuanceContext(inputs, tokenContext) ?: return null
        if (missingMandatoryClaimPaths(issuanceContext.mandatoryClaims, issuanceContext.attributes).isNotEmpty()) {
            return null
        }
        val businessMode = businessModeProvider()
        if (businessMode != "ordinary" && businessMode != "required") {
            return Err(IdkError.FORBIDDEN_ERROR(message = "issuer_business_policy_not_configured"))
        }
        com.sphereon.openid.oid4vci.issuer.lifecycle.authorizeIssuerBusinessAction(
            businessMode == "required",
            com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciBusinessAuthorizationArgs(
                session.instanceId, session.sessionId, correlationId, inputs.configId,
            ), lifecycleHook,
        ).getOrElse { return Err(it) }
        val preIssueRan =
            contributeOid4vciPhase(
                correlationId = correlationId,
                protocolSessionId = session.sessionId,
                phase = Oid4vciIssuancePhase.PRE_ISSUE,
                fields = preIssuePhaseFields(inputs, issuanceContext),
            )
        if (!preIssueRan) return null
        val response = runDispatch(entry, inputs, issuanceContext) ?: return null
        val postIssuanceRan =
            contributeOid4vciPhase(
                correlationId = correlationId,
                protocolSessionId = session.sessionId,
                phase = Oid4vciIssuancePhase.POST_ISSUANCE,
                fields = response.value.toPostIssuancePhaseFields(inputs.configId),
            )
        return if (postIssuanceRan) response else null
    }

    private suspend fun prepareDispatchInputs(
        entry: DeferredCredentialEntry,
        tokenContext: ValidatedTokenContext,
        session: IssuanceSession,
    ): DispatchInputs? {
        val configId = entry.credentialConfigurationId
        val configuration = issuerConfigProvider.credentialConfigurations[configId]
        val mergedInputs = configuration?.let { mergeIssuanceInputs(session, tokenContext, configId) }
        if (configuration == null || mergedInputs == null) {
            return null
        }
        val request = CredentialRequest(credentialConfigurationId = configId, format = configuration.format)
        val handler = formatHandlers.firstOrNull { it.canHandle(request, configuration) } ?: return null
        return DispatchInputs(
            configId = configId,
            configuration = configuration,
            attributes = mergedInputs.attributes,
            vcdmProperties = mergedInputs.vcdmProperties,
            credentialId = mergedInputs.credentialId,
            credentialSubjects = mergedInputs.credentialSubjects,
            request = request,
            handler = handler,
            deferredTransactionId = entry.transactionId,
        )
    }

    /**
     * Invoke the resolved format handler, persist the produced credential onto the entry as
     * READY, and return the credential response.
     *
     * The credential is persisted as READY, not DELIVERED: this response already carries the
     * credential to the caller, but marking DELIVERED here would bypass the single canonical
     * READY -> DELIVERED transition that fires when the wallet polls again.
     */
    private suspend fun runDispatch(
        entry: DeferredCredentialEntry,
        inputs: DispatchInputs,
        issuanceContext: IssuanceContext,
    ): IdkResult<CredentialResponse, IdkError>? {
        val envelope =
            inputs.handler
                .issueCredential(inputs.request, issuanceContext)
                .getOrElse { return null }
                .takeUnless { it.deferred } ?: return null
        val persisted =
            deferredStore.update(
                entry.copy(
                    status = DeferredCredentialStatus.READY,
                    credentialResponse = envelope.credential,
                    notificationId = envelope.notificationId ?: entry.notificationId,
                ),
            )
        return if (persisted.isErr) {
            null
        } else {
            Ok(
                CredentialResponse(
                    credentials = listOf(CredentialResponseItem(credential = envelope.credential)),
                    notificationId = envelope.notificationId,
                ),
            )
        }
    }

    /**
     * Merge the session-side attribute bag with the contributor's final-phase contributions.
     * Priority mirrors [HandleCredentialRequestCommandImpl]: preSeeded → accumulated → contributed.
     * Returns `null` if the contributor errors so the caller falls back to the 202 path.
     */
    private suspend fun mergeIssuanceInputs(
        session: IssuanceSession,
        tokenContext: ValidatedTokenContext,
        configId: String,
    ): MergedIssuanceInputs? {
        val merged = mutableMapOf<String, JsonElement>()
        session.preSeededAttributes?.let { merged.putAll(it) }
        session.accumulatedAttributes?.let { merged.putAll(it) }
        val contributed =
            attributeContributor
                .contribute(session, tokenContext, configId)
                .getOrElse { return null }
        merged.putAll(contributed.attributes)
        return MergedIssuanceInputs(
            attributes = merged,
            vcdmProperties = contributed.vcdmProperties,
            credentialId = contributed.credentialId,
            credentialSubjects = contributed.credentialSubjects,
        )
    }

    private suspend fun contributeOid4vciPhase(
        correlationId: String,
        protocolSessionId: String,
        phase: Oid4vciIssuancePhase,
        fields: Map<String, JsonElement>,
    ): Boolean =
        lifecycleHook
            .recordPhase(
                Oid4vciPhaseLifecycleArgs(
                    correlationId = correlationId,
                    protocolSessionId = protocolSessionId,
                    phase = phase,
                    fields = fields,
                ),
            ).isOk

    private suspend fun buildIssuanceContext(
        inputs: DispatchInputs,
        tokenContext: ValidatedTokenContext,
    ): IssuanceContext? {
        val signingConfig = issuerConfigProvider.signingConfigReloadingOnMiss(inputs.configId) ?: return null
        val expirationInDays = signingConfig.expirationInDays ?: return null
        val designContext = resolveDesignContext(inputs.configId)
        // DIIP v5 Appendix B, as on the immediate path. A membership that cannot be determined
        // keeps the transaction pending, like every other re-execution failure, so the next poll
        // retries instead of issuing a credential without the required federation content.
        val federationEntityIdentifier =
            resolveIssuerFederationEntityIdentifier(federationEntityResolver, issuerConfigProvider.issuerIdentifier)
                .getOrElse { return null }
        return IssuanceContext(
            subject = tokenContext.subject,
            clientId = tokenContext.clientId,
            issuerIdentifier = issuerConfigProvider.issuerIdentifier,
            credentialConfigurationId = inputs.configId,
            credentialConfiguration = inputs.configuration,
            // Holder binding key is not stored on the deferred entry; the format handlers
            // all tolerate a null binding (cnf claim is then omitted) which is the right
            // behaviour for re-execution that didn't see a fresh proof.
            holderBindingKey = null,
            attributes = inputs.attributes,
            vcdmProperties = inputs.vcdmProperties,
            credentialId = inputs.credentialId,
            credentialSubjects = inputs.credentialSubjects,
            sdPolicies = designContext.sdPolicies,
            mandatoryClaims = designContext.mandatoryClaims,
            signingKeyAlias = signingConfig.signingKeyAlias,
            signingKeyMode = signingConfig.signingKeyMode,
            signingVerificationMethodId = signingConfig.signingVerificationMethodId,
            dataIntegrityCryptosuite = signingConfig.dataIntegrityCryptosuite,
            signingX5c = signingConfig.signingX5c,
            issuanceClockSkewInSeconds = issuerConfigProvider.issuanceClockSkewInSeconds,
            expirationInDays = expirationInDays,
            federationEntityIdentifier = federationEntityIdentifier,
        )
    }

    private fun preIssuePhaseFields(
        inputs: DispatchInputs,
        issuanceContext: IssuanceContext,
    ): Map<String, JsonElement> =
        mapOf(
            "oid4vci.credentialConfigurationId" to JsonPrimitive(inputs.configId),
            "oid4vci.credentialFormat" to JsonPrimitive(inputs.configuration.format.toString()),
            "oid4vci.subject" to JsonPrimitive(issuanceContext.subject),
            "oid4vci.clientId" to JsonPrimitive(issuanceContext.clientId),
            "oid4vci.issuerIdentifier" to JsonPrimitive(issuanceContext.issuerIdentifier),
            "oid4vci.deferredTransactionId" to JsonPrimitive(inputs.deferredTransactionId),
        )

    private fun CredentialResponse.toPostIssuancePhaseFields(configId: String): Map<String, JsonElement> =
        buildMap {
            put("oid4vci.credentialConfigurationId", JsonPrimitive(configId))
            put("oid4vci.credentialCount", JsonPrimitive(credentials?.size ?: 0))
            notificationId?.let { put("oid4vci.notificationId", JsonPrimitive(it)) }
            transactionId?.let { put("oid4vci.transactionId", JsonPrimitive(it)) }
        }

    /**
     * Resolve `sdPolicies` + `mandatoryClaims` from the credential-design store. When no design
     * service is wired in or the design lookup fails the returned context is empty, mirroring
     * the default [IssuanceContext] values [HandleCredentialRequestCommandImpl] uses for the
     * same fallback path.
     */
    private suspend fun resolveDesignContext(configId: String): DesignContext {
        val service = credentialDesignService
        val tenantId = service?.let { tenantIdProvider() }
        val resolved = tenantId?.let { resolveDesign(service, it, configId) }
        return resolved?.let { mapDesignToContext(it.design.claims) } ?: DesignContext.EMPTY
    }

    private suspend fun resolveDesign(
        service: CredentialDesignService,
        tenantId: String,
        configId: String,
    ): com.sphereon.data.store.credential.design.model.ResolvedCredentialDesign? {
        val designs =
            service
                .findCredentialDesignByBindingKey(
                    tenantId,
                    DesignBindingKey.CREDENTIAL_CONFIGURATION_ID,
                    configId,
                ).getOrElse { emptyList() }
        return designs.firstOrNull()?.let { record ->
            service
                .resolveCredentialDesign(
                    tenantId,
                    ResolveCredentialDesignInput(designId = record.id),
                ).getOrNull()
        }
    }

    private fun mapDesignToContext(claims: List<ClaimPresentation>): DesignContext {
        val sdPolicies = designIssuanceSdPolicies(claims)
        val mandatoryClaims: Set<String> =
            claims
                .filter { it.mandatory }
                .map { Oid4vciDesignMapper.claimPathString(it) }
                .toSet()
        return DesignContext(sdPolicies, mandatoryClaims)
    }

    private data class DispatchInputs(
        val configId: String,
        val configuration: CredentialConfigurationSupported,
        val attributes: Map<String, JsonElement>,
        val vcdmProperties: JsonObject,
        val credentialId: String?,
        val credentialSubjects: List<JsonObject>,
        val request: CredentialRequest,
        val handler: CredentialFormatHandler,
        val deferredTransactionId: String,
    )

    private data class MergedIssuanceInputs(
        val attributes: Map<String, JsonElement>,
        val vcdmProperties: JsonObject,
        val credentialId: String?,
        val credentialSubjects: List<JsonObject>,
    )

    private data class DesignContext(
        val sdPolicies: Map<String, SdPolicy>,
        val mandatoryClaims: Set<String>,
    ) {
        companion object {
            val EMPTY = DesignContext(emptyMap(), emptySet())
        }
    }
}
