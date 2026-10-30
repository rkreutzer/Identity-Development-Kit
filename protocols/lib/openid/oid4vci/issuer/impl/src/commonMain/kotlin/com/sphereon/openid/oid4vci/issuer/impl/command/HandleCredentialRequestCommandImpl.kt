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

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.conf.ConfigLevel
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.events.EventTypes
import com.sphereon.core.api.service.ServiceCommandRegistry
import com.sphereon.core.api.service.SessionScopedCommandRegistry
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.events.SessionEventService
import com.sphereon.data.store.credential.design.CredentialDesignService
import com.sphereon.data.store.credential.design.impl.mapper.Oid4vciDesignMapper
import com.sphereon.data.store.credential.design.model.ClaimPathSegment
import com.sphereon.data.store.credential.design.model.DesignBindingKey
import com.sphereon.data.store.credential.design.model.ResolveCredentialDesignInput
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.signing.CapturedAsServerConfig
import com.sphereon.openid.oid4vci.common.model.CredentialRequest
import com.sphereon.openid.oid4vci.common.model.CredentialResponse
import com.sphereon.openid.oid4vci.common.model.CredentialResponseItem
import com.sphereon.openid.oid4vci.common.model.Oid4vciErrors
import com.sphereon.openid.oid4vci.issuer.Oid4vciIssuerSessionEventTypes
import com.sphereon.openid.oid4vci.issuer.attribute.CredentialAttributeContribution
import com.sphereon.openid.oid4vci.issuer.attribute.CredentialAttributeContributionWaiter
import com.sphereon.openid.oid4vci.issuer.attribute.CredentialAttributeContributor
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationGrant
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationPolicySnapshot
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationSelectionRequest
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationServerDeployment
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationServerSelection
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciCredentialAuthorizationSelection
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciIssuerAuthorizationPolicyProvider
import com.sphereon.openid.oid4vci.issuer.bridge.Oid4vciAuthorizationServerBridge
import com.sphereon.openid.oid4vci.issuer.bridge.ValidateAccessTokenArgs
import com.sphereon.openid.oid4vci.issuer.bridge.ValidatedTokenContext
import com.sphereon.openid.oid4vci.issuer.bridge.ValidatedWalletInstanceAttestationEvidence
import com.sphereon.openid.oid4vci.issuer.bridge.authorizationServerTarget
import com.sphereon.openid.oid4vci.issuer.command.HandleCredentialRequestArgs
import com.sphereon.openid.oid4vci.issuer.command.HandleCredentialRequestCommand
import com.sphereon.openid.oid4vci.issuer.command.MintDeferralScopedTokenArgs
import com.sphereon.openid.oid4vci.issuer.command.MintDeferralScopedTokenCommand
import com.sphereon.openid.oid4vci.issuer.config.MissingRequiredClaimsPolicy
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerInstanceIdProvider
import com.sphereon.openid.oid4vci.issuer.config.ResolveWalletProviderTrustArgs
import com.sphereon.openid.oid4vci.issuer.config.requireCanonicalOid4vciIssuerInstanceId
import com.sphereon.openid.oid4vci.issuer.config.resolveCredentialClaimSources
import com.sphereon.openid.oid4vci.issuer.format.CredentialFormatHandler
import com.sphereon.openid.oid4vci.issuer.format.IssuanceContext
import com.sphereon.openid.oid4vci.issuer.format.SdPolicy
import com.sphereon.openid.oid4vci.issuer.hook.PostIssuanceHookArgs
import com.sphereon.openid.oid4vci.issuer.impl.encryption.CredentialResponseEncryptor
import com.sphereon.openid.oid4vci.issuer.impl.event.emitOid4vciSessionHistoryEvent
import com.sphereon.openid.oid4vci.issuer.impl.hook.PostIssuanceHookDispatcher
import com.sphereon.openid.oid4vci.issuer.impl.nonce.NonceManager
import com.sphereon.openid.oid4vci.issuer.impl.proof.ProofVerifier
import com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciCompletenessLifecycleArgs
import com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciCompletenessLifecycleResult
import com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuanceLifecycleHook
import com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuancePhase
import com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciPhaseLifecycleArgs
import com.sphereon.openid.oid4vci.issuer.proof.VerifiedKeyAttestation
import com.sphereon.openid.oid4vci.issuer.proof.VerifiedProof
import com.sphereon.openid.oid4vci.issuer.spi.IssuerFederationEntityResolver
import com.sphereon.openid.oid4vci.issuer.store.CredentialIssuanceSessionStore
import com.sphereon.openid.oid4vci.issuer.store.CredentialRequestIdentity
import com.sphereon.openid.oid4vci.issuer.store.CredentialRequestIdentityStore
import com.sphereon.openid.oid4vci.issuer.store.DeferredCredentialEntry
import com.sphereon.openid.oid4vci.issuer.store.DeferredCredentialStatus
import com.sphereon.openid.oid4vci.issuer.store.DeferredCredentialStore
import com.sphereon.openid.oid4vci.issuer.store.IssuanceSession
import com.sphereon.openid.oid4vci.issuer.store.IssuanceSessionStatus
import com.sphereon.openid.oid4vci.issuer.store.NotificationStateStore
import com.sphereon.openid.oid4vci.issuer.store.Oid4vciSessionIdentity
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ExposeImplBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.put
import kotlin.time.Clock
import kotlin.time.Duration.Companion.hours
import kotlin.uuid.Uuid

/**
 * Orchestrates credential issuance per OID4VCI 1.0 Section 8.
 *
 * Immediate issuance flow (Phase 4a):
 * 1. Validate access token via AS bridge
 * 2. Parse + validate credential request
 * 3. Resolve credential configuration
 * 4. Verify proof of possession → extract holder binding key, consume nonce
 * 5. Call CredentialAttributeContributor → additional attributes
 * 6. Merge attributes: preSeeded → accumulatedAttributes → oauthClaims → contributed
 * 7. Dispatch to CredentialFormatHandler
 * 8. Issue fresh nonce for next request
 * 9. Return CredentialResponse
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<HandleCredentialRequestCommand>())
@ExposeImplBinding
class HandleCredentialRequestCommandImpl(
    execution: SessionExecution,
    private val asBridge: Oid4vciAuthorizationServerBridge,
    private val proofVerifiers: Set<ProofVerifier>,
    private val nonceManager: NonceManager,
    private val formatHandlers: Set<CredentialFormatHandler>,
    private val attributeContributor: CredentialAttributeContributor,
    private val sessionStore: CredentialIssuanceSessionStore,
    private val credentialRequestIdentityStore: CredentialRequestIdentityStore,
    private val deferredStore: DeferredCredentialStore,
    private val notificationStore: NotificationStateStore,
    private val encryptor: CredentialResponseEncryptor,
    private val issuerConfigProvider: Oid4vciIssuerConfigProvider,
    /**
     * Optional credential-design service. When present, design metadata is resolved
     * at issuance time to populate [IssuanceContext.sdPolicies] and
     * [IssuanceContext.mandatoryClaims]. Null-safe — deployments without the
     * credential-design module work unchanged.
     */
    private val credentialDesignService: CredentialDesignService? = null,
    private val eventService: SessionEventService? = null,
    private val instanceIdProvider: Oid4vciIssuerInstanceIdProvider,
    private val authorizationPolicyProvider: Oid4vciIssuerAuthorizationPolicyProvider,
    private val authorizationServerSelection: Oid4vciAuthorizationServerSelection,
    /**
     * Optional service-command registry for post-issuance hook dispatch. When
     * null (pure-IDK deployment that didn't wire the command-framework
     * registry) no hooks fire — the issuer is a zero-cost no-op at the
     * dispatch site. See [com.sphereon.openid.oid4vci.issuer.hook.PostIssuanceHookArgs].
     */
    private val serviceCommandRegistry: ServiceCommandRegistry? = null,
    private val sessionScopedCommandRegistry: SessionScopedCommandRegistry? = null,
    /**
     * Optional lifecycle hook. When present (EDK pipeline on the classpath) and the
     * resolved [IssuanceSession] carries a lifecycle correlation id, the §6.1
     * deferral decision tree runs
     * after the attribute contributor and before the format handler: incomplete bindings
     * are either deferred or rejected, and a binding still awaiting approval is deferred.
     * Null in pure-IDK deployments: the decision tree is skipped and issuance behaves
     * exactly as without a pipeline.
     */
    private val lifecycleHook: Oid4vciIssuanceLifecycleHook? = null,
    /**
     * Optional OAuth2 server config provider. When present the deferred-response helper
     * checks whether the issuing AS has `refresh_token` enabled — when it doesn't and a
     * [MintDeferralScopedTokenCommand] is on the classpath, a deferral-scoped access token
     * is minted and threaded onto the 202 response via [CredentialResponse.additionalParameters]
     * so the wallet has an auth credential that outlives its original access token. Pure-IDK
     * deployments leave this null and the common refresh-token path stays unchanged.
     */
    private val oauth2ConfigProvider: OAuth2ServersConfigProvider? = null,
    /**
     * Optional deferral-scoped token minter. Used by the deferred-response path when the AS
     * has refresh tokens disabled; ignored otherwise. Null in pure-IDK deployments without
     * the OAuth2-server-impl module on the classpath.
     */
    private val mintDeferralScopedTokenCommand: MintDeferralScopedTokenCommand? = null,
    /**
     * Optional callback coordinator for the §6.5.7 sync-wait fast-path. When the attribute
     * contributor reports a non-empty
     * [CredentialAttributeContribution.pendingAsyncCallbackSources] AND a coordinator is wired,
     * the request suspends up to
     * [CredentialAttributeContribution.syncWaitWindow] for those sources to land via the inbound
     * callback endpoint, then re-runs the contributor before deciding whether to defer. Pure-IDK
     * deployments leave this null and the wait block is a degenerate no-op (the NoOp contributor
     * never reports pending sources).
     */
    private val clock: Clock,
    private val contributionWaiter: CredentialAttributeContributionWaiter? = null,
    /**
     * Optional OpenID Federation membership of the issuer. When bound and the issuer is a
     * federation entity, its Entity Identifier is placed in every issued credential (DIIP v5
     * Appendix B). Null in deployments that do not host federation entities: credentials are
     * issued without federation content.
     */
    private val federationEntityResolver: IssuerFederationEntityResolver? = null,
) : TypedServiceCommandAdapter<HandleCredentialRequestArgs, CredentialResponse, IdkError>(
        commandId = HandleCredentialRequestCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<HandleCredentialRequestArgs>(),
        outputTypeToken = typeToken<CredentialResponse>(),
    ),
    HandleCredentialRequestCommand {
    override val commandId: String get() = HandleCredentialRequestCommand.COMMAND_ID

    /** Session-aware resolver with principal → tenant → app fallback. */
    private val propertyResolver = execution.conf.conf(ConfigLevel.PRINCIPAL)

    override suspend fun supports(args: Any): Boolean = args is HandleCredentialRequestArgs

    /**
     * Session correlation context captured during [doExecuteInternal]. Set
     * only when an [IssuanceSession] was resolved for the request; stays
     * null for sessionless flows. Read by [dispatchPostIssuanceHooks] to
     * populate [PostIssuanceHookArgs.boundUsageToken] / `preAuthCode` /
     * `subject` from the offer-side source of truth without re-resolving.
     *
     * Instance state is safe here: the command is session-scoped and a
     * single HTTP request is processed sequentially within its session.
     */
    private var pendingHookContext: HookContext? = null
    private var pendingHistorySession: IssuanceSession? = null
    private var pendingHistoryProtocolSessionId: String? = null
    private var pendingHistoryInstanceId: String? = null
    private var pendingHistoryOldState: String? = null
    private var pendingHistoryCredentialConfigurationId: String? = null

    private data class HookContext(
        val boundUsageToken: String?,
        val preAuthCode: String?,
        val subject: String?,
        val hookAllowList: List<String>?,
        val keyAttestations: List<VerifiedKeyAttestation> = emptyList(),
        val walletInstanceAttestation: ValidatedWalletInstanceAttestationEvidence? = null,
    )

    override suspend fun doExecute(
        args: HandleCredentialRequestArgs,
        applyDuring: (HandleCredentialRequestArgs) -> HandleCredentialRequestArgs,
    ): IdkResult<CredentialResponse, IdkError> {
        pendingHookContext = null
        pendingHistorySession = null
        pendingHistoryProtocolSessionId = null
        pendingHistoryInstanceId = null
        pendingHistoryOldState = null
        pendingHistoryCredentialConfigurationId = null
        val result = doExecuteInternal(args, applyDuring)
        emitOutcome(result)
        // OID4VCI 1.0 §8.3.4: a 202 deferral envelope (transactionId set, credentials null) is NOT
        // an issuance — no credential exists yet, so notification/webhook hooks must NOT fire. The
        // eventual issuance fires post-issuance hooks from the /deferred_credential poll command
        // when the credential is finally minted. Mirror the predicate used by [emitOutcome] for
        // OID4VCI_CREDENTIAL_ISSUED so the two outcome paths stay in lockstep.
        if (result.isOk && result.value.credentials != null && result.value.transactionId == null) {
            dispatchPostIssuanceHooks(args, result.value)
        }
        pendingHookContext = null
        pendingHistorySession = null
        pendingHistoryProtocolSessionId = null
        pendingHistoryInstanceId = null
        pendingHistoryOldState = null
        pendingHistoryCredentialConfigurationId = null
        return result
    }

    /**
     * Post-issuance hook fan-out. Resolves the configured set of hook
     * `ServiceCommand`s via [ServiceCommandRegistry] + [PropertyResolver] and
     * invokes each one whose [ServiceCommand.supports] returns true for the
     * args. Per-hook failures are isolated via `runCatching` so one failing
     * hook doesn't cascade to siblings or roll back the already-issued
     * credential. Retry semantics are the hook's own concern — the issuer
     * is fire-and-forget here.
     *
     * Pure-IDK deployments that didn't wire `serviceCommandRegistry` /
     * `sessionScopedCommandRegistry` get a zero-cost no-op. EDK-on-classpath
     * deployments with a registered `hook.post-issuance.*` command see it
     * invoked automatically; operator config under
     * `hooks.oid4vci.after-credential-issued.{commands,patterns}` overrides
     * the default pattern.
     */
    private suspend fun dispatchPostIssuanceHooks(
        args: HandleCredentialRequestArgs,
        response: CredentialResponse,
    ) {
        val discovery = serviceCommandRegistry ?: return
        val resolver = sessionScopedCommandRegistry ?: return
        val tenantId = runCatching { execution.sessionContext.context.tenant.tenantId }.getOrNull() ?: return
        val correlation = pendingHookContext

        val hookArgs =
            PostIssuanceHookArgs(
                credentialResponse = response,
                credentialConfigurationId = args.credentialRequest.credentialConfigurationId,
                tenantId = tenantId,
                issuedAt = clock.now(),
                boundUsageToken = correlation?.boundUsageToken,
                preAuthCode = correlation?.preAuthCode,
                keyAttestations = correlation?.keyAttestations.orEmpty(),
                walletInstanceAttestation = correlation?.walletInstanceAttestation,
                subject = correlation?.subject,
            )

        PostIssuanceHookDispatcher(
            resolver = discovery,
            sessionCommands = resolver,
            propertyResolver = propertyResolver,
        ).dispatch(
            args = hookArgs,
            sessionAllowList = correlation?.hookAllowList,
        )
    }

    private suspend fun emitOutcome(result: IdkResult<CredentialResponse, IdkError>,) {
        // OID4VCI 1.0 §8.3.4: an Ok with `transaction_id` and no `credentials` is the deferred
        // envelope, not a real issuance. Map it to OID4VCI_CREDENTIAL_DEFERRED so dashboards and
        // SIEM rules that filter on OID4VCI_CREDENTIAL_ISSUED don't count deferrals as issuances.
        // The eventual issuance event is OID4VCI_CREDENTIAL_DEFERRED_ISSUED, emitted by
        // HandleDeferredCredentialRequestCommandImpl when a poll returns the actual credential.
        val deferred = result.isOk && result.value.credentials == null && result.value.transactionId != null
        val type =
            when {
                deferred -> EventTypes.OID4VCI_CREDENTIAL_DEFERRED
                result.isOk -> EventTypes.OID4VCI_CREDENTIAL_ISSUED
                else -> EventTypes.OID4VCI_CREDENTIAL_FAILED
            }
        val es = eventService ?: return
        val session = pendingHistorySession
        val protocolSessionId =
            pendingHistoryProtocolSessionId
                ?: run {
                    check(!result.isOk) { "Successful credential request has no protocolSessionId for history" }
                    return
                }
        val instanceId =
            pendingHistoryInstanceId
                ?: run {
                    check(!result.isOk) { "Successful credential request has no instanceId for history" }
                    return
                }
        val newState =
            when {
                deferred -> IssuanceSessionStatus.DEFERRED.name
                result.isOk -> IssuanceSessionStatus.CREDENTIAL_ISSUED.name
                else -> IssuanceSessionStatus.FAILED.name
            }
        es.emitOid4vciSessionHistoryEvent(
            type = type,
            origin = HandleCredentialRequestCommand.COMMAND_ID,
            instanceId = instanceId,
            protocolSessionId = protocolSessionId,
            correlationId = session?.lifecycleCorrelationId,
            oldState = pendingHistoryOldState,
            newState = newState,
            stage = "CREDENTIAL_REQUEST",
            outcome =
                if (result.isOk) {
                    if (deferred) {
                        "DEFERRED"
                    } else {
                        "SUCCEEDED"
                    }
                } else {
                    "FAILED"
                },
            credentialConfigurationId = pendingHistoryCredentialConfigurationId,
        )
    }

    private suspend fun doExecuteInternal(
        args: HandleCredentialRequestArgs,
        applyDuring: (HandleCredentialRequestArgs) -> HandleCredentialRequestArgs,
    ): IdkResult<CredentialResponse, IdkError> {
        val applied = applyDuring(args)
        val request = applied.credentialRequest
        issuerConfigProvider.prepare()
        val credentialConfigurations = issuerConfigProvider.credentialConfigurations

        // A signed token's issuer_state is used only as an opaque lookup key here. No claim is
        // trusted until the token is verified against the immutable target recovered from the
        // session snapshot below.
        val unverifiedIssuerState =
            unverifiedIssuerState(
                accessToken = applied.accessToken,
                credentialIdentifier = request.credentialIdentifier,
            )
        val pinnedSession =
            unverifiedIssuerState?.let { state ->
                sessionStore.getByIssuerState(state).getOrElse { return Err(it) }
            }
        val validationSnapshot =
            pinnedSession?.authorizationPolicySnapshot ?: run {
                val explicitConfigId =
                    request.credentialConfigurationId
                        ?: return Err(IdkError.fromString(code = "invalid_token", message = "Cannot resolve an immutable authorization-server target before token validation"))
                val policyProvider = authorizationPolicyProvider
                val selector = authorizationServerSelection
                val instanceId =
                    instanceIdProvider.currentInstanceId()
                        ?: return Err(IdkError.INVALID_STATE(message = "OID4VCI issuer instance is required"))
                val tenantId = execution.sessionContext.context.tenant.tenantId
                val policy =
                    runCatching { policyProvider.resolve(tenantId, instanceId) }.getOrElse {
                        return Err(IdkError.INVALID_STATE(message = it.message ?: "Cannot resolve OID4VCI authorization policy"))
                    }
                runCatching {
                    selector.select(
                        policy,
                        Oid4vciAuthorizationSelectionRequest(
                            credentialSelections =
                                listOf(
                                    Oid4vciCredentialAuthorizationSelection(
                                        credentialConfigurationId = explicitConfigId,
                                        authorizationServerId = issuerConfigProvider.credentialAuthorizationServerId(explicitConfigId),
                                        allowedGrants = issuerConfigProvider.credentialAuthorizationServerAllowedGrants(explicitConfigId),
                                    ),
                                ),
                            requiredGrants = setOf(Oid4vciAuthorizationGrant.AUTHORIZATION_CODE),
                        ),
                    )
                }.getOrElse { return Err(IdkError.INVALID_STATE(message = it.message ?: "Cannot select OID4VCI authorization server")) }
            }

        // 1. Validate access token
        val tokenContext =
            asBridge
                .validateAccessToken(
                    ValidateAccessTokenArgs(
                        authorizationServer = validationSnapshot.authorizationServerTarget(),
                        expectedAudience = applied.issuerIdentifier ?: issuerConfigProvider.issuerIdentifier,
                        accessToken = applied.accessToken,
                        dpopProof = applied.dpopProof,
                        httpUrl = applied.httpUrl,
                        httpMethod = applied.httpMethod,
                    ),
                ).getOrElse { return Err(it) }

        // 2. Validate credential request basics
        if (request.credentialConfigurationId == null && request.credentialIdentifier == null && request.format == null) {
            return Err(IdkError.fromString(code = INVALID_CREDENTIAL_REQUEST, message = "credential_configuration_id, credential_identifier, or format is required"))
        }
        // OID4VCI Section 8.2: credential_configuration_id and credential_identifier are mutually exclusive
        if (request.credentialConfigurationId != null && request.credentialIdentifier != null) {
            return Err(IdkError.fromString(code = INVALID_CREDENTIAL_REQUEST, message = "credential_configuration_id and credential_identifier are mutually exclusive"))
        }
        // Validate an explicit configuration id before applying credential-identifier correlation
        // rules. A request that names an unknown configuration has one precise §8.3.1 error even
        // when the access token also carries identifiers for a different authorized credential.
        val explicitConfigId = request.credentialConfigurationId
        if (explicitConfigId != null && !credentialConfigurations.containsKey(explicitConfigId)) {
            return Err(
                IdkError.fromString(
                    code = "unknown_credential_configuration",
                    message = "Unknown credential_configuration_id: '$explicitConfigId'",
                ),
            )
        }
        // 2b. Validate credential_identifier against token authorization_details (OID4VCI 1.0 §8.2):
        // a credential_identifier MUST appear in the token's authorization_details. When the token
        // carries no `credential_identifiers` (deployment doesn't use the §5.3 RAR shape) any
        // request-supplied credential_identifier is by definition unknown — reject with the
        // dedicated `unknown_credential_identifier` error rather than letting the request fall
        // through to a generic configuration-resolution error.
        val correlation =
            resolveCredentialRequestCorrelation(
                requestedIdentifier = request.credentialIdentifier,
                tokenIdentifiers = tokenContext.credentialIdentifiers,
                tokenIssuerState = tokenContext.issuerState,
                tokenId = tokenContext.tokenId,
                sessionStore = sessionStore,
            ).getOrElse { return Err(it) }
        val session = correlation.issuanceSession
        validateAuthorizationServerSnapshot(
            session?.authorizationPolicySnapshot ?: validationSnapshot,
            tokenContext,
        ).getOrElse { return Err(it) }

        // 3. Resolve credential configuration
        val configId =
            resolveCredentialConfigurationId(
                requestedConfigurationId = request.credentialConfigurationId,
                requestedIdentifier = request.credentialIdentifier,
                identifierMappings = tokenContext.credentialIdentifierMappings,
                tokenConfigurationIds = tokenContext.credentialConfigurationIds,
            )
                ?: return Err(IdkError.fromString(code = "unknown_credential_configuration", message = "Cannot resolve credential configuration"))
        pendingHistoryCredentialConfigurationId = configId

        val configuration =
            credentialConfigurations[configId]
                ?: return Err(IdkError.fromString(code = "unknown_credential_configuration", message = "Unknown credential configuration"))
        if (request.credentialConfigurationId != null) {
            if (
                !tokenAuthorizesCredentialConfiguration(
                    requestedConfigurationId = configId,
                    tokenConfigurationIds = tokenContext.credentialConfigurationIds,
                    tokenScope = tokenContext.scope,
                    credentialScope = configuration.scope,
                )
            ) {
                return Err(IdkError.fromString(code = "invalid_token", message = "The access token does not authorize this credential configuration"))
            }
        }

        // 4. Offer-linked flows resolve the exact issuance session above. Wallet-initiated
        // configuration-id flows deliberately remain sessionless and use token jti correlation.
        if (session != null && configId !in session.credentialConfigurationIds) {
            return Err(
                IdkError.fromString(
                    code = "unknown_credential_configuration",
                    message = "Credential configuration is not authorized for the correlated issuance session",
                ),
            )
        }
        if (session != null) {
            validateIssuanceAuthorizationSnapshot(session, configId, request).getOrElse { return Err(it) }
        }
        val protocolSessionId =
            try {
                Oid4vciSessionIdentity.normalize("protocolSessionId", correlation.protocolSessionId)
            } catch (e: IllegalArgumentException) {
                return Err(IdkError.INVALID_STATE(message = e.message ?: "Invalid protocolSessionId"))
            }
        val walletIdentity =
            if (session == null) {
                credentialRequestIdentityStore.get(protocolSessionId).getOrElse { return Err(it) }
            } else {
                null
            }
        val selectedInstanceId =
            walletIdentity?.instanceId
                ?: resolveCredentialRequestIssuerInstanceId(session, instanceIdProvider).getOrElse { return Err(it) }
        val instanceId =
            if (session != null) {
                selectedInstanceId
            } else {
                val immutableIdentity =
                    walletIdentity ?: run {
                        val policyProvider = authorizationPolicyProvider
                        val selector = authorizationServerSelection
                        val tenantId = execution.sessionContext.context.tenant.tenantId
                        val policy =
                            runCatching { policyProvider.resolve(tenantId, selectedInstanceId) }.getOrElse {
                                return Err(IdkError.INVALID_STATE(message = it.message ?: "Cannot resolve OID4VCI authorization policy"))
                            }
                        val snapshot =
                            runCatching {
                                selector.select(
                                    policy,
                                    Oid4vciAuthorizationSelectionRequest(
                                        credentialSelections =
                                            listOf(
                                                Oid4vciCredentialAuthorizationSelection(
                                                    credentialConfigurationId = configId,
                                                    authorizationServerId = issuerConfigProvider.credentialAuthorizationServerId(configId),
                                                    allowedGrants = issuerConfigProvider.credentialAuthorizationServerAllowedGrants(configId),
                                                ),
                                            ),
                                        requiredGrants = setOf(Oid4vciAuthorizationGrant.AUTHORIZATION_CODE),
                                    ),
                                )
                            }.getOrElse {
                                return Err(IdkError.INVALID_STATE(message = it.message ?: "Cannot select OID4VCI authorization server"))
                            }
                        val nowEpochSeconds = clock.now().epochSeconds
                        val ttlSeconds =
                            ((tokenContext.expiresAtEpochSeconds ?: (nowEpochSeconds + WALLET_INITIATED_SESSION_TTL_SECONDS)) - nowEpochSeconds)
                                .coerceAtLeast(1L)
                        credentialRequestIdentityStore
                            .resolveOrCreate(
                                protocolSessionId = protocolSessionId,
                                instanceId = selectedInstanceId,
                                authorizationPolicySnapshot = snapshot,
                                ttlSeconds = ttlSeconds,
                            ).getOrElse { return Err(it) }
                    }
                validateWalletInitiatedAuthorizationSnapshot(immutableIdentity, configId, request).getOrElse { return Err(it) }
                immutableIdentity.instanceId
            }
        pendingHistoryProtocolSessionId = protocolSessionId
        pendingHistoryInstanceId = instanceId

        if (session != null) {
            val es = eventService
            es?.emitOid4vciSessionHistoryEvent(
                type = Oid4vciIssuerSessionEventTypes.TOKEN_VALIDATED,
                origin = HandleCredentialRequestCommand.COMMAND_ID,
                instanceId = instanceId,
                protocolSessionId = session.sessionId,
                correlationId = session.lifecycleCorrelationId,
                oldState = session.status.name,
                newState = session.status.name,
                stage = "TOKEN",
                outcome = "SUCCEEDED",
                credentialConfigurationId = configId,
            )
            val requestSession =
                if (session.status.ordinal < IssuanceSessionStatus.CREDENTIAL_REQUESTED.ordinal) {
                    session.copy(status = IssuanceSessionStatus.CREDENTIAL_REQUESTED).also {
                        sessionStore.update(it).getOrElse { error -> return Err(error) }
                    }
                } else {
                    session
                }
            pendingHistorySession = requestSession
            pendingHistoryOldState = requestSession.status.name
            es?.emitOid4vciSessionHistoryEvent(
                type = Oid4vciIssuerSessionEventTypes.CREDENTIAL_REQUESTED,
                origin = HandleCredentialRequestCommand.COMMAND_ID,
                instanceId = instanceId,
                protocolSessionId = session.sessionId,
                correlationId = session.lifecycleCorrelationId,
                oldState = session.status.name,
                newState = requestSession.status.name,
                stage = "CREDENTIAL_REQUEST",
                outcome = "ACCEPTED",
                credentialConfigurationId = configId,
            )
        } else {
            val es = eventService
            es?.emitOid4vciSessionHistoryEvent(
                type = Oid4vciIssuerSessionEventTypes.TOKEN_VALIDATED,
                origin = HandleCredentialRequestCommand.COMMAND_ID,
                instanceId = instanceId,
                protocolSessionId = protocolSessionId,
                oldState = null,
                newState = "TOKEN_VALIDATED",
                stage = "TOKEN",
                outcome = "SUCCEEDED",
                credentialConfigurationId = configId,
            )
            es?.emitOid4vciSessionHistoryEvent(
                type = Oid4vciIssuerSessionEventTypes.CREDENTIAL_REQUESTED,
                origin = HandleCredentialRequestCommand.COMMAND_ID,
                instanceId = instanceId,
                protocolSessionId = protocolSessionId,
                oldState = "TOKEN_VALIDATED",
                newState = IssuanceSessionStatus.CREDENTIAL_REQUESTED.name,
                stage = "CREDENTIAL_REQUEST",
                outcome = "ACCEPTED",
                credentialConfigurationId = configId,
            )
            pendingHistoryOldState = IssuanceSessionStatus.CREDENTIAL_REQUESTED.name
        }

        // Capture the session-side correlation fields for post-issuance hooks.
        // `subject` falls back to the token context's subject when the session
        // doesn't carry one explicitly.
        if (session != null) {
            pendingHookContext =
                HookContext(
                    boundUsageToken = session.boundUsageToken,
                    preAuthCode = session.preAuthCode,
                    subject = session.subject ?: tokenContext.subject,
                    hookAllowList = session.postIssuanceHookAllowList,
                    walletInstanceAttestation = tokenContext.walletInstanceAttestation,
                )
        } else {
            pendingHookContext =
                HookContext(
                    boundUsageToken = null,
                    preAuthCode = null,
                    subject = tokenContext.subject,
                    hookAllowList = null,
                    walletInstanceAttestation = tokenContext.walletInstanceAttestation,
                )
        }

        contributeOid4vciPhase(
            session = session,
            phase = Oid4vciIssuancePhase.TOKEN,
            fields = tokenContext.toTokenPhaseFields(configId),
            validatedTokenContext = tokenContext,
        ).getOrElse { return Err(it) }

        // 5. Verify proof of possession
        val expectedAudience = applied.issuerIdentifier ?: issuerConfigProvider.issuerIdentifier

        val proofs = request.proofs
        val isBatch = proofs != null && proofs.proofValues.size > 1

        // OID4VCI 1.0 §8.2.1.2: when `proof_types_supported` is non-empty on the credential
        // configuration, the credential request MUST include a proof of possession. Reject
        // missing proofs here so wallet flows get a precise `invalid_proof` instead of
        // silently issuing an unbound credential.
        if (proofs == null && !configuration.proofTypesSupported.isNullOrEmpty()) {
            return Err(
                IdkError.fromString(
                    code = "invalid_proof",
                    message =
                        "Credential request is missing the `proofs` parameter, but the credential " +
                            "configuration '$configId' declares proof_types_supported " +
                            "(${configuration.proofTypesSupported?.keys?.joinToString()}); " +
                            "proof of possession is REQUIRED (OID4VCI 1.0 §8.2.1.2).",
                ),
            )
        }

        val batchVerifiedProofs =
            if (proofs != null) {
                // §F.1 alg-allowlist + §11.2.3 key-attestation policy both live on the
                // proof_types_supported.<type> block — pass it whole rather than fanning fields out.
                val proofTypeSupported = configuration.proofTypesSupported?.get(proofs.proofType)
                verifyCredentialRequestProofs(
                    proofType = proofs.proofType,
                    proofValues = proofs.proofValues,
                    audience = expectedAudience,
                    expectedClientId = tokenContext.clientId.takeIf { it.isNotEmpty() },
                    credentialConfigId = configId,
                    session = session,
                    proofTypeSupported = proofTypeSupported,
                ).getOrElse { return Err(it) }
            } else {
                null
            }
        pendingHookContext =
            pendingHookContext?.copy(
                keyAttestations = batchVerifiedProofs?.mapNotNull { it.keyAttestation }.orEmpty(),
            )
        contributeOid4vciPhase(
            session = session,
            phase = Oid4vciIssuancePhase.CREDENTIAL_REQUEST,
            fields = request.toCredentialRequestPhaseFields(configId, batchVerifiedProofs.orEmpty()),
        ).getOrElse { return Err(it) }
        val initialContribution =
            if (session != null) {
                attributeContributor
                    .contribute(session, tokenContext, configId)
                    .getOrElse { return Err(it) }
            } else {
                CredentialAttributeContribution(attributes = emptyMap())
            }

        // 5b. §6.5.7 sync-wait window. If the contributor reports sources still pending an
        // async callback AND a CallbackCoordinator is wired, hold the response open for up to
        // the contributor-reported `syncWaitWindow` for ALL of them to land. On success, re-run
        // the contributor so the freshly-contributed attributes flow into the merge. On timeout
        // (TimeoutCancellationException) fall through to the §6.1 deferral decision.
        val contributionRefreshed =
            awaitPendingCredentialContributions(
                waiter = contributionWaiter,
                correlationId = session?.lifecycleCorrelationId,
                contribution = initialContribution,
            )
        val effectiveContribution =
            if (contributionRefreshed) {
                attributeContributor
                    .contribute(requireNotNull(session), tokenContext, configId)
                    .getOrElse { return Err(it) }
            } else {
                initialContribution
            }
        val contributedVcdmProperties = effectiveContribution.vcdmProperties
        val contributedCredentialId = effectiveContribution.credentialId
        val contributedCredentialSubjects = effectiveContribution.credentialSubjects

        // 6. Merge attributes (priority: wallet-initiated config → claim sources → preSeeded →
        // accumulated → contributed)
        val mergedAttributes = mutableMapOf<String, JsonElement>()
        if (session == null) {
            // Wallet-initiated authorization-code flows have no issuer-created offer/session.
            // Resolve attributes by authenticated subject through the explicit config-backed
            // source. A local AS login's UserInfo, surfaced only on the issuer's explicit opt-in,
            // overrides that baseline. Federated identity claims are never merged wholesale.
            mergedAttributes.putAll(
                resolveConfiguredWalletInitiatedSubjectAttributes(
                    propertyResolver = propertyResolver,
                    subject = tokenContext.subject,
                    credentialConfigurationId = configId,
                    issuerInstanceId = instanceIdProvider.currentInstanceId(),
                ).getOrElse { return Err(it) },
            )
            if (tokenContext.upstreamIssuer == null) {
                tokenContext.userinfoClaims?.let { mergedAttributes.putAll(it) }
            }
        }
        // Federated identity claims reach the credential only where a claim definition of this
        // credential configuration names them as its source. Offer data still wins over them.
        mergedAttributes.putAll(
            resolveCredentialClaimSources(
                sources = issuerConfigProvider.credentialClaimSources(configId).getOrElse { return Err(it) },
                token = tokenContext,
            ),
        )
        session?.preSeededAttributes?.let { mergedAttributes.putAll(it) }
        session?.accumulatedAttributes?.let { mergedAttributes.putAll(it) }
        mergedAttributes.putAll(effectiveContribution.attributes)

        // 6a. §6.1 completeness-driven deferral decision tree.
        val completenessResult = runCompletenessDeferral(session, configId, tokenContext.cnfJkt)
        if (completenessResult != null) return completenessResult

        // 6b. Resolve credential design if a design service is available
        val tenantId = execution.sessionContext.context.tenant.tenantId
        val resolvedDesign =
            credentialDesignService?.let { service ->
                val designs =
                    service
                        .findCredentialDesignByBindingKey(
                            tenantId,
                            DesignBindingKey.CREDENTIAL_CONFIGURATION_ID,
                            configId,
                        ).getOrElse { return Err(it) }

                designs.firstOrNull()?.let { designRecord ->
                    service
                        .resolveCredentialDesign(
                            tenantId,
                            ResolveCredentialDesignInput(designId = designRecord.id),
                        ).getOrElse { return Err(it) }
                }
            }

        val sdPolicies: Map<String, SdPolicy> =
            resolvedDesign?.design?.claims?.let(::designIssuanceSdPolicies) ?: emptyMap()

        // Extract mandatory claims from resolved design
        val mandatoryClaims: Set<String> =
            resolvedDesign
                ?.design
                ?.claims
                ?.filter { it.mandatory }
                ?.map { claim -> Oid4vciDesignMapper.claimPathString(claim) }
                ?.toSet() ?: emptySet()

        val missingMandatoryClaims = missingMandatoryClaimPaths(mandatoryClaims, mergedAttributes)
        if (missingMandatoryClaims.isNotEmpty()) {
            return Err(
                IdkError.fromString(
                    code = Oid4vciErrors.INVALID_CREDENTIAL_REQUEST,
                    message = "missing mandatory claims: ${missingMandatoryClaims.joinToString()}",
                ),
            )
        }

        // 7. Resolve signing configuration for this credential type
        val signingConfig =
            issuerConfigProvider.signingConfigReloadingOnMiss(configId)
                ?: return Err(
                    IdkError.fromString(
                        code = "invalid_credential_configuration",
                        message =
                            "Credential configuration '$configId' has no issuance signing configuration; " +
                                "refusing to issue without platform config",
                    ),
                )
        // A configured validity period is optional. Preserve its absence for the format
        // handler, which owns the credential's temporal representation and requirements.
        val expirationInDays = signingConfig.expirationInDays

        // 7b. Resolve the status-list binding, failing closed: a configuration that declares a
        // status list whose binding cannot be resolved must abort the request — issuing without
        // the status claim would produce a credential that can never be revoked.
        val statusListBinding =
            issuerConfigProvider.statusListBindingForIssuance(configId).getOrElse { return Err(it) }

        // DIIP v5 Appendix B: an issuer that is an OpenID Federation entity names its Entity
        // Identifier in every credential. Resolved once per request, before any status entry is
        // reserved; a membership that cannot be determined refuses the request instead of issuing
        // a credential that may lack the required federation content.
        val federationEntityIdentifier =
            resolveIssuerFederationEntityIdentifier(federationEntityResolver, expectedAudience)
                .getOrElse { return Err(it) }

        val businessMode = execution.conf.app.getPropertyAsString("oid4vci.business-authorization.mode")
        if (businessMode != "ordinary" && businessMode != "required") {
            return Err(IdkError.FORBIDDEN_ERROR(message = "issuer_business_policy_not_configured"))
        }
        com.sphereon.openid.oid4vci.issuer.lifecycle
            .authorizeIssuerBusinessAction(
                required = businessMode == "required",
                args =
                    com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciBusinessAuthorizationArgs(
                        instanceId,
                        session?.sessionId,
                        session?.lifecycleCorrelationId,
                        configId,
                    ),
                hook = lifecycleHook,
            ).getOrElse { return Err(it) }

        contributeOid4vciPhase(
            session = session,
            phase = Oid4vciIssuancePhase.PRE_ISSUE,
            fields =
                preIssuePhaseFields(
                    configId = configId,
                    expectedAudience = expectedAudience,
                    tokenContext = tokenContext,
                ),
        ).getOrElse { return Err(it) }

        // 8. Dispatch to format handler
        val handler =
            formatHandlers.firstOrNull { it.canHandle(request, configuration) }
                ?: return Err(IdkError.fromString(code = "unsupported_credential_format", message = "No format handler for format: ${configuration.format}"))

        // 8. Issue credential(s)
        val response =
            if (isBatch && batchVerifiedProofs != null) {
                // Batch issuance: issue one credential per proof in parallel
                val issuanceResults =
                    coroutineScope {
                        batchVerifiedProofs
                            .map { verifiedProof ->
                                async {
                                    val issuanceContext =
                                        IssuanceContext(
                                            subject = tokenContext.subject,
                                            clientId = tokenContext.clientId,
                                            issuerIdentifier = expectedAudience,
                                            credentialConfigurationId = configId,
                                            credentialConfiguration = configuration,
                                            holderBindingKey = verifiedProof.holderBindingKey,
                                            holderIdentifier = verifiedProof.holderIdentifier,
                                            holderKeyId = verifiedProof.keyId,
                                            keyAttestation = verifiedProof.keyAttestation,
                                            attributes = mergedAttributes,
                                            vcdmProperties = contributedVcdmProperties,
                                            credentialId = contributedCredentialId,
                                            credentialSubjects = contributedCredentialSubjects,
                                            sdPolicies = sdPolicies,
                                            mandatoryClaims = mandatoryClaims,
                                            signingKeyAlias = signingConfig.signingKeyAlias,
                                            signingKeyMode = signingConfig.signingKeyMode,
                                            signingVerificationMethodId = signingConfig.signingVerificationMethodId,
                                            dataIntegrityCryptosuite = signingConfig.dataIntegrityCryptosuite,
                                            signingX5c = signingConfig.signingX5c,
                                            issuanceClockSkewInSeconds = issuerConfigProvider.issuanceClockSkewInSeconds,
                                            expirationInDays = expirationInDays,
                                            statusListBinding = statusListBinding,
                                            federationEntityIdentifier = federationEntityIdentifier,
                                        )
                                    handler.issueCredential(request, issuanceContext)
                                }
                            }.awaitAll()
                    }

                // Check for errors after all complete
                val envelopes =
                    issuanceResults.map { result ->
                        result.getOrElse { return Err(it) }
                    }

                // If any credential in the batch is deferred, the entire response is deferred
                if (envelopes.any { it.deferred }) {
                    return Ok(createDeferredResponse(session, configId, tokenContext.cnfJkt).getOrElse { return Err(it) })
                }

                var notificationId: String? = null
                val items =
                    envelopes.map { envelope ->
                        if (notificationId == null) {
                            notificationId = envelope.notificationId
                        }
                        CredentialResponseItem(credential = envelope.credential)
                    }

                CredentialResponse(
                    credentials = items,
                    notificationId = notificationId,
                )
            } else {
                // Single issuance (single-proof or no-proof)
                val verifiedProof = batchVerifiedProofs?.firstOrNull()

                val issuanceContext =
                    IssuanceContext(
                        subject = tokenContext.subject,
                        clientId = tokenContext.clientId,
                        issuerIdentifier = expectedAudience,
                        credentialConfigurationId = configId,
                        credentialConfiguration = configuration,
                        holderBindingKey = verifiedProof?.holderBindingKey,
                        holderIdentifier = verifiedProof?.holderIdentifier,
                        holderKeyId = verifiedProof?.keyId,
                        keyAttestation = verifiedProof?.keyAttestation,
                        attributes = mergedAttributes,
                        vcdmProperties = contributedVcdmProperties,
                        credentialId = contributedCredentialId,
                        credentialSubjects = contributedCredentialSubjects,
                        sdPolicies = sdPolicies,
                        mandatoryClaims = mandatoryClaims,
                        signingKeyAlias = signingConfig.signingKeyAlias,
                        signingKeyMode = signingConfig.signingKeyMode,
                        signingVerificationMethodId = signingConfig.signingVerificationMethodId,
                        dataIntegrityCryptosuite = signingConfig.dataIntegrityCryptosuite,
                        signingX5c = signingConfig.signingX5c,
                        expirationInDays = expirationInDays,
                        statusListBinding = statusListBinding,
                        federationEntityIdentifier = federationEntityIdentifier,
                    )

                val envelope =
                    handler
                        .issueCredential(request, issuanceContext)
                        .getOrElse { return Err(it) }

                if (envelope.deferred) {
                    return Ok(createDeferredResponse(session, configId, tokenContext.cnfJkt).getOrElse { return Err(it) })
                }

                CredentialResponse(
                    credentials = listOf(CredentialResponseItem(credential = envelope.credential)),
                    notificationId = envelope.notificationId,
                )
            }

        // Register the exact protocol correlation before returning a response that exposes the
        // notification identifier. Offer sessions use their own lifetime; sessionless flows use
        // token expiry when available and otherwise retain the mapping for the established 24h
        // notification-state window.
        response.notificationId?.let { notificationId ->
            val now = Clock.System.now()
            val ttlSeconds =
                session?.let { ((it.expiresAt - now.toEpochMilliseconds() + 999L) / 1000L).coerceAtLeast(1L) }
                    ?: tokenContext.expiresAtEpochSeconds?.let { (it - now.epochSeconds).coerceAtLeast(1L) }
                    ?: DEFAULT_NOTIFICATION_TTL_SECONDS
            notificationStore
                .registerNotification(notificationId, protocolSessionId, instanceId, ttlSeconds)
                .getOrElse { return Err(it) }
        }

        // 9. Update session status to issued
        session?.let {
            sessionStore
                .update(it.copy(status = IssuanceSessionStatus.CREDENTIAL_ISSUED))
                .getOrElse { return Err(it) }
        }

        contributeOid4vciPhase(
            session = session,
            phase = Oid4vciIssuancePhase.POST_ISSUANCE,
            fields = response.toPostIssuancePhaseFields(configId),
        ).getOrElse { return Err(it) }

        return Ok(response)
    }

    private suspend fun contributeOid4vciPhase(
        session: IssuanceSession?,
        phase: Oid4vciIssuancePhase,
        fields: Map<String, JsonElement>,
        validatedTokenContext: ValidatedTokenContext? = null,
    ): IdkResult<Unit, IdkError> {
        val correlationId = session?.lifecycleCorrelationId ?: return Ok(Unit)
        val hook = lifecycleHook ?: return Ok(Unit)
        val args =
            Oid4vciPhaseLifecycleArgs(
                correlationId = correlationId,
                protocolSessionId = session.sessionId,
                phase = phase,
                fields = fields,
            )
        val result =
            if (validatedTokenContext != null &&
                hook is
                    com.sphereon.openid.oid4vci.issuer.lifecycle.ValidatedTokenOid4vciIssuanceLifecycleHook
            ) {
                hook.recordValidatedTokenPhase(args, validatedTokenContext)
            } else {
                // Existing hook implementations retain their original behavior and ABI.
                hook.recordPhase(args)
            }
        result.getOrElse { return Err(it) }
        return Ok(Unit)
    }

    private fun ValidatedTokenContext.toTokenPhaseFields(configId: String): Map<String, JsonElement> =
        buildMap {
            put("oid4vci.credentialConfigurationId", JsonPrimitive(configId))
            put("oid4vci.subject", JsonPrimitive(subject))
            put("oid4vci.clientId", JsonPrimitive(clientId))
            scope?.let { put("oid4vci.scope", JsonPrimitive(it)) }
            cnfJkt?.let { put("oid4vci.cnfJkt", JsonPrimitive(it)) }
            put(
                "oid4vci.authorizedCredentialConfigurationIds",
                buildJsonArray { credentialConfigurationIds.forEach { add(it) } },
            )
            credentialIdentifiers?.let { identifiers ->
                put(
                    "oid4vci.credentialIdentifiers",
                    buildJsonArray { identifiers.forEach { add(it) } },
                )
            }
            walletInstanceAttestation?.walletInstanceId?.let {
                put("oid4vci.walletInstanceId", JsonPrimitive(it))
            }
            acr?.let { put("oid4vci.acr", JsonPrimitive(it)) }
            authTime?.let { put("oid4vci.authTime", JsonPrimitive(it.toString())) }
            upstreamSubject?.let { put("oid4vci.upstreamSubject", JsonPrimitive(it)) }
            upstreamIssuer?.let { put("oid4vci.upstreamIssuer", JsonPrimitive(it)) }
            userinfoClaims?.takeIf { it.isNotEmpty() }?.let { claims ->
                put("oid4vci.userinfoClaims", Json.encodeToJsonElement(claims))
                claims.forEach { (name, value) ->
                    put("oid4vci.userinfoClaims.$name", value)
                }
            }
        }

    private fun com.sphereon.openid.oid4vci.common.model.CredentialRequest.toCredentialRequestPhaseFields(
        configId: String,
        proofs: List<VerifiedProof>,
    ): Map<String, JsonElement> =
        buildMap {
            put("oid4vci.credentialConfigurationId", JsonPrimitive(configId))
            credentialIdentifier?.let { put("oid4vci.credentialIdentifier", JsonPrimitive(it)) }
            format?.let { put("oid4vci.credentialFormat", JsonPrimitive(it)) }
            put("oid4vci.proofCount", JsonPrimitive(proofs.size))
            put("oid4vci.keyAttestationCount", JsonPrimitive(proofs.count { it.keyAttestation != null }))
            put("oid4vci.holderBindingKeyPresent", JsonPrimitive(proofs.isNotEmpty()))
        }

    private fun preIssuePhaseFields(
        configId: String,
        expectedAudience: String,
        tokenContext: ValidatedTokenContext,
    ): Map<String, JsonElement> =
        mapOf(
            "oid4vci.credentialConfigurationId" to JsonPrimitive(configId),
            "oid4vci.expectedAudience" to JsonPrimitive(expectedAudience),
            "oid4vci.subject" to JsonPrimitive(tokenContext.subject),
            "oid4vci.clientId" to JsonPrimitive(tokenContext.clientId),
        )

    private fun CredentialResponse.toPostIssuancePhaseFields(configId: String): Map<String, JsonElement> =
        buildMap {
            put("oid4vci.credentialConfigurationId", JsonPrimitive(configId))
            put("oid4vci.credentialResponse", Json.encodeToJsonElement(this@toPostIssuancePhaseFields))
            put("oid4vci.credentialCount", JsonPrimitive(credentials?.size ?: 0))
            notificationId?.let { put("oid4vci.notificationId", JsonPrimitive(it)) }
            transactionId?.let { put("oid4vci.transactionId", JsonPrimitive(it)) }
        }

    /**
     * §6.1 completeness-driven deferral decision tree.
     *
     * Runs only when an EDK pipeline is bound to this issuance (the session carries a
     * lifecycle correlation id) and the lifecycle hook is on the classpath. The attribute
     * contributor has already run the pipeline's CREDENTIAL_REQUEST phase, so the attribute bag
     * the verdicts are computed against is fully populated at this point.
     *
     * Returns:
     * - `null` when the gate does not fire (no lifecycle correlation id, lifecycle hook not
     *   injected, or all attributes complete with no approval pending): the caller falls through
     *   to the format handler.
     * - [Ok] with a deferred [CredentialResponse] when every deferral candidate is either
     *   incomplete-but-deferrable or awaiting approval, OR when a required claim is missing but
     *   the issuer instance's [MissingRequiredClaimsPolicy] is `DEFER`. The session status is
     *   updated to [IssuanceSessionStatus.DEFERRED].
     * - [Err] when at least one required claim is missing and the issuer instance's
     *   [MissingRequiredClaimsPolicy] is `REJECT` (the default).
     */
    private suspend fun runCompletenessDeferral(
        session: IssuanceSession?,
        configId: String,
        cnfJkt: String?,
    ): IdkResult<CredentialResponse, IdkError>? {
        val nonNullSession = session?.takeIf { it.lifecycleCorrelationId != null }
        val hook = lifecycleHook
        if (nonNullSession == null || hook == null) return null
        val completenessResult = evaluateCompleteness(nonNullSession, hook)
        if (completenessResult.isErr) return Err(completenessResult.error)
        return if (completenessResult.value) {
            createDeferredResponse(nonNullSession, configId, cnfJkt)
                .also {
                    if (it.isOk) {
                        sessionStore.update(nonNullSession.copy(status = IssuanceSessionStatus.DEFERRED))
                    }
                }
        } else {
            null
        }
    }

    /**
     * Evaluates whether issuance should be deferred based on attribute completeness verdicts from
     * the pipeline. Delegates the actual decision to [resolveCompletenessOutcome] once the
     * lifecycle hook's verdict is in hand; see that function for the full outcome matrix.
     */
    private suspend fun evaluateCompleteness(
        session: IssuanceSession,
        hook: Oid4vciIssuanceLifecycleHook,
    ): IdkResult<Boolean, IdkError> {
        val result =
            hook
                .evaluateCompleteness(Oid4vciCompletenessLifecycleArgs(session.lifecycleCorrelationId!!))
                .getOrElse { return Err(it) }
        return resolveCompletenessOutcome(result, issuerConfigProvider.missingRequiredClaims)
    }

    /**
     * Build the deferred-credential response: persist a PENDING [DeferredCredentialEntry] keyed by
     * a fresh transaction id and return the OID4VCI 1.0 §8.3.4 deferred response carrying that
     * `transaction_id` and the poll `interval`.
     *
     * Shared by every deferral trigger in this command: a format handler returning a deferred
     * envelope (single and batch) and the §6.1 completeness / approval-gate decision.
     *
     * §6.5 wallet-auth invariant: when the AS has refresh tokens disabled, the wallet's original
     * access token may expire before the deferral resolves. If a [mintDeferralScopedTokenCommand]
     * is wired and the configured AS does NOT advertise `refresh_token` in `grantTypesEnabled`,
     * a deferral-scoped token is minted here and threaded onto the response via
     * [CredentialResponse.additionalParameters]. The common refresh-token-enabled path adds
     * nothing and the response stays byte-identical to the prior 202 shape.
     */
    private suspend fun createDeferredResponse(
        session: IssuanceSession?,
        configId: String,
        cnfJkt: String?,
    ): IdkResult<CredentialResponse, IdkError> {
        val transactionId = Uuid.random().toString()
        val now = Clock.System.now()
        val entry =
            DeferredCredentialEntry(
                transactionId = transactionId,
                issuanceSessionId =
                    session?.sessionId
                        ?: pendingHistoryProtocolSessionId
                        ?: return Err(IdkError.INVALID_STATE(message = "protocolSessionId must be resolved before deferral")),
                instanceId =
                    session?.instanceId
                        ?: pendingHistoryInstanceId
                        ?: return Err(IdkError.INVALID_STATE(message = "instanceId must be resolved before deferral")),
                credentialConfigurationId = configId,
                status = DeferredCredentialStatus.PENDING,
                retryAfterSeconds = 5,
                createdAt = now.toEpochMilliseconds(),
                expiresAt = now.plus(1.hours).toEpochMilliseconds(),
            )
        deferredStore.create(entry).getOrElse { return Err(it) }
        val additional = buildDeferralAccessTokenAdditionals(session, transactionId, cnfJkt)
        return Ok(
            CredentialResponse(
                transactionId = transactionId,
                interval = entry.retryAfterSeconds,
                additionalParameters = additional,
            ),
        )
    }

    /**
     * Returns the additional response parameters to merge onto the deferred 202 — empty when
     * refresh tokens are enabled (or when no mint command is wired), populated with
     * `deferral_access_token` / `deferral_access_token_expires_in` when the fallback fires.
     *
     * Failure to mint is logged-and-swallowed via the falling-back-to-empty-map path: a deferral
     * response without the fallback token is still better than failing the whole credential
     * request — the wallet may still obtain the credential within its original token lifetime.
     */
    private suspend fun buildDeferralAccessTokenAdditionals(
        session: IssuanceSession?,
        transactionId: String,
        cnfJkt: String?,
    ): Map<String, JsonElement> {
        val request = prepareDeferralTokenMintRequest(session, transactionId, cnfJkt) ?: return emptyMap()
        val minted =
            request.mint
                .execute(
                    MintDeferralScopedTokenArgs(
                        correlationId = request.correlationId,
                        transactionId = transactionId,
                        ttlSeconds = request.ttlSeconds,
                        cnfJkt = cnfJkt,
                    ),
                ).getOrElse { return emptyMap() }
        return mapOf(
            DEFERRAL_ACCESS_TOKEN to JsonPrimitive(minted.accessToken),
            DEFERRAL_ACCESS_TOKEN_EXPIRES_IN to JsonPrimitive(minted.expiresInSeconds),
        )
    }

    /**
     * Resolves the inputs needed to mint a deferral-scoped access token, or returns null when any
     * precondition fails (no mint command wired, no AS config provider wired, refresh tokens are
     * already enabled on the AS, or the deferred session lacks both a pipeline correlation id and
     * a session id). Centralising the bail-outs keeps the mint call site free of `return`s.
     */
    private suspend fun prepareDeferralTokenMintRequest(
        session: IssuanceSession?,
        transactionId: String,
        @Suppress("UnusedParameter") cnfJkt: String?,
    ): DeferralTokenMintRequest? {
        val mint = mintDeferralScopedTokenCommand ?: return null
        val provider = oauth2ConfigProvider ?: return null
        val deferred = deferredStore.get(transactionId).getOrElse { return null } ?: return null
        val persistedSession = session ?: sessionStore.get(deferred.issuanceSessionId).getOrElse { return null }
        val identity = if (persistedSession == null) {
            credentialRequestIdentityStore.get(deferred.issuanceSessionId).getOrElse { return null }
        } else {
            null
        }
        val snapshot = persistedSession?.authorizationPolicySnapshot ?: identity?.authorizationPolicySnapshot ?: return null
        val issuerInstanceId = persistedSession?.instanceId ?: identity?.instanceId ?: return null
        if (deferred.instanceId != issuerInstanceId || snapshot.issuerId.toString() != issuerInstanceId ||
            snapshot.authorizationServerDeployment != Oid4vciAuthorizationServerDeployment.HOSTED
        ) return null
        val exactKey = snapshot.authorizationServerRuntimeKey ?: return null
        if (snapshot.authorizationServerIssuer.isBlank()) return null
        val captured = try {
            CapturedAsServerConfig.select(provider.getConfig(), exactKey)
        } catch (error: IllegalArgumentException) {
            return null
        } catch (error: IllegalStateException) {
            return null
        }
        val selectedServer = captured.server ?: return null
        if (selectedServer.issuer?.let { it != snapshot.authorizationServerIssuer } == true) return null
        if (REFRESH_TOKEN_GRANT in selectedServer.grantTypesEnabled) return null
        val correlationId = persistedSession?.lifecycleCorrelationId
            ?: persistedSession?.sessionId
            ?: identity?.protocolSessionId
            ?: return null
        return DeferralTokenMintRequest(
            mint = mint,
            correlationId = correlationId,
            ttlSeconds = resolveDeferralTokenTtlSeconds(),
        )
    }

    private data class DeferralTokenMintRequest(
        val mint: MintDeferralScopedTokenCommand,
        val correlationId: String,
        val ttlSeconds: Long,
    )

    /**
     * Returns the TTL the deferral-scoped token should carry. Reads the operator-configured
     * value at [CONFIG_KEY_DEFERRAL_SCOPED_TOKEN_TTL_SECONDS]; when unset, defaults to
     * [DEFAULT_DEFERRAL_SCOPED_TOKEN_TTL_SECONDS] (matches `CredentialDeferralPolicy.maxDeferralSeconds`'s
     * 7-day default). The token must outlive `maxDeferralSeconds` so wallets polling near the
     * end of the deferral window still authenticate; the §6.5 invariant validator
     * ([com.sphereon.openid.oid4vci.issuer.config.DeferralWalletAuthValidator]) enforces that
     * relationship at config-load time.
     */
    private fun resolveDeferralTokenTtlSeconds(): Long =
        propertyResolver
            ?.getProperty(CONFIG_KEY_DEFERRAL_SCOPED_TOKEN_TTL_SECONDS, Long::class)
            ?: DEFAULT_DEFERRAL_SCOPED_TOKEN_TTL_SECONDS

    /**
     * Dispatch proof verification to the appropriate [ProofVerifier] based on proof type.
     *
     * [proofValue] is a [JsonElement] — for JWT/CWT/attestation this is a [JsonPrimitive] string,
     * for di_vp it is a [JsonObject].
     */
    private suspend fun verifyCredentialRequestProofs(
        proofType: String,
        proofValues: List<JsonElement>,
        audience: String,
        expectedClientId: String?,
        credentialConfigId: String,
        session: IssuanceSession?,
        proofTypeSupported: com.sphereon.openid.oid4vci.common.model.ProofTypeSupported? = null,
    ): IdkResult<List<VerifiedProof>, IdkError> {
        val walletProviderTrustArgs =
            session?.issuanceTemplateResourceId?.let { templateId ->
                ResolveWalletProviderTrustArgs(
                    tenantId = execution.sessionContext.context.tenant.tenantId,
                    issuerInstanceId = session.instanceId,
                    issuanceTemplateResourceId = templateId,
                    credentialConfigurationId = credentialConfigId,
                )
            }
        return CredentialRequestProofBatchVerifier(proofVerifiers, nonceManager)
            .verify(
                proofType = proofType,
                proofValues = proofValues,
                audience = audience,
                expectedClientId = expectedClientId,
                credentialConfigId = credentialConfigId,
                walletProviderTrustArgs = walletProviderTrustArgs,
                proofTypeSupported = proofTypeSupported,
            )
    }

    private companion object {
        const val INVALID_CREDENTIAL_REQUEST = "invalid_credential_request"
        const val DEFAULT_NOTIFICATION_TTL_SECONDS = 24L * 60L * 60L
        const val WALLET_INITIATED_SESSION_TTL_SECONDS = 24L * 60L * 60L

        // §6.5 wallet-auth invariant — additional-parameter keys returned on the 202 when a
        // deferral-scoped access token is minted as a fallback for refresh-token-disabled AS.
        const val DEFERRAL_ACCESS_TOKEN = "deferral_access_token"
        const val DEFERRAL_ACCESS_TOKEN_EXPIRES_IN = "deferral_access_token_expires_in"
        const val REFRESH_TOKEN_GRANT = "refresh_token"

        // §6.5 wallet-auth invariant — operator-configured TTL for the minted deferral-scoped
        // access token. Must be sized to outlive the configured `CredentialDeferralPolicy.maxDeferralSeconds`;
        // the DeferralWalletAuthValidator enforces that relationship at config-load.
        const val CONFIG_KEY_DEFERRAL_SCOPED_TOKEN_TTL_SECONDS: String =
            "oid4vci.issuer.deferral-scoped-token.default-ttl-seconds"

        // 7 days — matches `CredentialDeferralPolicy.maxDeferralSeconds`'s default so an out-of-the-box
        // deployment with the deferral-scoped-token fallback enabled covers the full deferral
        // window without further tuning.
        const val DEFAULT_DEFERRAL_SCOPED_TOKEN_TTL_SECONDS: Long = 7L * 24 * 3600
        const val OID4VCI_PROTOCOL_SOURCE_ID: String = "oid4vci-protocol"
    }
}

/**
 * Selects the issuer UUID for a credential request. Offer-linked requests are pinned to the
 * immutable issuance session and never consult ambient routing. Wallet-initiated requests require
 * the currently routed canonical issuer resource UUID and fail closed when it is absent or invalid.
 */
internal fun resolveCredentialRequestIssuerInstanceId(
    session: IssuanceSession?,
    instanceIdProvider: Oid4vciIssuerInstanceIdProvider,
): IdkResult<String, IdkError> =
    try {
        Ok(requireCanonicalOid4vciIssuerInstanceId(session?.instanceId ?: instanceIdProvider.currentInstanceId()))
    } catch (error: IllegalArgumentException) {
        Err(IdkError.INVALID_STATE(message = error.message ?: "Invalid issuer instanceId"))
    }

/** Decode-only correlation hint. The returned value is never authorized until JWT verification succeeds. */
internal fun unverifiedIssuerState(
    accessToken: String,
    credentialIdentifier: String? = null,
): String? {
    val jwtHint =
        runCatching {
            val payload =
                accessToken.split('.').takeIf { it.size == 3 }?.get(1)
                    ?: error("Access token is not a compact JWT")
            val objectValue =
                Json.parseToJsonElement(payload.decodeFromBase64Url().decodeToString()) as? JsonObject
                    ?: error("Access token payload is not a JSON object")
            (objectValue["oid4vci.internal.issuer_state"] as? JsonPrimitive)?.content
        }.getOrNull()
    if (jwtHint != null) return jwtHint

    val identifier = credentialIdentifier ?: return null
    val prefix = "urn:vdx:oid4vci:credential:"
    if (!identifier.startsWith(prefix)) return null
    val sessionId = identifier.removePrefix(prefix).substringBefore(':').takeIf(String::isNotBlank) ?: return null
    return runCatching { Uuid.parse(sessionId).toString() }.getOrNull()
}

/** Binds verified issuer/resource provenance to the immutable issuance selection. */
internal fun validateAuthorizationServerSnapshot(
    snapshot: Oid4vciAuthorizationPolicySnapshot,
    tokenContext: ValidatedTokenContext,
): IdkResult<Unit, IdkError> {
    if (tokenContext.authorizationServerId != snapshot.authorizationServerId.toString()) {
        return Err(IdkError.fromString(code = "invalid_token", message = "Access token was verified by a different authorization-server resource"))
    }
    if (tokenContext.authorizationServerIssuer != snapshot.authorizationServerIssuer) {
        return Err(IdkError.fromString(code = "invalid_token", message = "Access token issuer does not match the immutable authorization-server snapshot"))
    }
    return Ok(Unit)
}

/**
 * Enforces the immutable authorization-server/profile decision at the credential endpoint.
 * Offer-linked authorization-code and pre-authorized-code requests must never re-resolve mutable
 * issuer configuration, and a session without the decision is invalid greenfield state.
 */
internal fun validateIssuanceAuthorizationSnapshot(
    session: IssuanceSession,
    credentialConfigurationId: String,
    request: CredentialRequest,
): IdkResult<Oid4vciAuthorizationPolicySnapshot, IdkError> {
    val snapshot =
        session.authorizationPolicySnapshot
            ?: return Err(IdkError.INVALID_STATE(message = "Issuance session has no immutable authorization-server/profile snapshot"))
    val issuerId =
        runCatching { Uuid.parse(session.instanceId) }.getOrElse {
            return Err(IdkError.INVALID_STATE(message = "Issuance session instanceId must be the issuer resource UUID"))
        }
    if (snapshot.issuerId != issuerId) {
        return Err(IdkError.INVALID_STATE(message = "Issuance session authorization snapshot belongs to another issuer"))
    }
    if (credentialConfigurationId !in session.credentialConfigurationIds) {
        return Err(IdkError.INVALID_STATE(message = "Credential configuration is outside the immutable issuance snapshot"))
    }
    val requiredGrant =
        if (session.preAuthCode != null) {
            Oid4vciAuthorizationGrant.PRE_AUTHORIZED_CODE
        } else {
            Oid4vciAuthorizationGrant.AUTHORIZATION_CODE
        }
    if (requiredGrant !in snapshot.applicableGrants) {
        return Err(IdkError.INVALID_STATE(message = "Immutable authorization snapshot does not permit the issuance grant"))
    }
    val encryption = request.credentialResponseEncryption
    if (encryption != null) {
        if (snapshot.profile.credentialResponseEncryptionAlgorithmRequired && encryption.alg.isNullOrBlank()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "${snapshot.profile.name} requires credential_response_encryption.alg"))
        }
        if (!snapshot.profile.credentialResponseEncryptionCompressionAllowed && encryption.zip != null) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "${snapshot.profile.name} does not define credential_response_encryption.zip"))
        }
    }
    return Ok(snapshot)
}

/** Validates the immutable first-use decision for a sessionless wallet-initiated request. */
internal fun validateWalletInitiatedAuthorizationSnapshot(
    identity: CredentialRequestIdentity,
    credentialConfigurationId: String,
    request: CredentialRequest,
): IdkResult<Oid4vciAuthorizationPolicySnapshot, IdkError> {
    val snapshot = identity.authorizationPolicySnapshot
    if (snapshot.issuerId.toString() != identity.instanceId) {
        return Err(IdkError.INVALID_STATE(message = "Credential-request authorization snapshot belongs to another issuer"))
    }
    if (Oid4vciAuthorizationGrant.AUTHORIZATION_CODE !in snapshot.applicableGrants) {
        return Err(IdkError.INVALID_STATE(message = "Immutable authorization snapshot does not permit authorization_code"))
    }
    if (credentialConfigurationId.isBlank()) {
        return Err(IdkError.INVALID_STATE(message = "Credential configuration is missing from wallet-initiated authorization snapshot"))
    }
    val encryption = request.credentialResponseEncryption
    if (encryption != null) {
        if (snapshot.profile.credentialResponseEncryptionAlgorithmRequired && encryption.alg.isNullOrBlank()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "${snapshot.profile.name} requires credential_response_encryption.alg"))
        }
        if (!snapshot.profile.credentialResponseEncryptionCompressionAllowed && encryption.zip != null) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "${snapshot.profile.name} does not define credential_response_encryption.zip"))
        }
    }
    return Ok(snapshot)
}

/*
 * §6.5.7 sync-wait fast-path. Returns true when every pending async-callback source resolved
 * via [CredentialAttributeContributionWaiter.awaitContribution] within the contribution's
 * [CredentialAttributeContribution.syncWaitWindow]. Returns false when any precondition was
 * missing (no [waiter] wired, no [correlationId] join key, empty pending set, zero or
 * negative window) OR when [withTimeout] fires before all awaits resolve.
 *
 * A `false` return signals the caller to keep the original contribution and fall through to the
 * §6.1 deferral decision (the natural 202 path). A `true` return signals the caller to re-run
 * the contributor so the freshly-arrived attributes flow into the merge before format dispatch.
 *
 * Hard-cap of [CredentialAttributeContribution.syncWaitWindow] against the LB / HTTP
 * request-timeout is a follow-up: the plan §7.5 calls for clamping at config-load to
 * `min(httpRequestTimeout, lbTimeout) - margin`, but those values are not currently surfaced to
 * the issuer command. TODO(phase-3-followup): wire those bounds in once the issuer config
 * provider exposes them.
 */
internal suspend fun awaitPendingCredentialContributions(
    waiter: CredentialAttributeContributionWaiter?,
    correlationId: String?,
    contribution: CredentialAttributeContribution,
): Boolean {
    if (
        waiter == null ||
        correlationId.isNullOrBlank() ||
        contribution.pendingAsyncCallbackSources.isEmpty() ||
        contribution.syncWaitWindow <= kotlin.time.Duration.ZERO
    ) {
        return false
    }

    return withTimeoutOrNull(contribution.syncWaitWindow) {
        coroutineScope {
            contribution.pendingAsyncCallbackSources
                .sorted()
                .map { contributorId ->
                    async {
                        waiter.awaitContribution(
                            correlationId = correlationId,
                            contributorId = contributorId,
                        )
                    }
                }.awaitAll()
        }
        true
    } ?: false
}

/**
 * Pure decision function for the OID4VCI §6.1 completeness gate at the credential endpoint.
 * Extracted from [HandleCredentialRequestCommandImpl] so the outcome matrix is unit-testable
 * without constructing the full command.
 *
 * Given the lifecycle hook's completeness verdict and the issuer instance's
 * [MissingRequiredClaimsPolicy]:
 * - When [Oid4vciCompletenessLifecycleResult.missingRequiredClaims] is non-empty (at least one
 *   incomplete binding has no deferral policy of its own recommending deferral), the missing-
 *   required-claims policy decides the outcome: [MissingRequiredClaimsPolicy.DEFER] returns
 *   [Ok]`(true)` (the same deferred/`transaction_id` response path used for a deferrable
 *   binding); [MissingRequiredClaimsPolicy.REJECT] (the default) returns [Err] with
 *   `invalid_credential_request` — a credential is never issued with a required claim absent.
 *   This check runs before the shouldDefer/awaitingApproval check below so a missing required
 *   claim is never silently swallowed by an unrelated awaiting-approval binding.
 * - Otherwise, [Ok]`(false)` when no binding is incomplete or awaiting approval (issuance
 *   proceeds normally), else [Ok]`(true)` (every incomplete binding is deferrable per its own
 *   policy, or a binding is awaiting approval).
 */
internal fun resolveCompletenessOutcome(
    result: Oid4vciCompletenessLifecycleResult,
    missingRequiredClaimsPolicy: MissingRequiredClaimsPolicy,
): IdkResult<Boolean, IdkError> {
    if (result.missingRequiredClaims.isNotEmpty()) {
        return when (missingRequiredClaimsPolicy) {
            MissingRequiredClaimsPolicy.DEFER -> {
                Ok(true)
            }

            MissingRequiredClaimsPolicy.REJECT -> {
                Err(
                    IdkError.fromString(
                        code = Oid4vciErrors.INVALID_CREDENTIAL_REQUEST,
                        message = "missing mandatory claims: ${result.missingRequiredClaims.joinToString()}",
                    ),
                )
            }
        }
    }
    if (!result.shouldDefer && !result.awaitingApproval) return Ok(false)
    return Ok(true)
}
