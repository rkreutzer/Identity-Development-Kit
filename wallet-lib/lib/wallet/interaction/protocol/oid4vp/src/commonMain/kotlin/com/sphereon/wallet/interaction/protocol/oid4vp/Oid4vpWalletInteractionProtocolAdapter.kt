/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import com.sphereon.wallet.interaction.WalletInteractionCompletionTransport
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.common.responseUri
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.holder.DigitalCredentialsAuthorizationRequest
import com.sphereon.openid.oid4vp.holder.Oid4vpHolderService
import com.sphereon.openid.oid4vp.holder.SubmissionResult
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.core.api.error.IdkError
import com.sphereon.wallet.credential.WalletCredentialStore
import com.sphereon.wallet.WalletHolderIdentityResolver
import com.sphereon.wallet.WalletHolderVerificationMethodResolver
import com.sphereon.wallet.interaction.WalletClaimDescriptor
import com.sphereon.wallet.interaction.WalletApprovalOperation
import com.sphereon.wallet.interaction.WalletApprovalOperations
import com.sphereon.wallet.interaction.WalletSecurityGrant
import com.sphereon.wallet.interaction.WalletAttendedAuthorizationRegistry
import com.sphereon.wallet.interaction.WalletCounterpartyRole
import com.sphereon.wallet.interaction.WalletCounterpartyAssociationRequest
import com.sphereon.wallet.interaction.WalletCounterpartyClientAuthentication
import com.sphereon.wallet.interaction.WalletCounterpartySummary
import com.sphereon.wallet.interaction.counterpartyDetailFromDcrMetadata
import com.sphereon.wallet.interaction.selfAssertedDisplayNameSource
import com.sphereon.wallet.interaction.WalletCounterpartyTrustRequest
import com.sphereon.wallet.interaction.WalletCredentialRequirement
import com.sphereon.wallet.interaction.WalletCredentialSelectionRequest
import com.sphereon.wallet.interaction.WalletCredentialSetOption
import com.sphereon.wallet.interaction.WalletCredentialSetRequirement
import com.sphereon.wallet.interaction.WalletDisclosureSummary
import com.sphereon.wallet.interaction.WalletDisplayMessage
import com.sphereon.wallet.interaction.WalletEntryPoint
import com.sphereon.wallet.interaction.WalletEntryPointKind
import com.sphereon.wallet.interaction.WalletInteractionAction
import com.sphereon.wallet.interaction.WalletInteractionActionType
import com.sphereon.wallet.interaction.WalletInteractionActivitySummary
import com.sphereon.wallet.interaction.WalletInteractionActivityType
import com.sphereon.wallet.interaction.WalletInteractionContext
import com.sphereon.wallet.interaction.WalletInteractionError
import com.sphereon.wallet.interaction.WalletInteractionFailureCodes
import com.sphereon.wallet.interaction.WalletInteractionFlowKind
import com.sphereon.wallet.interaction.WalletInteractionPrivateSessionData
import com.sphereon.wallet.interaction.WalletInteractionProtocolAdapter
import com.sphereon.wallet.interaction.WalletInteractionSession
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.interaction.WalletInteractionSensitiveInputPurpose
import com.sphereon.wallet.interaction.WalletProtocol
import com.sphereon.wallet.interaction.WalletProtocolCapability
import com.sphereon.wallet.interaction.WalletProtocolExecutionRequest
import com.sphereon.wallet.interaction.WalletProtocolMatch
import com.sphereon.wallet.interaction.WalletSecurityGateResult
import com.sphereon.wallet.interaction.WalletSecurityOperation
import com.sphereon.wallet.interaction.WalletSecurityGrantValidation
import com.sphereon.wallet.interaction.validateFor
import com.sphereon.wallet.interaction.WalletTrustStatus
import com.sphereon.wallet.interaction.WalletTrustPolicyAction
import com.sphereon.wallet.interaction.classifiedWalletInteractionError
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.time.Clock

class Oid4vpWalletInteractionProtocolAdapter(
    private val presentationExecutor: Oid4vpPresentationExecutor,
    private val holder: Oid4vpHolderService? = null,
    private val candidateResolver: Oid4vpCredentialCandidateResolver = Oid4vpCredentialCandidateResolver.none,
    private val securityContextResolver: Oid4vpPresentationSecurityContextResolver = Oid4vpPresentationSecurityContextResolver.none,
    private val walletConfigProvider: Oid4vpWalletConfigProvider = Oid4vpWalletConfigProvider.none,
    private val attendedAuthorizationRegistry: WalletAttendedAuthorizationRegistry = WalletAttendedAuthorizationRegistry.none,
    priority: Int = 90,
) : WalletInteractionProtocolAdapter {
    override val capability: WalletProtocolCapability =
        WalletProtocolCapability(
            adapterId = ADAPTER_ID,
            protocol = WalletProtocol.OID4VP,
            flowKinds = listOf(WalletInteractionFlowKind.CredentialPresent),
            priority = priority,
            labelKey = "wallet.interaction.adapter.oid4vp",
        )

    override suspend fun canHandle(entryPoint: WalletEntryPoint): WalletProtocolMatch {
        if (
            entryPoint.kind == WalletEntryPointKind.PARSED_OBJECT &&
            entryPoint.parsedType in DIGITAL_CREDENTIAL_PROTOCOLS
        ) {
            return WalletProtocolMatch.strong(capability.priority, "oid4vp.match.digital_credentials_api")
        }
        val raw = entryPoint.raw ?: return WalletProtocolMatch.none
        val lower = raw.lowercase()
        // ISO 18013-7 Annex B has its own mdoc-openid4vp deep link and its
        // restricted Presentation-Exchange profile. This adapter is the
        // regular OID4VP/DCQL path and must not claim the ISO profile.
        if (lower.startsWith("mdoc-openid4vp://")) return WalletProtocolMatch.none
        // A regular OpenID4VP request is DCQL-based. The shared holder resolver
        // still understands Presentation Definition input for the ISO Annex B
        // transport, but that compatibility must not make the regular wallet
        // adapter silently reinterpret PE as DCQL.
        if (lower.containsQueryParameter("presentation_definition") ||
            lower.containsQueryParameter("presentation_definition_uri")
        ) {
            return WalletProtocolMatch.none
        }
        return when {
            lower.startsWith("openid4vp://") ||
                lower.startsWith("haip-vp://") ->
                WalletProtocolMatch.strong(capability.priority, "oid4vp.match.scheme")
            "response_type=vp_token" in lower || "dcql_query=" in lower -> WalletProtocolMatch.strong(capability.priority, "oid4vp.match.authorization_request")
            "request_uri=" in lower && ("openid" in lower || "vp" in lower) -> WalletProtocolMatch.weak(capability.priority, "oid4vp.match.request_uri_candidate")
            else -> WalletProtocolMatch.none
        }
    }

    override suspend fun start(
        context: WalletInteractionContext,
        entryPoint: WalletEntryPoint,
    ): WalletInteractionSession {
        val digitalCredentialsRequest =
            if (
                entryPoint.kind == WalletEntryPointKind.PARSED_OBJECT &&
                entryPoint.parsedType in DIGITAL_CREDENTIAL_PROTOCOLS
            ) {
                DigitalCredentialsAuthorizationRequest(
                    protocol = requireNotNull(entryPoint.parsedType),
                    data = entryPoint.parsed as? JsonObject ?: JsonObject(emptyMap()),
                    origin = context.attributes[DIGITAL_CREDENTIAL_ORIGIN_METADATA_KEY].orEmpty(),
                )
            } else {
                null
            }
        val digitalCredentialsSelection =
            if (digitalCredentialsRequest != null) {
                try {
                    DigitalCredentialsSelectionMetadata.parse(context.attributes)
                } catch (_: Exception) {
                    val state =
                        context.baseState(
                            status = WalletInteractionStatus.Failed,
                            flowKind = WalletInteractionFlowKind.CredentialPresent,
                            protocol = WalletProtocol.OID4VP,
                            adapterId = capability.adapterId,
                            entryPoint = entryPoint,
                        ).copy(
                            terminal = true,
                            error =
                                classifiedWalletInteractionError(
                                    code = WalletInteractionFailureCodes.OID4VP_DCA_SELECTION_INVALID,
                                    messageKey = "wallet.interaction.error.oid4vp_digital_credentials_selection_invalid",
                                    arguments = mapOf("reason" to "invalid_selection_metadata"),
                                ),
                        )
                    return WalletInteractionSession(context.sessionId, state)
                }
            } else {
                null
            }
        val rawRequest = entryPoint.raw ?: digitalCredentialsRequest?.data?.toString()
        val launchState =
            context.baseState(
                status = WalletInteractionStatus.ResolvingEntryPoint,
                flowKind = WalletInteractionFlowKind.CredentialPresent,
                protocol = WalletProtocol.OID4VP,
                adapterId = capability.adapterId,
                entryPoint = entryPoint,
            )
        context.storePrivate(
            buildMap {
                put("entry_point.raw", rawRequest.orEmpty())
                put("entry_point.fingerprint", entryPoint.summary().fingerprint.orEmpty())
                entryPoint.parsedType
                    ?.takeIf { it in DIGITAL_CREDENTIAL_PROTOCOLS }
                    ?.let { put(DIGITAL_CREDENTIAL_PROTOCOL_PRIVATE_KEY, it) }
                digitalCredentialsSelection?.let { selection ->
                    selection.selectedEntryId?.let { put(DigitalCredentialsSelectionMetadata.SELECTED_ENTRY_ID_KEY, it) }
                    selection.selectedCredentialSetId?.let { put(DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_SET_ID_KEY, it) }
                    if (selection.constrainsCredentialIds) {
                        put(
                            DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_IDS_KEY,
                            JsonArray(selection.requiredCredentialIds.map(::JsonPrimitive)).toString(),
                        )
                    }
                }
            },
        )
        val parsed =
            when {
                digitalCredentialsRequest != null ->
                    holder?.parseDigitalCredentialsAuthorizationRequest(
                        digitalCredentialsRequest,
                        walletConfigProvider.walletConfig(context, launchState),
                    )
                rawRequest != null -> holder?.parseAuthorizationRequest(rawRequest, walletConfigProvider.walletConfig(context, launchState))
                else -> null
            }
        if (parsed != null && parsed.isErr) {
            val state =
                context
                    .baseState(
                        status = WalletInteractionStatus.Failed,
                        flowKind = WalletInteractionFlowKind.CredentialPresent,
                        protocol = WalletProtocol.OID4VP,
                        adapterId = capability.adapterId,
                        entryPoint = entryPoint,
                    ).copy(
                        terminal = true,
                        error = parsed.error.toOid4vpRequestError(),
                    )
            return WalletInteractionSession(context.sessionId, state)
        }

        val parsedRequest = parsed?.takeIf { it.isOk }?.value
        if (parsedRequest != null) {
            context.storePrivate(mapOf("authorization_request" to json.encodeToString(AuthorizationRequest.serializer(), parsedRequest)))
        }
        val resolvedResult = parsedRequest?.let { holder?.resolveAuthorizationRequest(it) }
        if (resolvedResult != null && resolvedResult.isErr) {
            val state =
                context
                    .baseState(
                        status = WalletInteractionStatus.Failed,
                        flowKind = WalletInteractionFlowKind.CredentialPresent,
                        protocol = WalletProtocol.OID4VP,
                        adapterId = capability.adapterId,
                        entryPoint = entryPoint,
                    ).copy(
                        terminal = true,
                        error =
                            classifiedWalletInteractionError(
                                code = WalletInteractionFailureCodes.OID4VP_REQUEST_RESOLVE_FAILED,
                                messageKey = "wallet.interaction.error.oid4vp_request_resolve_failed",
                                arguments = mapOf("providerErrorCode" to resolvedResult.error.code),
                            ),
                    )
            return WalletInteractionSession(context.sessionId, state)
        }
        val resolved = resolvedResult?.takeIf { it.isOk }?.value
        if (resolved != null && resolved.request.hasPresentationExchangeParameters()) {
            val state =
                context
                    .baseState(
                        status = WalletInteractionStatus.Failed,
                        flowKind = WalletInteractionFlowKind.CredentialPresent,
                        protocol = WalletProtocol.OID4VP,
                        adapterId = capability.adapterId,
                        entryPoint = entryPoint,
                    ).copy(
                        terminal = true,
                        error =
                            classifiedWalletInteractionError(
                                code = WalletInteractionFailureCodes.OID4VP_REQUEST_RESOLVE_FAILED,
                                messageKey = "wallet.interaction.error.oid4vp_request_resolve_failed",
                                arguments = mapOf("providerErrorCode" to "OID4VP_PRESENTATION_EXCHANGE_UNSUPPORTED"),
                            ),
                    )
            return WalletInteractionSession(context.sessionId, state)
        }
        val interactionPurpose = context.resolveInteractionPurpose(parsedRequest, resolved)
        val activityType =
            when (interactionPurpose) {
                Oid4vpInteractionPurpose.LOGIN -> WalletInteractionActivityType.LOGIN
                Oid4vpInteractionPurpose.PRESENTATION -> WalletInteractionActivityType.CREDENTIAL_PRESENTATION
            }
        val interactionContext = interactionPurpose.metadataValue
        val unresolvedVerifier =
            resolved?.verifierInfo?.let {
                WalletCounterpartySummary(
                    role = WalletCounterpartyRole.VERIFIER,
                    identifier = it.clientId,
                    displayName = it.displayName ?: it.clientId,
                    displayNameSource = selfAssertedDisplayNameSource(it.displayName),
                    logoUri = it.logoUri,
                    detail = counterpartyDetailFromDcrMetadata(resolved.request.additionalParameters["client_metadata"]),
                    metadata =
                        buildMap {
                            put("client_id_scheme", it.clientIdScheme.name)
                            put("interaction_context", interactionContext)
                            put("activity_type", activityType.name)
                            (resolved.request.requestUri ?: parsedRequest.requestUri)?.let { uri -> put("request_uri", uri) }
                            resolved.request.responseUri?.let { uri -> put("response_uri", uri) }
                            it.trustRoot?.let { uri -> put("trust_root", uri) }
                        },
                )
            } ?: fallbackVerifier(entryPoint, activityType, interactionContext)
        val encounter = context.recordCounterpartyEncounter(WalletProtocol.OID4VP, unresolvedVerifier)
        val verifier = encounter.counterparty
        val activity =
            WalletInteractionActivitySummary(
                type = activityType,
                counterparty = verifier,
                metadata =
                    mapOf(
                        "interaction_context" to interactionContext,
                        "protocol" to WalletProtocol.OID4VP.name,
                    ),
            )

        val requestError = resolved?.authorizationError
        val discoveredCandidateCredentialIds =
            if (requestError == null) resolved?.let { candidateResolver.candidateCredentialIds(context, it) }.orEmpty() else emptyMap()
        val restrictedCandidates = digitalCredentialsSelection?.restrictCandidates(discoveredCandidateCredentialIds)
        val unknownPlatformCredentialIds = restrictedCandidates?.unavailableSelectedIds.orEmpty()
        val platformSelectionInvalid =
            unknownPlatformCredentialIds.isNotEmpty() ||
                (digitalCredentialsSelection?.constrainsCredentialIds == true &&
                    digitalCredentialsSelection.requiredCredentialIds.isEmpty() &&
                    resolved?.dcqlQuery?.credentials.orEmpty().isNotEmpty())
        if (requestError == null && platformSelectionInvalid) {
            val state =
                context.baseState(
                    status = WalletInteractionStatus.Failed,
                    flowKind = WalletInteractionFlowKind.CredentialPresent,
                    protocol = WalletProtocol.OID4VP,
                    adapterId = capability.adapterId,
                    entryPoint = entryPoint,
                ).copy(
                    activity = activity,
                    counterparty = verifier,
                    counterpartyEncounter = encounter,
                    terminal = true,
                    error =
                        classifiedWalletInteractionError(
                            code = WalletInteractionFailureCodes.OID4VP_DCA_SELECTION_UNAVAILABLE,
                            messageKey = "wallet.interaction.error.oid4vp_digital_credentials_selection_unavailable",
                            arguments = mapOf("unavailableCredentialCount" to unknownPlatformCredentialIds.size.toString()),
                        ),
                )
            return WalletInteractionSession(context.sessionId, state)
        }
        val candidateCredentialIds = restrictedCandidates?.byRequirement ?: discoveredCandidateCredentialIds
        val resolvedRequirements =
            resolved?.dcqlQuery?.toCredentialSelectionRequest(candidateCredentialIds)
                ?: WalletCredentialSelectionRequest(emptyList(), satisfiable = false)
        val requirements = resolvedRequirements
        val requestedClaims = requirements.requirements.flatMap { requirement -> requirement.requiredClaimPaths.map { WalletClaimDescriptor(path = it) } }
        context.storePrivate(
            mapOf(
                "verifier_id" to verifier.identifier,
                "dcql_requirement_ids" to requirements.requirements.joinToString(",") { it.id },
                "interaction_context" to interactionContext,
                "activity_type" to activityType.name,
            ),
        )
        val clientAuthentication = resolved?.verifierInfo?.toWalletCounterpartyClientAuthentication()
        clientAuthentication?.let {
            context.storePrivate(
                mapOf(CLIENT_AUTHENTICATION_PRIVATE_KEY to json.encodeToString(WalletCounterpartyClientAuthentication.serializer(), it)),
            )
        }
        val trust =
            context.trustResolver
                .resolve(
                    WalletCounterpartyTrustRequest(
                        counterparty = verifier,
                        protocol = WalletProtocol.OID4VP,
                        clientAuthentication = clientAuthentication,
                    ),
                ).let { trust -> trust.copy(policyAction = context.trustPolicy.evaluate(trust).action) }
                .copy(counterparty = verifier)
        if (requestError != null) {
            val authenticatedRequest = requireNotNull(resolved)
            // A captured request is user interaction. Return only its protocol error after the
            // client identity and the wallet's assigned trust policy have both been checked.
            val submitted = if (authenticatedRequest.verifierInfo.clientIdValid && trust.status == WalletTrustStatus.TRUSTED &&
                trust.policyAction == WalletTrustPolicyAction.ALLOW) {
                holder?.submitAuthorizationErrorResponse(authenticatedRequest, requestError)
            } else null
            val completionUri = (submitted?.getOrNull() as? SubmissionResult.Success)?.redirectUri
            val completionRef = completionUri?.let { uri ->
                context.sensitiveInputAuthority.register(
                    sessionId = context.sessionId,
                    purpose = WalletInteractionSensitiveInputPurpose.PROTOCOL_COMPLETION_HANDOFF,
                    value = uri,
                )
            }
            val state = context.baseState(
                status = WalletInteractionStatus.Failed,
                flowKind = WalletInteractionFlowKind.CredentialPresent,
                protocol = WalletProtocol.OID4VP,
                adapterId = capability.adapterId,
                entryPoint = entryPoint,
            ).copy(
                activity = activity,
                counterparty = verifier,
                counterpartyEncounter = encounter,
                trust = trust,
                completionHandoffRef = completionRef,
                completionHandoffTransport = completionRef?.let { WalletInteractionCompletionTransport.BROWSER_REDIRECT },
                terminal = true,
                error = classifiedWalletInteractionError(
                    code = WalletInteractionFailureCodes.OID4VP_REQUEST_RESOLVE_FAILED,
                    messageKey = "wallet.interaction.error.oid4vp_request_resolve_failed",
                    arguments = mapOf(
                        "providerErrorCode" to requestError.error,
                        "errorResponseSubmitted" to (submitted?.getOrNull() is SubmissionResult.Success || submitted?.getOrNull() is SubmissionResult.DigitalCredential).toString(),
                    ),
                ),
            )
            return WalletInteractionSession(context.sessionId, state)
        }
        if (!encounter.organizationCreated && trust.policyAction == WalletTrustPolicyAction.BLOCK) {
            val state =
                context
                    .baseState(
                        status = WalletInteractionStatus.Failed,
                        flowKind = WalletInteractionFlowKind.CredentialPresent,
                        protocol = WalletProtocol.OID4VP,
                        adapterId = capability.adapterId,
                        entryPoint = entryPoint,
                    ).copy(
                        activity = activity,
                        counterparty = verifier,
                        counterpartyEncounter = encounter,
                        trust = trust,
                        credentialSelection = requirements,
                        disclosure = WalletDisclosureSummary(verifier = verifier, requestedClaims = requestedClaims),
                        terminal = true,
                        error =
                            classifiedWalletInteractionError(
                                code = WalletInteractionFailureCodes.OID4VP_VERIFIER_BLOCKED,
                                messageKey = "wallet.interaction.error.verifier_blocked",
                            ),
                    )
            return WalletInteractionSession(context.sessionId, state)
        }
        val reviewStatus =
            if (encounter.organizationCreated) {
                WalletInteractionStatus.CounterpartyNotice
            } else if (encounter.firstInteraction ||
                trust.policyAction == WalletTrustPolicyAction.WARN ||
                trust.policyAction == WalletTrustPolicyAction.ASK_USER ||
                trust.policyAction == WalletTrustPolicyAction.FIRST_CONTACT_PROMPT
            ) {
                WalletInteractionStatus.TrustReview
            } else if (requirements.requirements.isEmpty()) {
                WalletInteractionStatus.DisclosureConsent
            } else {
                WalletInteractionStatus.CredentialSelection
            }
        val state =
            context
                .baseState(
                    status = reviewStatus,
                    flowKind = WalletInteractionFlowKind.CredentialPresent,
                    protocol = WalletProtocol.OID4VP,
                    adapterId = capability.adapterId,
                    entryPoint = entryPoint,
                ).copy(
                    activity = activity,
                    counterparty = verifier,
                    counterpartyEncounter = encounter,
                    trust = trust,
                    credentialSelection = requirements,
                    disclosure = WalletDisclosureSummary(verifier = verifier, requestedClaims = requestedClaims),
                )
        return WalletInteractionSession(context.sessionId, state)
    }

    override suspend fun handle(
        context: WalletInteractionContext,
        sessionState: WalletInteractionState,
        action: WalletInteractionAction,
    ): WalletInteractionState =
        when (action.type) {
            WalletInteractionActionType.DECLINE -> {
                sessionState.next(WalletInteractionStatus.Cancelled, terminal = true)
            }

            WalletInteractionActionType.RESOLVE_COUNTERPARTY_CONTACT -> {
                context.resolveCounterpartyContact(sessionState, action)
            }

            WalletInteractionActionType.SELECT_CREDENTIALS,
            WalletInteractionActionType.CONTINUE,
            -> {
                if (sessionState.status == WalletInteractionStatus.CounterpartyNotice) {
                    sessionState.rejectAction(WalletInteractionFailureCodes.OID4VP_COUNTERPARTY_RESOLUTION_REQUIRED)
                } else if (sessionState.status == WalletInteractionStatus.TrustReview) {
                    sessionState.copy(
                        status =
                            if (sessionState.credentialSelection
                                    ?.requirements
                                    .orEmpty()
                                    .isEmpty()
                            ) {
                                WalletInteractionStatus.DisclosureConsent
                            } else {
                                WalletInteractionStatus.CredentialSelection
                            },
                        revision = sessionState.revision + 1,
                    )
                } else {
                    val invalidSelection = sessionState.validateCredentialSelection(action, context)
                    if (invalidSelection != null) {
                        sessionState.copy(
                            status = WalletInteractionStatus.CredentialSelection,
                            revision = sessionState.revision + 1,
                            error = invalidSelection,
                        )
                    } else {
                        val selectedCredentialIds =
                            action.selection
                                ?.selectedCredentialIdsByRequirement
                                ?.values
                                .orEmpty()
                                .flatten()
                        val existingSelectedCredentialIds = sessionState.disclosure?.selectedCredentialIds.orEmpty()
                        if (selectedCredentialIds.isNotEmpty()) {
                            context.storePrivate(
                                mapOf(
                                    "selected_credential_ids" to selectedCredentialIds.joinToString(","),
                                    "selected_credential_ids_by_requirement" to json.encodeToString(action.selection?.selectedCredentialIdsByRequirement.orEmpty()),
                                ),
                            )
                        }
                        context.authorizePresentationSharing(
                            sessionState.copy(
                                disclosure =
                                    sessionState.disclosure?.copy(
                                        selectedCredentialIds = selectedCredentialIds.ifEmpty { existingSelectedCredentialIds },
                                    ),
                            ),
                        )
                    }
                }
            }

            WalletInteractionActionType.REVEAL_CLAIM_VALUES -> {
                sessionState.copy(
                    revision = sessionState.revision + 1,
                    disclosure = sessionState.disclosure?.copy(claimValuesRevealed = true),
                )
            }

            WalletInteractionActionType.APPROVE_SECURITY_CHALLENGE -> {
                val grant = action.sensitiveInputRef?.let { context.sensitiveInputAuthority.consumeSecurityGrant(sessionState.sessionId, it) }
                val validation =
                    grant?.validateFor(
                        sessionState.securityChallenge,
                        sessionState.walletUnitId,
                        sessionState.counterparty?.identifier,
                        Clock.System.now().epochSeconds,
                    )
                if (grant == null || validation is WalletSecurityGrantValidation.Invalid) {
                    sessionState.next(
                        status = WalletInteractionStatus.Failed,
                        error =
                            classifiedWalletInteractionError(
                                WalletInteractionFailureCodes.OID4VP_SECURITY_GRANT_REF_INVALID,
                                "wallet.interaction.error.security_grant_ref_invalid",
                            ),
                    )
                } else if (sessionState.securityChallenge?.operations.orEmpty().isNotEmpty()) {
                    context.applySharingApproval(sessionState, grant, requireNotNull(sessionState.securityChallenge).operations)
                } else {
                    val operationBinding = grant.evidence["operation_binding"].orEmpty()
                    context.storePrivate(
                        mapOf(
                            "security_grant_id" to grant.grantId,
                            SECURITY_OPERATION_BINDING_PRIVATE_KEY to operationBinding,
                        ),
                    )
                    attendedAuthorizationRegistry.authorize(sessionState.walletUnitId, operationBinding, grant)
                    context.applyPresentationResult(
                        sessionState.copy(revision = sessionState.revision + 1, securityChallenge = null),
                    )
                }
            }

            else -> {
                if (sessionState.status == WalletInteractionStatus.Sharing) {
                    sessionState.next(WalletInteractionStatus.Completed, terminal = true)
                } else {
                    sessionState.next()
                }
            }
        }

    private suspend fun WalletInteractionContext.resolveCounterpartyContact(
        sessionState: WalletInteractionState,
        action: WalletInteractionAction,
    ): WalletInteractionState {
        if (sessionState.status != WalletInteractionStatus.CounterpartyNotice) {
            return sessionState.rejectAction(WalletInteractionFailureCodes.OID4VP_ACTION_COUNTERPARTY_RESOLUTION_NOT_ALLOWED)
        }
        val encounter = sessionState.counterpartyEncounter
            ?: return sessionState.rejectAction(WalletInteractionFailureCodes.OID4VP_COUNTERPARTY_ENCOUNTER_MISSING)
        val decision = action.counterpartyAssociation
            ?: return sessionState.rejectAction(WalletInteractionFailureCodes.OID4VP_COUNTERPARTY_ASSOCIATION_MISSING)
        val resolvedEncounter =
            counterpartyEncounterRegistry.resolveAssociation(
                WalletCounterpartyAssociationRequest(
                    walletUnitId = sessionState.walletUnitId,
                    encounter = encounter,
                    decision = decision,
                ),
            )
        require(resolvedEncounter.resolved) { "wallet_counterparty_association_unresolved" }
        require(resolvedEncounter.associationCandidates.isEmpty()) { "wallet_counterparty_association_candidates_remaining" }
        require(resolvedEncounter.counterparty.role == encounter.counterparty.role) { "wallet_counterparty_association_role_changed" }
        require(resolvedEncounter.counterparty.identifier == encounter.counterparty.identifier) { "wallet_counterparty_association_identifier_changed" }

        val counterparty = resolvedEncounter.counterparty
        val clientAuthentication =
            privateSessionStore.get(sessionId, capability.adapterId)?.values?.get(CLIENT_AUTHENTICATION_PRIVATE_KEY)
                ?.let { json.decodeFromString(WalletCounterpartyClientAuthentication.serializer(), it) }
        val trust =
            trustResolver
                .resolve(
                    WalletCounterpartyTrustRequest(
                        counterparty = counterparty,
                        protocol = WalletProtocol.OID4VP,
                        clientAuthentication = clientAuthentication,
                    ),
                ).let { resolved -> resolved.copy(policyAction = trustPolicy.evaluate(resolved).action) }
                .copy(counterparty = counterparty)
        val activity = sessionState.activity?.copy(counterparty = counterparty)
        val disclosure = sessionState.disclosure?.copy(verifier = counterparty)
        if (trust.policyAction == WalletTrustPolicyAction.BLOCK) {
            return sessionState.copy(
                status = WalletInteractionStatus.Failed,
                revision = sessionState.revision + 1,
                activity = activity,
                counterparty = counterparty,
                counterpartyEncounter = resolvedEncounter,
                trust = trust,
                disclosure = disclosure,
                terminal = true,
                error =
                    classifiedWalletInteractionError(
                        code = WalletInteractionFailureCodes.OID4VP_VERIFIER_BLOCKED,
                        messageKey = "wallet.interaction.error.verifier_blocked",
                    ),
            )
        }
        val nextStatus =
            if (resolvedEncounter.firstInteraction ||
                trust.policyAction == WalletTrustPolicyAction.WARN ||
                trust.policyAction == WalletTrustPolicyAction.ASK_USER ||
                trust.policyAction == WalletTrustPolicyAction.FIRST_CONTACT_PROMPT
            ) {
                WalletInteractionStatus.TrustReview
            } else if (sessionState.credentialSelection?.requirements.orEmpty().isEmpty()) {
                WalletInteractionStatus.DisclosureConsent
            } else {
                WalletInteractionStatus.CredentialSelection
            }
        return sessionState.copy(
            status = nextStatus,
            revision = sessionState.revision + 1,
            activity = activity,
            counterparty = counterparty,
            counterpartyEncounter = resolvedEncounter,
            trust = trust,
            disclosure = disclosure,
            error = null,
        )
    }

    private fun WalletInteractionState.rejectAction(code: String): WalletInteractionState =
        copy(
            revision = revision + 1,
            error =
                classifiedWalletInteractionError(
                    code = code,
                    messageKey = "wallet.interaction.error.action_not_allowed",
                ),
        )

    private suspend fun WalletInteractionContext.authorizePresentationSharing(sessionState: WalletInteractionState): WalletInteractionState {
        val securityContext = securityContextResolver.resolve(this, sessionState)
        val operationId = "${sessionState.sessionId.value}-share"
        val operationBinding = securityContext.operationBinding ?: "operation:$operationId"
        storePrivate(mapOf(SECURITY_OPERATION_BINDING_PRIVATE_KEY to operationBinding))
        var preparedWalletAccountId: String? = null
        val operations =
            when (val preparation = presentationExecutor.preparePresentation(this, sessionState)) {
                Oid4vpPresentationPreparation.Ready -> emptyList()
                is Oid4vpPresentationPreparation.ApprovalRequired -> {
                    preparedWalletAccountId = preparation.walletAccountId
                    preparation.operations
                }
                is Oid4vpPresentationPreparation.Failed ->
                    return sessionState.next(
                        status = WalletInteractionStatus.Failed,
                        terminal = !preparation.retryable,
                        error = classifiedWalletInteractionError(preparation.code, preparation.messageKey, preparation.arguments),
                    )
            }
        if (operations.isNotEmpty()) {
            val approval =
                authorizeProtocolOperation(
                    WalletProtocolExecutionRequest(
                        operationId = operationId,
                        sessionId = sessionState.sessionId,
                        sessionWalletUnitId = sessionState.walletUnitId,
                        protocol = WalletProtocol.OID4VP,
                        operation = WalletSecurityOperation.PRESENT_CREDENTIALS,
                        audience = sessionState.counterparty?.identifier,
                        walletUnitId = sessionState.walletUnitId,
                        // A backend-owned interaction names the account through its prepared holder keys.
                        walletAccountId = securityContext.walletAccountId ?: preparedWalletAccountId,
                        operationBinding = operationBinding,
                        operations = operations,
                    ),
                )
            return when (approval) {
                is WalletSecurityGateResult.Authorized -> applySharingApproval(sessionState, approval.grant, operations)
                is WalletSecurityGateResult.ChallengeRequired ->
                    sessionState.copy(
                        status = WalletInteractionStatus.SecurityUnlockRequired,
                        revision = sessionState.revision + 1,
                        securityChallenge = approval.challenge.copy(operations = operations),
                    )
                is WalletSecurityGateResult.Denied ->
                    sessionState.next(
                        status = WalletInteractionStatus.Failed,
                        terminal = true,
                        error =
                            classifiedWalletInteractionError(
                                code = WalletInteractionFailureCodes.OID4VP_SECURITY_DENIED,
                                messageKey = approval.reasonKey,
                                arguments = approval.arguments,
                            ),
                    )
            }
        }
        val result =
            authorizeProtocolOperation(
                WalletProtocolExecutionRequest(
                    operationId = operationId,
                    sessionId = sessionState.sessionId,
                    sessionWalletUnitId = sessionState.walletUnitId,
                    protocol = WalletProtocol.OID4VP,
                    operation = WalletSecurityOperation.PRESENT_CREDENTIALS,
                    audience = sessionState.counterparty?.identifier,
                    keyRef = securityContext.keyRef,
                    walletUnitId = securityContext.walletUnitId,
                    walletAccountId = securityContext.walletAccountId,
                    activationDecisionId = securityContext.activationDecisionId,
                    operationType = securityContext.operationType,
                    operationBinding = operationBinding,
                    operationHash = securityContext.operationHash,
                    nonce = securityContext.nonce,
                ),
            )
        return when (result) {
            is WalletSecurityGateResult.Authorized -> {
                val operationBinding = result.grant.evidence["operation_binding"].orEmpty()
                storePrivate(
                    mapOf(
                        "security_grant_id" to result.grant.grantId,
                        SECURITY_OPERATION_BINDING_PRIVATE_KEY to operationBinding,
                    ),
                )
                attendedAuthorizationRegistry.authorize(sessionState.walletUnitId, operationBinding, result.grant)
                applyPresentationResult(sessionState.copy(revision = sessionState.revision + 1, securityChallenge = null))
            }

            is WalletSecurityGateResult.ChallengeRequired -> {
                sessionState.copy(
                    status = WalletInteractionStatus.SecurityUnlockRequired,
                    revision = sessionState.revision + 1,
                    securityChallenge = result.challenge,
                )
            }

            is WalletSecurityGateResult.Denied -> {
                sessionState.next(
                    status = WalletInteractionStatus.Failed,
                    terminal = true,
                    error =
                        classifiedWalletInteractionError(
                            code = WalletInteractionFailureCodes.OID4VP_SECURITY_DENIED,
                            messageKey = result.reasonKey,
                            arguments = result.arguments,
                        ),
                )
            }
        }
    }

    /**
     * Records the holder's approval of exactly [operations], the signatures of the prepared
     * presentation on this wallet unit, and shares it. The grant handed to the signer lists the
     * approved operations from this server's own challenge, never from the client.
     */
    private suspend fun WalletInteractionContext.applySharingApproval(
        sessionState: WalletInteractionState,
        grant: WalletSecurityGrant,
        operations: List<WalletApprovalOperation>,
    ): WalletInteractionState {
        val operationBinding =
            privateSessionStore.get(sessionId, ADAPTER_ID)?.values?.get(SECURITY_OPERATION_BINDING_PRIVATE_KEY)
                ?: return sessionState.rejectAction(WalletInteractionFailureCodes.OID4VP_SECURITY_GRANT_REF_INVALID)
        storePrivate(mapOf("security_grant_id" to grant.grantId))
        attendedAuthorizationRegistry.authorize(
            sessionState.walletUnitId,
            operationBinding,
            grant.copy(
                evidence =
                    grant.evidence +
                        mapOf(
                            "operation_binding" to operationBinding,
                            WalletApprovalOperations.EVIDENCE_KEY to WalletApprovalOperations.encode(operations),
                        ),
            ),
        )
        return applyPresentationResult(sessionState.copy(revision = sessionState.revision + 1, securityChallenge = null))
    }

    private suspend fun WalletInteractionContext.applyPresentationResult(sessionState: WalletInteractionState): WalletInteractionState =
        when (val result = presentationExecutor.submitPresentation(this, sessionState)) {
            is Oid4vpPresentationExecutionResult.Submitted -> {
                sessionState.next(
                    status = WalletInteractionStatus.Completed,
                    terminal = true,
                    message = WalletDisplayMessage(titleKey = result.titleKey),
                )
            }

            is Oid4vpPresentationExecutionResult.Sharing -> {
                sessionState.copy(
                    status = WalletInteractionStatus.Sharing,
                    message = WalletDisplayMessage(titleKey = result.titleKey),
                    error = null,
                )
            }

            is Oid4vpPresentationExecutionResult.RedirectRequired -> {
                val handoffRef =
                    sensitiveInputAuthority.register(
                        sessionId = sessionState.sessionId,
                        purpose = WalletInteractionSensitiveInputPurpose.PROTOCOL_COMPLETION_HANDOFF,
                        value = result.redirectUri,
                    )
                sessionState.copy(
                    status = WalletInteractionStatus.Completed,
                    revision = sessionState.revision + 1,
                    completionHandoffRef = handoffRef,
                    completionHandoffTransport = WalletInteractionCompletionTransport.BROWSER_REDIRECT,
                    message = WalletDisplayMessage(titleKey = "wallet.interaction.oid4vp.shared"),
                    error = null,
                    terminal = true,
                )
            }

            is Oid4vpPresentationExecutionResult.DigitalCredentialResponse -> {
                val privateValues =
                    privateSessionStore
                        .get(sessionState.sessionId, ADAPTER_ID)
                        ?.values
                        .orEmpty()
                val protocol = privateValues[DIGITAL_CREDENTIAL_PROTOCOL_PRIVATE_KEY]
                if (protocol == null) {
                    sessionState.next(
                        status = WalletInteractionStatus.Failed,
                        terminal = true,
                        error =
                            classifiedWalletInteractionError(
                                code = WalletInteractionFailureCodes.OID4VP_DIGITAL_CREDENTIAL_PROTOCOL_MISSING,
                                messageKey = "wallet.interaction.error.oid4vp_digital_credential_protocol_missing",
                            ),
                    )
                } else {
                    val response =
                        buildJsonObject {
                            put("protocol", JsonPrimitive(protocol))
                            put("data", result.data)
                        }
                    val handoffRef =
                        sensitiveInputAuthority.register(
                            sessionId = sessionState.sessionId,
                            purpose = WalletInteractionSensitiveInputPurpose.PROTOCOL_COMPLETION_HANDOFF,
                            value = response.toString(),
                        )
                    sessionState.copy(
                        status = WalletInteractionStatus.Completed,
                        revision = sessionState.revision + 1,
                        completionHandoffRef = handoffRef,
                    completionHandoffTransport = WalletInteractionCompletionTransport.DIGITAL_CREDENTIALS_API,
                        message = WalletDisplayMessage(titleKey = "wallet.interaction.oid4vp.shared"),
                        error = null,
                        terminal = true,
                    )
                }
            }

            is Oid4vpPresentationExecutionResult.Failed -> {
                sessionState.next(
                    status = WalletInteractionStatus.Failed,
                    terminal = !result.retryable,
                    error =
                        classifiedWalletInteractionError(
                            code = result.code,
                            messageKey = result.messageKey,
                            arguments = result.arguments,
                        ),
                )
            }
        }

    private suspend fun WalletInteractionState.validateCredentialSelection(
        action: WalletInteractionAction,
        context: WalletInteractionContext,
    ): WalletInteractionError? {
        val request = credentialSelection ?: return null
        val requirements = request.requirements
        if (requirements.isEmpty()) return null

        fun error(
            code: String,
            arguments: Map<String, String> = emptyMap(),
        ): WalletInteractionError =
            classifiedWalletInteractionError(
                code = code,
                messageKey = "wallet.interaction.error.oid4vp_credential_selection_invalid",
                arguments = arguments,
            )

        if (!request.satisfiable) {
            return error(WalletInteractionFailureCodes.OID4VP_SELECTION_UNSATISFIABLE)
        }

        val selectedByRequirement = action.selection?.selectedCredentialIdsByRequirement.orEmpty()
        val privateValues = context.privateSessionStore.get(sessionId, ADAPTER_ID)?.values.orEmpty()
        val platformSelectedIdsJson = privateValues[DigitalCredentialsSelectionMetadata.SELECTED_CREDENTIAL_IDS_KEY]
        if (platformSelectedIdsJson != null) {
            val platformSelectedIds =
                runCatching {
                    Json.parseToJsonElement(platformSelectedIdsJson).jsonArray.map { it.jsonPrimitive.content }
                }.getOrNull() ?: return error(WalletInteractionFailureCodes.OID4VP_DCA_SELECTION_INVALID)
            val submittedIds = selectedByRequirement.values.flatten()
            if (submittedIds.toSet() != platformSelectedIds.toSet()) {
                return error(WalletInteractionFailureCodes.OID4VP_DCA_SELECTION_MISMATCH)
            }
        }
        val requirementIds = requirements.map { it.id }.toSet()
        val unknownRequirementId = selectedByRequirement.keys.firstOrNull { it !in requirementIds }
        if (unknownRequirementId != null) {
            return error(WalletInteractionFailureCodes.OID4VP_SELECTION_UNKNOWN_REQUIREMENT, mapOf("requirementId" to unknownRequirementId))
        }

        if (request.credentialSets.isNotEmpty()) {
            val selectedRequirementIds = selectedByRequirement.filterValues { it.isNotEmpty() }.keys
            val coveredRequirementIds = mutableSetOf<String>()
            request.credentialSets.forEach { set ->
                if (set.options.isEmpty() || set.options.any { option ->
                        option.requirementIds.isEmpty() || option.requirementIds.any { it !in requirementIds }
                    }
                ) {
                    return error(WalletInteractionFailureCodes.OID4VP_SELECTION_UNSATISFIABLE)
                }
                val satisfiedOptions = set.options.filter { option ->
                    option.satisfiable && option.requirementIds.all { it in selectedRequirementIds }
                }
                if (set.required && satisfiedOptions.isEmpty()) {
                    return error(WalletInteractionFailureCodes.OID4VP_SELECTION_MISSING_REQUIREMENT, mapOf("requirementId" to set.id))
                }
                satisfiedOptions.forEach { coveredRequirementIds.addAll(it.requirementIds) }
            }
            if (selectedRequirementIds.isEmpty() || selectedRequirementIds.any { it !in coveredRequirementIds }) {
                return error(WalletInteractionFailureCodes.OID4VP_SELECTION_UNSATISFIABLE)
            }
        }

        requirements.forEach { requirement ->
            val selectedCredentialIds = selectedByRequirement[requirement.id].orEmpty()
            if (selectedCredentialIds.isEmpty()) {
                if (request.credentialSets.isEmpty()) {
                    return error(WalletInteractionFailureCodes.OID4VP_SELECTION_MISSING_REQUIREMENT, mapOf("requirementId" to requirement.id))
                }
                return@forEach
            }
            if (selectedCredentialIds.size != selectedCredentialIds.distinct().size) {
                return error(WalletInteractionFailureCodes.OID4VP_SELECTION_CREDENTIAL_NOT_CANDIDATE, mapOf("requirementId" to requirement.id))
            }
            if (!requirement.multipleAllowed && selectedCredentialIds.size > 1) {
                return error(WalletInteractionFailureCodes.OID4VP_SELECTION_MULTIPLE_NOT_ALLOWED, mapOf("requirementId" to requirement.id))
            }
            val unavailableCredentialId = selectedCredentialIds.firstOrNull { it !in requirement.candidateCredentialIds }
            if (unavailableCredentialId != null) {
                return error(
                    WalletInteractionFailureCodes.OID4VP_SELECTION_CREDENTIAL_NOT_CANDIDATE,
                    mapOf(
                        "requirementId" to requirement.id,
                        "credentialId" to unavailableCredentialId,
                    ),
                )
            }
        }

        return null
    }

    private suspend fun WalletInteractionContext.storePrivate(values: Map<String, String>) {
        val sanitized = values.filterValues { it.isNotBlank() }
        if (sanitized.isEmpty()) return
        val existing = privateSessionStore.get(sessionId, capability.adapterId)?.values.orEmpty()
        privateSessionStore.put(
            sessionId,
            WalletInteractionPrivateSessionData(
                namespace = capability.adapterId,
                values = existing + sanitized,
            ),
        )
    }

    companion object {
        const val ADAPTER_ID: String = "oid4vp"
        const val SECURITY_OPERATION_BINDING_PRIVATE_KEY: String = "security_operation_binding"
        const val DIGITAL_CREDENTIAL_PROTOCOL_UNSIGNED: String = "openid4vp-v1-unsigned"
        const val DIGITAL_CREDENTIAL_PROTOCOL_SIGNED: String = "openid4vp-v1-signed"
        const val DIGITAL_CREDENTIAL_PROTOCOL_MULTI_SIGNED: String = "openid4vp-v1-multisigned"
        const val DIGITAL_CREDENTIAL_ORIGIN_METADATA_KEY: String = "digital_credentials.origin"
        internal const val DIGITAL_CREDENTIAL_PROTOCOL_PRIVATE_KEY: String = "digital_credential.protocol"
        internal const val CLIENT_AUTHENTICATION_PRIVATE_KEY: String = "verifier_client_authentication"
        internal val DIGITAL_CREDENTIAL_PROTOCOLS: Set<String> =
            setOf(DIGITAL_CREDENTIAL_PROTOCOL_UNSIGNED, DIGITAL_CREDENTIAL_PROTOCOL_SIGNED, DIGITAL_CREDENTIAL_PROTOCOL_MULTI_SIGNED)
        internal val json: Json =
            Json {
                ignoreUnknownKeys = true
                encodeDefaults = false
            }

        fun walletStoreBacked(
            holder: Oid4vpHolderService,
            credentialStore: WalletCredentialStore,
            sdJwtHolderBindingProvider: Oid4vpSdJwtHolderBindingProvider,
            dataIntegrityHolderBindingProvider: Oid4vpDataIntegrityHolderBindingProvider = Oid4vpDataIntegrityHolderBindingProvider.none,
            holderIdentityResolver: WalletHolderIdentityResolver = WalletHolderIdentityResolver.none,
            holderVerificationMethodResolver: WalletHolderVerificationMethodResolver? = null,
            walletConfigProvider: Oid4vpWalletConfigProvider = Oid4vpWalletConfigProvider.none,
            jarmOptionsProvider: Oid4vpJarmOptionsProvider = Oid4vpJarmOptionsProvider.none,
            responseMode: ResponseMode? = null,
            attendedAuthorizationRegistry: WalletAttendedAuthorizationRegistry = WalletAttendedAuthorizationRegistry.none,
            priority: Int = 90,
            preparedJwtSigningProvider: Oid4vpPreparedJwtSigningProvider? = null,
            mdocHolderSigningProvider: Oid4vpMdocHolderSigningProvider? = null,
            credentialClaimValuesResolver: WalletCredentialClaimValuesResolver? = null,
        ): Oid4vpWalletInteractionProtocolAdapter {
            val resolver =
                WalletStoreOid4vpCredentialResolver(
                    credentialStore = credentialStore,
                    holderIdentityResolver = holderIdentityResolver,
                    holderVerificationMethodResolver = holderVerificationMethodResolver,
                    credentialClaimValuesResolver = credentialClaimValuesResolver,
                )
            return Oid4vpWalletInteractionProtocolAdapter(
                holder = holder,
                presentationExecutor =
                    Oid4vpHolderPresentationExecutor(
                        holder = holder,
                        selectedCredentialResolver = resolver,
                        walletConfigProvider = walletConfigProvider,
                        jarmOptionsProvider = jarmOptionsProvider,
                        responseMode = responseMode,
                        sdJwtHolderBindingProvider = sdJwtHolderBindingProvider,
                        dataIntegrityHolderBindingProvider = dataIntegrityHolderBindingProvider,
                        preparedJwtSigningProvider = preparedJwtSigningProvider,
                        mdocHolderSigningProvider = mdocHolderSigningProvider,
                    ),
                candidateResolver = resolver,
                securityContextResolver = resolver,
                walletConfigProvider = walletConfigProvider,
                attendedAuthorizationRegistry = attendedAuthorizationRegistry,
                priority = priority,
            )
        }
    }
}

private fun IdkError.toOid4vpRequestError(): WalletInteractionError {
    val publicCode =
        when {
            code == "HTTP_410" -> WalletInteractionFailureCodes.OID4VP_REQUEST_URI_EXPIRED
            code == "HTTP_404" -> WalletInteractionFailureCodes.OID4VP_REQUEST_URI_NOT_FOUND
            code == "HTTP_REQUEST_FAILED" || code == "HTTP_408" || code == "HTTP_429" || code.startsWith("HTTP_5") ->
                WalletInteractionFailureCodes.OID4VP_REQUEST_URI_FETCH_FAILED
            code.startsWith("HTTP_4") -> WalletInteractionFailureCodes.OID4VP_REQUEST_URI_REJECTED
            else -> WalletInteractionFailureCodes.OID4VP_REQUEST_PARSE_FAILED
        }
    return classifiedWalletInteractionError(
        code = publicCode,
        messageKey = "wallet.interaction.error.oid4vp_request_parse_failed",
        arguments = mapOf("providerErrorCode" to code),
    )
}

interface Oid4vpCredentialCandidateResolver {
    suspend fun candidateCredentialIds(
        context: WalletInteractionContext,
        resolvedRequest: ResolvedOid4vpRequest,
    ): Map<String, List<String>>

    companion object {
        val none: Oid4vpCredentialCandidateResolver =
            object : Oid4vpCredentialCandidateResolver {
                override suspend fun candidateCredentialIds(
                    context: WalletInteractionContext,
                    resolvedRequest: ResolvedOid4vpRequest,
                ): Map<String, List<String>> = emptyMap()
            }
    }
}

fun DcqlQuery.toCredentialSelectionRequest(candidateCredentialIds: Map<String, List<String>>): WalletCredentialSelectionRequest {
    val requirements =
        credentials.map { credential ->
            WalletCredentialRequirement(
                id = credential.id,
                format = credential.format,
                multipleAllowed = credential.multiple,
                requiredClaimPaths = credential.claims.orEmpty().map { it.path.components },
                candidateCredentialIds = candidateCredentialIds[credential.id].orEmpty(),
                // candidateDisclosures stay empty: listing yields ids, not each candidate's claim tree.
            )
        }
    val credentialSets =
        credential_sets.orEmpty().mapIndexed { index, set ->
            WalletCredentialSetRequirement(
                id = "dcql_credential_set_$index",
                required = set.required,
                options =
                    set.options.map { option ->
                        WalletCredentialSetOption(
                            requirementIds = option,
                            satisfiable = option.all { id -> candidateCredentialIds[id].orEmpty().isNotEmpty() },
                        )
                    },
            )
        }
    val requiredSetsSatisfied =
        credentialSets
            .filter { it.required }
            .all { set -> set.options.any { option -> option.satisfiable } }
    return WalletCredentialSelectionRequest(
        requirements = requirements,
        satisfiable =
            if (credentialSets.isEmpty()) {
                requirements.all { it.candidateCredentialIds.isNotEmpty() }
            } else {
                requiredSetsSatisfied
            },
        credentialSets = credentialSets,
    )
}

private fun WalletInteractionContext.resolveInteractionPurpose(
    parsedRequest: AuthorizationRequest?,
    resolvedRequest: ResolvedOid4vpRequest?,
): Oid4vpInteractionPurpose =
    if (attributes.indicateLogin() || parsedRequest.indicatesLogin() || resolvedRequest?.request.indicatesLogin()) {
        Oid4vpInteractionPurpose.LOGIN
    } else {
        Oid4vpInteractionPurpose.PRESENTATION
    }

private enum class Oid4vpInteractionPurpose(
    val metadataValue: String,
) {
    PRESENTATION("presentation"),
    LOGIN("login"),
}

private fun Map<String, String>.indicateLogin(): Boolean =
    any { (key, value) ->
        key in loginPurposeMetadataKeys && value.indicatesLoginPurpose()
    }

private fun AuthorizationRequest?.indicatesLogin(): Boolean {
    if (this == null) return false
    if (prompt?.split(' ')?.any { it.equals("login", ignoreCase = true) } == true) return true
    return additionalParameters.any { (key, value) ->
        key in loginPurposeMetadataKeys && value.asString().indicatesLoginPurpose()
    }
}

private fun String?.indicatesLoginPurpose(): Boolean =
    when (this?.trim()?.lowercase()) {
        "login",
        "sign_in",
        "signin",
        "sign-in",
        "authentication",
        "auth",
        "credential_login",
        "credential-based-login",
        "credential_based_login",
        -> true

        else -> false
    }

private fun kotlinx.serialization.json.JsonElement.asString(): String? = (this as? JsonPrimitive)?.contentOrNull ?: runCatching { jsonPrimitive.contentOrNull }.getOrNull()

private fun String.containsQueryParameter(name: String): Boolean =
    split('?', '&')
        .asSequence()
        .map { it.substringBefore('=').trim() }
        .any { it.equals(name, ignoreCase = true) }

private fun AuthorizationRequest.hasPresentationExchangeParameters(): Boolean =
    additionalParameters.keys.any {
        it.equals("presentation_definition", ignoreCase = true) ||
            it.equals("presentation_definition_uri", ignoreCase = true)
    }

private val loginPurposeMetadataKeys =
    setOf(
        "purpose",
        "interaction_purpose",
        "wallet.interaction.purpose",
        "wallet_interaction_purpose",
        "presentation_purpose",
        "oid4vp.purpose",
        "activity_type",
        "activityType",
        "presentation_variant",
        "variant",
        "flow",
        "use_case",
        "context",
        "client_purpose",
    )

private fun fallbackVerifier(
    entryPoint: WalletEntryPoint,
    activityType: WalletInteractionActivityType,
    interactionContext: String,
): WalletCounterpartySummary =
    WalletCounterpartySummary(
        role = WalletCounterpartyRole.VERIFIER,
        identifier = entryPoint.raw?.substringAfter("client_id=", missingDelimiterValue = "unknown-verifier")?.substringBefore("&") ?: "unknown-verifier",
        metadata =
            mapOf(
                "interaction_context" to interactionContext,
                "activity_type" to activityType.name,
            ),
    )
