/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import com.sphereon.data.store.party.model.IdentifierType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.SelectedCredential
import com.sphereon.openid.oid4vp.holder.HolderJwtVpSigningIdentifier
import com.sphereon.openid.oid4vp.holder.credentialDisclosurePathOptions
import com.sphereon.wallet.credential.CredentialBindingRef
import com.sphereon.wallet.credential.CredentialFormat
import com.sphereon.wallet.credential.CredentialLifecycleState
import com.sphereon.wallet.credential.CredentialMetadata
import com.sphereon.wallet.credential.CredentialMetadataFilter
import com.sphereon.wallet.credential.CredentialRecord
import com.sphereon.wallet.credential.CredentialTypeRef
import com.sphereon.wallet.credential.CredentialTypeRefKind
import com.sphereon.wallet.credential.CredentialTypeRefSource
import com.sphereon.wallet.credential.CredentialValidityState
import com.sphereon.wallet.credential.IdentifierRef
import com.sphereon.wallet.credential.WalletCredentialStore
import com.sphereon.wallet.WalletHolderIdentityResolver
import com.sphereon.wallet.WalletHolderVerificationMethodResolver
import com.sphereon.wallet.interaction.WalletInteractionContext
import com.sphereon.wallet.interaction.WalletInteractionState
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlin.time.Clock

class WalletStoreOid4vpCredentialResolver(
    private val credentialStore: WalletCredentialStore,
    private val holderIdentityResolver: WalletHolderIdentityResolver = WalletHolderIdentityResolver.none,
    private val holderVerificationMethodResolver: WalletHolderVerificationMethodResolver? = null,
    private val credentialClaimValuesResolver: WalletCredentialClaimValuesResolver? = null,
) : Oid4vpCredentialCandidateResolver,
    Oid4vpSelectedCredentialResolver,
    Oid4vpPresentationSecurityContextResolver {
    override suspend fun candidateCredentialIds(
        context: WalletInteractionContext,
        resolvedRequest: ResolvedOid4vpRequest,
    ): Map<String, List<String>> =
        resolvedRequest.dcqlQuery
            ?.credentials
            .orEmpty()
            .associate { query ->
                query.id to candidateMetadata(context.walletUnitId, resolvedRequest, query).map { it.credentialRecordId }
            }

    override suspend fun resolveSelectedCredentials(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedRequest: ResolvedOid4vpRequest,
        selectedCredentialIdsByRequirement: Map<String, List<String>>,
    ): List<SelectedCredential> {
        val queries = resolvedRequest.dcqlQuery?.credentials.orEmpty()
        val selectedCredentials = mutableListOf<SelectedCredential>()
        val now = Clock.System.now()

        for (query in queries) {
            for (credentialRecordId in selectedCredentialIdsByRequirement[query.id].orEmpty().distinct()) {
                val record = credentialStore.requireCredential(context.walletUnitId, credentialRecordId)
                val instance =
                    record.presentableOid4vpInstance(now)
                        ?: error("Credential record '$credentialRecordId' has no presentable instance")
                val holderVerificationMethod =
                    if (
                        instance.format == CredentialFormat.JWT_VC_JSON ||
                        instance.format == CredentialFormat.JWT_VC_JSON_LD ||
                        instance.format == CredentialFormat.LDP_VC
                    ) {
                        val resolver = holderVerificationMethodResolver
                            ?: error("OID4VP VCDM selection requires an explicit holder signing-identifier association")
                        val holderKeyRef = instance.holderKeyRef
                            ?: error("VCDM credential '${instance.id}' holder key reference is missing")
                        val configuredMethod = resolver.resolve(context.walletUnitId, holderKeyRef)
                            ?: error("VCDM credential '${instance.id}' holder verification-method association is missing")
                        val storedMethod = holderKeyRef.kid
                            ?: error("VCDM credential '${instance.id}' did not persist its holder verification method")
                        if (configuredMethod.value != storedMethod) {
                            error("VCDM credential '${instance.id}' holder verification-method association changed after storage")
                        }
                        configuredMethod
                    } else {
                        null
                    }
                selectedCredentials +=
                    SelectedCredential(
                        credentialQueryId = query.id,
                        credentialId = instance.id,
                        presentation = instance.presentationElement(),
                        credentialFormat = instance.format,
                        holderKeyRef = instance.holderKeyRef?.alias,
                        holderId = selectedHolderId(context.walletUnitId, instance),
                        holderVerificationMethod = holderVerificationMethod?.value,
                        holderJwtVpSigningIdentifier = holderVerificationMethod?.toJwtVpSigningIdentifier(),
                        holderSigningAlgorithm = holderVerificationMethod?.signingAlgorithm,
                        dataIntegrityCryptosuite =
                            if (instance.format == CredentialFormat.LDP_VC) {
                                selectDataIntegrityCryptosuite(resolvedRequest, requireNotNull(holderVerificationMethod))
                            } else {
                                null
                            },
                    )
            }
        }

        return selectedCredentials
    }

    override suspend fun resolve(
        context: WalletInteractionContext,
        state: WalletInteractionState,
    ): Oid4vpPresentationSecurityContext =
        Oid4vpPresentationSecurityContext(
            keyRef = selectedHolderKeyAlias(context, state),
            walletUnitId = context.securityAttribute(Oid4vpPresentationSecurityAttributes.WALLET_UNIT_ID),
            walletAccountId = context.securityAttribute(Oid4vpPresentationSecurityAttributes.WALLET_ACCOUNT_ID),
            activationDecisionId = context.securityAttribute(Oid4vpPresentationSecurityAttributes.ACTIVATION_DECISION_ID),
            operationType = context.securityAttribute(Oid4vpPresentationSecurityAttributes.OPERATION_TYPE),
            operationBinding = context.securityAttribute(Oid4vpPresentationSecurityAttributes.OPERATION_BINDING),
            operationHash = context.securityAttribute(Oid4vpPresentationSecurityAttributes.OPERATION_HASH),
            nonce = context.securityAttribute(Oid4vpPresentationSecurityAttributes.NONCE),
        )

    override suspend fun recordPresentationSubmitted(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedRequest: ResolvedOid4vpRequest,
        selectedCredentialIdsByRequirement: Map<String, List<String>>,
        selectedCredentials: List<SelectedCredential>,
    ) {
        if (selectedCredentials.isEmpty() || selectedCredentialIdsByRequirement.isEmpty()) return

        val selectedInstanceIdsByRequirement =
            selectedCredentials
                .groupBy { it.credentialQueryId }
                .mapValues { (_, credentials) -> credentials.map { it.credentialId }.toSet() }
        val selectedRequirementIdsByRecordAndInstance = linkedMapOf<String, MutableMap<String, MutableSet<String>>>()
        for ((requirementId, credentialRecordIds) in selectedCredentialIdsByRequirement) {
            val selectedInstanceIds = selectedInstanceIdsByRequirement[requirementId].orEmpty()
            if (selectedInstanceIds.isEmpty()) continue
            for (credentialRecordId in credentialRecordIds.distinct()) {
                val requirementIdsByInstance = selectedRequirementIdsByRecordAndInstance.getOrPut(credentialRecordId) { linkedMapOf() }
                for (instanceId in selectedInstanceIds) {
                    requirementIdsByInstance.getOrPut(instanceId) { linkedSetOf() }.add(requirementId)
                }
            }
        }
        if (selectedRequirementIdsByRecordAndInstance.isEmpty()) return
        val verifierRef = resolvedRequest.verifierInfo.clientId.toVerifierRef()
        val boundAt = Clock.System.now()
        for ((credentialRecordId, requirementIdsByInstance) in selectedRequirementIdsByRecordAndInstance) {
            val updateResult =
                credentialStore.updateCredentialEnvelope(context.walletUnitId, credentialRecordId) { record ->
                    if (record.instances.none { it.id in requirementIdsByInstance }) return@updateCredentialEnvelope record
                    record.copy(
                        instances =
                            record.instances.map { instance ->
                                val presentationIds = requirementIdsByInstance[instance.id].orEmpty()
                                if (presentationIds.isEmpty()) {
                                    instance
                                } else {
                                    instance.copy(
                                        bindingRefs =
                                            instance.bindingRefs +
                                                presentationIds.map { presentationId ->
                                                    CredentialBindingRef(
                                                        verifierRef = verifierRef,
                                                        boundAt = boundAt,
                                                        presentationId = presentationId,
                                                    )
                                                },
                                        updatedAt = boundAt,
                                    )
                                }
                            },
                        updatedAt = boundAt,
                        syncState = record.syncState.copy(localRevision = record.syncState.localRevision + 1),
                    )
                }
            if (updateResult.isErr) error("Failed to update wallet presentation history: ${updateResult.error.code}")
            if (updateResult.value == null) error("Failed to update wallet presentation history: credential record is unavailable")
        }
    }

    private suspend fun candidateMetadata(
        walletUnitId: String,
        resolvedRequest: ResolvedOid4vpRequest,
        query: DcqlCredentialQuery,
    ): List<CredentialMetadata> {
        val requestedTypeRefs = query.credentialTypeRefs()
        val metadata =
            if (requestedTypeRefs.isNotEmpty()) {
                val collected = linkedMapOf<String, CredentialMetadata>()
                for (ref in requestedTypeRefs) {
                    val result = credentialStore.findByCredentialTypeRef(walletUnitId, ref)
                    if (result.isErr) error("Failed to query wallet credential metadata: ${result.error.code}")
                    for (candidate in result.value) {
                        collected[candidate.credentialRecordId] = candidate
                    }
                }
                collected.values.toList()
            } else {
                val format = CredentialFormat.fromValueLenient(query.format)
                val result =
                    credentialStore.listMetadata(
                        walletUnitId = walletUnitId,
                        filter =
                            CredentialMetadataFilter(
                                formats = format?.let { setOf(it) }.orEmpty(),
                                lifecycleStates = setOf(CredentialLifecycleState.ACTIVE),
                            ),
                    )
                if (result.isErr) error("Failed to query wallet credential metadata: ${result.error.code}")
                result.value
            }

        val now = Clock.System.now()
        val candidates = mutableListOf<CredentialMetadata>()
        for (candidate in metadata) {
            if (!candidate.isPresentationCandidate()) continue
            val record = if (candidate.format.isMdoc || query.claims != null) {
                credentialStore.requireCredential(walletUnitId, candidate.credentialRecordId)
            } else {
                null
            }
            val presentableInstance = record?.presentableOid4vpInstance(now)
            if (candidate.format.isMdoc) {
                if (presentableInstance == null) continue
            }
            if (query.claims != null) {
                val claimResolver = credentialClaimValuesResolver ?: continue
                val recordValue = requireNotNull(record)
                val instance = presentableInstance ?: recordValue.presentableOid4vpInstance(now) ?: continue
                val matchesOption =
                    resolvedRequest.credentialDisclosurePathOptionsOrEmpty(query.id).any { option ->
                        option.all { path -> claimResolver.containsDisclosurePath(recordValue, instance.id, path) }
                    }
                if (!matchesOption) continue
            }
            candidates += candidate
        }
        return candidates
    }

    private suspend fun WalletCredentialStore.requireCredential(
        walletUnitId: String,
        credentialRecordId: String,
    ): CredentialRecord {
        val result = getCredential(walletUnitId, credentialRecordId)
        if (result.isErr) error("Failed to open wallet credential '$credentialRecordId': ${result.error.code}")
        return result.value ?: error("Wallet credential '$credentialRecordId' was not found")
    }

    private suspend fun selectedHolderKeyAlias(
        context: WalletInteractionContext,
        state: WalletInteractionState,
    ): String? {
        val now = Clock.System.now()
        val selectedCredentialIds =
            state.disclosure
                ?.selectedCredentialIds
                .orEmpty()
                .distinct()
        for (credentialRecordId in selectedCredentialIds) {
            val record = credentialStore.requireCredential(context.walletUnitId, credentialRecordId)
            val alias =
                record
                    .presentableOid4vpInstance(now)
                    ?.holderKeyRef
                    ?.alias
            if (!alias.isNullOrBlank()) return alias
        }
        return null
    }

    private suspend fun selectedHolderId(
        walletUnitId: String,
        instance: com.sphereon.wallet.credential.CredentialInstance,
    ): String? {
        val format = instance.format
        if (format != CredentialFormat.JWT_VC_JSON && format != CredentialFormat.JWT_VC_JSON_LD && format != CredentialFormat.LDP_VC) return null
        val holderKeyRef = instance.holderKeyRef ?: error("VCDM credential '${instance.id}' holder key reference is missing")
        return holderIdentityResolver.resolve(walletUnitId, holderKeyRef)
            ?.takeIf { it.isNotBlank() }
            ?: error("VCDM credential '${instance.id}' holder identifier is missing")
    }
}

/**
 * Candidate matching uses the same ordered DCQL claim options as holder response creation. The
 * existing format-specific claim resolver provides namespace/element paths for mdoc and flattened
 * paths for SD-JWT; claim values are compared only in memory and are never placed in interaction
 * state or candidate projections.
 */
private fun ResolvedOid4vpRequest.credentialDisclosurePathOptionsOrEmpty(credentialQueryId: String): List<List<List<JsonElement>>> =
    runCatching { credentialDisclosurePathOptions(credentialQueryId) }.getOrNull().orEmpty()

internal fun Map<String, JsonElement>.containsDisclosurePath(
    path: List<JsonElement>,
): Boolean {
    val first = path.firstOrNull() as? JsonPrimitive ?: return false
    if (!first.isString) return false
    val firstValue = this[first.content] ?: return false
    return firstValue.containsDisclosurePath(path.drop(1))
}

private fun JsonElement.containsDisclosurePath(path: List<JsonElement>): Boolean {
    var selected = listOf(this)
    for (component in path) {
        val next = mutableListOf<JsonElement>()
        for (value in selected) {
            when {
                component == JsonNull -> {
                    val array = value as? JsonArray ?: return false
                    next.addAll(array)
                }
                component is JsonPrimitive && component.isString -> {
                    val objectValue = value as? JsonObject ?: return false
                    objectValue[component.content]?.let(next::add)
                }
                component is JsonPrimitive -> {
                    val index = component.intOrNull?.takeIf { it >= 0 } ?: return false
                    val array = value as? JsonArray ?: return false
                    array.getOrNull(index)?.let(next::add)
                }
                else -> return false
            }
        }
        selected = next
        if (selected.isEmpty()) return false
    }
    return selected.isNotEmpty()
}

private fun selectDataIntegrityCryptosuite(
    resolvedRequest: ResolvedOid4vpRequest,
    holderMethod: com.sphereon.wallet.credential.WalletHolderVerificationMethod,
): String {
    val compatible =
        when (holderMethod.signingAlgorithm) {
            SignatureAlgorithm.ED25519 -> listOf("eddsa-rdfc-2022", "eddsa-jcs-2022")
            SignatureAlgorithm.ECDSA_SHA256,
            SignatureAlgorithm.ECDSA_SHA384,
            -> listOf("ecdsa-rdfc-2019")
            else -> error("OID4VP Data Integrity does not support holder key algorithm ${holderMethod.signingAlgorithm}")
        }
    val verifierAllowlist =
        resolvedRequest.clientMetadata
            ?.vpFormatsSupported
            ?.get(CredentialFormat.LDP_VC.value)
            ?.cryptosuiteValues
    return compatible.firstOrNull { verifierAllowlist == null || it in verifierAllowlist }
        ?: error("OID4VP verifier and holder key have no mutually supported Data Integrity cryptosuite")
}

private fun com.sphereon.wallet.credential.WalletHolderVerificationMethod.toJwtVpSigningIdentifier(): HolderJwtVpSigningIdentifier =
    when (kind) {
        com.sphereon.wallet.credential.WalletHolderIdentifierKind.DID_VERIFICATION_METHOD ->
            HolderJwtVpSigningIdentifier.DidVerificationMethod(value)
        com.sphereon.wallet.credential.WalletHolderIdentifierKind.JWKS_KID ->
            HolderJwtVpSigningIdentifier.JwksKid(value)
        com.sphereon.wallet.credential.WalletHolderIdentifierKind.MANAGED_KID ->
            HolderJwtVpSigningIdentifier.ManagedKid(value)
        com.sphereon.wallet.credential.WalletHolderIdentifierKind.X509 ->
            HolderJwtVpSigningIdentifier.X509(value, certificateChain)
    }

private fun com.sphereon.wallet.credential.CredentialInstance.presentationElement(): JsonElement {
    val raw = requireRaw()
    if (format != CredentialFormat.LDP_VC) return JsonPrimitive(raw)
    val parsed = try {
        Json.parseToJsonElement(raw)
    } catch (expected: Exception) {
        error("Data Integrity credential '$id' is not valid JSON: ${expected.message}")
    }
    require(parsed is JsonObject) { "Data Integrity credential '$id' must be a JSON object" }
    return parsed
}

private fun WalletInteractionContext.securityAttribute(key: String): String? = attributes[key]?.takeIf { it.isNotBlank() }

internal fun DcqlCredentialQuery.credentialTypeRefs(): Set<CredentialTypeRef> {
    val format = CredentialFormat.fromValueLenient(format)

    return buildSet {
        val sdJwtFormat = format?.takeIf { it.isSdJwt } ?: CredentialFormat.SD_JWT_VC
        val vctValues = meta["vct_values"]
        if (vctValues is JsonArray) {
            for (entry in vctValues) {
                if (entry is JsonPrimitive && entry.isString) {
                    add(
                        CredentialTypeRef(
                            format = sdJwtFormat,
                            kind = CredentialTypeRefKind.SD_JWT_VCT,
                            value = entry.content,
                            source = CredentialTypeRefSource.IMPORT_METADATA,
                            primary = true,
                        ),
                    )
                }
            }
        }

        val doctypeValue = meta["doctype_value"]
        if (doctypeValue is JsonPrimitive && doctypeValue.isString) {
            add(
                CredentialTypeRef(
                    format = CredentialFormat.MSO_MDOC,
                    kind = CredentialTypeRefKind.MDOC_DOCTYPE,
                    value = doctypeValue.content,
                    source = CredentialTypeRefSource.IMPORT_METADATA,
                    primary = true,
                ),
            )
        }

        val w3cFormat = format?.takeUnless { it.isSdJwt || it.isMdoc } ?: CredentialFormat.JWT_VC_JSON
        addAll(
            credentialW3cTypeRefs(
                format = w3cFormat,
                types = jsonStringList(meta["type_values"]) + jsonStringList(meta["types"]),
            ),
        )
    }
}

private fun CredentialMetadata.isPresentationCandidate(): Boolean =
    activeInstanceCount > 0 &&
        lifecycleSummary.lifecycleState == CredentialLifecycleState.ACTIVE &&
        lifecycleSummary.validityState != CredentialValidityState.NOT_YET_VALID &&
        lifecycleSummary.validityState != CredentialValidityState.EXPIRED

private fun credentialW3cTypeRefs(
    format: CredentialFormat,
    types: List<String>,
): Set<CredentialTypeRef> {
    val cleanTypes = types.map { it.trim() }.filter { it.isNotBlank() }.distinct()
    val primaryType = cleanTypes.firstOrNull { it != "VerifiableCredential" } ?: cleanTypes.firstOrNull()
    return cleanTypes
        .map {
            CredentialTypeRef(
                format = format,
                kind = CredentialTypeRefKind.W3C_VC_TYPE,
                value = it,
                source = CredentialTypeRefSource.IMPORT_METADATA,
                primary = it == primaryType,
            )
        }.toSet()
}

private fun jsonStringList(element: JsonElement?): List<String> =
    when (element) {
        is JsonArray -> element.mapNotNull { (it as? JsonPrimitive)?.contentOrNull }
        is JsonPrimitive -> element.contentOrNull?.let(::listOf).orEmpty()
        else -> emptyList()
    }

private fun String.toVerifierRef(): IdentifierRef {
    val verifierType = if (startsWith("did:")) IdentifierType.DID else IdentifierType("https")
    return IdentifierRef(type = verifierType, value = this)
}
