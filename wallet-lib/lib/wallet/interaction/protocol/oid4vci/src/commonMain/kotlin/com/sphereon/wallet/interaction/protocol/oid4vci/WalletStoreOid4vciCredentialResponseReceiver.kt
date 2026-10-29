/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vci

import com.sphereon.core.compat.Uuid
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.data.store.party.model.IdentifierType
import com.sphereon.openid.oid4vci.common.model.CredentialConfigurationSupported
import com.sphereon.openid.oid4vci.common.model.CredentialResponse
import com.sphereon.openid.oid4vci.holder.ResolvedCredentialOffer
import com.sphereon.wallet.credential.BodyStorageKind
import com.sphereon.wallet.credential.BodyStorageRef
import com.sphereon.wallet.credential.CredentialClaimDisplay
import com.sphereon.wallet.credential.CredentialClaimMetadata
import com.sphereon.wallet.credential.CredentialDisplayMetadata
import com.sphereon.wallet.credential.CredentialDisplayProperties
import com.sphereon.wallet.credential.CredentialFormat
import com.sphereon.wallet.credential.CredentialImageProperties
import com.sphereon.wallet.credential.CredentialInstance
import com.sphereon.wallet.credential.CredentialLifecycleState
import com.sphereon.wallet.credential.CredentialLogoProperties
import com.sphereon.wallet.credential.CredentialMetadataFilter
import com.sphereon.wallet.credential.CredentialRecord
import com.sphereon.wallet.credential.CredentialRefreshMethod
import com.sphereon.wallet.credential.CredentialTypeRef
import com.sphereon.wallet.credential.CredentialTypeRefKind
import com.sphereon.wallet.credential.CredentialTypeRefSource
import com.sphereon.wallet.credential.CredentialValidityWindow
import com.sphereon.wallet.credential.IdentifierRef
import com.sphereon.wallet.credential.IssuanceProvenance
import com.sphereon.wallet.credential.KeyRef
import com.sphereon.wallet.credential.RefreshPolicy
import com.sphereon.wallet.credential.RefreshState
import com.sphereon.wallet.credential.WalletCredentialStore
import com.sphereon.wallet.credential.WalletIssuanceSessionStore
import com.sphereon.wallet.WalletHolderVerificationMethodResolver
import com.sphereon.wallet.interaction.WalletCounterpartyRole
import com.sphereon.wallet.interaction.WalletCounterpartySummary
import com.sphereon.wallet.interaction.selfAssertedDisplayNameSource
import com.sphereon.wallet.interaction.WalletCredentialPreview
import com.sphereon.wallet.interaction.WalletCredentialBranding
import com.sphereon.wallet.interaction.WalletInteractionContext
import com.sphereon.wallet.interaction.WalletInteractionFailureCodes
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.admitForIssuer
import com.sphereon.wallet.interaction.WalletProtocol
import com.sphereon.wallet.interaction.WalletIssuerAuthenticationRequest
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.time.Clock
import com.sphereon.openid.oid4vc.common.DisplayProperties as Oid4vcDisplayProperties
import com.sphereon.openid.oid4vc.common.ImageProperties as Oid4vcImageProperties
import com.sphereon.openid.oid4vc.common.LogoProperties as Oid4vcLogoProperties
import com.sphereon.openid.oid4vci.common.model.ClaimDisplay as Oid4vciClaimDisplay
import com.sphereon.openid.oid4vci.common.model.CredentialClaim as Oid4vciCredentialClaim

private val walletOid4vciJson = Json { encodeDefaults = false; explicitNulls = false }

class WalletStoreOid4vciCredentialResponseReceiver(
    private val credentialStore: WalletCredentialStore,
    private val issuanceSessionStore: WalletIssuanceSessionStore,
    private val acceptance: Oid4vciIssuedCredentialAcceptance,
    private val holderVerificationMethodResolver: WalletHolderVerificationMethodResolver? = null,
) : Oid4vciCredentialResponseReceiver {
    override suspend fun receiveCredentialResponse(
        context: WalletInteractionContext,
        state: WalletInteractionState,
        resolvedOffer: ResolvedCredentialOffer,
        credentialResponse: CredentialResponse,
    ): List<WalletCredentialPreview> {
        var stage = "credential-response-validation"
        var reason = "operation_failed"
        var providerError: IdkErrorType? = null
        try {
            val sessionState = context.oid4vciState()
            val credentialConfigurationId =
                sessionState.credentialConfigurationId?.takeIf { it.isNotBlank() }
                    ?: state.credentialOffer?.credentialConfigurationIds?.firstOrNull()
                    ?: resolvedOffer.offer.credentialConfigurationIds.firstOrNull()
                    ?: error("OID4VCI credential response cannot be stored without a credential configuration id")
            val credentialConfiguration =
                resolvedOffer.issuerMetadata.credentialConfigurationsSupported[credentialConfigurationId]
                    ?: error("OID4VCI issuer metadata does not contain credential configuration '$credentialConfigurationId'")
            val credentialFormat =
                CredentialFormat.fromValueLenient(credentialConfiguration.format)
                    ?: error("Unsupported OID4VCI credential format '${credentialConfiguration.format}'")
            val responseItems =
                credentialResponse.credentials
                    ?.takeIf { it.isNotEmpty() }
                    ?: error("OID4VCI credential response contained no credentials")
            val holderKeyAliases =
                sessionState.holderKeyAliases
                    .takeIf { it.isNotEmpty() }
                    ?: error("OID4VCI credential response cannot be stored without holder key aliases")
            if (holderKeyAliases.size != responseItems.size) {
                error("OID4VCI credential response item count ${responseItems.size} does not match holder key count ${holderKeyAliases.size}")
            }
            stage = "holder-verification-method"
            val holderVerificationMethods =
                if (
                    credentialFormat == CredentialFormat.JWT_VC_JSON ||
                    credentialFormat == CredentialFormat.JWT_VC_JSON_LD ||
                    credentialFormat == CredentialFormat.LDP_VC
                ) {
                    val resolver = holderVerificationMethodResolver
                        ?: run {
                            reason = "holder_resolver_missing"
                            error("OID4VCI VCDM storage requires an explicit holder signing-identifier association")
                        }
                    holderKeyAliases.map { alias ->
                        resolver.resolve(context.walletUnitId, KeyRef(alias = alias))
                            ?: run {
                                reason = "holder_association_missing"
                                error("OID4VCI VCDM storage has no holder signing-identifier association for key '$alias'")
                            }
                    }
                } else {
                    emptyList()
                }
            stage = "credential-type-metadata"
            val issuerRef = resolvedOffer.offer.credentialIssuer.toIssuerRef()
            val typeRefs = credentialConfiguration.typeRefs(credentialFormat, credentialConfigurationId)
            require(typeRefs.isNotEmpty()) {
                "OID4VCI credential configuration '$credentialConfigurationId' produced no wallet credential type references"
            }

            // REFRESH TARGET: a wallet-initiated refresh names the EXACT existing
            // record by id - it must not be re-derived through the issuer+credential-configuration
            // heuristic below, which assumes at most one record per (issuer, credentialConfigurationId)
            // and would silently mis-target a wallet holding more than one.
            val refreshTargetCredentialRecordId = sessionState.refreshTargetCredentialRecordId?.takeIf { it.isNotBlank() }
            stage = "existing-credential-read"
            val existingRecord =
                if (refreshTargetCredentialRecordId != null) {
                    val getResult = credentialStore.getCredentialEnvelope(context.walletUnitId, refreshTargetCredentialRecordId)
                    if (getResult.isErr) {
                        providerError = getResult.error
                        error("Failed to load OID4VCI refresh target credential record '$refreshTargetCredentialRecordId': ${getResult.error.message.defaultMessage}")
                    }
                    getResult.value
                        ?: error("OID4VCI refresh target credential record '$refreshTargetCredentialRecordId' was not found")
                } else {
                    existingRecord(context.walletUnitId, issuerRef, credentialConfigurationId)
                }
            stage = "refresh-target-validation"
            val refreshTargetCredentialInstanceIds =
                if (refreshTargetCredentialRecordId != null) {
                    val target = existingRecord ?: error("OID4VCI refresh target credential record '$refreshTargetCredentialRecordId' was not found")
                    val requested = sessionState.refreshTargetCredentialInstanceIds
                    val selected =
                        if (requested.isNotEmpty()) requested
                        else target.instances.filter { it.lifecycleState == CredentialLifecycleState.ACTIVE }.map { it.id }
                    require(selected.isNotEmpty()) { "OID4VCI refresh target credential record has no active credential instances" }
                    require(selected.distinct().size == selected.size) { "OID4VCI refresh target credential instances must be distinct" }
                    require(selected.all { id -> target.instances.any { it.id == id && it.lifecycleState == CredentialLifecycleState.ACTIVE } }) {
                        "OID4VCI refresh target credential instances must identify active instances in the target record"
                    }
                    require(
                        selected.zip(holderKeyAliases).all { (id, alias) ->
                            target.instances.single { it.id == id }.holderKeyRef?.alias == alias
                        },
                    ) {
                        "OID4VCI refresh target instance and holder-key alias mappings must match exactly"
                    }
                    selected
                } else {
                    emptyList()
                }
            val now = Clock.System.now()
            val credentialRecordId = existingRecord?.id ?: Uuid.v4String()
            val refreshToken = sessionState.tokens?.refreshToken?.takeIf { it.isNotBlank() }
            stage = "credential-body-validation"
            val newInstances =
                responseItems.mapIndexed { index, item ->
                    val raw =
                        if (credentialFormat == CredentialFormat.LDP_VC) {
                            (item.credential as? JsonObject)?.let {
                                walletOid4vciJson.encodeToString(JsonElement.serializer(), it)
                            } ?: error("OID4VCI ldp_vc credential response item must be a JSON object")
                        } else {
                            (item.credential as? JsonPrimitive)?.content
                                ?: error("OID4VCI credential response item is not a primitive credential string")
                        }
                    val credentialInstanceId = Uuid.v4String()
                    CredentialInstance(
                        id = credentialInstanceId,
                        walletUnitId = context.walletUnitId,
                        credentialRecordId = credentialRecordId,
                        format = credentialFormat,
                        raw = raw,
                        bodyStorageRef =
                            BodyStorageRef(
                                kind = BodyStorageKind.WALLET_STORE,
                                path = credentialBodyPath(context.walletUnitId, credentialRecordId, credentialInstanceId),
                            ),
                        holderKeyRef =
                            KeyRef(
                                alias = holderKeyAliases[index],
                                kid = holderVerificationMethods.getOrNull(index)?.value,
                            ),
                        lifecycleState = CredentialLifecycleState.ACTIVE,
                        validity =
                            if (credentialFormat.isMdoc) {
                                acceptance.mdocValidityWindow(raw)
                                    ?: error("OID4VCI mso_mdoc credential has no decodable MSO validity window")
                            } else {
                                CredentialValidityWindow()
                            },
                        issuedAt = now,
                        storedAt = now,
                        updatedAt = now,
                    )
                }

            // VERIFY: for SD-JWT VC formats, verify the issuer signature of every newly issued
            // instance before storing anything; a failed verification rejects the whole store
            // operation.
            stage = "credential-signature-verification"
            // OID4VCI 1.0 §14.4: the Credential Issuer Identifier is the HTTPS URL, but a VCDM
            // credential signed with a DID key names that DID as its issuer. Its keys are then
            // resolved for that DID through the deployment's issuer-authentication resolver, which
            // establishes the DID's admission; the verified issuer must still equal it.
            val claimedDidIssuer =
                acceptance.claimedJwtVcIssuer(credentialFormat, newInstances)
                    ?.takeIf { it != resolvedOffer.offer.credentialIssuer && it.startsWith("did:") }
            val issuerAuthentication =
                if (claimedDidIssuer == null) {
                    state.issuerAuthentication
                } else {
                    context.issuerAuthenticationResolver
                        .resolve(
                            WalletIssuerAuthenticationRequest(
                                counterparty = WalletCounterpartySummary(role = WalletCounterpartyRole.ISSUER, identifier = claimedDidIssuer),
                                protocol = WalletProtocol.OID4VCI,
                            ),
                        )?.admitForIssuer(claimedDidIssuer)
                }
            val verifyResult =
                acceptance.verify(
                    credentialConfigurationId = credentialConfigurationId,
                    credentialFormat = credentialFormat,
                    instances = newInstances,
                    issuerAuthentication = issuerAuthentication,
                    expectedIssuer = claimedDidIssuer ?: resolvedOffer.offer.credentialIssuer,
                )
            if (verifyResult.isErr) {
                providerError = verifyResult.error
                error(verifyResult.error.message.defaultMessage)
            }

            // RECONCILE: derive ACTUAL type refs from each issued payload; expected (issuer-metadata)
            // refs above stay canonical on the provenance record, and a mismatch is recorded as a
            // diagnostic rather than silently dropped. Issued credentials with no derivable payload
            // type refs are rejected.
            stage = "credential-type-reconciliation"
            val actualTypeRefsResult = acceptance.actualTypeRefs(credentialConfigurationId, credentialFormat, newInstances)
            if (actualTypeRefsResult.isErr) {
                providerError = actualTypeRefsResult.error
                error(actualTypeRefsResult.error.message.defaultMessage)
            }
            val actualTypeRefs = actualTypeRefsResult.value
            val diagnostics = acceptance.diagnostics(expected = typeRefs, actual = actualTypeRefs, observedAt = now)
            // Persist a rotated refresh token only after every response item has been validated. A
            // short/invalid batch must leave both the credential record and its token unchanged.
            stage = "refresh-token-store"
            val rotatedRefreshTokenRef =
                refreshToken?.let { token ->
                    val storedToken = issuanceSessionStore.storeRefreshToken(context.walletUnitId, credentialRecordId, token)
                    if (storedToken.isErr) {
                        providerError = storedToken.error
                        error("Failed to persist OID4VCI refresh token: ${storedToken.error.message.defaultMessage}")
                    }
                    storedToken.value
                }
            val refreshState: RefreshState? =
                rotatedRefreshTokenRef?.let { ref ->
                    RefreshState(refreshMethod = CredentialRefreshMethod.OID4VCI_REISSUANCE, refreshTokenRef = ref, policy = RefreshPolicy())
                }

            stage = "credential-record-assembly"
            val updatedRecord =
                if (refreshTargetCredentialRecordId != null) {
                    // SUPERSEDE: refresh/reissuance replaces only the selected holder instances rather
                    // than topping them up. Untargeted active siblings remain active and every new item
                    // carries the exact instance id it replaces.
                    // Unlike the append/new-record branches below, issuanceProvenance is left untouched
                    // on refresh; only refreshState (rotated token ref, lastRefreshAt, refresh-scoped
                    // diagnostics) and instances change.
                    val target =
                        existingRecord
                            ?: error("OID4VCI refresh target credential record '$refreshTargetCredentialRecordId' was not found")
                    val preservedRefreshState =
                        if (rotatedRefreshTokenRef != null) {
                            (target.refreshState ?: refreshState)?.copy(refreshTokenRef = rotatedRefreshTokenRef)
                        } else {
                            target.refreshState
                        }
                    require(refreshTargetCredentialInstanceIds.size == newInstances.size) {
                        "OID4VCI refresh response item count must match the selected target instance count"
                    }
                    val refreshedBase =
                        target.copy(refreshState = preservedRefreshState).withRefreshedInstance(
                            newInstances.first().copy(replacesInstanceId = refreshTargetCredentialInstanceIds.first()),
                            actualTypeRefs,
                        )
                    val selectedIds = refreshTargetCredentialInstanceIds.toSet()
                    val replacedExistingInstances =
                        target.instances.map { instance ->
                            if (instance.id in selectedIds && instance.lifecycleState == CredentialLifecycleState.ACTIVE && target.refreshState?.policy?.supersedePreviousActiveInstance != false) {
                                instance.copy(lifecycleState = CredentialLifecycleState.SUPERSEDED, updatedAt = now)
                            } else {
                                instance
                            }
                        }
                    refreshedBase.copy(
                        instances =
                            replacedExistingInstances +
                                newInstances.mapIndexed { index, instance ->
                                    instance.copy(replacesInstanceId = refreshTargetCredentialInstanceIds[index])
                                },
                    )
                } else if (existingRecord != null) {
                    val existingProvenance = existingRecord.issuanceProvenance
                    newInstances.fold(
                        existingRecord.copy(
                            credentialTypeRefs = existingRecord.credentialTypeRefs + actualTypeRefs,
                            refreshState = refreshState ?: existingRecord.refreshState,
                            issuanceProvenance = existingProvenance?.copy(diagnostics = existingProvenance.diagnostics + diagnostics),
                        ),
                    ) { record, instance ->
                        record.withAddedInstance(instance)
                    }
                } else {
                    // SUBJECTS: populate credential subjects from the first issued instance once, when
                    // the record is newly created; existing records are not re-populated on append.
                    stage = "credential-subject-resolution"
                    val subjectsResult = acceptance.resolveSubjects(credentialFormat, newInstances.first().requireRaw())
                    if (subjectsResult.isErr) {
                        providerError = subjectsResult.error
                        error(subjectsResult.error.message.defaultMessage)
                    }
                    CredentialRecord(
                        id = credentialRecordId,
                        walletUnitId = context.walletUnitId,
                        issuerRef = issuerRef,
                        subjectRefs = subjectsResult.value,
                        format = credentialFormat,
                        credentialTypeRefs = actualTypeRefs,
                        display =
                            CredentialDisplayMetadata(
                                issuerDisplay = resolvedOffer.issuerMetadata.display.toWalletDisplayProperties(),
                                credentialDisplay = credentialConfiguration.resolvedCredentialDisplay().toWalletDisplayProperties(),
                                claims = credentialConfiguration.resolvedWalletClaimMetadata(),
                            ),
                        instances = newInstances,
                        refreshState = refreshState,
                        issuanceProvenance =
                            IssuanceProvenance(
                                issuanceSessionId = context.sessionId.value,
                                credentialIssuerUrl = resolvedOffer.offer.credentialIssuer,
                                credentialConfigurationId = credentialConfigurationId,
                                expectedCredentialTypeRefs = typeRefs,
                                diagnostics = diagnostics,
                                issuedAt = now,
                                notificationId = credentialResponse.notificationId,
                            ),
                        createdAt = now,
                        updatedAt = now,
                    )
                }
            stage = "credential-store"
            val stored = credentialStore.putCredential(context.walletUnitId, updatedRecord)
            if (stored.isErr) {
                providerError = stored.error
                val cause = stored.error.exception
                throw IllegalStateException(
                    "Failed to store OID4VCI credential response: ${stored.error.message.defaultMessage}" +
                        cause?.let { " (${it::class.simpleName}: ${it.message})" }.orEmpty(),
                    cause,
                )
            }

            stage = "credential-preview"
            return listOf(
                WalletCredentialPreview(
                    id = stored.value.id,
                    name = stored.value.displayName() ?: credentialConfigurationId,
                    format = credentialFormat.value,
                    issuer = stored.value.toStoredIssuerSummary(),
                    branding = stored.value.toResolvedBranding(credentialConfigurationId),
                ),
            )
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            context.diagnostics.warn(
                event = "oid4vci.credential_receive.failed",
                sessionId = context.sessionId,
                details = buildMap {
                    put("code", WalletInteractionFailureCodes.OID4VCI_CREDENTIAL_RECEIVER_FAILED)
                    put("stage", stage)
                    put("reason", (providerError as? IssuedCredentialVerificationError)?.reason?.diagnosticCode ?: reason)
                    put("causeType", failure::class.simpleName ?: "Exception")
                    // Closed throw site (class.method only, never the message) for failures that carry no provider error.
                    failureSite(failure)?.let { put("failureSite", it) }
                    var cause = failure.cause
                    var depth = 1
                    while (cause != null && depth <= 4) {
                        put("cause${depth}Type", cause::class.simpleName ?: "Exception")
                        cause = cause.cause?.takeIf { it !== cause }
                        depth++
                    }
                    var provider = providerError
                    var providerDepth = 0
                    while (provider != null && providerDepth <= 4) {
                        val prefix = if (providerDepth == 0) "providerError" else "providerCause$providerDepth"
                        put("${prefix}Code", provider.code)
                        provider.exception?.let { put("${prefix}Type", it::class.simpleName ?: "Exception") }
                        provider = provider.causes.firstOrNull()
                        providerDepth++
                    }
                },
            )
            throw failure
        }
    }

    private suspend fun existingRecord(
        walletUnitId: String,
        issuerRef: IdentifierRef,
        credentialConfigurationId: String,
    ): CredentialRecord? {
        val matchingMetadata =
            credentialStore.listMetadata(
                walletUnitId = walletUnitId,
                filter =
                    CredentialMetadataFilter(
                        issuerRef = issuerRef,
                        credentialConfigurationId = credentialConfigurationId,
                    ),
            )
        if (matchingMetadata.isErr) {
            error("Failed to query existing OID4VCI wallet credentials: ${matchingMetadata.error.message.defaultMessage}")
        }
        val existingId = matchingMetadata.value.firstOrNull()?.credentialRecordId ?: return null
        val existing = credentialStore.getCredentialEnvelope(walletUnitId, existingId)
        if (existing.isErr) {
            error("Failed to load existing OID4VCI wallet credential '$existingId': ${existing.error.message.defaultMessage}")
        }
        return existing.value
    }

    private fun String.toIssuerRef(): IdentifierRef =
        IdentifierRef(
            type = if (startsWith("did:")) IdentifierType.DID else IdentifierType("https"),
            value = this,
        )

    private fun CredentialConfigurationSupported.typeRefs(
        format: CredentialFormat,
        credentialConfigurationId: String,
    ): Set<CredentialTypeRef> =
        buildSet {
            when {
                format.isSdJwt -> {
                    vct?.takeIf { it.isNotBlank() }?.let {
                        add(
                            CredentialTypeRef(
                                format = format,
                                kind = CredentialTypeRefKind.SD_JWT_VCT,
                                value = it,
                                source = CredentialTypeRefSource.ISSUER_METADATA,
                                primary = true,
                            ),
                        )
                    }
                }

                format.isMdoc -> {
                    doctype?.takeIf { it.isNotBlank() }?.let {
                        add(
                            CredentialTypeRef(
                                format = format,
                                kind = CredentialTypeRefKind.MDOC_DOCTYPE,
                                value = it,
                                source = CredentialTypeRefSource.ISSUER_METADATA,
                                primary = true,
                            ),
                        )
                    }
                }

                else -> {
                    addAll(w3cTypeRefs(format, credentialDefinition?.type.orEmpty()))
                }
            }
            if (isEmpty()) {
                add(
                    CredentialTypeRef(
                        format = format,
                        kind = CredentialTypeRefKind.W3C_VC_TYPE,
                        value = credentialConfigurationId,
                        source = CredentialTypeRefSource.ISSUER_METADATA,
                        primary = true,
                    ),
                )
            }
        }

    private fun w3cTypeRefs(
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
                    source = CredentialTypeRefSource.ISSUER_METADATA,
                    primary = it == primaryType,
                )
            }.toSet()
    }

    private fun List<Oid4vcDisplayProperties>?.toWalletDisplayProperties(): List<CredentialDisplayProperties> =
        orEmpty().map {
            CredentialDisplayProperties(
                name = it.name,
                locale = it.locale,
                logo = it.logo.toWalletLogoProperties(),
                description = it.description,
                backgroundColor = it.backgroundColor,
                backgroundImage = it.backgroundImage.toWalletImageProperties(),
                textColor = it.textColor,
            )
        }

    private fun CredentialConfigurationSupported.resolvedCredentialDisplay(): List<Oid4vcDisplayProperties>? =
        credentialMetadata?.display?.takeIf { it.isNotEmpty() } ?: display

    private fun CredentialConfigurationSupported.resolvedWalletClaimMetadata(): List<CredentialClaimMetadata> =
        credentialMetadata
            ?.claims
            ?.takeIf { it.isNotEmpty() }
            ?.map { claim ->
                CredentialClaimMetadata(
                    path =
                        claim.path.map { element ->
                            (element as? JsonPrimitive)?.content
                                ?: error("OID4VCI credential metadata claim paths must contain only string or integer elements")
                        },
                    mandatory = claim.mandatory,
                    valueType = null,
                    display = claim.display.toWalletClaimDisplay(),
                )
            }
            ?: claims.toWalletClaimMetadata()

    private fun CredentialRecord.toResolvedBranding(credentialConfigurationId: String): WalletCredentialBranding? {
        val resolved = display.credentialDisplay.firstOrNull() ?: return null
        return WalletCredentialBranding(
            credentialConfigurationId = credentialConfigurationId,
            name = resolved.name,
            locale = resolved.locale,
            description = resolved.description,
            logoUri = resolved.logo?.uri,
            backgroundImageUri = resolved.backgroundImage?.uri,
            backgroundColor = resolved.backgroundColor,
            textColor = resolved.textColor,
        )
    }

    private fun CredentialRecord.toStoredIssuerSummary(): WalletCounterpartySummary {
        val resolved = display.issuerDisplay.firstOrNull()
        return WalletCounterpartySummary(
            role = WalletCounterpartyRole.ISSUER,
            identifier = issuerRef.value,
            displayName = resolved?.name ?: issuerRef.value,
            displayNameSource = selfAssertedDisplayNameSource(resolved?.name),
            logoUri = resolved?.logo?.uri,
        )
    }

    private fun Oid4vcLogoProperties?.toWalletLogoProperties(): CredentialLogoProperties? =
        this?.let {
            CredentialLogoProperties(
                uri = it.uri,
                altText = it.altText,
            )
        }

    private fun Oid4vcImageProperties?.toWalletImageProperties(): CredentialImageProperties? =
        this?.let {
            CredentialImageProperties(uri = it.uri)
        }

    private fun List<Oid4vciCredentialClaim>?.toWalletClaimMetadata(): List<CredentialClaimMetadata> =
        orEmpty().map {
            CredentialClaimMetadata(
                path = it.path,
                mandatory = it.mandatory,
                valueType = it.valueType,
                display = it.display.toWalletClaimDisplay(),
            )
        }

    private fun List<Oid4vciClaimDisplay>?.toWalletClaimDisplay(): List<CredentialClaimDisplay> =
        orEmpty().map {
            CredentialClaimDisplay(
                name = it.name,
                locale = it.locale,
            )
        }

    private fun credentialBodyPath(
        walletUnitId: String,
        credentialRecordId: String,
        credentialInstanceId: String,
    ): String = "wallet-units/$walletUnitId/credentials/$credentialRecordId/instances/$credentialInstanceId/body"

    private fun failureSite(failure: Throwable): String? =
        FAILURE_SITE_FRAME.find(failure.stackTraceToString())?.let { "${it.groupValues[1]}.${it.groupValues[2]}" }

    private companion object {
        val FAILURE_SITE_FRAME = Regex("""at com\.sphereon\.(?:[\w$]+\.)*?([A-Z][\w$]*)\.([\w$<>-]+)\(""")
    }
}
