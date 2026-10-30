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

package com.sphereon.openid.oid4vci.rest.impl.command

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.log.Log
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.api.validation.validate
import com.sphereon.core.events.SessionEventService
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vc.common.QrCodeOptions
import com.sphereon.openid.oid4vc.common.QrCodeService
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationSelectionException
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationSelectionRequest
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationGrant
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciAuthorizationPolicySnapshot
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciCredentialAuthorizationSelection
import com.sphereon.openid.oid4vci.issuer.authorization.Oid4vciIssuerAuthorizationPolicyProvider
import com.sphereon.openid.oid4vci.issuer.command.CreateCredentialOfferArgs
import com.sphereon.openid.oid4vci.issuer.command.CreateCredentialOfferCommand
import com.sphereon.openid.oid4vci.issuer.command.nothingWritten
import com.sphereon.openid.oid4vci.issuer.config.MutableOid4vciIssuerInstanceIdProvider
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerConfigProvider
import com.sphereon.openid.oid4vci.issuer.config.requireCanonicalOid4vciIssuerInstanceId
import com.sphereon.openid.oid4vci.issuer.config.requireCurrentInstanceId
import com.sphereon.openid.oid4vci.issuer.impl.authorization.Oid4vciAuthorizationServerSelector
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferInput
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferOutput
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferServiceCommand
import com.sphereon.openid.oid4vci.rest.CredentialOfferSession
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStatus
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStore
import com.sphereon.openid.oid4vci.rest.CredentialOfferTemplate
import com.sphereon.openid.oid4vci.rest.OfferRequestClaim
import com.sphereon.openid.oid4vci.rest.OfferRequestOutcome
import com.sphereon.openid.oid4vci.rest.OfferRequestReservation
import com.sphereon.openid.oid4vci.rest.OfferRequestState
import com.sphereon.openid.oid4vci.rest.Oid4vciRestConfigProvider
import com.sphereon.openid.oid4vci.rest.Oid4vciRestErrorCodes
import com.sphereon.openid.oid4vci.rest.Oid4vciRestEventTypes
import com.sphereon.openid.oid4vci.rest.error.Oid4vciRestError
import com.sphereon.openid.oid4vci.rest.impl.event.putSessionEventIdentity
import com.sphereon.openid.oid4vci.rest.validation.validateCreateCredentialOfferInput
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import io.ktor.http.encodeURLPathPart
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.coroutines.cancellation.CancellationException
import kotlin.time.Clock
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Creates a credential offer and the session that tracks it.
 *
 * A correlation id makes the command idempotent. The key is claimed on the session store before the issuer is called, so
 * that no second offer can follow a lost response, and the offer is recorded on the claim before it is handed out, so an
 * attempt whose claim was taken over meanwhile never answers with an offer. A repeat of the same intent is answered from
 * the offer the first attempt recorded, a different intent under the key is refused, an attempt that recorded nothing is
 * in doubt until its offer would have expired, and a key whose offer expired or was deleted never creates another one.
 * The key is released only when the issuer reports that it wrote nothing before refusing, because then no offer exists.
 *
 * The claim protocol is written against the session store's own atomic operations, because this module cannot depend on
 * the platform's idempotency store. A deployment that wants that store behind the claim supplies a
 * [CredentialOfferSessionStore] that implements the claim operations on it.
 *
 * The session-created event is emitted once, by the attempt that created the offer, and is best effort: a repeat does
 * not emit it again, and a failure to emit it is logged and does not undo an offer that exists.
 */
@OptIn(ExperimentalUuidApi::class)
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<CreateCredentialOfferServiceCommand>())
class CreateCredentialOfferServiceCommandImpl(
    private val sessionExecution: SessionExecution,
    private val createCredentialOfferCommand: CreateCredentialOfferCommand,
    private val credentialOfferSessionStore: CredentialOfferSessionStore,
    private val qrCodeService: QrCodeService,
    private val configProvider: Oid4vciRestConfigProvider,
    private val issuerConfigProvider: Oid4vciIssuerConfigProvider,
    private val instanceIdProvider: MutableOid4vciIssuerInstanceIdProvider,
    private val sessionEventService: SessionEventService,
    private val authorizationPolicyProvider: Oid4vciIssuerAuthorizationPolicyProvider,
    private val authorizationServerSelector: Oid4vciAuthorizationServerSelector,
) : TypedServiceCommandAdapter<CreateCredentialOfferInput, CreateCredentialOfferOutput, IdkError>(
        commandId = CreateCredentialOfferServiceCommand.COMMAND_ID,
        execution = sessionExecution,
        inputTypeToken = typeToken<CreateCredentialOfferInput>(),
        outputTypeToken = typeToken<CreateCredentialOfferOutput>(),
    ),
    CreateCredentialOfferServiceCommand {
    override val commandId: String get() = CreateCredentialOfferServiceCommand.COMMAND_ID

    override suspend fun doExecute(
        args: CreateCredentialOfferInput,
        applyDuring: (CreateCredentialOfferInput) -> CreateCredentialOfferInput,
    ): IdkResult<CreateCredentialOfferOutput, IdkError> {
        val input = applyDuring(args)
        validate(validateCreateCredentialOfferInput, input) { errors -> Oid4vciRestError.ValidationError(errors = errors) }
            .mapError { IdkError.fromDTO(it) }
            .getOrElse { return Err(it) }
        if (input.credentialConfigurationIds.isEmpty()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "credential_configuration_ids must not be empty"))
        }
        return withIssuerInstance(input.issuerInstanceId) { instanceId -> createOffer(input, instanceId) }
    }

    /**
     * Runs [block] with the issuer instance the request is bound to. An HTTP request is bound by its route and passes no
     * [requested] id, which then must equal the bound one when given. A caller outside HTTP binds the instance here, for
     * the duration of [block] only, as the HTTP adapters do: the holder is session wide, and a binding that outlived the
     * call would answer for the next, unrelated call of the session.
     */
    private suspend fun <T> withIssuerInstance(
        requested: String?,
        block: suspend (String) -> IdkResult<T, IdkError>,
    ): IdkResult<T, IdkError> {
        val bound = instanceIdProvider.currentInstanceId()
        val bindsHere = requested != null && bound == null
        val instanceId =
            try {
                if (requested != null) {
                    if (bound == null) {
                        instanceIdProvider.setCurrentInstanceId(requested)
                    } else {
                        require(bound == requireCanonicalOid4vciIssuerInstanceId(requested)) {
                            "issuer_instance_id does not match the issuer instance of the request"
                        }
                    }
                }
                instanceIdProvider.requireCurrentInstanceId()
            } catch (error: IllegalArgumentException) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = error.message ?: "Invalid OID4VCI issuer instance selector"))
            }
        try {
            return block(instanceId)
        } finally {
            if (bindsHere) {
                instanceIdProvider.clearCurrentInstanceId()
            }
        }
    }

    private suspend fun createOffer(
        input: CreateCredentialOfferInput,
        instanceId: String,
    ): IdkResult<CreateCredentialOfferOutput, IdkError> {
        val ttl = input.ttlSeconds ?: CredentialOfferSessionStore.DEFAULT_TTL_SECONDS
        val suppliedId = input.correlationId
        // Without a correlation id no idempotency was asked for: nothing is claimed and every call creates its own offer.
        val claim: OfferRequestClaim? =
            if (suppliedId == null) {
                null
            } else {
                when (val outcome = claimOrReplay(input, suppliedId, instanceId, ttl).getOrElse { return Err(it) }) {
                    is RequestOutcome.Replayed -> return Ok(outcome.output)
                    is RequestOutcome.Claimed -> outcome.claim
                }
            }
        if (claim != null) {
            rejectIdOfUnclaimedSession(claim.reservation.key)?.let { return Err(releaseClaim(claim, it)) }
        }

        val prepared = prepareOffer(input, instanceId).getOrElse { refusal -> return Err(releaseClaim(claim, refusal)) }
        val issued =
            try {
                createCredentialOfferCommand.execute(prepared.args)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                // An exception does not say whether the issuer wrote anything, so the claim stays and a repeat is in doubt.
                return Err(IdkError.UNKNOWN_ERROR(message = "The issuer failed while creating the credential offer: ${failure.message}", exception = failure))
            }
        val created =
            issued.getOrElse { error ->
                // Only a refusal that says it wrote nothing frees the key. Any other failure may have left an offer behind.
                return Err(if (error.nothingWritten) releaseClaim(claim, error) else error)
            }

        val correlationId = suppliedId ?: generateCorrelationId()
        val now = Clock.System.now().toEpochMilliseconds()
        val offerExpiresAt = now + (ttl * 1000)

        if (claim != null) {
            val outcome = OfferRequestOutcome(created.offerUri, created.sessionId, created.instanceId, offerExpiresAt)
            val recorded = credentialOfferSessionStore.completeRequest(claim, outcome).getOrElse { return Err(it) }
            if (!recorded.claimed) {
                log.warn("Correlation id '${claim.reservation.key}' was taken over while its offer was created: the new offer is not handed out")
                return Err(correlationIdInDoubt(claim.reservation.key))
            }
        }

        // Snapshot the replayable creation inputs so the GET handler can mint a fresh inner
        // offer on each fetch of a reusable URI. Populated for every offer (the snapshot is
        // small and harmless for single-use sessions, which simply never replay it).
        val args = prepared.args
        val offerTemplate =
            CredentialOfferTemplate(
                issuerId = args.issuerId,
                credentialConfigurationIds = args.credentialConfigurationIds,
                preAuthorizedCodeGrant = args.preAuthorizedCodeGrant,
                authorizationCodeGrant = args.authorizationCodeGrant,
                txCodeRequired = args.txCodeRequired,
                txCodeLength = args.txCodeLength,
                txCodeInputMode = args.txCodeInputMode,
                preSeededAttributes = args.preSeededAttributes,
                initialConnectorFields = args.initialLifecycleFields,
                offerTtlSeconds = args.offerTtlSeconds,
                scheme = args.scheme,
            )

        val session =
            CredentialOfferSession(
                correlationId = correlationId,
                instanceId = created.instanceId,
                offerId = created.offerId,
                issuanceSessionId = created.sessionId,
                status = CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED,
                callbackConfig = input.callback,
                state = input.state,
                createdAt = now,
                lastUpdatedAt = now,
                expiresAt = offerExpiresAt,
                uriLifecycle = input.uriLifecycle,
                rateLimit = input.rateLimit,
                offerTemplate = offerTemplate,
                authorizationPolicySnapshot = prepared.authorizationSnapshot,
            )

        credentialOfferSessionStore.create(session).getOrElse { error ->
            return Err(error)
        }

        val statusUri = statusUri(created.instanceId, correlationId)
        val qrUri = renderQr(created.offerUri, input.qrCodeOptions).getOrElse { return Err(it) }

        try {
            emitSessionCreatedEvent(
                created.instanceId,
                correlationId,
                created.sessionId,
                input.credentialConfigurationIds,
                input.templateId,
            )
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            // Observational and emitted once: a repeat replays the recorded offer without emitting, so a failure here could
            // never be repaired by a retry, and it must not turn an offer that exists into an error.
            log.warn("The session-created event of '$correlationId' was not emitted: ${failure.message}")
        }

        return Ok(
            CreateCredentialOfferOutput(
                correlationId = correlationId,
                sessionId = created.sessionId,
                offerUri = created.offerUri,
                statusUri = statusUri,
                qrUri = qrUri,
                txCode = created.txCode,
            ),
        )
    }

    private fun generateCorrelationId(): String = Uuid.random().toString()

    private class PreparedOffer(
        val args: CreateCredentialOfferArgs,
        val authorizationSnapshot: Oid4vciAuthorizationPolicySnapshot,
    )

    /**
     * Resolves the issuer policy and builds the issuer arguments. Nothing is written here, so a refusal frees a claim.
     * An issuer instance that does not exist in the caller's tenant is answered as not found, the same for an unknown and
     * for a foreign id.
     */
    private suspend fun prepareOffer(
        input: CreateCredentialOfferInput,
        instanceId: String,
    ): IdkResult<PreparedOffer, IdkError> {
        val hasPreAuth = input.grants?.preAuthorizedCode != null
        val hasAuthCode = input.grants?.authorizationCode != null
        val txCodeConfig = input.grants?.preAuthorizedCode?.txCode
        val txCodeRequired = txCodeConfig != null

        val authorizationSnapshot =
            try {
                issuerConfigProvider.prepare()
                val requiredGrants =
                    buildSet {
                        if (hasAuthCode) add(Oid4vciAuthorizationGrant.AUTHORIZATION_CODE)
                        if (hasPreAuth || (!hasPreAuth && !hasAuthCode)) add(Oid4vciAuthorizationGrant.PRE_AUTHORIZED_CODE)
                    }
                val policy =
                    authorizationPolicyProvider.resolve(
                        sessionExecution.sessionContext.context.tenant.tenantId,
                        instanceId,
                    )
                authorizationServerSelector.select(
                    policy,
                    Oid4vciAuthorizationSelectionRequest(
                        credentialSelections =
                            input.credentialConfigurationIds.map { configurationId ->
                                Oid4vciCredentialAuthorizationSelection(
                                    credentialConfigurationId = configurationId,
                                    authorizationServerId = issuerConfigProvider.credentialAuthorizationServerId(configurationId),
                                    allowedGrants = issuerConfigProvider.credentialAuthorizationServerAllowedGrants(configurationId),
                                )
                            },
                        templateAuthorizationServerId = input.templateAuthorizationServerId?.let(Uuid::parse),
                        templateAllowedGrants = input.templateAuthorizationServerAllowedGrants,
                        requiredGrants = requiredGrants,
                    ),
                )
            } catch (error: Oid4vciAuthorizationSelectionException) {
                return Err(IdkError.INVALID_STATE(message = "${error.error}: ${error.message}"))
            } catch (error: IllegalArgumentException) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = error.message ?: "Invalid authorization-server UUID selector"))
            } catch (error: IllegalStateException) {
                // The policy provider refuses an issuer instance it cannot find in the tenant, without saying which of the two it is.
                log.warn("The issuer instance '$instanceId' is not available for this request: ${error.message}")
                return Err(IdkError.NOT_FOUND_ERROR(message = "The OID4VCI issuer instance is not available in this tenant"))
            }

        // Prefer the Credential Issuer Identifier (OID4VCI §11.2.2) — may include a path
        // component (e.g. "${BASE}/oid4vci").
        val effectiveIssuerId =
            input.issuerId?.takeIf { it.isNotBlank() }
                ?: issuerConfigProvider.issuerIdentifier.takeIf { it.isNotBlank() }
                ?: return Err(IdkError.INVALID_STATE(message = "Credential issuer identifier is not configured"))

        val args =
            CreateCredentialOfferArgs(
                instanceId = instanceId,
                issuerId = effectiveIssuerId,
                credentialConfigurationIds = input.credentialConfigurationIds,
                issuanceTemplateResourceId = input.templateId,
                preAuthorizedCodeGrant = hasPreAuth || (!hasPreAuth && !hasAuthCode),
                authorizationCodeGrant = hasAuthCode,
                txCodeRequired = txCodeRequired,
                txCodeLength = txCodeConfig?.length,
                txCodeInputMode = txCodeConfig?.inputMode,
                preSeededAttributes = input.credentialSubjectData,
                initialLifecycleFields = input.initialConnectorFields,
                offerTtlSeconds = input.ttlSeconds ?: CredentialOfferSessionStore.DEFAULT_TTL_SECONDS,
                scheme = input.scheme,
                uriLifecycle = input.uriLifecycle,
                rateLimit = input.rateLimit,
                authorizationPolicySnapshot = authorizationSnapshot,
            )
        return Ok(PreparedOffer(args, authorizationSnapshot))
    }

    private sealed interface RequestOutcome {
        /** This caller holds the correlation id and goes on to create the offer. */
        data class Claimed(val claim: OfferRequestClaim) : RequestOutcome

        /** An earlier attempt created the offer, and this is its answer. */
        data class Replayed(val output: CreateCredentialOfferOutput) : RequestOutcome
    }

    /**
     * Claims [correlationId] for this intent, or answers from the offer an earlier attempt recorded. Repeating the intent
     * returns that offer while it lives, a different intent is refused, and an earlier attempt that recorded nothing is in
     * doubt until its offer has expired, because it may have created an offer whose response was lost. An id whose offer
     * expired or was deleted is never used for another offer.
     *
     * An expired claim that recorded nothing, and a released one, are taken over with
     * [CredentialOfferSessionStore.reclaimRequest], which is decided by the claim this caller read. Of several callers that
     * read the same claim one wins, and the others see the winner's live claim on the next round and are told the outcome is
     * in doubt.
     */
    private suspend fun claimOrReplay(
        input: CreateCredentialOfferInput,
        correlationId: String,
        instanceId: String,
        ttl: Long,
    ): IdkResult<RequestOutcome, IdkError> {
        val intent = input.intentDigest(instanceId)
        var claim = credentialOfferSessionStore.claimRequest(newReservation(correlationId, intent, ttl)).getOrElse { return Err(it) }
        repeat(MAX_CLAIM_ROUNDS) {
            if (claim.claimed) return Ok(RequestOutcome.Claimed(claim))
            val held = claim.reservation
            // A released key is free whatever the next caller asks for: the digest it carries belongs to the attempt that gave it back.
            if (held.state != OfferRequestState.RELEASED && held.intentDigest != intent) {
                log.warn("Correlation id '$correlationId' was used for a different request")
                return Err(
                    IdkError.fromString(
                        code = Oid4vciRestErrorCodes.CORRELATION_ID_CONFLICT,
                        message = "Correlation id '$correlationId' was used for a different request",
                        category = ErrorCategory.CONFLICT,
                    ),
                )
            }
            when (held.state) {
                OfferRequestState.COMPLETED -> return replayCompleted(input, correlationId, held)
                OfferRequestState.WITHDRAWN -> {
                    log.info("Correlation id '$correlationId' refers to an offer that was deleted")
                    return Err(
                        IdkError.fromString(
                            code = Oid4vciRestErrorCodes.CORRELATION_ID_WITHDRAWN,
                            message = "The offer created under correlation id '$correlationId' was deleted, so the id creates no other offer. Use a new correlation id.",
                            category = ErrorCategory.CONFLICT,
                        ),
                    )
                }
                OfferRequestState.ACTIVE ->
                    if (held.expiresAt >= Clock.System.now().toEpochMilliseconds()) {
                        log.warn("Correlation id '$correlationId' has an earlier attempt of unknown outcome")
                        return Err(correlationIdInDoubt(correlationId))
                    }
                OfferRequestState.RELEASED -> Unit
            }
            log.info("Correlation id '$correlationId' is taken over from a ${held.state.name.lowercase()} claim")
            claim = credentialOfferSessionStore.reclaimRequest(claim, newReservation(correlationId, intent, ttl)).getOrElse { return Err(it) }
        }
        if (claim.claimed) return Ok(RequestOutcome.Claimed(claim))
        return Err(correlationIdInDoubt(correlationId))
    }

    /** The answer for a key whose offer was recorded: that offer while it lives, otherwise the fact that it expired. */
    private suspend fun replayCompleted(
        input: CreateCredentialOfferInput,
        correlationId: String,
        held: OfferRequestReservation,
    ): IdkResult<RequestOutcome, IdkError> {
        val outcome =
            held.outcome
                ?: return Err(IdkError.INVALID_STATE(message = "Correlation id '$correlationId' is completed but records no offer"))
        if (outcome.offerExpiresAt <= Clock.System.now().toEpochMilliseconds()) {
            log.info("Correlation id '$correlationId' refers to an offer that expired")
            return Err(
                IdkError.fromString(
                    code = Oid4vciRestErrorCodes.CORRELATION_ID_EXPIRED,
                    message = "The offer created under correlation id '$correlationId' has expired, so the id creates no other offer. Use a new correlation id.",
                    category = ErrorCategory.CONFLICT,
                ),
            )
        }
        log.info("Correlation id '$correlationId' is answered from its recorded offer")
        return replayed(input, correlationId, outcome).map { RequestOutcome.Replayed(it) }
    }

    private fun correlationIdInDoubt(correlationId: String): IdkError =
        IdkError.fromString(
            code = Oid4vciRestErrorCodes.CORRELATION_ID_IN_DOUBT,
            message = "An earlier attempt for correlation id '$correlationId' has an unknown outcome until its offer expires",
            category = ErrorCategory.CONFLICT,
        )

    /**
     * The claim outlives the offer by [CLAIM_MARGIN_SECONDS]: the issuer stamps the offer's expiry from its own clock, a
     * little after this one, and the key must not be free while that offer can still be redeemed.
     */
    private fun newReservation(correlationId: String, intent: String, ttl: Long): OfferRequestReservation {
        val now = Clock.System.now().toEpochMilliseconds()
        return OfferRequestReservation(correlationId, intent, now, now + (ttl + CLAIM_MARGIN_SECONDS) * 1000)
    }

    /**
     * The answer of the original attempt, rebuilt from the offer it recorded. A transaction code is shown once and never
     * stored, so a repeat carries none, and a QR code is rendered from the repeat's own options.
     */
    private suspend fun replayed(
        input: CreateCredentialOfferInput,
        correlationId: String,
        outcome: OfferRequestOutcome,
    ): IdkResult<CreateCredentialOfferOutput, IdkError> {
        val qrUri = renderQr(outcome.offerUri, input.qrCodeOptions).getOrElse { return Err(it) }
        return Ok(
            CreateCredentialOfferOutput(
                correlationId = correlationId,
                sessionId = outcome.issuanceSessionId,
                offerUri = outcome.offerUri,
                statusUri = statusUri(outcome.instanceId, correlationId),
                qrUri = qrUri,
            ),
        )
    }

    /**
     * The QR code of the offer, null when none was asked for. A QR code that was asked for and cannot be rendered is an
     * error: the offer exists, and a repeat under the same correlation id answers from it and renders again.
     */
    private fun renderQr(
        offerUri: String,
        options: QrCodeOptions?,
    ): IdkResult<String?, IdkError> {
        if (options == null) return Ok(null)
        return try {
            Ok(qrCodeService.generateDataUri(offerUri, options))
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: Exception) {
            Err(IdkError.UNKNOWN_ERROR(message = "The QR code of the credential offer could not be rendered: ${failure.message}", exception = failure))
        }
    }

    /**
     * A claimed correlation id names the session that tracks the offer, so no session may exist under it yet. One does when
     * the id is the server generated id of an earlier call that asked for no idempotency: that call recorded no intent to
     * compare with, and the store would overwrite its session.
     */
    private suspend fun rejectIdOfUnclaimedSession(correlationId: String): IdkError? {
        val existing = credentialOfferSessionStore.get(correlationId).getOrElse { return it }
        return existing?.let {
            IdkError.fromString(
                code = Oid4vciRestErrorCodes.CORRELATION_ID_CONFLICT,
                message = "Correlation id '$correlationId' belongs to an offer that was created without it as an idempotency key",
                category = ErrorCategory.CONFLICT,
            )
        }
    }

    /**
     * Gives the claim back after a refusal that wrote nothing. When the release does not take, the refusal still reaches
     * the caller, marked with the fact that the key stays claimed.
     */
    private suspend fun releaseClaim(
        claim: OfferRequestClaim?,
        refusal: IdkError,
    ): IdkError {
        if (claim == null) return refusal
        val key = claim.reservation.key
        val released =
            credentialOfferSessionStore.releaseRequest(claim).getOrElse { failure ->
                log.warn("Correlation id '$key' stays claimed after the issuer refused the offer (${refusal.code}), because releasing it failed: ${failure.message.defaultMessage}")
                return refusal.withMeta(CORRELATION_ID_CLAIMED_META, true)
            }
        if (!released) {
            log.warn("Correlation id '$key' stays claimed after the issuer refused the offer (${refusal.code}): another attempt holds it by now")
            return refusal.withMeta(CORRELATION_ID_CLAIMED_META, true)
        }
        return refusal
    }

    private fun IdkError.withMeta(
        key: String,
        value: Any?,
    ): IdkError =
        IdkError(
            code = code,
            message = message,
            severity = severity,
            category = category,
            causes = causes,
            meta = meta + (key to value),
            exception = exception,
            source = source,
        )

    private suspend fun statusUri(instanceId: String, correlationId: String): String? =
        configProvider.getConfig().externalBaseUrl?.let {
            // The status endpoint is the origin-rooted backend admin API. The issuer's
            // external base URL carries the instance path, which serves protocol endpoints
            // only; prefixing the admin path with it advertises a URL nothing routes.
            val base = it.trimEnd('/')
            val origin = ORIGIN.find(base)?.groupValues?.get(1) ?: base
            "$origin/api/oid4vci/v1/instances/$instanceId/backend/credential/offers/${correlationId.encodeURLPathPart()}"
        }

    private companion object {
        private val log = Log.app().withTag("Oid4vciRestCreateCredentialOffer")

        private val ORIGIN = Regex("^(https?://[^/]+)")

        /** How often a caller reads a claim and tries to take it over before it concludes the key is contended. */
        const val MAX_CLAIM_ROUNDS: Int = 3

        /** How long the claim on a key outlives the offer it covers. */
        const val CLAIM_MARGIN_SECONDS: Long = 60

        /** Meta key on a refusal whose correlation id could not be given back and stays claimed. */
        const val CORRELATION_ID_CLAIMED_META: String = "oid4vci.correlation_id.still_claimed"
    }

    private suspend fun emitSessionCreatedEvent(
        instanceId: String,
        correlationId: String,
        protocolSessionId: String,
        credentialConfigurationIds: List<String>,
        templateId: String?,
    ) {
        sessionEventService.emit(
                sessionEventService
                    .eventBuilder()
                    .type(Oid4vciRestEventTypes.SESSION_CREATED)
                    .origin(CreateCredentialOfferServiceCommand.COMMAND_ID)
                    .payload(
                        buildJsonObject {
                            put("correlationId", correlationId)
                            put("credentialConfigurationIds", buildJsonArray {
                                credentialConfigurationIds.forEach { add(JsonPrimitive(it)) }
                            })
                            putSessionEventIdentity(
                                protocolSessionId = protocolSessionId,
                                instanceId = instanceId,
                                newState = CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED.name,
                                templateId = templateId,
                                creationSnapshot = buildJsonObject {
                                    put("correlationId", correlationId)
                                    put("credentialConfigurationIds", buildJsonArray {
                                        credentialConfigurationIds.forEach { add(JsonPrimitive(it)) }
                                    })
                                    templateId?.let { put("templateId", it) }
                                },
                                currentResult = buildJsonObject {
                                    put("correlationId", correlationId)
                                    put("sessionId", protocolSessionId)
                                    put("status", CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED.name)
                                },
                            )
                        },
                    ).build(),
            )
    }
}
