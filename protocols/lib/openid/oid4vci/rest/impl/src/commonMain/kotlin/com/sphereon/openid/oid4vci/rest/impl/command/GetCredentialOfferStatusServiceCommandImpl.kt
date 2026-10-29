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
import com.sphereon.core.events.SessionEventService
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vc.common.SessionError
import com.sphereon.openid.oid4vci.issuer.store.CredentialIssuanceSessionStore
import com.sphereon.openid.oid4vci.issuer.store.IssuanceSessionStatus
import com.sphereon.openid.oid4vci.rest.CredentialOfferSession
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStatus
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStore
import com.sphereon.openid.oid4vci.rest.GetCredentialOfferStatusInput
import com.sphereon.openid.oid4vci.rest.GetCredentialOfferStatusOutput
import com.sphereon.openid.oid4vci.rest.GetCredentialOfferStatusServiceCommand
import com.sphereon.openid.oid4vci.rest.IssuanceData
import com.sphereon.openid.oid4vci.rest.Oid4vciRestErrorCodes
import com.sphereon.openid.oid4vci.rest.Oid4vciRestEventTypes
import com.sphereon.openid.oid4vci.rest.impl.event.putSessionEventIdentity
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.time.Clock

/**
 * Reads the status of a credential offer from its protocol session.
 *
 * Despite the name this command also writes: when the protocol session's status moved, the stored offer session is
 * refreshed so that it follows the last read. The refresh is best effort, a failure to store it is logged and is not part
 * of the answer. It is also what lets a poll after the protocol session expired still learn how the offer ended: the
 * stored session keeps the terminal status the last read recorded.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<GetCredentialOfferStatusServiceCommand>())
class GetCredentialOfferStatusServiceCommandImpl(
    execution: SessionExecution,
    private val credentialOfferSessionStore: CredentialOfferSessionStore,
    private val issuanceSessionStore: CredentialIssuanceSessionStore,
    private val sessionEventService: SessionEventService,
) : TypedServiceCommandAdapter<GetCredentialOfferStatusInput, GetCredentialOfferStatusOutput, IdkError>(
        commandId = GetCredentialOfferStatusServiceCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<GetCredentialOfferStatusInput>(),
        outputTypeToken = typeToken<GetCredentialOfferStatusOutput>(),
    ),
    GetCredentialOfferStatusServiceCommand {
    override val commandId: String get() = GetCredentialOfferStatusServiceCommand.COMMAND_ID

    override suspend fun doExecute(
        args: GetCredentialOfferStatusInput,
        applyDuring: (GetCredentialOfferStatusInput) -> GetCredentialOfferStatusInput,
    ): IdkResult<GetCredentialOfferStatusOutput, IdkError> {
        val input = applyDuring(args)

        val session =
            credentialOfferSessionStore.get(input.correlationId).getOrElse { error ->
                return Err(error)
            } ?: return Err(IdkError.NOT_FOUND_ERROR(message = "Session not found for correlation ID: ${input.correlationId}"))

        // A session of another instance is answered like a missing one, so a caller cannot probe correlation ids across instances.
        if (input.instanceId != null && session.instanceId != input.instanceId) {
            return Err(IdkError.NOT_FOUND_ERROR(message = "Session not found for correlation ID: ${input.correlationId}"))
        }

        val currentStatus = resolveCurrentStatus(session).getOrElse { return Err(it) }
        val now = Clock.System.now().toEpochMilliseconds()

        if (currentStatus != session.status) {
            val updatedSession =
                session.copy(
                    status = currentStatus,
                    lastUpdatedAt = now,
                )
            credentialOfferSessionStore.update(updatedSession).fold(
                success = { },
                failure = { failure ->
                    log.warn("The stored status of '${session.correlationId}' was not refreshed to ${currentStatus.name}: ${failure.message.defaultMessage}")
                },
            )
        }

        val error =
            if (currentStatus == CredentialOfferSessionStatus.ERROR) {
                SessionError(code = "issuance_error", message = "Credential issuance failed")
            } else {
                null
            }

        val issuanceData =
            if (currentStatus == CredentialOfferSessionStatus.CREDENTIAL_ISSUED) {
                buildIssuanceData(session)
            } else {
                null
            }

        emitStatusPolledEvent(session, currentStatus)

        return Ok(
            GetCredentialOfferStatusOutput(
                correlationId = input.correlationId,
                status = currentStatus,
                lastUpdated = now,
                sessionId = session.issuanceSessionId,
                offerId = session.offerId,
                issuanceSessionId = session.issuanceSessionId,
                createdAt = session.createdAt,
                expiresAt = session.expiresAt,
                error = error,
                issuanceData = issuanceData,
            ),
        )
    }

    /**
     * The protocol session's status. A protocol session that cannot be read is an error, never the stored status, because a
     * stale status would be reported as if it were current. The protocol session is written before the offer session, so
     * one that is missing for a stored offer session has expired or been removed.
     *
     * Then only a terminal status that an earlier read stored is evidence of how the offer ended, and it is answered. Any
     * other stored status proves nothing, so the outcome is unknown, and is reported as such with a code of its own: it is
     * not the answer for a correlation id that never existed.
     */
    private suspend fun resolveCurrentStatus(session: CredentialOfferSession): IdkResult<CredentialOfferSessionStatus, IdkError> {
        val internalSession = issuanceSessionStore.get(session.issuanceSessionId).getOrElse { return Err(it) }
        if (internalSession != null) {
            return Ok(mapInternalStatus(internalSession.status))
        }
        if (session.status in TERMINAL_STATUSES) {
            return Ok(session.status)
        }
        return Err(
            IdkError.fromString(
                code = Oid4vciRestErrorCodes.OFFER_OUTCOME_UNKNOWN,
                message =
                    "The protocol session of correlation ID '${session.correlationId}' no longer exists, " +
                        "so what became of its offer is unknown",
                category = ErrorCategory.CONFLICT,
            ),
        )
    }

    private suspend fun buildIssuanceData(session: CredentialOfferSession): IssuanceData? {
        val internalSessionId = session.issuanceSessionId

        val internalSession =
            issuanceSessionStore.get(internalSessionId).getOrElse {
                return null
            } ?: return null

        return IssuanceData(
            credentialConfigurationIds = internalSession.credentialConfigurationIds,
            credentialIdentifiers = internalSession.credentialIdentifiers.ifEmpty { null },
        )
    }

    private suspend fun emitStatusPolledEvent(
        session: CredentialOfferSession,
        status: CredentialOfferSessionStatus,
    ) {
        sessionEventService.emit(
                sessionEventService
                    .eventBuilder()
                    .type(Oid4vciRestEventTypes.STATUS_POLLED)
                    .origin(GetCredentialOfferStatusServiceCommand.COMMAND_ID)
                    .payload(
                        buildJsonObject {
                            put("correlationId", session.correlationId)
                            put("status", status.name)
                            putSessionEventIdentity(
                                protocolSessionId = session.issuanceSessionId,
                                instanceId = session.instanceId,
                                oldState = session.status.name,
                                newState = status.name,
                                currentResult = buildJsonObject {
                                    put("correlationId", session.correlationId)
                                    put("status", status.name)
                                    put("sessionId", session.issuanceSessionId)
                                    put("offerId", session.offerId)
                                    put("createdAt", session.createdAt)
                                    put("expiresAt", session.expiresAt)
                                    put("lastUpdated", Clock.System.now().toEpochMilliseconds())
                                },
                            )
                        },
                    ).build(),
            )
    }

    companion object {
        private val log = Log.app().withTag("Oid4vciRestGetCredentialOfferStatus")

        /** The stored statuses that no later protocol state can change. */
        private val TERMINAL_STATUSES = setOf(CredentialOfferSessionStatus.CREDENTIAL_ISSUED, CredentialOfferSessionStatus.ERROR)

        fun mapInternalStatus(status: IssuanceSessionStatus): CredentialOfferSessionStatus =
            when (status) {
                IssuanceSessionStatus.OFFER_CREATED -> CredentialOfferSessionStatus.CREDENTIAL_OFFER_CREATED

                IssuanceSessionStatus.OFFER_RECEIVED -> CredentialOfferSessionStatus.CREDENTIAL_OFFER_RETRIEVED

                IssuanceSessionStatus.TOKEN_REQUESTED -> CredentialOfferSessionStatus.TOKEN_REQUESTED

                IssuanceSessionStatus.CREDENTIAL_REQUESTED -> CredentialOfferSessionStatus.CREDENTIAL_REQUESTED

                IssuanceSessionStatus.CREDENTIAL_ISSUED,
                IssuanceSessionStatus.COMPLETED,
                -> CredentialOfferSessionStatus.CREDENTIAL_ISSUED

                IssuanceSessionStatus.DEFERRED -> CredentialOfferSessionStatus.CREDENTIAL_REQUESTED

                IssuanceSessionStatus.EXPIRED,
                IssuanceSessionStatus.FAILED,
                -> CredentialOfferSessionStatus.ERROR
            }
    }
}
