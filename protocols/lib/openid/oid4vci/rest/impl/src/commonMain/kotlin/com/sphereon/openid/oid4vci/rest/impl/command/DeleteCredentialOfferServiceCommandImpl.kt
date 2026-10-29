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
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.events.SessionEventService
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vci.issuer.store.CredentialOfferStore
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStore
import com.sphereon.openid.oid4vci.rest.DeleteCredentialOfferOutput
import com.sphereon.openid.oid4vci.rest.DeleteCredentialOfferServiceCommand
import com.sphereon.openid.oid4vci.rest.GetCredentialOfferStatusInput
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
 * Deletes a credential offer and its session.
 *
 * A correlation id claimed for the offer is withdrawn by the session store when the session is deleted. A repeat of the same
 * request is then answered that the offer was deleted, instead of creating a new offer, because deleting an offer withdraws
 * the intent the key stood for. The key stays withdrawn for as long as the store keeps the claim.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<DeleteCredentialOfferServiceCommand>())
class DeleteCredentialOfferServiceCommandImpl(
    execution: SessionExecution,
    private val credentialOfferSessionStore: CredentialOfferSessionStore,
    private val credentialOfferStore: CredentialOfferStore,
    private val sessionEventService: SessionEventService,
) : TypedServiceCommandAdapter<GetCredentialOfferStatusInput, DeleteCredentialOfferOutput, IdkError>(
        commandId = DeleteCredentialOfferServiceCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<GetCredentialOfferStatusInput>(),
        outputTypeToken = typeToken<DeleteCredentialOfferOutput>(),
    ),
    DeleteCredentialOfferServiceCommand {
    override val commandId: String get() = DeleteCredentialOfferServiceCommand.COMMAND_ID

    override suspend fun doExecute(
        args: GetCredentialOfferStatusInput,
        applyDuring: (GetCredentialOfferStatusInput) -> GetCredentialOfferStatusInput,
    ): IdkResult<DeleteCredentialOfferOutput, IdkError> {
        val input = applyDuring(args)

        val session =
            credentialOfferSessionStore.get(input.correlationId).getOrElse { error ->
                return Err(error)
            } ?: return Err(IdkError.NOT_FOUND_ERROR(message = "Session not found for correlation ID: ${input.correlationId}"))

        // A session of another instance is answered like a missing one, so a caller cannot probe correlation ids across instances.
        if (input.instanceId != null && session.instanceId != input.instanceId) {
            return Err(IdkError.NOT_FOUND_ERROR(message = "Session not found for correlation ID: ${input.correlationId}"))
        }

        credentialOfferStore.delete(session.offerId)
        credentialOfferSessionStore.delete(input.correlationId)

        sessionEventService.emit(
                sessionEventService
                    .eventBuilder()
                    .type(Oid4vciRestEventTypes.SESSION_DELETED)
                    .origin(DeleteCredentialOfferServiceCommand.COMMAND_ID)
                    .payload(
                        buildJsonObject {
                            put("correlationId", input.correlationId)
                            putSessionEventIdentity(
                                protocolSessionId = session.issuanceSessionId,
                                instanceId = session.instanceId,
                            )
                            put(
                                "deletedAt",
                                Clock.System
                                    .now()
                                    .toEpochMilliseconds()
                                    .toString(),
                            )
                        },
                    ).build(),
            )

        return Ok(DeleteCredentialOfferOutput(correlationId = input.correlationId))
    }
}
