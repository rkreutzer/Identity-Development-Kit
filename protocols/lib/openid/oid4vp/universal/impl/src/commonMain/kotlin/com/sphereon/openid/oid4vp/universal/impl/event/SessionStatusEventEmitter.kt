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

package com.sphereon.openid.oid4vp.universal.impl.event

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.events.SessionEventService
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vp.universal.UniversalOid4vpCategories
import com.sphereon.openid.oid4vp.universal.UniversalOid4vpEventTypes
import com.sphereon.openid.oid4vp.universal.UniversalOid4vpSubsystems
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.time.Clock

/**
 * Service for emitting events when authorization session status changes.
 *
 * Webhook callbacks are not sent from here: the authorization session store dispatches exactly one
 * per persisted status change.
 *
 * Designed to be called by components that modify session status (e.g., store implementations,
 * HTTP command handlers).
 */
interface SessionStatusEventEmitter {
    /**
     * Emit an event for a session status change.
     *
     * @param session The session that changed
     * @param previousStatus The status before the change (null for newly created sessions)
     */
    suspend fun onStatusChange(
        session: AuthorizationSession,
        previousStatus: AuthorizationSessionStatus?,
    ): IdkResult<Unit, IdkError>

    /**
     * Emit a session deleted event.
     *
     * @param session The deleted protocol session, retained long enough to emit its identity
     */
    suspend fun onSessionDeleted(session: AuthorizationSession): IdkResult<Unit, IdkError>

    /**
     * Emit a status polled event.
     *
     * @param session The session that was polled
     */
    suspend fun onStatusPolled(session: AuthorizationSession): IdkResult<Unit, IdkError>

    /**
     * Graph interface for DI.
     */
    @SingleIn(SessionScope::class)
    @ContributesTo(SessionScope::class)
    interface Graph {
        val sessionStatusEventEmitter: SessionStatusEventEmitter
    }
}

/**
 * Default implementation of [SessionStatusEventEmitter].
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<SessionStatusEventEmitter>())
class SessionStatusEventEmitterImpl(
    private val sessionEventService: SessionEventService,
) : SessionStatusEventEmitter {
    override suspend fun onStatusChange(
        session: AuthorizationSession,
        previousStatus: AuthorizationSessionStatus?,
    ): IdkResult<Unit, IdkError> {
        // 1. Emit SESSION_STATUS_CHANGED event
        val eventType =
            if (previousStatus == null) {
                UniversalOid4vpEventTypes.SESSION_CREATED
            } else {
                UniversalOid4vpEventTypes.SESSION_STATUS_CHANGED
            }

        val event =
            sessionEventService
                .eventBuilder()
                .type(eventType)
                .origin("universal-oid4vp")
                .subsystem(UniversalOid4vpSubsystems.UNIVERSAL_OID4VP)
                .category(UniversalOid4vpCategories.SESSION)
                .correlationId(session.correlationId)
                .payload(
                    buildJsonObject {
                        put("correlationId", session.correlationId)
                        put("status", session.status.name)
                        previousStatus?.let { put("previousStatus", it.name) }
                        put("updatedAt", session.updatedAt)
                        putSessionEventIdentity(
                            protocolSessionId = session.sessionId,
                            instanceId = session.instanceId,
                            oldState = previousStatus?.name,
                            newState = session.status.name,
                            templateId = session.templateId,
                            creationSnapshot = if (previousStatus == null) {
                                buildJsonObject {
                                    put("correlationId", session.correlationId)
                                    session.queryId?.let { put("queryId", it) }
                                    session.templateId?.let { put("templateId", it) }
                                    put("createdAt", session.createdAt)
                                }
                            } else null,
                            currentResult = buildJsonObject {
                                put("correlationId", session.correlationId)
                                session.queryId?.let { put("queryId", it) }
                                put("sessionId", session.sessionId)
                                put("status", session.status.name)
                                put("createdAt", session.createdAt)
                                put("expiresAt", session.expiresAt)
                                put("lastUpdated", session.updatedAt)
                                session.error?.code?.let { put("errorCode", it) }
                            },
                        )
                    },
                ).build()

        sessionEventService.emit(event)

        return Ok(Unit)
    }

    override suspend fun onSessionDeleted(session: AuthorizationSession): IdkResult<Unit, IdkError> {
        val event =
            sessionEventService
                .eventBuilder()
                .type(UniversalOid4vpEventTypes.SESSION_DELETED)
                .origin("universal-oid4vp")
                .subsystem(UniversalOid4vpSubsystems.UNIVERSAL_OID4VP)
                .category(UniversalOid4vpCategories.SESSION)
                .correlationId(session.correlationId)
                .payload(
                    buildJsonObject {
                        put("correlationId", session.correlationId)
                        put("deletedAt", Clock.System.now().toEpochMilliseconds())
                        putSessionEventIdentity(
                            protocolSessionId = session.sessionId,
                            instanceId = session.instanceId,
                            oldState = session.status.name,
                        )
                    },
                ).build()

        sessionEventService.emit(event)

        return Ok(Unit)
    }

    override suspend fun onStatusPolled(session: AuthorizationSession): IdkResult<Unit, IdkError> {
        val event =
            sessionEventService
                .eventBuilder()
                .type(UniversalOid4vpEventTypes.STATUS_POLLED)
                .origin("universal-oid4vp")
                .subsystem(UniversalOid4vpSubsystems.UNIVERSAL_OID4VP)
                .category(UniversalOid4vpCategories.SESSION)
                .correlationId(session.correlationId)
                .payload(
                    buildJsonObject {
                        put("correlationId", session.correlationId)
                        put("status", session.status.name)
                        put("polledAt", Clock.System.now().toEpochMilliseconds())
                        putSessionEventIdentity(
                            protocolSessionId = session.sessionId,
                            instanceId = session.instanceId,
                            oldState = session.status.name,
                            newState = session.status.name,
                            currentResult = buildJsonObject {
                                put("correlationId", session.correlationId)
                                session.queryId?.let { put("queryId", it) }
                                put("sessionId", session.sessionId)
                                put("status", session.status.name)
                                put("createdAt", session.createdAt)
                                put("expiresAt", session.expiresAt)
                                put("lastUpdated", session.updatedAt)
                                session.error?.code?.let { put("errorCode", it) }
                            },
                        )
                    },
                ).build()

        sessionEventService.emit(event)

        return Ok(Unit)
    }
}
