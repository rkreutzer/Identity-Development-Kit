package com.sphereon.openid.oid4vp.universal.impl

import com.sphereon.core.events.EventStore
import com.sphereon.core.events.SessionEventService
import com.sphereon.di.context.PrincipalType
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.universal.UniversalOid4vpEventTypes
import com.sphereon.openid.oid4vp.universal.impl.event.SessionStatusEventEmitterImpl
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionCallbackConfig
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The emitter publishes session events only. Webhook delivery belongs to the authorization session
 * store, which sends exactly one callback per persisted status change, so a session that configures
 * a callback must not make the emitter send a second one or record a callback event of its own.
 */
class SessionStatusEventEmitterTest {
    @Test
    fun shouldEmitTheStatusChangeEventAndNoCallbackEventsForASessionWithACallback() = runTest {
        val app = createJvmUniversalOid4vpTestAppGraph(this)
        val sessionInstance =
            app.userContextManager
                .getAnonymous()
                .sessionContextManager
                .createOrGetFromId("status-event-emitter", principalType = PrincipalType.USER)
        val sessionEventService = (sessionInstance.graph as SessionEventService.Graph).sessionEventService
        val eventStore = (app as EventStore.Graph).eventStore
        val correlationId = "status-event-emitter-correlation"
        val created = session(correlationId)
        val updated =
            created.copy(
                status = AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED,
                updatedAt = created.updatedAt + 1,
            )

        val result = SessionStatusEventEmitterImpl(sessionEventService).onStatusChange(updated, created.status)

        assertTrue(result.isOk)
        val types = eventStore.getRecent(100).getOrElse { error("event store read failed: $it") }
            .filter { it.context.correlationId == correlationId }
            .map { it.type }
        assertEquals(1, types.count { it == UniversalOid4vpEventTypes.SESSION_STATUS_CHANGED })
        for (callbackType in listOf(
            UniversalOid4vpEventTypes.CALLBACK_ATTEMPTED,
            UniversalOid4vpEventTypes.CALLBACK_DISPATCHED,
            UniversalOid4vpEventTypes.CALLBACK_FAILED,
        )) {
            assertFalse(callbackType in types, "the emitter must not record $callbackType")
        }
    }

    @Test
    fun shouldEmitSessionCreatedForANewSession() = runTest {
        val app = createJvmUniversalOid4vpTestAppGraph(this)
        val sessionInstance =
            app.userContextManager
                .getAnonymous()
                .sessionContextManager
                .createOrGetFromId("status-event-emitter-created", principalType = PrincipalType.USER)
        val sessionEventService = (sessionInstance.graph as SessionEventService.Graph).sessionEventService
        val eventStore = (app as EventStore.Graph).eventStore
        val correlationId = "status-event-emitter-created-correlation"

        SessionStatusEventEmitterImpl(sessionEventService).onStatusChange(session(correlationId), previousStatus = null)

        val types = eventStore.getRecent(100).getOrElse { error("event store read failed: $it") }
            .filter { it.context.correlationId == correlationId }
            .map { it.type }
        assertTrue(UniversalOid4vpEventTypes.SESSION_CREATED in types)
    }

    private fun session(correlationId: String): AuthorizationSession {
        val now = 1_800_000_000_000L
        return AuthorizationSession(
            instanceId = "status-event-emitter-instance",
            sessionId = "status-event-emitter-session",
            correlationId = correlationId,
            dcqlQuery = DcqlQuery(
                credentials = listOf(
                    DcqlCredentialQuery(
                        id = "callback-credential",
                        format = "dc+sd-jwt",
                        meta = sdJwtVcMeta("urn:test:callback"),
                    ),
                ),
            ),
            authorizationRequest = AuthorizationRequest(
                clientId = "https://verifier.example.test",
                redirectUri = "https://verifier.example.test/callback",
                state = correlationId,
            ),
            status = AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED,
            callback = AuthorizationSessionCallbackConfig(
                url = "https://callback.example.test/status",
                statuses = listOf(AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED),
            ),
            createdAt = now,
            updatedAt = now,
            expiresAt = now + 600_000,
        )
    }
}
