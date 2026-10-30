/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Err
import com.sphereon.core.api.Ok
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.log.AppLogManager
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.events.EventSubsystems
import com.sphereon.core.events.SessionCallbackDescriptor
import com.sphereon.core.events.SessionEventService
import com.sphereon.core.events.SessionStatusChange
import com.sphereon.core.events.SessionStatusEventPublisher
import com.sphereon.core.events.SessionStatusEventTypes
import com.sphereon.data.store.kv.impl.KvStoreManager
import com.sphereon.data.store.kv.impl.KvStoreService
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vp.common.store.StoreMetadata
import com.sphereon.openid.oid4vp.dcql.store.DcqlQueryConfigurationStore
import com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse
import com.sphereon.openid.oid4vp.verifier.ValidationResult
import com.sphereon.openid.oid4vp.verifier.callback.AuthorizationSessionCallbackDispatcher
import com.sphereon.openid.oid4vp.verifier.callback.AuthorizationSessionStatusResponseMapper
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionCreateArgs
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionError
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.openid.oid4vp.verifier.store.AuthorizationSessionStore
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlin.time.Clock

/**
 * Announces every authorization session status transition through [SessionStatusEventPublisher].
 * Each transition of the wrapped store is observed once, whichever store method produced it.
 */
@SingleIn(SessionScope::class)
@ContributesBinding(
    SessionScope::class,
    binding = binding<AuthorizationSessionStore>(),
    replaces = [KvAuthorizationSessionStore::class],
)
class EventPublishingAuthorizationSessionStore private constructor(
    private val delegate: KvAuthorizationSessionStore,
    private val publisher: SessionStatusEventPublisher,
    private val execution: SessionExecution,
) : AuthorizationSessionStore by delegate {
    // This class replaces the key-value store's own contribution, which is then not injectable,
    // so the store it wraps is built here from the collaborators it would have received.
    @Inject
    constructor(
        kvStoreManager: KvStoreManager,
        kvStoreService: KvStoreService,
        dcqlQueryConfigurationStore: DcqlQueryConfigurationStore,
        callbackDispatcher: AuthorizationSessionCallbackDispatcher,
        statusResponseMapper: AuthorizationSessionStatusResponseMapper,
        appLogManager: AppLogManager,
        execution: SessionExecution,
        clock: Clock,
        publisher: SessionStatusEventPublisher,
        eventService: SessionEventService? = null,
    ) : this(
        KvAuthorizationSessionStore(
            kvStoreManager,
            kvStoreService,
            dcqlQueryConfigurationStore,
            callbackDispatcher,
            statusResponseMapper,
            appLogManager,
            execution,
            clock,
            eventService,
        ),
        publisher,
        execution,
    )

    override suspend fun createSession(
        correlationId: String?,
        args: AuthorizationSessionCreateArgs,
        ttlSeconds: Long,
    ): IdkResult<AuthorizationSession, IdkError> {
        val created = delegate.createSession(correlationId, args, ttlSeconds)
        if (created.isOk) publish(previous = null, current = created.value)
        return created
    }

    override suspend fun updateStatus(
        correlationId: String,
        status: AuthorizationSessionStatus,
        error: AuthorizationSessionError?,
    ): IdkResult<AuthorizationSession, IdkError> = transition(correlationId) { delegate.updateStatus(correlationId, status, error) }

    override suspend fun storeResponse(
        correlationId: String,
        parsedResponse: ParsedAuthorizationResponse,
    ): IdkResult<AuthorizationSession, IdkError> = transition(correlationId) { delegate.storeResponse(correlationId, parsedResponse) }

    override suspend fun storeValidationResult(
        correlationId: String,
        validationResult: ValidationResult,
    ): IdkResult<AuthorizationSession, IdkError> = transition(correlationId) { delegate.storeValidationResult(correlationId, validationResult) }

    override suspend fun storeValidationResultDeferred(
        correlationId: String,
        validationResult: ValidationResult,
    ): IdkResult<AuthorizationSession, IdkError> = delegate.storeValidationResultDeferred(correlationId, validationResult)

    override suspend fun dispatchDeferredValidation(
        correlationId: String,
        previous: AuthorizationSession?,
    ): IdkResult<Unit, IdkError> {
        val current = delegate.get(correlationId).getOrElse { return Err(it) } ?: return Ok(Unit)
        val result = delegate.dispatchDeferredValidation(correlationId, previous)
        if (result.isErr) return Err(result.error)
        if (previous?.status != current.status) publish(previous, current)
        return Ok(Unit)
    }

    override suspend fun getForRequestUri(
        correlationId: String,
        markRetrieved: Boolean,
    ): IdkResult<AuthorizationSession?, IdkError> {
        if (!markRetrieved) return delegate.getForRequestUri(correlationId, markRetrieved)
        val previous = current(correlationId)
        val result = delegate.getForRequestUri(correlationId, markRetrieved)
        val session = if (result.isOk) result.value else null
        if (session != null && previous?.status != session.status) publish(previous, session)
        return result
    }

    override suspend fun put(
        key: String,
        value: AuthorizationSession,
        ttlSeconds: Long,
    ): IdkResult<StoreMetadata, IdkError> {
        val previous = current(key)
        val result = delegate.put(key, value, ttlSeconds)
        if (result.isOk && previous?.status != value.status) publish(previous, value)
        return result
    }

    private suspend fun transition(
        correlationId: String,
        change: suspend () -> IdkResult<AuthorizationSession, IdkError>,
    ): IdkResult<AuthorizationSession, IdkError> {
        val previous = current(correlationId)
        val result = change()
        if (result.isOk && previous?.status != result.value.status) publish(previous, result.value)
        return result
    }

    private suspend fun current(key: String): AuthorizationSession? =
        delegate.get(key).let { if (it.isOk) it.value else null }

    private suspend fun publish(previous: AuthorizationSession?, current: AuthorizationSession) {
        publisher.publish(
            SessionStatusChange(
                type = SessionStatusEventTypes.OID4VP_VERIFICATION_SESSION_STATUS_CHANGED,
                subsystem = EventSubsystems.OID4VP,
                sessionId = current.sessionId,
                correlationId = current.correlationId,
                instanceId = current.instanceId,
                tenantId = execution.tenantId,
                previousStatus = previous?.status?.name,
                status = current.status.name,
                callback = current.callback?.let { callback ->
                    SessionCallbackDescriptor(
                        url = callback.url,
                        statuses = callback.statuses.map { it.name },
                        includeData = false,
                        secretRef = callback.secretRef,
                        signing = callback.signing,
                    )
                },
            ),
        )
    }
}
