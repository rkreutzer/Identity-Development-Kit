/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.openid.oid4vci.rest.impl

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.log.AppLogManager
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.events.EventSubsystems
import com.sphereon.core.events.SessionCallbackDescriptor
import com.sphereon.core.events.SessionStatusChange
import com.sphereon.core.events.SessionStatusEventPublisher
import com.sphereon.core.events.SessionStatusEventTypes
import com.sphereon.data.store.kv.impl.KvStoreManager
import com.sphereon.data.store.kv.impl.KvStoreService
import com.sphereon.di.session.SessionScope
import com.sphereon.openid.oid4vci.rest.CredentialOfferSession
import com.sphereon.openid.oid4vci.rest.CredentialOfferSessionStore
import com.sphereon.openid.oid4vci.rest.Oid4vciRestConfigProvider
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

/**
 * Announces every credential-offer session status transition through [SessionStatusEventPublisher].
 * Wrapping the store keeps the announcement in one place instead of at each command that writes a
 * new status.
 */
@SingleIn(SessionScope::class)
@ContributesBinding(
    SessionScope::class,
    binding = binding<CredentialOfferSessionStore>(),
    replaces = [KvCredentialOfferSessionStore::class],
)
class EventPublishingCredentialOfferSessionStore private constructor(
    private val delegate: KvCredentialOfferSessionStore,
    private val publisher: SessionStatusEventPublisher,
    private val execution: SessionExecution,
) : CredentialOfferSessionStore by delegate {
    // This class replaces the key-value store's own contribution, which is then not injectable,
    // so the store it wraps is built here from the collaborators it would have received.
    @Inject
    constructor(
        kvStoreManager: KvStoreManager,
        kvStoreService: KvStoreService,
        execution: SessionExecution,
        appLogManager: AppLogManager,
        publisher: SessionStatusEventPublisher,
        configProvider: Oid4vciRestConfigProvider,
    ) : this(
        KvCredentialOfferSessionStore(kvStoreManager, kvStoreService, execution, appLogManager, configProvider),
        publisher,
        execution,
    )

    override suspend fun create(session: CredentialOfferSession): IdkResult<CredentialOfferSession, IdkError> {
        val created = delegate.create(session)
        if (created.isOk) publish(previous = null, current = created.value)
        return created
    }

    override suspend fun update(session: CredentialOfferSession): IdkResult<CredentialOfferSession, IdkError> {
        val previous = delegate.get(session.correlationId).let { if (it.isOk) it.value else null }
        val updated = delegate.update(session)
        if (updated.isOk && previous?.status != updated.value.status) publish(previous, updated.value)
        return updated
    }

    private suspend fun publish(previous: CredentialOfferSession?, current: CredentialOfferSession) {
        publisher.publish(
            SessionStatusChange(
                type = SessionStatusEventTypes.OID4VCI_ISSUANCE_SESSION_STATUS_CHANGED,
                subsystem = EventSubsystems.OID4VCI,
                sessionId = current.issuanceSessionId,
                correlationId = current.correlationId,
                instanceId = current.instanceId,
                tenantId = execution.tenantId,
                previousStatus = previous?.status?.name,
                status = current.status.name,
                callback = current.callbackConfig?.let { callback ->
                    SessionCallbackDescriptor(
                        url = callback.url,
                        statuses = callback.statuses.map { it.name },
                        includeData = callback.includeIssuanceData,
                        secretRef = callback.secretRef,
                        signing = callback.signing,
                    )
                },
            ),
        )
    }
}
