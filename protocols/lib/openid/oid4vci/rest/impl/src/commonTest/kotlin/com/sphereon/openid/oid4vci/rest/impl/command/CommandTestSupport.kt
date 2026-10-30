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

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.AppConfigService
import com.sphereon.core.api.conf.ConfigLevel
import com.sphereon.core.api.conf.ConfigService
import com.sphereon.core.api.conf.PrincipalConfigService
import com.sphereon.core.api.conf.TenantConfigService
import com.sphereon.core.api.context.ContextConfig
import com.sphereon.core.api.context.IdkScope
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.log.AsyncLogService
import com.sphereon.core.api.log.LogMessage
import com.sphereon.core.api.log.LogService
import com.sphereon.core.api.log.LoggerConfig
import com.sphereon.core.api.log.SessionLogManager
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.core.events.Event
import com.sphereon.core.events.EventBuilder
import com.sphereon.core.events.EventHub
import com.sphereon.core.events.SessionEventService
import com.sphereon.core.events.UserEventService
import com.sphereon.core.events.impl.DefaultEventBuilder
import com.sphereon.core.events.impl.EventHubImpl
import com.sphereon.di.context.NoOpSessionContext
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionContextManager

/** The collaborators of the offer commands that the command tests stand in for without a backend. */
internal class NoOpSessionLogService(
    override val sessionContext: SessionContext = NoOpSessionContext,
) : SessionLogService {
    override val id: String = "wiring-test-log"
    override val isEnabled: Boolean = false
    override val scope: IdkScope = IdkScope.SESSION
    override val logManager: SessionLogManager get() = throw NotImplementedError("not needed for wiring test")

    override suspend fun setConfig(config: LoggerConfig): LogService = this

    override fun executeAsync(message: LogMessage): IdkResult<Unit, IdkErrorType> = Ok(Unit)

    override fun toAsync(): AsyncLogService = throw NotImplementedError("not needed for wiring test")
}

internal class NoOpContextConfig : ContextConfig {
    override val app: AppConfigService get() = throw NotImplementedError("not needed for wiring test")
    override val tenant: TenantConfigService get() = throw NotImplementedError("not needed for wiring test")
    override val principal: PrincipalConfigService get() = throw NotImplementedError("not needed for wiring test")

    override fun conf(level: ConfigLevel): ConfigService = throw NotImplementedError("not needed for wiring test")
}

internal class TestSessionExecution(
    override val sessionContext: SessionContext = NoOpSessionContext,
) : SessionExecution {
    override val sessionContextManager: SessionContextManager get() = throw NotImplementedError("not needed for wiring test")
    override val log: SessionLogService = NoOpSessionLogService(sessionContext)
    override val conf: ContextConfig = NoOpContextConfig()
}

/**
 * Records every event passed to [emit] so tests can assert on emission without a real event hub backend. A [failure] makes
 * every emission throw, for the tests that need an event service which is down.
 */
internal class RecordingSessionEventService(
    private val failure: Exception? = null,
) : SessionEventService {
    val emitted = mutableListOf<Event>()
    private val hub = EventHubImpl()

    override val scope: IdkScope = IdkScope.SESSION
    override val eventHub: EventHub = hub
    override val parent: UserEventService get() = throw NotImplementedError("not needed for wiring test")
    override val sessionContext: SessionContext = NoOpSessionContext

    override suspend fun emit(event: Event) {
        failure?.let { throw it }
        emitted += event
        hub.publish(event)
    }

    override suspend fun emit(
        event: Event,
        sign: Boolean,
        encrypt: Boolean,
        keyAlias: String?,
        encryptionKeyAlias: String?,
        encryptParts: Set<com.sphereon.core.events.EncryptedPart>,
    ) {
        failure?.let { throw it }
        emitted += event
        hub.publish(event)
    }

    override fun eventBuilder(): EventBuilder = DefaultEventBuilder(IdkScope.SESSION)
}
