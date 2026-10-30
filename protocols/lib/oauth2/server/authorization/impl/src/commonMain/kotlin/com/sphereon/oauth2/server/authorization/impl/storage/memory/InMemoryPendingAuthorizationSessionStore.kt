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

package com.sphereon.oauth2.server.authorization.impl.storage.memory

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.oauth2.server.authorization.model.AuthorizationSession
import com.sphereon.oauth2.server.authorization.storage.PendingAuthorizationSessionStore
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.Named
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.CancellationException
import com.sphereon.oauth2.server.authorization.time.OAUTH2_ARTIFACT_CLOCK
import kotlin.time.Clock

/**
 * In-memory backing for [PendingAuthorizationSessionStore] suitable for development, OIDF
 * conformance, and single-node deployments. Bound at [AppScope] because the redirect flow spans
 * multiple HTTP requests (each its own [com.sphereon.di.session.SessionScope] instance), so the
 * map must outlive any individual session instance.
 *
 * Per `feedback_idk_persistence_drivers.md` IDK ships in-memory only; EDK and product overlays
 * supply durable replacements via `@ContributesBinding(replaces = [...])`.
 */
@Inject
@SingleIn(AppScope::class)
@ContributesBinding(AppScope::class, binding = binding<PendingAuthorizationSessionStore>())
class InMemoryPendingAuthorizationSessionStore(
    @param:Named(OAUTH2_ARTIFACT_CLOCK) private val clock: Clock = Clock.System,
) : PendingAuthorizationSessionStore {
    private val mutex = Mutex()
    private val sessions = mutableMapOf<String, AuthorizationSession>()

    override suspend fun consume(sessionId: String): IdkResult<AuthorizationSession?, IdkError> =
        try {
            Ok(mutex.withLock { sessions.remove(sessionId)?.takeIf { it.expiresAt > clock.now() } })
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { Err(IdkError.fromString(code = "storage_error", message = "Failed to consume pending authorization session")) }

    override suspend fun create(session: AuthorizationSession): IdkResult<AuthorizationSession, IdkError> =
        try {
            mutex.withLock { sessions[session.sessionId] = session }
            Ok(session)
        } catch (expected: Exception) {
            Err(
                IdkError.fromString(
                    code = "storage_error",
                    message = "Failed to store pending authorization session: ${expected.message}",
                ),
            )
        }

    override suspend fun findById(sessionId: String): IdkResult<AuthorizationSession?, IdkError> =
        try {
            Ok(mutex.withLock { sessions[sessionId] })
        } catch (expected: Exception) {
            Err(
                IdkError.fromString(
                    code = "storage_error",
                    message = "Failed to look up pending authorization session: ${expected.message}",
                ),
            )
        }

    override suspend fun remove(sessionId: String): IdkResult<Unit, IdkError> =
        try {
            mutex.withLock { sessions.remove(sessionId) }
            Ok(Unit)
        } catch (expected: Exception) {
            Err(
                IdkError.fromString(
                    code = "storage_error",
                    message = "Failed to remove pending authorization session: ${expected.message}",
                ),
            )
        }
}
