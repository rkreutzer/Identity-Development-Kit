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

package com.sphereon.oauth2.server.authorization.storage

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Err
import com.sphereon.core.api.error.IdkError
import com.sphereon.oauth2.server.authorization.model.AuthorizationSession

/**
 * Storage abstraction for pending authorization sessions captured at `/authorize` and consumed at
 * `/authorize/callback`. Each entry is a short-lived bookmark of the authorization request that
 * survives the user's hop out to the authentication system and back.
 *
 * The store must be reachable across [com.sphereon.di.session.SessionScope] instances because each
 * inbound HTTP request creates its own session: the redirect flow spans at least two requests
 * (`/authorize` writes; `/authorize/callback` atomically consumes). An in-process map needs
 * AppScope; a durable adapter can live at SessionScope because its database outlives requests.
 */
interface PendingAuthorizationSessionStore {
    /** Atomically obtain and remove an unexpired pending session. Never emulate with find/remove. */
    suspend fun consume(sessionId: String): IdkResult<AuthorizationSession?, IdkError> =
        Err(IdkError.fromString(code = "storage_error", message = "Atomic pending-session consumption is unavailable"))

    /**
     * Persist [session] keyed by [AuthorizationSession.sessionId]. Writes are last-write-wins to
     * mirror the static-map semantics the in-memory implementation replaces; the EDK overlay can
     * tighten this if its persistence guarantees demand it.
     */
    suspend fun create(session: AuthorizationSession): IdkResult<AuthorizationSession, IdkError>

    /**
     * Look up a previously stored session by id. Returns `Ok(null)` when the session is not (or
     * no longer) present, distinguishing absence from storage failure.
     */
    suspend fun findById(sessionId: String): IdkResult<AuthorizationSession?, IdkError>

    /**
     * Atomically delete the session for [sessionId]. Idempotent: removing an unknown id is a
     * success. The callback flow uses this to enforce single-use of the pending record.
     */
    suspend fun remove(sessionId: String): IdkResult<Unit, IdkError>
}
