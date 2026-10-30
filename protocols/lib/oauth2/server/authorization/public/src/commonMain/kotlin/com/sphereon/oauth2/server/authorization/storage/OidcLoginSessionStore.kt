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
import com.sphereon.core.api.error.ErrorCategory
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.oauth2.server.authorization.provider.AuthenticationMethod
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement
import kotlin.time.Instant

/**
 * Browser login session created on successful end-user authentication and addressed by the opaque
 * `oidc_login_sid` cookie. Distinct from [PendingAuthorizationSessionStore], which bookmarks a
 * single authorization request between `/authorize` and `/authorize/callback`. A login session
 * spans many authorization requests and is the substrate `prompt`, `max_age` and `id_token_hint`
 * read in subsequent groups.
 *
 * Three lifetimes apply:
 * - [createdAt] freezes the moment the session record was minted.
 * - [authTime] freezes the moment the underlying user authentication completed (RFC 9068 / OIDC
 *   Core 1.0 §2 `auth_time`). For step-up flows the AS may refresh the session's
 *   [idleExpiresAt] without resetting [authTime].
 * - [absoluteExpiresAt] caps total wall-clock lifetime; [idleExpiresAt] caps inactivity.
 */
@Serializable
data class OidcLoginSession(
    val sessionId: String,
    val sub: String,
    val authTime: Instant,
    val authMethod: AuthenticationMethod,
    val acr: String? = null,
    val amr: List<String>? = null,
    val claims: Map<String, JsonElement> = emptyMap(),
    val createdAt: Instant,
    val absoluteExpiresAt: Instant,
    val idleExpiresAt: Instant,
    /**
     * RPs that received an id_token bound to this login session, keyed by `client_id`. The
     * value is the OIDC `sid` claim emitted in the id_token (OIDC Core 1.0 §2 / Back-Channel
     * Logout 1.0 §4.1). Populated by [com.sphereon.oauth2.server.authorization.provider.SessionParticipationRecorder]
     * at id_token issuance time and consumed by the end-session orchestrator to fan out
     * Front-Channel and Back-Channel logout requests only to RPs that actually participated
     * in this session, per OIDC Back-Channel Logout 1.0 §2.4 / Front-Channel Logout 1.0 §3.
     */
    val rpSessions: Map<String, String> = emptyMap(),
)

/**
 * Storage abstraction for [OidcLoginSession] records keyed by [OidcLoginSession.sessionId]. Records
 * must outlive individual HTTP requests. The default in-process store lives at AppScope; a
 * durable adapter may live at SessionScope when its persisted state is tenant and AS scoped.
 *
 * Per `feedback_idk_persistence_drivers.md` IDK ships in-memory only; EDK / VDX overlays supply
 * durable replacements via `@ContributesBinding(replaces = [...])`.
 */
interface OidcLoginSessionStore {
    /**
     * Persist [session] keyed by [OidcLoginSession.sessionId]. Last-write-wins to mirror the
     * other in-memory IDK stores; durable backends MAY tighten this if their semantics demand.
     */
    suspend fun create(session: OidcLoginSession): IdkResult<OidcLoginSession, OidcLoginSessionStoreError>

    /**
     * Look up an active session by id. Returns `Ok(null)` when the record is missing OR has
     * passed [OidcLoginSession.absoluteExpiresAt] / [OidcLoginSession.idleExpiresAt]; expiry is
     * indistinguishable from absence to the caller and the entry is removed on observation.
     */
    suspend fun findById(sessionId: String): IdkResult<OidcLoginSession?, OidcLoginSessionStoreError>

    /**
     * Bump [OidcLoginSession.idleExpiresAt] to `now + idleTtlSeconds` while leaving
     * [OidcLoginSession.absoluteExpiresAt] untouched. No-op (`Ok(null)`) when the session is
     * absent or already past its absolute expiry. Used by the cookie-read path to keep an active
     * browser session alive across consecutive authorization requests.
     */
    suspend fun touch(
        sessionId: String,
        now: Instant,
        idleTtlSeconds: Int,
    ): IdkResult<OidcLoginSession?, OidcLoginSessionStoreError>

    /**
     * Atomically merge an RP participation entry into [OidcLoginSession.rpSessions]. The
     * id_token issuance path drives this on every successful token mint so the end-session
     * orchestrator can later fan out Front-Channel / Back-Channel logout to the RPs that
     * actually held a session backed by this login. Last-write-wins on the `(clientId, sid)`
     * tuple. Returns `Ok(null)` when the session id is unknown OR has already expired (the
     * caller still got a successful token issuance, but the recorder degrades to a warn).
     */
    suspend fun recordRpParticipation(
        sessionId: String,
        clientId: String,
        sid: String,
    ): IdkResult<OidcLoginSession?, OidcLoginSessionStoreError>

    /**
     * Atomically delete the session for [sessionId]. Idempotent: removing an unknown id is a
     * success. The OIDC RP-initiated logout flow drives this.
     */
    suspend fun revoke(sessionId: String): IdkResult<Unit, OidcLoginSessionStoreError>

    /**
     * Delete every session whose [OidcLoginSession.sub] matches. Used for back-channel logout and
     * administrative kill-all paths. Idempotent.
     */
    suspend fun revokeAllForUser(sub: String): IdkResult<Unit, OidcLoginSessionStoreError>
}

/**
 * Errors emitted by [OidcLoginSessionStore]. Mirrors [FederationSessionStoreError] in shape so
 * transports can dispatch on stable [code] values without parsing free-form messages.
 */
sealed interface OidcLoginSessionStoreError : IdkErrorType {
    data class StorageFailure(
        val reason: String,
        val cause: Throwable? = null,
        override val code: String = "OIDC_LOGIN_SESSION_STORAGE_FAILURE",
        override val message: IdkError.Message =
            IdkError.Message(
                i18nKey = "oauth2.oidc.login-session.error.storage-failure",
                defaultMessage = "OIDC login session store failure: $reason",
            ),
        override val severity: IdkError.Severity = IdkError.Severity.ERROR,
        override val category: ErrorCategory = ErrorCategory.INTERNAL,
        override val exception: Throwable? = cause,
        override val causes: List<IdkErrorType> = emptyList(),
        override val meta: Map<String, Any?> = mapOf("reason" to reason),
    ) : OidcLoginSessionStoreError
}
