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
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.model.ResponseType
import com.sphereon.oauth2.server.authorization.model.ClientType
import kotlinx.serialization.Serializable
import kotlin.time.Instant

/**
 * The single durable store for an authorization server's OAuth2 clients, whether they arrived
 * through dynamic registration (RFC 7591 / RFC 7592) or through an administration surface.
 *
 * This is the persistence seam BEHIND [ClientRegistry], not a second registry: runtime client
 * lookups keep flowing through the single `ClientRegistry` binding, whose implementation
 * overlays configured (`oauth2.clients.*` family) clients on top of whatever this store holds.
 * The volatile in-process map that dynamic registrations used to live in survives restarts
 * only as long as the process does, which made device-flow enrollment (RFC 8628) unusable for
 * provisioned infrastructure clients such as hand-off screens; implementations of this store
 * remove that gap. An in-memory default ships in `oauth2-server-authorization-impl`; EDK ships
 * a Postgres-backed implementation in `vdx/edk/lib/oauth2/server/authorization/store-postgres/`
 * that swaps in via `replaces` when the module is on the classpath.
 *
 * Tenancy: every method takes a `tenantId`, mirroring [SigningKeyStore]. Single-tenant
 * deployments pass a fixed default (typically `"default"`).
 *
 * Secrets: plaintext client secrets are NEVER persisted. The register/update caller hashes the
 * secret with the deployment's verifier and hands only the hash to [save]; verification happens
 * through `ClientRegistry.verifyClientCredentials`. Public clients (device-flow screens) carry
 * a null hash.
 *
 * No contentRevision: the request-scoped configured-client memoization re-resolves every
 * inbound session, so unlike [SigningKeyStore] there is no AppScope snapshot that would need an
 * atomically advanced collection revision. Add one alongside an AppScope cache if one ever
 * reads this store.
 */
interface ClientRegistrationStore {
    /**
     * Inserts a new registration or replaces the existing one for the same
     * `(tenantId, authorizationServerId, clientId)`. Implementations MUST reject saving over a
     * REVOKED row when the saved record carries [ClientRegistrationStatus.ACTIVE]
     * (revocation is one-way through [revoke], including when save races with revoke).
     */
    suspend fun save(
        tenantId: String,
        registration: StoredClientRegistration,
    ): IdkResult<Unit, ClientRegistrationStoreError>

    /**
     * Returns the registration for [clientId] on [authorizationServerId] within [tenantId],
     * including REVOKED tombstones, or null when absent. Callers decide whether a tombstone is
     * servable; storage stays neutral so admin views can reconstruct history like signing-key
     * stores do.
     */
    suspend fun findByClientId(
        tenantId: String,
        authorizationServerId: String,
        clientId: String,
    ): IdkResult<StoredClientRegistration?, ClientRegistrationStoreError>

    /**
     * Revokes the registration: the row transitions to [ClientRegistrationStatus.REVOKED] and
     * stops being served by the registry. Returns false when the client does not exist or is
     * already revoked.
     */
    suspend fun revoke(
        tenantId: String,
        authorizationServerId: String,
        clientId: String,
    ): IdkResult<Boolean, ClientRegistrationStoreError>

    /**
     * Removes the registration outright and returns the row as it stood, so the caller can purge
     * the secret the row referenced. Prefer [revoke], which keeps the audit trail; this exists
     * for an administration surface whose contract is removal rather than tombstoning. Returns
     * null when the client does not exist.
     */
    suspend fun delete(
        tenantId: String,
        authorizationServerId: String,
        clientId: String,
    ): IdkResult<StoredClientRegistration?, ClientRegistrationStoreError>

    /**
     * Lists registrations for one authorization server, newest-first by registration time,
     * paginated. Includes REVOKED rows so operator views see them; callers filter by status when
     * needed.
     */
    suspend fun list(
        tenantId: String,
        authorizationServerId: String,
        limit: Int = 100,
        offset: Int = 0,
    ): IdkResult<List<StoredClientRegistration>, ClientRegistrationStoreError>
}

/**
 * A dynamically registered OAuth2 client as persisted by [ClientRegistrationStore].
 *
 * Deliberately narrower than `com.sphereon.oauth2.server.authorization.model.ClientRegistration`:
 * that type carries non-serializable contextual metadata and defaults tuned for config-defined
 * clients. Registries map this record onto a full `ClientRegistration` (filling the same
 * defaults the config binder uses) so token-path consumers cannot distinguish provenance.
 */
@Serializable
data class StoredClientRegistration(
    val tenantId: String,
    /**
     * The authorization server the client belongs to. A tenant hosts several servers, and a
     * client id is only unique within one of them, so this is part of the identity rather than
     * a filter.
     */
    val authorizationServerId: String,
    val clientId: String,
    /** Server-generated secret hash; null for public clients. Plaintext secrets never persist. */
    val clientSecretHash: String? = null,
    /**
     * Handle into the secret abstraction holding the write-once secret, with the record version
     * that identifies the exact stored revision. Both are null for a public client, and they are
     * set or cleared together so a rotation cannot strand the previous value.
     */
    val secretResourceHandle: String? = null,
    val secretRecordVersion: Long? = null,
    val status: ClientRegistrationStatus = ClientRegistrationStatus.ACTIVE,
    val registeredAt: Instant,
    val updatedAt: Instant,
    val registration: DynamicClientRegistrationMetadata,
) {
    init {
        require((secretResourceHandle == null) == (secretRecordVersion == null)) {
            "A secret resource handle and its record version are set or cleared together"
        }
    }
}

/**
 * Every client property the authorization server honours, plus a free-form `metadata` bag for
 * issuance-policy claims (for example `handoff_role` on screen clients). This is the persisted
 * counterpart of `ClientRegistration` and carries the same fields, so a client survives a
 * round trip through storage without losing anything an administration surface set.
 * Serialized as JSON by durable implementations, so adding fields is backward compatible.
 */
@Serializable
data class DynamicClientRegistrationMetadata(
    val clientName: String? = null,
    val clientType: ClientType = ClientType.CONFIDENTIAL,
    /** A disabled client stays registered and is refused at the token and authorization endpoints. */
    val enabled: Boolean = true,
    val grantTypes: List<GrantType> = emptyList(),
    val responseTypes: List<ResponseType> = emptyList(),
    val redirectUris: List<String> = emptyList(),
    val allowedScopes: List<String>? = null,
    val defaultAccessTokenAudience: String? = null,
    val allowedAccessTokenAudiences: Set<String> = emptySet(),
    /** Roles minted as the `roles` claim on client_credentials access tokens. */
    val principalRoles: List<String> = emptyList(),
    val tokenEndpointAuthMethod: ClientAuthenticationMethod = ClientAuthenticationMethod.NONE,
    val tokenEndpointAuthSigningAlg: List<String>? = null,
    val jwks: List<Jwk>? = null,
    val jwksUri: String? = null,
    /** Null defers to the runtime default, which requires PKCE for a public client. */
    val requirePkce: Boolean? = null,
    val requirePushedAuthorizationRequests: Boolean = false,
    val dpopBoundAccessTokens: Boolean = false,
    val accessTokenLifetime: Int = 3600,
    val refreshTokenLifetime: Int? = null,
    val authorizationCodeLifetime: Int = 600,
    val credentialConfigurationIds: Set<String>? = null,
    val trustedAttesterIssuers: List<String>? = null,
    val trustedAttesterJwks: List<Jwk>? = null,
    val trustedAttesterJwksUris: List<String>? = null,
    val postLogoutRedirectUris: List<String> = emptyList(),
    val frontchannelLogoutUri: String? = null,
    val frontchannelLogoutSessionRequired: Boolean = false,
    val backchannelLogoutUri: String? = null,
    val backchannelLogoutSessionRequired: Boolean = false,
    val idTokenSignedResponseAlg: String? = null,
    val authorizationSignedResponseAlg: String? = null,
    val authorizationEncryptedResponseAlg: String? = null,
    val authorizationEncryptedResponseEnc: String? = null,
    val requestObjectSigningAlg: String? = null,
    val requestUris: List<String> = emptyList(),
    val tlsClientAuthSubjectDn: String? = null,
    val tlsClientAuthSanDns: String? = null,
    val tlsClientAuthSanEmail: String? = null,
    val tlsClientAuthSanIp: String? = null,
    val tlsClientAuthSanUri: String? = null,
    val tlsClientCertificateBoundAccessTokens: Boolean = false,
    val policyIds: List<String> = emptyList(),
    /** Issuance-policy claims minted into access tokens (allowlisted names only at mint time). */
    val metadata: Map<String, String> = emptyMap(),
    /** Epoch seconds after which the registration is no longer served; null for a registration without expiry. */
    val expiresAt: Long? = null,
)

/**
 * Lifecycle state of a stored client registration. `ACTIVE` registrations are served by the
 * registry; `REVOKED` is a one-way tombstone kept for audit, never served again.
 */
enum class ClientRegistrationStatus {
    ACTIVE,
    REVOKED,
}

/**
 * Typed errors surfaced by [ClientRegistrationStore], mirroring the [SigningKeyStoreError]
 * discipline: diagnostics carry an operation name and MUST NOT reach wire responses.
 */
sealed class ClientRegistrationStoreError {
    data class StorageFailure(
        val operation: String,
        val details: String,
    ) : ClientRegistrationStoreError()

    data class DuplicateClient(
        val tenantId: String,
        val clientId: String,
    ) : ClientRegistrationStoreError()

    data class ClientNotFound(
        val tenantId: String,
        val clientId: String,
    ) : ClientRegistrationStoreError()
}
