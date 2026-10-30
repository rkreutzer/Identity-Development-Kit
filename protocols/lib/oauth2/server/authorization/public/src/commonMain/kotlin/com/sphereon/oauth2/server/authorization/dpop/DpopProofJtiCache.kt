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

package com.sphereon.oauth2.server.authorization.dpop

import kotlin.time.Instant

/**
 * Replay-protection cache for DPoP proof JWT `jti` claims observed at the OAuth2 authorization
 * server (token endpoint, PAR endpoint). RFC 9449 §11.1 SHOULD: track jti values for the proof
 * iat tolerance window so a captured proof cannot be replayed before its `iat` ages out.
 *
 * Implementations must be thread-safe and free expired entries on read so memory stays bounded.
 *
 * Distinct from `com.sphereon.oauth2.server.resource.cache.DpopNonceCache` (resource-server side)
 * to keep the authorization-server impl module independent of the resource-server impl module.
 *
 * **Tenancy partitioning contract**:
 *
 * IDK ships an in-memory implementation that is single-tenant: all observed `jti` values share
 * one keyspace. Implementations backing a multi-tenant deployment MUST partition the `jti`
 * keyspace by tenant so that tenant A cannot block tenant B from accepting a proof that happens
 * to use the same `jti`, nor confirm replay of a proof tenant B has not yet seen. Hosted durable
 * implementations (Redis, SQL, or tenant-scoped stores) are responsible for this
 * partitioning, using an explicit tenant cache key or per-tenant table partition.
 * Failing to partition lets a hostile tenant pre-poison `jti` values to block legitimate proofs
 * on other tenants.
 */
interface DpopProofJtiCache {
    /**
     * Atomically reserves a verified proof replay address until [expiresAt]. Only `true` permits
     * authentication to continue. `false` covers replay and unavailable storage; exceptions
     * must never be interpreted as acceptance. Cancellation remains cancellation.
     * The default deliberately refuses implementations that have only the legacy peek/mark API.
     */
    suspend fun recordIfNew(jti: String, expiresAt: Instant): Boolean = false

    /**
     * Returns `true` when [jti] is still present (and not expired) in the cache, indicating a
     * replay. Returns `false` when the jti has never been observed or its previous record has
     * already expired and been evicted.
     */
    suspend fun hasBeenUsed(jti: String): Boolean

    /**
     * Records [jti] as used until [expiresAt]. Subsequent [hasBeenUsed] calls before that instant
     * MUST return `true`.
     */
    suspend fun markAsUsed(
        jti: String,
        expiresAt: Instant,
    )

    /** Drops every recorded jti. Intended for tests and shutdown. */
    suspend fun clear()
}
