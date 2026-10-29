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
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import kotlin.time.Instant

/**
 * Per-tenant durable registry of OAuth2 AS signing keys with rotation lifecycle.
 *
 * Replaces the single-key-by-alias seam that the early IDK shipped: the AS now tracks one or
 * more keys per tenant in a state machine ([OAuth2SigningKeyState]: `ACTIVE` / `LEGACY` /
 * `DISABLED`) so a key rotation can introduce a new signer without invalidating in-flight
 * tokens. A tenant may have one active signer per algorithm. JWKS publishes both `ACTIVE` and
 * `LEGACY` keys; signatures without an algorithm preference use the highest-priority `ACTIVE`
 * key; verification by `kid` succeeds against any non-disabled entry.
 *
 * **The store itself never holds private key bytes.** Each [OAuth2SigningKey] carries a
 * [com.sphereon.crypto.core.KeyInfo] reference (`kid`, `alias`, `providerId`, algorithm
 * metadata); the actual bytes live where the deployment puts them — software keystore in dev,
 * AWS KMS / Azure Key Vault / HashiCorp Vault Transit in production. A DB compromise of this
 * store leaks the kid catalog and the rotation timestamps; it does NOT leak signing material.
 *
 * Tenancy: every method takes a `tenantId` so a multi-tenant deployment partitions keys per
 * realm. Single-tenant deployments pass a fixed default (typically `"default"`).
 *
 * Implementations live downstream: an in-memory implementation ships in
 * `oauth2-server-authorization-impl` for IDK consumers and tests; a Postgres-backed impl ships
 * in EDK (`vdx/edk/lib/oauth2/server/authorization/store-postgres/`) for production.
 */
interface SigningKeyStore {
    /**
     * Monotonic revision of the authoritative signing-key collection for [tenantId].
     *
     * Implementations MUST advance this value atomically with every insert, update, or delete
     * that can change signing-key selection or publication. Persistent implementations must keep
     * the revision in the same database as the key collection so every replica observes the same
     * value and out-of-band database mutations cannot leave an AppScope snapshot valid forever.
     */
    suspend fun contentRevision(tenantId: String): IdkResult<Long, SigningKeyStoreError>

    /**
     * Returns the highest-priority `ACTIVE` key for [tenantId], or null when none is
     * registered. The AS sign paths (access token, id token, JARM, signed metadata, logout
     * token) MUST use this entry; rotation changes which key it returns.
     */
    suspend fun getActive(tenantId: String): IdkResult<OAuth2SigningKey?, SigningKeyStoreError>

    /**
     * Returns every key for [tenantId] in any state OTHER than `DISABLED` — i.e. the JWKS
     * publication set. `ACTIVE` keys verify both new and old tokens; `LEGACY` keys verify
     * tokens issued before the most recent rotation but cannot sign new ones. Order is
     * priority-descending so JWKS consumers see the current signer first.
     */
    suspend fun listPublishable(tenantId: String): IdkResult<List<OAuth2SigningKey>, SigningKeyStoreError>

    /**
     * Returns every key for [tenantId] regardless of state. Operator views (admin console,
     * audit reports) consume this; runtime sign / verify paths SHOULD prefer [getActive] /
     * [listPublishable] to avoid surfacing disabled key bytes.
     */
    suspend fun listAll(tenantId: String): IdkResult<List<OAuth2SigningKey>, SigningKeyStoreError>

    /**
     * Look up a single key by its [kid] within [tenantId]. Returns null when no key with that
     * id is registered for the tenant. Used by signature-verification paths that read the
     * inbound JWT header's `kid` claim.
     */
    suspend fun findByKid(
        tenantId: String,
        kid: String,
    ): IdkResult<OAuth2SigningKey?, SigningKeyStoreError>

    /**
     * Insert a new key into the store. The store does NOT generate the key material — that
     * happens in the KMS provider; the caller passes the resulting [KeyInfo] alongside the
     * lifecycle metadata. Inserting an `ACTIVE` key does NOT auto-demote the previous active
     * (callers MUST use [rotate] for that pattern); this method is intentionally low-level so
     * a deployment can backfill historical keys at startup without triggering rotation events.
     */
    suspend fun register(key: OAuth2SigningKey): IdkResult<Unit, SigningKeyStoreError>

    /**
     * Atomically adds an eligible ACTIVE signing descriptor without changing the current
     * default signer or demoting any existing key. The store derives the appended key's
     * priority; caller-supplied priority is never authoritative for this operation.
     *
     * Requires an existing eligible default, an unused tenant-local kid, and an ACTIVE key
     * whose notBefore has arrived. On failure the collection and its revision remain unchanged.
     * The returned descriptor carries the durable priority actually selected by the store.
     * Implementations that cannot provide this atomic guarantee must fail closed.
     */
    suspend fun appendPreservingDefault(key: OAuth2SigningKey): IdkResult<OAuth2SigningKey, SigningKeyStoreError> =
        Err(SigningKeyStoreError.StorageFailure(
            operation = "appendPreservingDefault",
            details = "Atomic default-preserving signing-key append is not supported by this store",
        ))

    /**
     * Atomic rotation: insert [newActive] as the highest-priority `ACTIVE` key for its
     * tenant and algorithm, and demote currently-`ACTIVE` keys for that same algorithm to
     * `LEGACY`. Active keys for other algorithms remain available so clients can select any
     * signing algorithm the server advertises. Returns the rotated keys
     * (the new active and the demoted previous-active(s)) so the caller can audit the
     * transition.
     *
     * The atomicity guarantee matters because a non-atomic rotation would briefly publish two
     * `ACTIVE` keys (RPs cache the JWKS and may pick the wrong one for verification) or
     * briefly publish zero (no key to sign with).
     */
    suspend fun rotate(newActive: OAuth2SigningKey): IdkResult<RotationResult, SigningKeyStoreError>

    /**
     * Move the key identified by [kid] in [tenantId] to the [newState]. Used by the cleanup
     * job that demotes `LEGACY` keys to `DISABLED` once their issuance window has elapsed
     * past every issued token's lifetime. Returns false when the key does not exist or is
     * already in [newState].
     */
    suspend fun setState(
        tenantId: String,
        kid: String,
        newState: OAuth2SigningKeyState,
    ): IdkResult<Boolean, SigningKeyStoreError>
}

/**
 * Single signing-key entry tracked by [SigningKeyStore]. Composes the AS-specific lifecycle
 * metadata (state, priority, timestamps) on top of the [KeyInfo] that identifies the actual
 * key material in the KMS provider.
 *
 * The [keyInfo] is the single source of truth for the wire-visible identity: its `kid` is
 * what JWS headers and the JWKS endpoint publish; its `alias` + `providerId` is what the
 * KMS uses to address the actual private bytes; its `signatureAlgorithm` is what the JWS
 * library uses for the `alg` header. The store does NOT persist private bytes — only the
 * KeyInfo descriptor and the lifecycle metadata.
 *
 * Non-null guarantees: `keyInfo.kid` and `keyInfo.signatureAlgorithm` are nullable on the
 * [KeyInfo] type for general use, but a registered AS signing key MUST carry both. The
 * `init` block validates this at construction so downstream sign / JWKS paths can call
 * [kid] and [algorithm] without nullability noise.
 */
data class OAuth2SigningKey(
    /**
     * Per-tenant scoping. Single-tenant deployments use a fixed default value
     * (typically `"default"`); multi-tenant deployments scope keys per realm so a tenant's
     * key rotation does not affect other tenants' tokens.
     */
    val tenantId: String,
    /**
     * Reference to the actual key material, held in the KMS provider. The store does NOT
     * persist the private bytes — only the descriptor the KMS uses to locate them.
     * `keyInfo.alias` + `keyInfo.providerId` together address the key in the deployment's
     * KMS configuration; `keyInfo.kid` is the wire-visible identifier that JWS headers and
     * the JWKS endpoint publish.
     *
     * Persisted by the Postgres impl as a small projection of these fields (kid + alias +
     * provider_id + alg); the in-memory impl holds the full object directly.
     */
    val keyInfo: KeyInfo<KeyType>,
    /**
     * Current lifecycle state. See [OAuth2SigningKeyState] for transitions.
     */
    val state: OAuth2SigningKeyState,
    /**
     * Sort order among same-tenant `ACTIVE` keys. The highest [priority] wins for new
     * signatures; ties are broken by [createdAt] (newer first). Operators can pre-stage a
     * future signer at lower priority and promote it by raising the priority during a
     * controlled rollout.
     */
    val priority: Int,
    /**
     * Wall-clock instant the key was registered with the store. Drives JWKS ordering as a
     * tiebreaker to [priority] and is preserved across state transitions for audit purposes.
     */
    val createdAt: Instant,
    /**
     * Earliest instant the key may sign new tokens. Lets an operator pre-stage a key in
     * `ACTIVE` state but defer its first use (e.g. to align with a deployment cutover); sign
     * paths skip keys whose `notBefore` is in the future. Defaults to [createdAt].
     */
    val notBefore: Instant,
) {
    init {
        require(!keyInfo.kid.isNullOrBlank()) {
            "OAuth2SigningKey requires keyInfo.kid (the wire-visible JWS / JWKS identifier); got null/blank"
        }
        require(keyInfo.signatureAlgorithm != null) {
            "OAuth2SigningKey requires keyInfo.signatureAlgorithm (drives the JWS `alg` header); got null"
        }
    }

    /**
     * Wire-visible key identifier. Convenience accessor over [keyInfo]'s `kid`; non-null
     * guaranteed by [init]. Carried as the JWS `kid` header on every token signed with this
     * key and as the JWKS entry's `kid`, so RPs can pick the right entry for verification.
     */
    val kid: String get() = keyInfo.kid!!

    /**
     * JWS algorithm this key signs with (e.g. `RS256`, `ES256`, `EdDSA`). Convenience
     * accessor over [keyInfo]'s `signatureAlgorithm`; non-null guaranteed by [init].
     * Surfaced as the JWKS `alg` parameter and as the sign path's JWS `alg` header.
     */
    val algorithm: SignatureAlgorithm get() = keyInfo.signatureAlgorithm!!
}

/**
 * Lifecycle state of an [OAuth2SigningKey]. Transitions are one-way except for emergency
 * undo by the operator (which is not part of the SPI; use direct DB intervention with audit
 * log).
 *
 * `ACTIVE` → `LEGACY`: triggered by [SigningKeyStore.rotate] when a new key takes over.
 * `LEGACY` → `DISABLED`: triggered by the cleanup job once the issuance window has elapsed.
 * `DISABLED` → (terminal): never returns to publishable / signable state.
 */
enum class OAuth2SigningKeyState {
    /**
     * Eligible to sign new tokens AND to verify existing tokens. Published in JWKS. The
     * highest-priority ACTIVE key for a tenant is its default signer, while algorithm-aware
     * paths select the highest-priority ACTIVE key for the requested algorithm.
     */
    ACTIVE,

    /**
     * NOT eligible to sign new tokens, but still eligible to verify tokens issued before
     * the most recent rotation. Published in JWKS so RPs caching the previous JWKS still
     * find the verification key for in-flight tokens. Once every token issued against this
     * key has expired, the cleanup job moves it to `DISABLED`.
     */
    LEGACY,

    /**
     * Not eligible to sign or verify; not published in JWKS. Retained as a tombstone so the
     * `kid` is never reused for a new key — reusing a kid would let an attacker who captured
     * an old token replay it against a fresh signer with the same id. Operator can prune
     * tombstones once compliance retention has elapsed (typically 1-2 years past expiry of
     * any token signed with the key).
     */
    DISABLED,
}

/**
 * Outcome of [SigningKeyStore.rotate]. Lets the caller observe both the new active key and
 * the keys that were demoted, so an audit event can record the full transition (old kid(s)
 * → new kid).
 */
data class RotationResult(
    val newActive: OAuth2SigningKey,
    val demotedToLegacy: List<OAuth2SigningKey>,
)

/**
 * Typed errors surfaced by [SigningKeyStore]. Most operations return one of these wrapped in
 * an [IdkResult.Err]; the OAuth2 sign / verify paths translate them into appropriate wire
 * responses (typically `server_error` since a missing or unhealthy signing key is an AS
 * outage, not a client problem).
 */
sealed class SigningKeyStoreError {
    /**
     * The store backend (DB, in-memory map) failed to read or write. [operation] names the
     * SPI method that triggered it; [details] is a free-text diagnostic that MUST NOT be
     * surfaced to RPs.
     */
    data class StorageFailure(
        val operation: String,
        val details: String,
    ) : SigningKeyStoreError()

    /**
     * Caller attempted to insert a key whose `kid` already exists for the same tenant. The
     * store enforces uniqueness so a kid is never reused (see [OAuth2SigningKeyState.DISABLED]
     * for the rationale).
     */
    data class DuplicateKid(
        val tenantId: String,
        val kid: String,
    ) : SigningKeyStoreError()

    /**
     * Caller asked for a state transition on a kid that does not exist for [tenantId].
     */
    data class KeyNotFound(
        val tenantId: String,
        val kid: String,
    ) : SigningKeyStoreError()
}
