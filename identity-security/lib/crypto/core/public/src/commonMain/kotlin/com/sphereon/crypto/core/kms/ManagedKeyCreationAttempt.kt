/* Copyright 2026 Sphereon International B.V. */
package com.sphereon.crypto.core.kms

import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext

/** Durable creation authority belongs to the caller's owning transactional journal. */
enum class ManagedKeyCreationAttemptState { UNCLAIMED, CLAIMED, REVOKED }
enum class ManagedKeyCreationAttemptIntent { CREATE_OR_RECOVER, RECOVER_FOR_REVOCATION }

/**
 * In-process capability for providers whose create and alias operations are separate.
 * The token and exact provider/alias come from authenticated owning state, never a wire input.
 * A lost create response permanently removes creation permission; recovery must discover the
 * atomically tagged physical object instead of inferring absence from eventually consistent reads.
 */
class ManagedKeyCreationAttempt(
    val providerId: String,
    val backingAlias: String,
    val operationToken: String,
    private val readState: suspend () -> ManagedKeyCreationAttemptState,
    private val claim: suspend () -> Boolean,
    private val recover: suspend () -> Boolean,
    val intent: ManagedKeyCreationAttemptIntent = ManagedKeyCreationAttemptIntent.CREATE_OR_RECOVER,
    private val confirmRevoked: suspend () -> Unit = {},
) : AbstractCoroutineContextElement(Key) {
    init { require(providerId.isNotBlank() && backingAlias.isNotBlank() && operationToken.isNotBlank() && operationToken.length <= 256) }
    suspend fun state(): ManagedKeyCreationAttemptState = readState()
    suspend fun claimCreateOnce(): Boolean = claim()
    suspend fun authorizeRecovery(): Boolean = recover()
    suspend fun reportRevoked() { check(intent == ManagedKeyCreationAttemptIntent.RECOVER_FOR_REVOCATION); confirmRevoked() }
    companion object Key : CoroutineContext.Key<ManagedKeyCreationAttempt>
}

/** A claimed operation with no currently discoverable receipt must remain recoverable. */
class ManagedKeyCreationUncertainException : IllegalStateException("Managed key creation requires receipt recovery")

/** Exact tagged material is already irreversibly scheduled for revocation. */
class ManagedKeyCreationAlreadyRevokedException : IllegalStateException("Managed key creation receipt is already revoked")
