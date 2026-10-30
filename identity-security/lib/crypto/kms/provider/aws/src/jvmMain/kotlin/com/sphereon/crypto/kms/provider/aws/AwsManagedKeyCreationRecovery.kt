/* Copyright 2026 Sphereon International B.V. */
package com.sphereon.crypto.kms.provider.aws

import aws.sdk.kotlin.services.kms.KmsClient
import aws.sdk.kotlin.services.kms.withConfig
import aws.sdk.kotlin.services.kms.model.*
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.kms.ManagedKeyCreationAttempt
import com.sphereon.crypto.core.kms.ManagedKeyCreationAttemptState
import com.sphereon.crypto.core.kms.ManagedKeyCreationAttemptIntent
import com.sphereon.crypto.core.kms.ManagedKeyCreationAlreadyRevokedException
import com.sphereon.crypto.core.kms.ManagedKeyCreationUncertainException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive

internal const val MANAGED_OPERATION_TAG = "sphereon:managed-key-operation"
internal const val MANAGED_OPERATION_PURPOSE_TAG = "sphereon:managed-key-purpose"
internal const val MANAGED_OPERATION_PURPOSE = "durable-operation-v1"

internal fun managedCreationTags(attempt: ManagedKeyCreationAttempt) = listOf(
    Tag { tagKey = MANAGED_OPERATION_TAG; tagValue = attempt.operationToken },
    Tag { tagKey = MANAGED_OPERATION_PURPOSE_TAG; tagValue = MANAGED_OPERATION_PURPOSE },
)

internal suspend fun recoverManagedCreationKey(
    client: KmsClient, attempt: ManagedKeyCreationAttempt, algorithm: SignatureAlgorithm,
): String {
    check(attempt.authorizeRecovery() && attempt.state() == ManagedKeyCreationAttemptState.CLAIMED) { "Managed creation recovery is not authorized" }
    val matches = linkedSetOf<String>()
    var revoked = false
    val seenMarkers = mutableSetOf<String>()
    var marker: String? = null
    var pages = 0
    do {
        currentCoroutineContext().ensureActive()
        check(++pages <= 1000) { "Managed creation recovery exceeded its bounded scan" }
        val page = client.listKeys(ListKeysRequest { this.marker = marker; limit = 1000 })
        for (entry in page.keys.orEmpty()) {
            val id = entry.keyId?.takeIf(String::isNotBlank) ?: error("Managed creation scan key identity is missing")
            if (!hasManagedCreationTags(client, id, attempt)) continue
            val metadata = client.describeKey(DescribeKeyRequest { keyId = id }).keyMetadata ?: error("Managed creation metadata is missing")
            val pending = metadata.keyState == KeyState.PendingDeletion && attempt.intent == ManagedKeyCreationAttemptIntent.RECOVER_FOR_REVOCATION
            require(metadata.keyId == id && ((metadata.enabled == true && metadata.keyState == KeyState.Enabled) || pending) &&
                metadata.keyUsage == KeyUsageType.SignVerify && metadata.origin == OriginType.AwsKms &&
                metadata.keyManager == KeyManagerType.Customer && !metadata.arn.isNullOrBlank() && metadata.keySpec == expectedManagedKeySpec(algorithm)) {
                "Managed creation receipt does not match the requested key"
            }
            revoked = pending
            matches += id
            check(matches.size <= 1) { "Managed creation token identifies multiple keys" }
        }
        marker = if (page.truncated) page.nextMarker?.takeIf { it.isNotBlank() && seenMarkers.add(it) }
            ?: error("Managed creation key pagination is invalid") else null
    } while (marker != null)
    check(attempt.authorizeRecovery() && attempt.state() == ManagedKeyCreationAttemptState.CLAIMED) { "Managed creation authority changed" }
    val receipt = matches.singleOrNull() ?: throw ManagedKeyCreationUncertainException()
    if (revoked) { attempt.reportRevoked(); throw ManagedKeyCreationAlreadyRevokedException() }
    return receipt
}

internal suspend fun hasManagedCreationTags(client: KmsClient, id: String, attempt: ManagedKeyCreationAttempt): Boolean {
    val tags = linkedMapOf<String, String>()
    val seenMarkers = mutableSetOf<String>()
    var marker: String? = null
    var pages = 0
    do {
        currentCoroutineContext().ensureActive()
        check(++pages <= 100) { "Managed creation tag recovery exceeded its bounded scan" }
        val page = client.listResourceTags(ListResourceTagsRequest { keyId = id; this.marker = marker; limit = 50 })
        for (tag in page.tags.orEmpty()) {
            val key = tag.tagKey ?: error("Managed creation tag key is missing")
            if (key !in setOf(MANAGED_OPERATION_TAG, MANAGED_OPERATION_PURPOSE_TAG)) continue
            val value = tag.tagValue ?: error("Managed creation tag value is missing")
            check(tags.put(key, value) == null) { "Managed creation purpose tag is duplicated" }
        }
        marker = if (page.truncated) page.nextMarker?.takeIf { it.isNotBlank() && seenMarkers.add(it) }
            ?: error("Managed creation tag pagination is invalid") else null
    } while (marker != null)
    return tags[MANAGED_OPERATION_TAG] == attempt.operationToken && tags[MANAGED_OPERATION_PURPOSE_TAG] == MANAGED_OPERATION_PURPOSE
}

internal fun expectedManagedKeySpec(algorithm: SignatureAlgorithm): KeySpec = when (algorithm) {
    SignatureAlgorithm.ECDSA_SHA256 -> KeySpec.EccNistP256
    SignatureAlgorithm.ECDSA_SHA384 -> KeySpec.EccNistP384
    SignatureAlgorithm.ECDSA_SHA512 -> KeySpec.EccNistP521
    SignatureAlgorithm.RSA_SHA256, SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1 -> KeySpec.Rsa2048
    SignatureAlgorithm.RSA_SHA384, SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1 -> KeySpec.Rsa3072
    SignatureAlgorithm.RSA_SHA512, SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1 -> KeySpec.Rsa4096
    else -> error("Managed creation signature algorithm is unsupported")
}

/** Preserve the existing credential/transport configuration while prohibiting automatic creates. */
internal fun singleAttemptManagedCreationClient(client: KmsClient): KmsClient = client.withConfig {
    retryStrategy { maxAttempts = 1 }
}