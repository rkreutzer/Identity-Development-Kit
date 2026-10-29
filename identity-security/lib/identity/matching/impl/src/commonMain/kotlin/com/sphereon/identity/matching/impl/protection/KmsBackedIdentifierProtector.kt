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

package com.sphereon.identity.matching.impl.protection

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.log.Log
import com.sphereon.core.api.json.jcs.Jcs
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyReference
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.KeyOperations
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.kms.ContentEncryptionAlgorithm
import com.sphereon.crypto.core.kms.command.DecryptArgs
import com.sphereon.crypto.core.kms.command.DecryptCommand
import com.sphereon.crypto.core.kms.command.EncryptArgs
import com.sphereon.crypto.core.kms.command.EncryptCommand
import com.sphereon.crypto.core.kms.command.GenerateKeyArgs
import com.sphereon.crypto.core.kms.command.GenerateKeyCommand
import com.sphereon.crypto.core.kms.command.GenerateMacArgs
import com.sphereon.crypto.core.kms.command.GenerateMacCommand
import com.sphereon.crypto.core.kms.command.ListKeysArgs
import com.sphereon.crypto.core.kms.command.ListKeysCommand
import com.sphereon.data.store.party.model.IdentifierProtectionMode
import com.sphereon.data.store.party.model.IdentifierType
import com.sphereon.data.store.party.model.ProtectedIdentifierValue
import com.sphereon.identity.matching.protection.IdentifierProtectionErrors
import com.sphereon.identity.matching.protection.IdentifierProtectionKeyAccess
import com.sphereon.identity.matching.protection.IdentifierProtectionKeyProvisioner
import com.sphereon.identity.matching.protection.IdentifierProtectionPolicy
import com.sphereon.identity.matching.protection.IdentifierProtector
import com.sphereon.identity.matching.protection.IdentifierValueEncryption
import com.sphereon.identity.matching.protection.normalizeIdentifier
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * KMS-backed [IdentifierProtector].
 *
 * Reuses the platform KMS for every cryptographic operation: blind indexing is a
 * domain-separated HMAC-SHA256 via [GenerateMacCommand] and reversible encryption is
 * AES-256-GCM via [EncryptCommand] and [DecryptCommand]. No new algorithms are introduced.
 *
 * Key references are tenant-scoped aliases:
 * - blind-index HMAC key alias  = "idfr:bi:<tenantId>"
 * - value encryption key alias  = "idfr:enc:<tenantId>"
 *
 * Both the blind-index message and the encryption AAD are canonicalized with RFC 8785 JCS
 * ([Jcs]) so the same logical input always yields identical bytes across calls and platforms.
 *
 * Keys are created only by [provisionKeys], which tenant onboarding and platform setup call.
 * Protecting, blind indexing and revealing resolve the existing key and refuse with
 * [IdentifierProtectionErrors.KEY_NOT_PROVISIONED] when there is none. A key generated on one of
 * those paths would silently replace the key every stored blind index and ciphertext was derived
 * from, so existing logins and lookups would stop matching.
 *
 * A key is used through the provider it is recorded under. Resolution first asks the configured
 * provider for the exact alias and then the tenant's key reference index across all providers. A
 * key recorded under another provider, for example after the tenant's provider binding moved, keeps
 * being used from that recorded provider; it is never re-created in the configured one.
 *
 * All key lifecycle and cryptographic work uses commands, not the process-local KMS service. This
 * keeps resolve, generate, MAC, encryption, and decryption on the same routed KMS owner in split
 * deployments. Key discovery uses metadata-only references and never returns private key material.
 *
 * @param providerId KMS provider new identifier keys are created in, and the provider asked first
 *   when an existing key is resolved. Provisioning refuses when it is null: selecting a provider by
 *   algorithm alone can place tenant material in a transient system provider.
 * @param keyVersion Current key-version label recorded in the protected envelope.
 */
class KmsBackedIdentifierProtector(
    private val generateKeyCommand: GenerateKeyCommand,
    private val listKeysCommand: ListKeysCommand,
    private val generateMacCommand: GenerateMacCommand,
    private val encryptCommand: EncryptCommand,
    private val decryptCommand: DecryptCommand,
    private val providerId: String? = null,
    private val keyVersion: String = "v1",
    private val valueEncryption: IdentifierValueEncryption? = null,
    private val keyAccess: IdentifierProtectionKeyAccess? = null,
) : IdentifierProtector, IdentifierProtectionKeyProvisioner {
    private val keyReferenceCacheMutex = Mutex()
    private val keyReferenceCache = mutableMapOf<TenantKeyCacheKey, ManagedKeyReference>()

    private companion object {
        const val BI_KEY_PREFIX = "idfr:bi:"
        const val ENC_KEY_PREFIX = "idfr:enc:"
        const val BI_LABEL = "blind-index"
        const val ENC_LABEL = "encryption"
        const val SCOPE_TENANT = "tenant"
        const val IV_LENGTH = 12
        const val TAG_LENGTH = 16
        const val PURPOSE_BI = "identifier-bi"
        const val PURPOSE_ENC = "identifier-enc"

        /**
         * Serializes identifier-key provisioning across protector instances in this process.
         *
         * Protector instances are session-scoped, while their KMS aliases are tenant-scoped. Without
         * process-wide coordination, two concurrent provisioning calls can both observe a missing alias
         * and each generate a different key. Software PKCS12 stores allow alias replacement by default,
         * so the second write could make blind indexes or ciphertext created with the first key
         * unreadable once the in-process key cache is lost on restart.
         */
        val keyProvisioningMutex = Mutex()
    }

    /**
     * Creates the tenant's blind-index and value-encryption keys when they do not exist yet.
     *
     * Idempotent: an existing key, under the configured provider or recorded under any other
     * provider, is kept and nothing is generated. A key created by a concurrent caller in another
     * process after the lookup is detected by one exact re-read after the failed generation.
     */
    override suspend fun provisionKeys(tenantId: String): IdkResult<Unit, IdkError> {
        if (tenantId.isBlank()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Identifier key provisioning requires a tenant id"))
        }
        val configuredProvider =
            providerId?.takeIf(String::isNotBlank)
                ?: return Err(
                    IdkError.INVALID_STATE(
                        message = "Identifier key provisioning requires an explicitly configured KMS provider",
                    ),
                )
        ensureTenantKey(BI_KEY_PREFIX + tenantId, BI_LABEL, tenantId) { alias ->
            GenerateKeyArgs(
                providerId = configuredProvider,
                alias = alias,
                use = JwkUse.sig,
                alg = SignatureAlgorithm.HMAC_SHA256,
                keyVisibility = KeyVisibility.PRIVATE,
            )
        }.getOrElse { return Err(it) }
        // AES has no [SignatureAlgorithm], so the encryption key keeps `alg` unset and is
        // constrained by `use=enc` plus the encrypt/decrypt key operations. The software provider
        // then mints the generic 256-bit oct key required by AES-GCM.
        ensureTenantKey(ENC_KEY_PREFIX + tenantId, ENC_LABEL, tenantId) { alias ->
            GenerateKeyArgs(
                providerId = configuredProvider,
                alias = alias,
                use = JwkUse.enc,
                keyOperations = arrayOf(KeyOperations.ENCRYPT, KeyOperations.DECRYPT),
                keyVisibility = KeyVisibility.PRIVATE,
            )
        }.getOrElse { return Err(it) }
        return Ok(Unit)
    }

    override suspend fun protect(
        tenantId: String,
        identityId: String?,
        type: IdentifierType,
        plaintext: String,
        policy: IdentifierProtectionPolicy,
        salt: ByteArray?,
    ): IdkResult<ProtectedIdentifierValue, IdkError> {
        val normalized = normalizeIdentifier(plaintext, policy.normalization)

        return when (policy.mode) {
            IdentifierProtectionMode.PLAINTEXT -> {
                Ok(
                    ProtectedIdentifierValue(
                        mode = IdentifierProtectionMode.PLAINTEXT,
                        plaintext = normalized,
                    ),
                )
            }

            IdentifierProtectionMode.SEARCHABLE_ENCRYPTED,
            IdentifierProtectionMode.SEARCHABLE_BLIND_INDEX -> {
                protectBlinded(
                    tenantId = tenantId,
                    identityId = identityId,
                    type = type,
                    normalized = normalized,
                    mode = policy.mode,
                    scope = SCOPE_TENANT,
                )
            }

            IdentifierProtectionMode.SALTED_BLINDED -> {
                val saltBytes =
                    salt
                        ?: return Err(
                            IdkError.ILLEGAL_ARGUMENT_ERROR(
                                message = "SALTED_BLINDED protection requires a non-null salt",
                            ),
                        )
                protectBlinded(
                    tenantId = tenantId,
                    identityId = identityId,
                    type = type,
                    normalized = normalized,
                    mode = IdentifierProtectionMode.SALTED_BLINDED,
                    scope = saltBytes.encodeToBase64(),
                )
            }
        }
    }

    private suspend fun protectBlinded(
        tenantId: String,
        identityId: String?,
        type: IdentifierType,
        normalized: String,
        mode: IdentifierProtectionMode,
        scope: String,
    ): IdkResult<ProtectedIdentifierValue, IdkError> {
        // Both keys must already exist; resolve them together before any cryptographic call so a
        // tenant without provisioned keys is refused without touching the KMS further. The MAC and
        // the encryption use distinct keys and have no data dependency, so they run together too.
        val (blindIndexKey, encryptionKey) =
            coroutineScope {
                val blindIndex = async { resolveTenantKey(BI_KEY_PREFIX + tenantId, BI_LABEL, tenantId) }
                val encryption = async { resolveTenantKey(ENC_KEY_PREFIX + tenantId, ENC_LABEL, tenantId) }
                blindIndex.await() to encryption.await()
            }
        val blindIndexKeyInfo = blindIndexKey.getOrElse { return Err(it) }
        val encryptionKeyInfo = encryptionKey.getOrElse { return Err(it) }

        val (blindIndexResult, encryptionResult) =
            coroutineScope {
                val blindIndex = async { computeBlindIndex(tenantId, type, normalized, scope, blindIndexKeyInfo) }
                val encryption = async { encrypt(tenantId, identityId, type, normalized, encryptionKeyInfo) }
                blindIndex.await() to encryption.await()
            }
        val hmac = blindIndexResult.getOrNull() ?: return Err(blindIndexResult.errorOrNull() ?: unknown("blind index failed"))
        val ciphertext = encryptionResult.getOrNull() ?: return Err(encryptionResult.errorOrNull() ?: unknown("encryption failed"))

        return Ok(
            ProtectedIdentifierValue(
                mode = mode,
                valueCiphertext = ciphertext,
                encKeyRef = ENC_KEY_PREFIX + tenantId,
                encKeyVersion = keyVersion,
                valueHmac = hmac,
                hmacKeyRef = BI_KEY_PREFIX + tenantId,
                hmacKeyVersion = keyVersion,
            ),
        )
    }

    override suspend fun blindIndex(
        tenantId: String,
        type: IdentifierType,
        plaintext: String,
        policy: IdentifierProtectionPolicy,
        salt: ByteArray?,
    ): IdkResult<String, IdkError> {
        val normalized = normalizeIdentifier(plaintext, policy.normalization)
        val scope =
            when (policy.mode) {
                IdentifierProtectionMode.SALTED_BLINDED -> {
                    val saltBytes =
                        salt
                            ?: return Err(
                                IdkError.ILLEGAL_ARGUMENT_ERROR(
                                    message = "SALTED_BLINDED blind index requires a non-null salt",
                                ),
                            )
                    saltBytes.encodeToBase64()
                }

                else -> {
                    SCOPE_TENANT
                }
            }
        val keyInfo = resolveTenantKey(BI_KEY_PREFIX + tenantId, BI_LABEL, tenantId).getOrElse { return Err(it) }
        return computeBlindIndex(tenantId, type, normalized, scope, keyInfo)
    }

    /**
     * Resolve-or-provision a per-tenant identifier key under [alias]. Only [provisionKeys] calls
     * this. Idempotent and concurrency-tolerant: a key created by a racing caller is treated as
     * success, and a key recorded under any provider is never replaced.
     */
    private suspend fun ensureTenantKey(
        alias: String,
        label: String,
        tenantId: String,
        generate: (alias: String) -> GenerateKeyArgs,
    ): IdkResult<ManagedKeyReference, IdkError> =
        keyProvisioningMutex.withLock {
            val existing = findTenantKey(alias, label, tenantId).getOrElse { return@withLock Err(it) }
            if (existing != null) return@withLock Ok(existing)

            val generated = generateKeyCommand.execute(generate(alias))
            if (generated.isOk) {
                val reference = generated.value.keyReference
                    ?: return@withLock Err(unknown("$label key generation returned no metadata receipt for tenant $tenantId"))
                val validated = validateGeneratedKeyReference(reference, alias, label, tenantId)
                    .getOrElse { return@withLock Err(it) }
                cacheKeyReference(TenantKeyCacheKey(tenantId, alias), validated)
                Log.app().withTag("IdentifierProtection").info("IDENTIFIER_KEY_PROVISIONED purpose=$label")
                return@withLock Ok(validated)
            }

            // A different process may have created the same tenant alias after our exact lookup.
            // Reconcile that one explicit conflict case with one exact re-read; unrelated command
            // failures remain the authoritative error and never trigger provider/default guessing.
            val reconciled = findTenantKey(alias, label, tenantId).getOrNull()
            if (reconciled != null) Ok(reconciled) else Err(generated.error)
        }

    /**
     * Resolve the existing key under [alias]. Never creates one: a tenant without the key is
     * refused with [IdentifierProtectionErrors.KEY_NOT_PROVISIONED].
     */
    private suspend fun resolveTenantKey(
        alias: String,
        label: String,
        tenantId: String,
    ): IdkResult<ManagedKeyReference, IdkError> {
        val found = findTenantKey(alias, label, tenantId).getOrElse { return Err(it) }
        if (found != null) return Ok(found)
        Log.app().withTag("IdentifierProtection").warn("IDENTIFIER_PROTECTION_REFUSED stage=key-not-provisioned purpose=$label")
        return Err(IdentifierProtectionErrors.keyNotProvisioned(label, tenantId))
    }

    /**
     * Find the key recorded under [alias], or null when the tenant has none.
     *
     * The configured provider is asked first for the exact alias. When it does not hold the alias,
     * the tenant's key reference index is searched across all providers; a single match there is
     * the key's recorded provider and is used as-is. Lookup failures and ambiguous or unrelated
     * answers are errors, never a reason to treat the key as missing.
     */
    private suspend fun findTenantKey(
        alias: String,
        label: String,
        tenantId: String,
    ): IdkResult<ManagedKeyReference?, IdkError> {
        val cacheKey = TenantKeyCacheKey(tenantId = tenantId, alias = alias)
        cachedKeyReference(cacheKey)?.let { return Ok(it) }

        val configured = providerId?.takeIf(String::isNotBlank)
        if (configured != null) {
            val exact = lookupTenantKey(alias, label, tenantId, configured).getOrElse { return Err(it) }
            if (exact != null) {
                cacheKeyReference(cacheKey, exact)
                return Ok(exact)
            }
        }
        val recorded = lookupTenantKey(alias, label, tenantId, lookupProviderId = null).getOrElse { return Err(it) }
            ?: return Ok(null)
        if (configured != null) {
            Log.app().withTag("IdentifierProtection").warn(
                "IDENTIFIER_KEY_RESOLVED_FROM_RECORDED_PROVIDER purpose=$label configured=$configured",
            )
        }
        cacheKeyReference(cacheKey, recorded)
        return Ok(recorded)
    }

    private suspend fun lookupTenantKey(
        alias: String,
        label: String,
        tenantId: String,
        lookupProviderId: String?,
    ): IdkResult<ManagedKeyReference?, IdkError> {
        val args = ListKeysArgs(providerId = lookupProviderId, alias = alias)
        val lookup = keyAccess?.listKeys(tenantId, args) ?: listKeysCommand.execute(args)
        if (lookup.isErr) {
            Log.app().withTag("IdentifierProtection").warn("IDENTIFIER_PROTECTION_REFUSED stage=key-lookup code=${lookup.error.code}")
        }
        val references =
            lookup.getOrNull()?.keys
                ?: return Err(
                    lookup.errorOrNull()
                        ?: unknown("$label key resolution failed for tenant $tenantId"),
                )
        if (references.any { reference ->
                reference.alias != alias || (lookupProviderId != null && reference.providerId != lookupProviderId)
            }
        ) {
            return Err(unknown("$label exact key resolution returned an unrelated reference for tenant $tenantId"))
        }
        if (references.isEmpty()) return Ok(null)
        val resolved = references.singleOrNull()
            ?: return Err(unknown("$label key provider resolution was ambiguous for tenant $tenantId"))
        if (resolved.providerId.isBlank()) {
            return Err(unknown("$label key provider resolution failed for tenant $tenantId"))
        }
        return Ok(resolved)
    }

    private fun validateGeneratedKeyReference(
        reference: ManagedKeyReference,
        alias: String,
        label: String,
        tenantId: String,
    ): IdkResult<ManagedKeyReference, IdkError> {
        if (reference.alias != alias) {
            return Err(unknown("$label key generation returned an unexpected alias for tenant $tenantId"))
        }
        if (reference.providerId.isNullOrBlank() || reference.providerId != providerId) {
            return Err(unknown("$label key generation returned an unexpected provider for tenant $tenantId"))
        }
        return Ok(reference)
    }

    private suspend fun cachedKeyReference(key: TenantKeyCacheKey): ManagedKeyReference? =
        keyReferenceCacheMutex.withLock { keyReferenceCache[key] }

    private suspend fun cacheKeyReference(
        key: TenantKeyCacheKey,
        reference: ManagedKeyReference,
    ) {
        keyReferenceCacheMutex.withLock { keyReferenceCache[key] = reference }
    }

    private data class TenantKeyCacheKey(
        val tenantId: String,
        val alias: String,
    )

    /**
     * Deterministic, domain-separated blind index over the normalized value. The HMAC message is
     * the JCS canonicalization of a fixed-shape object, so the same inputs always hash identically.
     */
    private suspend fun computeBlindIndex(
        tenantId: String,
        type: IdentifierType,
        normalized: String,
        scope: String,
        keyInfo: ManagedKeyReference,
    ): IdkResult<String, IdkError> {
        val keyAlias = BI_KEY_PREFIX + tenantId
        val message =
            Jcs.canonicalize(
                JsonObject(
                    mapOf(
                        "purpose" to JsonPrimitive(PURPOSE_BI),
                        "tenant_id" to JsonPrimitive(tenantId),
                        "type" to JsonPrimitive(type.value),
                        "scope" to JsonPrimitive(scope),
                        "value" to JsonPrimitive(normalized),
                    ),
                ),
            )

        // Always name the provider the key is recorded under, so neither a multi-provider registry
        // default nor a changed tenant provider binding can select another keystore for the MAC.
        val resolvedProviderId = keyInfo.providerId
        return generateBlindIndexMac(tenantId, keyAlias, message, resolvedProviderId)
    }

    private suspend fun generateBlindIndexMac(
        tenantId: String,
        keyAlias: String,
        message: ByteArray,
        providerId: String,
    ): IdkResult<String, IdkError> {
        val args = GenerateMacArgs(
            keyId = keyAlias,
            message = message,
            digestAlgorithm = DigestAlg.SHA256,
            providerId = providerId,
        )
        val result = keyAccess?.generateMac(tenantId, args) ?: generateMacCommand.execute(args)
        if (result.isErr) {
            Log.app().withTag("IdentifierProtection").warn("IDENTIFIER_PROTECTION_REFUSED stage=blind-index-mac code=${result.error.code}")
        }
        val macResult = result.getOrNull() ?: return Err(result.errorOrNull() ?: unknown("MAC generation failed"))
        return Ok(macResult.macMultibase)
    }

    /**
     * AES-256-GCM encrypt the normalized value, binding it to the tenant/identity/type via AAD.
     * Stores IV(12) | authTag(16) | ciphertext as a single Base64Url blob.
     */
    private suspend fun encrypt(
        tenantId: String,
        identityId: String?,
        type: IdentifierType,
        normalized: String,
        keyInfo: ManagedKeyReference,
    ): IdkResult<String, IdkError> {
        val aad = encryptionAad(tenantId, identityId, type)

        val args = EncryptArgs(
                    keyInfo = keyInfo,
                    plaintext = normalized.encodeToByteArray(),
                    algorithm = ContentEncryptionAlgorithm.A256GCM,
                    additionalAuthenticatedData = aad,
                )
        val result = valueEncryption?.encrypt(tenantId, args) ?: encryptCommand.execute(args)
        val encryptResult = result.getOrNull() ?: run {
            val error = result.errorOrNull() ?: unknown("encryption failed")
            val code = error.code.takeIf { it.matches(Regex("[A-Za-z0-9_.:-]{1,160}")) } ?: "unavailable"
            Log.app().withTag("IdentifierProtection").warn(
                "Identifier protection refused stage=kms-encrypt code=$code",
            )
            return Err(error)
        }

        val combined = encryptResult.iv + encryptResult.authTag + encryptResult.ciphertext
        return Ok(combined.encodeToBase64Url())
    }

    override suspend fun reveal(
        protected: ProtectedIdentifierValue,
        tenantId: String,
        identityId: String?,
        type: IdentifierType,
    ): IdkResult<String, IdkError> {
        val blob =
            protected.valueCiphertext
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Protected value carries no ciphertext to reveal (mode=${protected.mode})",
                    ),
                )

        val combined = blob.decodeFromBase64Url()
        if (combined.size < IV_LENGTH + TAG_LENGTH) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Invalid ciphertext blob: too short"))
        }
        val iv = combined.copyOfRange(0, IV_LENGTH)
        val authTag = combined.copyOfRange(IV_LENGTH, IV_LENGTH + TAG_LENGTH)
        val ciphertext = combined.copyOfRange(IV_LENGTH + TAG_LENGTH, combined.size)

        val keyInfo = resolveTenantKey(ENC_KEY_PREFIX + tenantId, ENC_LABEL, tenantId).getOrElse { return Err(it) }
        val aad = encryptionAad(tenantId, identityId, type)

        val args = DecryptArgs(
                    keyInfo = keyInfo,
                    ciphertext = ciphertext,
                    algorithm = ContentEncryptionAlgorithm.A256GCM,
                    iv = iv,
                    authTag = authTag,
                    additionalAuthenticatedData = aad,
                )
        val result = valueEncryption?.decrypt(tenantId, args) ?: decryptCommand.execute(args)
        val decryptResult = result.getOrNull() ?: run {
            val error = result.errorOrNull() ?: unknown("decryption failed")
            val code = error.code.takeIf { it.matches(Regex("[A-Za-z0-9_.:-]{1,160}")) } ?: "unavailable"
            Log.app().withTag("IdentifierProtection").warn("Identifier protection refused stage=kms-decrypt code=$code")
            return Err(error)
        }
        return Ok(decryptResult.plaintext.decodeToString())
    }

    /** Deterministic AAD bound to tenant/identity/type, canonicalized via JCS for stability. */
    private fun encryptionAad(
        tenantId: String,
        identityId: String?,
        type: IdentifierType,
    ): ByteArray =
        Jcs.canonicalize(
            JsonObject(
                mapOf(
                    "v" to JsonPrimitive(1),
                    "tenant_id" to JsonPrimitive(tenantId),
                    "purpose" to JsonPrimitive(PURPOSE_ENC),
                    "identity_id" to JsonPrimitive(identityId ?: ""),
                    "type" to JsonPrimitive(type.value),
                ),
            ),
        )

    private fun unknown(message: String): IdkError = IdkError.UNKNOWN_ERROR(message = message)
}
