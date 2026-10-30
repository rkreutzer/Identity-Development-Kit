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
 *
 */

package com.sphereon.crypto.kms.keystore.memory

import com.sphereon.core.api.error.NotFoundException
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.crypto.core.CoseJoseKeyMappingService
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyInfo
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.ManagedKeyReference
import com.sphereon.crypto.core.PKIException
import com.sphereon.crypto.core.ResolvedKeyInfoType
import com.sphereon.crypto.core.generic.KeyTypeMapping
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.kms.KeyStore
import com.sphereon.crypto.core.kms.KeyStoreConfig
import com.sphereon.crypto.core.kms.KeyStoreService
import com.sphereon.crypto.core.kms.model.KeyProviderSettings
import com.sphereon.crypto.core.kms.model.PredefinedKeyStoreTypes
import com.sphereon.crypto.core.toKeyReference
import com.sphereon.crypto.core.x509.Certificate
import dev.zacsweers.metro.Assisted
import dev.zacsweers.metro.AssistedInject
import dev.zacsweers.metro.Inject

class PublicFromPrivateKeyStore(
    private val privateKeyStore: KeyStoreService,
) : KeyStoreService {
    // KIWA-43: Legacy property from KeyStoreService interface - return null until interface is refactored
    override val settings: KeyProviderSettings?
        get() = null

    init {
        require(privateKeyStore.keyVisibility() === KeyVisibility.PRIVATE) { "A public from private key store needs to have a private key store exposing private keys" }
        // TODO: Is that true? If the "private" keystore is using hardware, we simply could delegate as that would only expose pub keys anyway
    }

    override suspend fun listKeys(): Array<ManagedKeyReference> = privateKeyStore.listKeys()

    override suspend fun getKey(keyInfo: KeyInfoType<*>) = privateKeyStore.getKey(keyInfo).toManagedPublicKeyInfo()

    override suspend fun storeKey(
        keyInfo: ResolvedKeyInfoType<*>,
        providerId: String,
        alias: String,
        certChain: Array<Certificate>?,
    ): ManagedKeyInfoType<*> {
        require(keyInfo.keyVisibility === KeyVisibility.PRIVATE) {
            "Public key to private key store adapter is backed by a private key store. This means for storing you can only use private keys, as the key would otherwise not be backed"
        }
        return privateKeyStore.storeKey(keyInfo, providerId, alias, certChain).toManagedPublicKeyInfo()
    }

    override suspend fun deleteKey(keyInfo: KeyInfoType<*>): Boolean = privateKeyStore.deleteKey(keyInfo)

    override fun keyVisibility() = KeyVisibility.PUBLIC
}

@JsExportCompat
@dev.zacsweers.metro.AssistedFactory
interface MemoryKeyStoreServiceFactory {
    fun create(
        @Assisted config: KeyStoreConfig,
        @Assisted backingStorage: MemoryKeyStoreBackingStorage?,
        @Assisted partitionKey: StoragePartitionKey?,
    ): MemoryKeyStoreService
}

@AssistedInject
class MemoryKeyStoreService(
    @Assisted private val config: KeyStoreConfig,
    @Assisted private val backingStorage: MemoryKeyStoreBackingStorage? = null,
    @Assisted private val partitionKey: StoragePartitionKey? = null,
) : KeyStore {
    override val id = config.id
    override val keyStoreType = config.keyStoreType
    override val keyTypesSupported = KeyTypeMapping.asList.toTypedArray()
    override val signatureAlgorithmsSupported = SignatureAlgorithm.asList.toTypedArray() // config.signatureAlgorithmsSupported

    // KIWA-43: Legacy property from KeyStoreService interface - return null until interface is refactored
    override val settings: KeyProviderSettings?
        get() = null

    private val directStorage = StoragePartition()

    private fun <T> withStorage(block: StoragePartition.() -> T): T {
        val storage = backingStorage?.let { backing -> partitionKey?.let(backing::getPartition) } ?: directStorage
        return storage.withLock { storage.block() }
    }

    init {
        require(config.keyStoreType === PredefinedKeyStoreTypes.MEMORY.keyStoreType) { "A memory keystore needs to be of config type MEMORY" }
    }

    override fun exposesPrivateKeysForSigning(): Boolean = true

    override fun keyVisibility() = KeyVisibility.fromValue(config.keyVisibility)

    override suspend fun listKeys(): Array<ManagedKeyReference> = withStorage { keys.map { it.value.toKeyReference() }.toTypedArray() }

    override suspend fun getKey(keyInfo: KeyInfoType<*>): ManagedKeyInfoType<*> = withStorage { getKeyLocked(keyInfo) }

    private fun StoragePartition.getKeyLocked(keyInfo: KeyInfoType<*>): ManagedKeyInfoType<*> {
        var managedKeyInfo = keyInfo
        if (managedKeyInfo.alias === null) {
            // Lookup precedence: kid match first, then EC public-coordinate match. Two safety
            // properties enforced here:
            //   1. The EC-coordinate fallback is gated on both supplied AND stored keys having
            //      non-null x/y. Non-EC keys (RSA, oct, OKP) return null for x/y, so a naive
            //      `null == null` comparison would match every stored key of those families and
            //      silently substitute an unrelated key, breaking authenticity guarantees of
            //      every cryptographic operation downstream.
            //   2. When the caller supplies key material along with a kid, a kid match is only
            //      honoured if the stored key's public material matches the supplied material.
            //      A bare kid collision (different RSA modulus, different EC point) MUST NOT
            //      cause the stored key to override the caller's explicit choice, since the
            //      caller has already declared which exact key to use.
            val supplied = keyInfo.key
            val suppliedX = supplied?.getXAsString()
            val suppliedY = supplied?.getYAsString()
            val matchingKey =
                keys.values.find { stored ->
                    if (keyInfo.kid !== null && stored.kid == keyInfo.kid) {
                        if (supplied === null) {
                            return@find true
                        }
                        return@find isSameKeyMaterial(supplied, stored.key)
                    }
                    if (suppliedX === null || suppliedY === null) {
                        return@find false
                    }
                    val storedKey = stored.key ?: return@find false
                    val storedX = storedKey.getXAsString() ?: return@find false
                    val storedY = storedKey.getYAsString() ?: return@find false
                    storedX == suppliedX && storedY == suppliedY
                }
            if (matchingKey != null) {
                managedKeyInfo = matchingKey
            } else {
                // Direct alias-shaped fallback: callers regularly carry the provisioning
                // alias in `kid` (e.g. GenerateMacArgs.keyId is looked up as
                // KeyInfo(kid = keyId)). When neither the kid metadata nor the EC
                // coordinates matched, treat the kid value as an alias — the store
                // supports direct alias gets, so a lookup that succeeds by alias must
                // also succeed when the same value is carried as kid. The same
                // key-material safety property as above applies: supplied material, if
                // any, must match the stored key.
                val kid = keyInfo.kid
                val aliasShaped = if (kid !== null) keys[kid] else null
                if (aliasShaped !== null && (supplied === null || isSameKeyMaterial(supplied, aliasShaped.key))) {
                    managedKeyInfo = aliasShaped
                }
            }
        }

        require(managedKeyInfo.key !== null || managedKeyInfo.kid !== null || managedKeyInfo.alias !== null) { "Either a kid needs to be provided or a key needs to be passed in" }
        val visibility = managedKeyInfo.keyVisibility ?: config.keyVisibility
        if (config.keyVisibility === KeyVisibility.PUBLIC.keyVisibility && visibility === KeyVisibility.PRIVATE) {
            throw PKIException("Cannot get private key info for a public key store")
        }

        val kid = managedKeyInfo.kid ?: managedKeyInfo.key?.kid

        val alias = managedKeyInfo.alias
        require(alias !== null) { "Need to provide a alias" }
        val keyInfoResult = keys[alias]
        require(keyInfoResult !== null) { "Could not find key for alias $alias, kid $kid" }
        return if (visibility === KeyVisibility.PUBLIC) {
            ManagedKeyInfo(
                alias = alias,
                providerId = keyInfoResult.providerId,
                resolvedKeyInfo = keyInfoResult.toResolvedPublicKeyInfo(),
            )
        } else {
            require(keyInfoResult.keyVisibility === KeyVisibility.PRIVATE) {
                "Key with alias $alias is not a private key, whilst a private key is requested"
            }
            keyInfoResult
        }
    }

    /**
     * Delete a key from the store.
     * @return true if the key was found and deleted, false if the key was not found
     */
    override suspend fun deleteKey(keyInfo: KeyInfoType<*>): Boolean = withStorage {
        try {
            val storedKeyInfo = getKeyLocked(keyInfo)
            keys.remove(storedKeyInfo.alias) != null
        } catch (_: NotFoundException) {
            // Ignored: key not found is expected for delete
            false
        } catch (_: IllegalArgumentException) {
            // Ignored: key lookup failed, nothing to delete
            false
        }
    }

    override suspend fun storeKey(
        keyInfo: ResolvedKeyInfoType<*>,
        providerId: String,
        alias: String,
        certChain: Array<Certificate>?,
    ): ManagedKeyInfoType<*> = withStorage {
        val visibility = keyInfo.keyVisibility ?: config.keyVisibility
        if (config.keyVisibility === KeyVisibility.PUBLIC.keyVisibility && visibility === KeyVisibility.PRIVATE) {
            throw PKIException("Cannot get private key info for a public key store")
        }
        if (!config.overwriteAlias) {
            check(!this.keys.containsKey(alias)) { "Cannot overwrite key alias $alias, as alias already exists in keystore and overwriting is not enabled" }
        }
        // The supplied chain replaces any x5c already on the key, as the file-backed stores do.
        val storedKeyInfo =
            if (certChain.isNullOrEmpty()) {
                keyInfo
            } else {
                val x5c = certChain.map { it.derToBase64() }.toTypedArray()
                val jwkKeyInfo = CoseJoseKeyMappingService.toResolvedJwkKeyInfo(keyInfo)
                jwkKeyInfo.copy(key = jwkKeyInfo.key.copy(x5c = x5c), x5c = x5c, noCache = keyInfo.noCache)
            }
        val managedKeyInfo = ManagedKeyInfo(providerId = providerId, alias = alias, resolvedKeyInfo = storedKeyInfo)
        this.keys[alias] = managedKeyInfo
        if (!certChain.isNullOrEmpty()) {
            certificateChains[alias] = certChain
        }
        managedKeyInfo
    }

    override suspend fun storeCertificateChain(
        alias: String,
        certificates: Array<Certificate>,
        keyInfo: ResolvedKeyInfoType<*>?,
    ) = withStorage {
        if (!config.overwriteAlias) {
            check(!this.certificateChains.containsKey(alias)) { "Cannot overwrite certificate chain alias $alias, as alias already exists in keystore and overwriting is not enabled" }
        }
        if (certificates.size == 1) {
            // Let's also store the cert itself
            this.certificates[alias] = certificates[0]
        }
        certificateChains[alias] = certificates
    }

    override suspend fun listCertificateChainAliases(): Array<String> = withStorage { certificateChains.keys.toTypedArray() }

    override suspend fun getCertificateChain(alias: String): Array<Certificate> = withStorage {
        certificateChains[alias] ?: certificates[alias]?.let {
            arrayOf(it)
        } ?: throw NotFoundException("Could not find certificate chain for alias $alias")
    }

    /**
     * Delete a certificate chain from the store.
     * @return true if the chain was found and deleted, false if not found
     */
    override suspend fun deleteCertificateChain(alias: String): Boolean = withStorage { certificateChains.remove(alias) != null }

    override suspend fun storeTrustedCertificate(
        alias: String,
        certificate: Certificate,
    ) = withStorage {
        if (!config.overwriteAlias) {
            check(!this.certificates.containsKey(alias)) { "Cannot overwrite certificate alias $alias, as alias already exists in keystore and overwriting is not enabled" }
        }
        certificates[alias] = certificate
    }

    override suspend fun listCertificateAliases(): Array<String> = withStorage { certificates.keys.toTypedArray() }

    override suspend fun getCertificate(alias: String): Certificate = withStorage {
        certificates[alias] ?: certificateChains[alias]?.get(0) ?: throw NotFoundException("Could not find certificate for alias $alias")
    }

    /**
     * Delete a certificate from the store.
     * @return true if the certificate was found and deleted, false if not found
     */
    override suspend fun deleteCertificate(alias: String): Boolean = withStorage { certificates.remove(alias) != null }

    /**
     * Compares two key materials by their public-identifying fields. Used when a caller has
     * supplied key material alongside a kid that collides with a stored key: substitution of the
     * stored key for the supplied one is only safe when the public material matches.
     *
     * EC keys are compared on the (x, y) affine coordinates. RSA keys are compared on the
     * modulus n. Symmetric (oct) keys are compared on the raw key bytes k. When neither side
     * exposes any of those identifying fields, the comparison is conservative and returns false.
     */
    private fun isSameKeyMaterial(
        supplied: com.sphereon.crypto.core.KeyType,
        stored: com.sphereon.crypto.core.KeyType?,
    ): Boolean {
        if (stored === null) return false
        val sx = supplied.getXAsString()
        val sy = supplied.getYAsString()
        if (sx !== null && sy !== null) {
            return sx == stored.getXAsString() && sy == stored.getYAsString()
        }
        val suppliedJwk = supplied as? com.sphereon.crypto.core.jose.JwkType
        val storedJwk = stored as? com.sphereon.crypto.core.jose.JwkType
        if (suppliedJwk !== null && storedJwk !== null) {
            val sn = suppliedJwk.n
            if (sn !== null) {
                return sn == storedJwk.n
            }
            val sk = suppliedJwk.k
            if (sk !== null) {
                return sk == storedJwk.k
            }
        }
        return false
    }
}
