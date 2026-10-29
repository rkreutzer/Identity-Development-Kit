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

@file:Suppress("TooGenericExceptionCaught") // Keystore operations can fail with various JVM security exceptions

package com.sphereon.crypto.kms.keystore.software

import com.sphereon.core.api.Encoding
import com.sphereon.core.api.decodeFrom
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.NotFoundException
import com.sphereon.core.compat.LocalDateTimeKMP
import com.sphereon.crypto.core.CoseJoseKeyMappingService.toJoseJwk
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyInfo
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.ManagedKeyReference
import com.sphereon.crypto.core.PKIException
import com.sphereon.crypto.core.ResolvedKeyInfo
import com.sphereon.crypto.core.ResolvedKeyInfoType
import com.sphereon.crypto.core.generic.Curve
import com.sphereon.crypto.core.generic.KeyTypeMapping
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.generic.X509DistinguishedNameElements
import com.sphereon.crypto.core.interop.derPrivateKeyToJwk
import com.sphereon.crypto.core.interop.derPublicKeyToJwk
import com.sphereon.crypto.core.interop.resolveEcdsaKmpCurve
import com.sphereon.crypto.core.interop.toEcdsaPrivateKey
import com.sphereon.crypto.core.interop.toEdDsaPrivateKey
import com.sphereon.crypto.core.interop.toRsaPkcs1PrivateKey
import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.kms.KeyStoreConfig
import com.sphereon.crypto.core.kms.KeyStoreLoaderOpts
import com.sphereon.crypto.core.kms.PublicKeyAliasResolver
import com.sphereon.crypto.core.kms.X509CertificateExtensionSpec
import com.sphereon.crypto.core.kms.model.KeyProviderSettings
import com.sphereon.crypto.core.kms.model.KeyStoreAccessMode
import com.sphereon.crypto.core.kms.model.PredefinedKeyStoreTypes
import com.sphereon.crypto.core.toKeyReference
import com.sphereon.crypto.core.x509.Certificate
import com.sphereon.crypto.core.x509.CertificateCreationUtils
import com.sphereon.crypto.core.x509.certificateFromDer
import com.sphereon.crypto.core.x509.certificateJwkDecode
import com.sphereon.crypto.core.x509.certificateJwkEncode
import com.sphereon.crypto.core.x509.convertToJavaPrivateKey
import com.sphereon.crypto.core.x509.javaX509CertificateFromDer
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.zacsweers.metro.Assisted
import dev.zacsweers.metro.AssistedInject
import dev.zacsweers.metro.Inject
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import javax.net.ssl.KeyManagerFactory
import com.sphereon.crypto.core.kms.KeyStore as KeyStoreService

/**
 * A service class for managing cryptographic keys, certificate chains, and trusted certificates
 * in software-based keystores such as PKCS12 and JKS.
 *
 * Supported keystore types:
 * - **PKCS12**: A widely used keystore format supporting both private and trusted entries.
 * - **JKS**: Java's traditional keystore format (less portable, but still in use).
 */
@AssistedInject
actual class SoftwareKeyStoreService actual constructor(
    @Assisted config: KeyStoreConfig,
) : KeyStoreService,
    PublicKeyAliasResolver {
    private val config: SoftwareKeyStoreConfig = config as SoftwareKeyStoreConfig
    actual override val id = config.id
    actual override val keyStoreType = config.keyStoreType
    actual override val keyTypesSupported: Array<KeyTypeMapping> =
        arrayOf(
            KeyTypeMapping.RSA,
            KeyTypeMapping.EC,
            KeyTypeMapping.OKP,
            KeyTypeMapping.Symmetric,
        )
    actual override val signatureAlgorithmsSupported: Array<SignatureAlgorithm> =
        arrayOf(
            SignatureAlgorithm.ECDSA_SHA256,
            SignatureAlgorithm.ECDSA_SHA384,
            SignatureAlgorithm.ECDSA_SHA512,
            SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1,
            SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1,
            SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1,
            SignatureAlgorithm.RSA_SHA256,
            SignatureAlgorithm.RSA_SHA384,
            SignatureAlgorithm.RSA_SHA512,
            SignatureAlgorithm.ED25519,
            SignatureAlgorithm.ED448,
        )

    // KIWA-43: Legacy property from KeyStoreService interface - return null until interface is refactored
    actual override val settings: KeyProviderSettings?
        get() = null
    private val source: KeyStoreLoaderOpts.Source
    private val password: CharArray = this.config.password?.toCharArray() ?: throw IllegalArgumentException("Password must be provided")

    // Performance: Reuse password protection object to avoid repeated allocation
    private val passwordProtection by lazy { KeyStore.PasswordProtection(password) }

    // Performance: Cache resolved key info to avoid expensive repeated conversions (DER->JWK, cert encoding).
    // The state is held app-level and sharded per keystore identity rather than on this instance,
    // because a provider lookup builds a new service every call and an instance-local cache could
    // never survive one. See [SoftwareKeyStoreStateCache]. Invalidated on write operations.
    private suspend fun sharedState(): SharedKeyStoreState =
        SoftwareKeyStoreStateCache.stateFor(keyStoreCacheKey(config.keyStoreType, source, String(password)))

    private suspend fun isCacheValid(): Boolean = sharedState().isValid

    private suspend fun cachedResolvedKey(alias: String): ResolvedKeyInfoType<*>? = sharedState().resolved(alias) as? ResolvedKeyInfoType<*>

    // Background scope for async I/O operations
    private val backgroundScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // Atomic counter to track pending changes and ensure no updates are lost
    private val pendingChanges = AtomicLong(0)
    private val lastPersistedVersion = AtomicLong(0)

    // Mutex to ensure consistency for critical read operations
    private val persistenceMutex = Mutex()

    // Flag to track if persistence coroutine is currently running
    @Volatile
    private var isPersistenceRunning = false

    // Deferred that completes when all pending persistence is done
    @Volatile
    private var currentPersistenceJob: Deferred<Unit>? = null

    // Keep the revision belonging to the actual loaded snapshot, never a newer
    // filesystem timestamp sampled after a cached older KeyStore was returned.
    @Volatile
    private var reloadedKeyStore: KeyStore? = null

    @Volatile
    private var loadedFileRevision: String? = null

    // Guards reload-from-disk so concurrent reads do not load the file multiple times in parallel.
    private val reloadMutex = Mutex()

    init {
        with(this.config) {
            require(
                keyStoreType == PredefinedKeyStoreTypes.PKCS12.keyStoreType ||
                    keyStoreType == PredefinedKeyStoreTypes.BKS.keyStoreType ||
                    keyStoreType == PredefinedKeyStoreTypes.JKS.keyStoreType,
            ) {
                "A software keystore needs to be of config type ${PredefinedKeyStoreTypes.PKCS12.keyStoreType}, ${PredefinedKeyStoreTypes.BKS.keyStoreType} or ${PredefinedKeyStoreTypes.JKS.keyStoreType}"
            }

            val providerPath = path
            val providerBytes = bytes
            source =
                when {
                    providerPath != null -> KeyStoreLoaderOpts.Source.File(providerPath, autoCreate = persist)
                    providerBytes != null -> KeyStoreLoaderOpts.Source.Bytes(providerBytes)
                    else -> error("Either a keystore 'path' or 'bytes' must be provided in the config")
                }
        }
    }

    private data class LoadedKeyStoreData(
        val keyStore: KeyStore,
        val resolvedSource: KeyStoreLoaderOpts.Source,
    )

    private val keyStoreData: Deferred<LoadedKeyStoreData> by lazy {
        backgroundScope.async {
            val loadedSnapshot =
                withContext(Dispatchers.IO) {
                    KeyStoreLoaderFactory.loadSnapshot(
                        KeyStoreLoaderOpts(
                            type = config.keyStoreType,
                            source = source,
                            keyStorePassword = String(password),
                        ),
                    )
                }
            // The KeyStoreLoaderFactory resolves path placeholders internally, but we need to capture
            // the resolved source for later use in persistence. We use the same PathPlaceholderInterpreter
            // that the KeyStoreLoaderFactory uses to ensure consistent resolution.
            val resolvedSource =
                when (val src = source) {
                    is KeyStoreLoaderOpts.Source.File -> {
                        val resolvedFile = PathPlaceholderInterpreter.resolve(src.path) ?: java.io.File(src.path)
                        src.copy(path = resolvedFile.absolutePath)
                    }

                    else -> {
                        src
                    }
                }
            loadedFileRevision = loadedSnapshot.fileRevision
            LoadedKeyStoreData(loadedSnapshot.keyStore, resolvedSource)
        }
    }

    val platformKeyStore by lazy { runBlocking { keyStoreData.await().keyStore } }
    val platformKeyManagerFactory by lazy {
        KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply {
            init(platformKeyStore, password)
        }
    }

    /**
     * Returns the keystore to read from: the disk-reloaded overlay when present, otherwise the
     * lazily-loaded one. Callers that may serve stale data should call [maybeReloadFromDisk] first.
     */
    private suspend fun currentKeyStore(): KeyStore = reloadedKeyStore ?: keyStoreData.await().keyStore

    /** Reloads changed encrypted file contents; memory sources retain their normal cache behavior. */
    private suspend fun maybeReloadFromDisk() {
        val resolvedSource = keyStoreData.await().resolvedSource as? KeyStoreLoaderOpts.Source.File ?: return
        val diskRevision = KeyStoreLoaderFactory.fileRevision(resolvedSource)
        if (diskRevision == loadedFileRevision) return
        reloadMutex.withLock {
            if (KeyStoreLoaderFactory.fileRevision(resolvedSource) == loadedFileRevision) return
            val snapshot = KeyStoreLoaderFactory.loadSnapshot(
                KeyStoreLoaderOpts(
                    type = config.keyStoreType,
                    source = resolvedSource,
                    keyStorePassword = String(password),
                ),
                forceReload = true,
            )
            reloadedKeyStore = snapshot.keyStore
            loadedFileRevision = snapshot.fileRevision
            invalidateCache()
        }
    }

    /**
     * Lists all managed private keys stored in the underlying keystore.
     *
     * Performance optimizations:
     * - Uses cached password protection object
     * - Early filtering with isKeyEntry() before expensive getEntry() calls
     * - Parallel processing of entries using coroutines
     * - Utilizes cached resolved key info when available
     *
     * @return An array of [ManagedKeyInfoType] objects representing the private keys found in the keystore.
     * @throws IllegalStateException If the current access mode is `KeyProviderAccessMode.WRITE`.
     */
    actual override suspend fun listKeys(): Array<ManagedKeyReference> = listKeysInternal().map { it.toKeyReference() }.toTypedArray()

    /**
     * Internal version of listKeys that returns full ManagedKeyInfoType objects (with key material).
     * Used by matchKey() which needs access to the actual key data for comparison.
     */
    private suspend fun listKeysInternal(): Array<ManagedKeyInfoType<*>> {
        require(config.accessMode != KeyStoreAccessMode.WRITE.accessMode) { "Cannot list keys in WRITE mode" }

        // Wait for any pending persistence to ensure consistency
        awaitPendingPersistence()
        // Pick up durable writes made by another instance to the same file.
        maybeReloadFromDisk()

        val ks = currentKeyStore()

        return withContext(Dispatchers.Default) {
            // Performance: First filter to only key entries before expensive operations
            val keyAliases = ks.aliases().toList().filter { ks.isKeyEntry(it) }

            // Performance: Process entries in parallel using async
            // Use chunked processing to avoid creating too many coroutines
            @Suppress("MagicNumber")
            val chunkSize = maxOf(1, keyAliases.size / 10) // Adaptive chunk size

            keyAliases
                .chunked(chunkSize)
                .flatMap { aliasChunk ->
                    aliasChunk
                        .map { alias ->
                            async {
                                try {
                                    // Performance: Reuse password protection object
                                    val entry = ks.getEntry(alias, passwordProtection)
                                    when (entry) {
                                        is KeyStore.PrivateKeyEntry -> {
                                            ManagedKeyInfo(
                                                alias = alias,
                                                providerId = config.id,
                                                ManagedKeyInfo(
                                                    alias,
                                                    providerId = config.id,
                                                    resolvedKeyInfo = getCachedOrResolveKeyInfo(alias, entry),
                                                ),
                                            )
                                        }

                                        is KeyStore.SecretKeyEntry -> {
                                            ManagedKeyInfo(
                                                alias = alias,
                                                providerId = config.id,
                                                ManagedKeyInfo(
                                                    alias,
                                                    providerId = config.id,
                                                    resolvedKeyInfo = resolvedKeyInfoFromSecretEntry(alias, entry),
                                                ),
                                            )
                                        }

                                        else -> {
                                            null
                                        }
                                    }
                                } catch (_: Exception) {
                                    // Log error but don't fail the entire listing
                                    null
                                }
                            }
                        }.mapNotNull { it.await() }
                }.toTypedArray()
        }
    }

    /**
     * Resolves an asymmetric key's public material directly from its certificate chain.
     *
     * This path deliberately does not open the private-key entry and therefore does not require
     * its password. Symmetric entries and aliases without a certificate chain are rejected.
     */
    override suspend fun resolvePublicKeyByAlias(alias: String): ManagedKeyInfoType<*> {
        require(config.accessMode != KeyStoreAccessMode.WRITE.accessMode) { "Cannot get keys in WRITE mode" }
        require(alias.isNotBlank()) { "Need to provide an alias" }

        awaitPendingPersistence()
        maybeReloadFromDisk()

        val ks = currentKeyStore()
        if (!ks.containsAlias(alias) || !ks.isKeyEntry(alias)) {
            throw NotFoundException(
                resource = "key:$alias",
                message = "Could not find key entry for alias $alias",
            )
        }

        val certificateChain =
            ks.getCertificateChain(alias)
                ?.takeIf { it.isNotEmpty() }
                ?: throw PKIException("Key entry for alias $alias has no public certificate chain")
        val storageWrapper = isStorageWrapperChain(certificateChain)
        val leaf =
            certificateChain.firstOrNull() as? X509Certificate
                ?: throw PKIException("Key entry for alias $alias has no X.509 leaf certificate")
        val x5c = certificateChain.takeUnless { storageWrapper }?.map { certificateJwkEncode(it.encoded) }?.toTypedArray()
        val publicJwk = derPublicKeyToJwk(leaf.publicKey.encoded).copy(x5c = x5c)
        if (publicJwk.kty == JwaKeyType.oct) {
            throw PKIException("Symmetric key entry for alias $alias has no public verification material")
        }
        val jwaAlgorithm = JwaAlgorithm.fromValue(leaf.sigAlgName)
        val resolvedKeyInfo =
            ResolvedKeyInfo(
                key = publicJwk,
                alias = alias,
                providerId = config.id,
                keyVisibility = KeyVisibility.PUBLIC,
                keyType = publicJwk.getKeyType(),
            x5c = x5c,
                signatureAlgorithm = jwaAlgorithm?.let { SignatureAlgorithm.fromJose(it) },
            )
        return ManagedKeyInfo(
            alias = alias,
            providerId = config.id,
            resolvedKeyInfo = resolvedKeyInfo,
        )
    }

    /**
     * Retrieves a managed private key from the keystore based on the given key info.
     *
     * Performance optimizations:
     * - Uses cached password protection object
     * - Utilizes cached resolved key info to avoid expensive DER->JWK conversions
     * - Only performs keystore access when necessary
     *
     * @param keyInfo The metadata identifying the key to retrieve.
     * @return The corresponding [ManagedKeyInfoType] containing the resolved key.
     *
     * @throws NotFoundException If the key cannot be found.
     * @throws PKIException If the keystore only contains public keys and cannot provide private key info.
     * @throws IllegalArgumentException If an alias cannot be found.
     * @throws IllegalArgumentException If no kid or key has been passed in.
     */
    actual override suspend fun getKey(keyInfo: KeyInfoType<*>): ManagedKeyInfoType<*> {
        require(config.accessMode != KeyStoreAccessMode.WRITE.accessMode) { "Cannot get keys in WRITE mode" }

        // Wait for any pending persistence to ensure consistency
        awaitPendingPersistence()
        // Pick up durable writes made by another instance to the same file, including an alias whose
        // entry was overwritten on disk (e.g. the license recipient key after a bundle import).
        maybeReloadFromDisk()

        val ks = currentKeyStore()

        val managedKeyInfo = matchKey(keyInfo)
        val alias = managedKeyInfo.alias
        require(alias != null) { "Need to provide a alias" }

        // Honour the CALLER's requested visibility first. matchKey() may fabricate a fresh KeyInfo to
        // carry the matched alias/kid, and KeyInfo.keyVisibility defaults to PUBLIC — so reading it off
        // matchKey's result would silently downgrade a caller that explicitly asked for PRIVATE (e.g.
        // the KMS decrypt/sign path resolving the recipient/signing key) and strip the private `d`/`k`
        // component below. Resolve against the original request, then matchKey's, then the config.
        val visibility = keyInfo.keyVisibility ?: managedKeyInfo.keyVisibility ?: config.keyVisibility
        if (config.keyVisibility === KeyVisibility.PUBLIC.keyVisibility && visibility === KeyVisibility.PRIVATE) {
            throw PKIException("Cannot get private key info for a public key store")
        }

        val kid = managedKeyInfo.kid ?: managedKeyInfo.key?.kid

        // Performance: Try cache first before expensive keystore access
        val cachedResolvedKeyInfo =
            if (isCacheValid()) {
                cachedResolvedKey(alias)
            } else {
                null
            }
        val resolvedKeyInfo =
            if (cachedResolvedKeyInfo != null) {
                cachedResolvedKeyInfo
            } else {
                // Performance: Reuse password protection object
                val entry = ks.getEntry(alias, passwordProtection)
                when (entry) {
                    is KeyStore.PrivateKeyEntry -> getCachedOrResolveKeyInfo(alias, entry)

                    is KeyStore.SecretKeyEntry -> resolvedKeyInfoFromSecretEntry(alias, entry)

                    // NotFoundException's first parameter is `resource`, NOT the exception
                    // message — pass `message` explicitly so callers that report
                    // `exception.message` (e.g. the KMS encrypt command) stay diagnosable
                    // instead of surfacing "Encryption failed: null".
                    else -> throw NotFoundException(
                        resource = "key:$alias",
                        message = "Could not find key for alias $alias, kid $kid",
                    )
                }
            }

        val managedKeyInfoResult =
            ManagedKeyInfo(
                alias,
                providerId = config.id,
                resolvedKeyInfo = resolvedKeyInfo,
            )

        return if (visibility === KeyVisibility.PUBLIC) {
            ManagedKeyInfo(
                alias = alias,
                providerId = managedKeyInfoResult.providerId,
                resolvedKeyInfo = managedKeyInfoResult.toResolvedPublicKeyInfo(),
            )
        } else {
            managedKeyInfoResult
        }
    }

    /**
     * Stores a resolved private key and its certificate chain in the keystore under the given alias.
     *
     * @param keyInfo The resolved key information, including the private key and certificate chain.
     * @param providerId The ID of the provider storing the key.
     * @param alias The alias under which the key will be stored.
     * @return The [ManagedKeyInfoType] representing the stored key.
     *
     * @throws IllegalStateException If the keystore is in `KeyProviderAccessMode.READ` mode.
     * @throws PKIException If storing a private key is attempted in a public-only keystore.
     * @throws IllegalArgumentException If the alias already exists or the certificate chain (`x5c`) is missing.
     */
    actual override suspend fun storeKey(
        keyInfo: ResolvedKeyInfoType<*>,
        providerId: String,
        alias: String,
        certChain: Array<Certificate>?,
    ): ManagedKeyInfoType<*> {
        require(config.accessMode != KeyStoreAccessMode.READ.accessMode) { "Cannot store keys in READ mode" }
        // Apply the write against the active keystore (the disk-reloaded overlay when present) so it
        // sits on top of any durable write another instance already made to the same file.
        maybeReloadFromDisk()
        val ks = currentKeyStore()

        val visibility = keyInfo.keyVisibility ?: config.keyVisibility
        if (config.keyVisibility === KeyVisibility.PUBLIC.keyVisibility && visibility === KeyVisibility.PRIVATE) {
            throw PKIException("Cannot get private key info for a public key store")
        }

        if (!config.overwriteAlias) {
            check(!ks.containsAlias(alias)) { "Cannot overwrite key alias $alias, as alias already exists in keystore and overwriting is not enabled" }
        }

        val managedKeyInfo =
            ManagedKeyInfo(
                providerId = providerId,
                alias = alias,
                resolvedKeyInfo = keyInfo,
            )

        // Symmetric keys use SecretKeyEntry (no certificate chain needed)
        if (keyInfo.keyType == KeyTypeMapping.Symmetric) {
            val jwk =
                keyInfo.key as? Jwk
                    ?: throw IllegalArgumentException("Symmetric key must be a JWK")
            val kValue =
                jwk.k
                    ?: throw IllegalArgumentException("Symmetric JWK must have a 'k' field")
            val keyBytes = kValue.decodeFrom(Encoding.BASE64URL)
            val algorithmName =
                when {
                    jwk.alg?.value?.startsWith("HS") == true -> "HmacSHA${jwk.alg!!.value!!.removePrefix("HS")}"
                    else -> "HmacSHA256"
                }
            val secretKey = javax.crypto.spec.SecretKeySpec(keyBytes, algorithmName)
            ks.setEntry(alias, KeyStore.SecretKeyEntry(secretKey), passwordProtection)

            // Performance: Invalidate cache on write
            invalidateCache()

            // Flush durably before returning so a later keystore instance loading the same
            // file (cross-session/scope read) sees this key. See [persistDurably].
            persistDurably()

            return managedKeyInfo
        }

        // PKCS12/JKS private-key entries require a non-empty certificate chain. When the caller
        // supplies neither a `certChain` nor a `keyInfo.x5c`, mint a minimal self-signed wrapper
        // certificate so the keystore accepts the entry. This is a keystore-storage constraint
        // only; the certificate is never used for trust. The license recipient enc key (a bare EC
        // JWK with no x5c) takes this path — it only needs to round-trip through the keystore so a
        // later session can read it back to unwrap the license JWE.
        val resolvedCertChain: Array<Certificate> =
            certChain?.takeIf { it.isNotEmpty() }
                ?: keyInfo.x5c
                    ?.takeIf { it.isNotEmpty() }
                    ?.map { certificateFromDer(certificateJwkDecode(it)) }
                    ?.toTypedArray()
                ?: arrayOf(selfSignedWrapperCertificate(keyInfo, alias))

        // Perform key conversion and validation on Default dispatcher to avoid blocking I/O
        val (privateKey, certificates) =
            withContext(Dispatchers.Default) {
                val privateKey = convertToJavaPrivateKey(keyInfo)
                val certificates = resolvedCertChain.map { javaX509CertificateFromDer(it.der) }.toMutableList()
                Pair(privateKey, certificates)
            }

        // Store in keystore (this is typically fast as it's in-memory)
        ks.setKeyEntry(alias, privateKey, password, certificates.toTypedArray())

        // Performance: Invalidate cache on write
        invalidateCache()

        // Flush durably before returning so a later keystore instance loading the same
        // file (cross-session/scope read) sees this key. See [persistDurably].
        persistDurably()

        return managedKeyInfo
    }

    /**
     * Deletes a key from the keystore based on the provided key info.
     *
     * @param keyInfo The metadata identifying the key to delete.
     * @return `true` if the key was successfully deleted, `false` otherwise.
     *
     * @throws IllegalStateException If the keystore is in `KeyProviderAccessMode.READ` mode.
     * @throws PKIException If the key cannot be retrieved for deletion.
     */
    actual override suspend fun deleteKey(keyInfo: KeyInfoType<*>): Boolean {
        require(config.accessMode != KeyStoreAccessMode.READ.accessMode) { "Cannot delete keys in READ mode" }

        // A PKCS12/JKS private-key entry must retain a physical certificate. After logical
        // certificate-chain deletion that physical entry is our marked storage wrapper, which
        // intentionally cannot be resolved as public key material. Deletion needs only the
        // authenticated metadata address, not a DER/JWK reconstruction, so resolve the alias
        // directly and remove the physical key entry.
        val matched = matchKey(keyInfo)
        val alias = matched.alias ?: throw PKIException("Could not resolve key alias for deletion")
        return deleteEntry(alias)
    }

    /**
     * Deletes an entry from the keystore by its alias.
     *
     * @param alias The alias of the entry to delete.
     * @return `true` if the entry was successfully deleted, `false` otherwise.
     */
    private suspend fun deleteEntry(alias: String): Boolean {
        val ks = currentKeyStore()
        try {
            ks.deleteEntry(alias)

            // Performance: Invalidate cache on write
            invalidateCache()

            // Flush durably before returning so a later keystore instance loading the same
            // file (cross-session/scope read) observes the deletion. See [persistDurably].
            persistDurably()
            return true
        } catch (_: Exception) {
            // Ignored: keystore entry deletion failed for alias
        }

        return false
    }

    /**
     * Stores a certificate chain for the given alias and associated private key in the keystore.
     *
     * @param alias The alias under which the certificate chain will be stored.
     * @param certificates The array of [Certificate]s representing the certificate chain.
     * @param keyInfo Optional key information. Existing private-key entries are resolved by alias,
     * so callers do not need to submit private key material when attaching a certificate chain.
     *
     * @throws IllegalStateException If the keystore is in `KeyProviderAccessMode.READ` mode.
     * @throws IllegalArgumentException If the certificate array is empty, the alias does not match
     * the supplied key alias, or a new alias is requested without private key information.
     * @throws PKIException If storing the key or certificate chain fails.
     */
    actual override suspend fun storeCertificateChain(
        alias: String,
        certificates: Array<Certificate>,
        keyInfo: ResolvedKeyInfoType<*>?,
    ) {
        require(config.accessMode != KeyStoreAccessMode.READ.accessMode) { "Cannot store certificate chains in READ mode" }
        require(certificates.isNotEmpty()) { "Storing a certificate chain requires certificates to be present" }
        keyInfo?.let { require(alias == it.alias) { "Alias '$alias' need to match key alias '${it.alias}'" } }

        maybeReloadFromDisk()
        val ks = currentKeyStore()
        val existingEntry = ks.getEntry(alias, passwordProtection) as? KeyStore.PrivateKeyEntry
        if (existingEntry != null) {
            val javaCertificates =
                withContext(Dispatchers.Default) {
                    certificates.map { javaX509CertificateFromDer(it.der) }.toTypedArray()
                }
            ks.setKeyEntry(alias, existingEntry.privateKey, password, javaCertificates)
            invalidateCache()
            persistDurably()
            return
        }

        require(keyInfo != null) {
            "Storing a certificate chain for a new alias requires keyInfo containing private key material"
        }

        val (certChain, resolvedKeyInfo) =
            withContext(Dispatchers.Default) {
                val certChain = certificates.map { it -> certificateJwkEncode(it.der) }.toTypedArray()
                val resolvedKeyInfo =
                    ResolvedKeyInfo(
                        key = keyInfo.key,
                        keyVisibility = keyInfo.keyVisibility,
                        keyType = keyInfo.keyType,
                        alias = keyInfo.alias,
                        kid = keyInfo.kid,
                        signatureAlgorithm = keyInfo.signatureAlgorithm,
                        x5c = certChain,
                    )
                Pair(certChain, resolvedKeyInfo)
            }

        storeKey(
            keyInfo = resolvedKeyInfo,
            providerId = keyInfo.providerId ?: config.id,
            alias = alias,
        )

        // storeKey already flushed durably; this extra flush is a no-op when no further
        // change is pending, kept for symmetry with the other write paths.
        persistDurably()
    }

    /**
     * Stores a single certificate in the keystore under the specified alias.
     *
     * @param alias The alias under which to store the certificate.
     * @param certificate The certificate to be stored.
     *
     * @throws IllegalStateException If the keystore is in `KeyProviderAccessMode.READ` mode.
     * @throws IllegalArgumentException If the alias already exists in the keystore.
     */
    actual override suspend fun storeTrustedCertificate(
        alias: String,
        certificate: Certificate,
    ) {
        require(config.accessMode != KeyStoreAccessMode.READ.accessMode) { "Cannot store certificates in READ mode" }
        maybeReloadFromDisk()
        val ks = currentKeyStore()
        val exists = ks.containsAlias(alias)

        if (!config.overwriteAlias) {
            check(!exists) { "Cannot overwrite certificate alias $alias, as alias already exists in keystore and overwriting is not enabled" }
        }

        if (exists) {
            ks.deleteEntry(alias)
        }

        // Convert certificate on Default dispatcher
        val javaCert =
            withContext(Dispatchers.Default) {
                javaX509CertificateFromDer(certificate.der)
            }

        ks.setCertificateEntry(alias, javaCert)
        // Flush durably before returning so a later keystore instance loading the same
        // file (cross-session/scope read) sees this certificate. See [persistDurably].
        persistDurably()
    }

    /**
     * Lists all aliases in the keystore that have associated certificate chains.
     * Only aliases linked to private key entries are included.
     *
     * Performance optimization:
     * - Uses isKeyEntry() check to avoid unnecessary getEntry() calls when possible
     * - Uses cached password protection object
     *
     * @return An array of aliases with certificate chains.
     *
     * @throws IllegalStateException If the keystore is in `KeyProviderAccessMode.WRITE` mode.
     */
    actual override suspend fun listCertificateChainAliases(): Array<String> {
        require(config.accessMode != KeyStoreAccessMode.WRITE.accessMode) { "Cannot list certificate chains in WRITE mode" }

        // Wait for any pending persistence to ensure consistency
        awaitPendingPersistence()
        maybeReloadFromDisk()

        val ks = currentKeyStore()

        return ks
            .aliases()
            .toList()
            .filter { alias ->
                // Performance: Early exit if not a key entry
                if (!ks.isKeyEntry(alias)) {
                    false
                } else {
                    // Performance: Reuse password protection object
                    (ks.getEntry(alias, passwordProtection) as? KeyStore.PrivateKeyEntry)
                        ?.let { entry -> !isStorageWrapperChain(entry.certificateChain) }
                        ?: false
                }
            }.toTypedArray()
    }

    /**
     * Retrieves the certificate chain associated with the specified alias.
     *
     * @param alias The alias of the certificate chain to retrieve.
     * @return An array of [Certificate] objects forming the certificate chain.
     *
     * @throws IllegalStateException If the keystore is in `KeyProviderAccessMode.WRITE` mode.
     * @throws NotFoundException If no certificate chain is found for the given alias.
     */
    actual override suspend fun getCertificateChain(alias: String): Array<Certificate> {
        require(config.accessMode != KeyStoreAccessMode.WRITE.accessMode) { "Cannot get certificate chains in WRITE mode" }

        // Wait for any pending persistence to ensure consistency
        awaitPendingPersistence()
        maybeReloadFromDisk()

        val ks = currentKeyStore()

        val certChain = ks.getCertificateChain(alias)
        if (certChain === null) {
            throw NotFoundException("Could not find certificate chain for alias $alias")
        }
        if (isStorageWrapperChain(certChain)) {
            throw NotFoundException("Could not find certificate chain for alias $alias")
        }

        return certChain.map { cert -> certificateFromDer(cert.encoded) }.toTypedArray()
    }

    /**
     * Deletes the certificate chain associated with the given alias.
     *
     * @param alias The alias of the certificate chain to delete.
     * @return `true` if the certificate chain was successfully deleted, `false` otherwise.
     *
     * @throws IllegalStateException If the keystore is in `KeyProviderAccessMode.READ` mode.
     */
    actual override suspend fun deleteCertificateChain(alias: String): Boolean {
        require(config.accessMode != KeyStoreAccessMode.READ.accessMode) { "Cannot delete certificate chains in READ mode" }
        maybeReloadFromDisk()
        val ks = currentKeyStore()
        val entry = ks.getEntry(alias, passwordProtection) as? KeyStore.PrivateKeyEntry ?: return false
        if (isStorageWrapperChain(entry.certificateChain)) return false

        // JKS and PKCS12 cannot hold a private-key entry without a certificate chain. Replacing
        // the logical chain with a marked storage wrapper preserves the private key while making
        // the chain absent through the public CertificateStoreService contract.
        val wrapper = selfSignedWrapperCertificate(resolvedKeyInfoFrom(alias, entry), alias)
        ks.setKeyEntry(alias, entry.privateKey, password, arrayOf(javaX509CertificateFromDer(wrapper.der)))
        invalidateCache()
        persistDurably()
        return true
    }

    /**
     * Lists all aliases in the keystore that correspond to trusted certificates.
     *
     * @return An array of aliases for certificate entries.
     *
     * @throws IllegalStateException If the keystore is in `KeyProviderAccessMode.WRITE` mode.
     */
    actual override suspend fun listCertificateAliases(): Array<String> {
        require(config.accessMode != KeyStoreAccessMode.WRITE.accessMode) { "Cannot list certificates in WRITE mode" }

        // Wait for any pending persistence to ensure consistency
        awaitPendingPersistence()
        maybeReloadFromDisk()

        val ks = currentKeyStore()

        return ks
            .aliases()
            .toList()
            .filter { alias ->
                if (ks.isCertificateEntry(alias)) {
                    true
                } else if (ks.isKeyEntry(alias)) {
                    // Secret-key entries and key-only wrapper entries legitimately have no
                    // certificate chain. java.security.KeyStore returns null in that case.
                    val chain = ks.getCertificateChain(alias)
                    !chain.isNullOrEmpty() && !isStorageWrapperChain(chain)
                } else {
                    false
                }
            }.toTypedArray()
    }

    /**
     * Retrieves a trusted certificate by its alias from the keystore.
     *
     * @param alias The alias of the certificate to retrieve.
     * @return The [Certificate] associated with the given alias.
     *
     * @throws IllegalStateException If the keystore is in `KeyProviderAccessMode.WRITE` mode.
     * @throws NotFoundException If no certificate is found for the given alias.
     */
    actual override suspend fun getCertificate(alias: String): Certificate {
        require(config.accessMode != KeyStoreAccessMode.WRITE.accessMode) { "Cannot get certificates in WRITE mode" }

        // Wait for any pending persistence to ensure consistency
        awaitPendingPersistence()
        maybeReloadFromDisk()

        val ks = currentKeyStore()

        val cert = ks.getCertificate(alias)
        if (cert === null) {
            throw NotFoundException("Could not find certificate for alias $alias")
        }

        return certificateFromDer(cert.encoded)
    }

    /**
     * Deletes a trusted certificate from the keystore by its alias.
     *
     * @param alias The alias of the certificate to delete.
     * @return `true` if the certificate was successfully deleted, `false` otherwise.
     *
     * @throws IllegalStateException If the keystore is in `KeyProviderAccessMode.READ` mode.
     * @throws IllegalArgumentException If the alias does not exist in the keystore.
     */
    actual override suspend fun deleteCertificate(alias: String): Boolean {
        require(config.accessMode != KeyStoreAccessMode.READ.accessMode) { "Cannot delete certificates in READ mode" }
        maybeReloadFromDisk()
        val ks = currentKeyStore()

        require(ks.containsAlias(alias)) { "Could not find certificate for alias $alias" }
        return deleteEntry(alias)
    }

    actual override fun keyVisibility() = KeyVisibility.fromValue(config.keyVisibility)

    actual override fun exposesPrivateKeysForSigning(): Boolean = true

    private suspend fun matchKey(keyInfo: KeyInfoType<*>): KeyInfoType<*> {
        if (keyInfo.alias != null) {
            // Read the active keystore (callers reload before matching), so an alias whose entry was
            // durably overwritten on disk by another instance resolves to the reloaded entry.
            val ks = currentKeyStore()
            if (ks.containsAlias(keyInfo.alias) && ks.isKeyEntry(keyInfo.alias)) {
                return keyInfo
            }

            // An explicitly supplied alias is authoritative. Do not let a caller-controlled kid
            // redirect the lookup to a different key when that alias is stale or missing.
            throw NotFoundException(
                resource = "key:${keyInfo.alias}",
                message = "Could not find key entry for alias ${keyInfo.alias}",
            )
        }

        // Step 1: metadata matching via listKeys() (no key material needed)
        val refs = listKeys()
        val metadataMatch =
            if (keyInfo.kid != null) {
                refs.find { it.alias == keyInfo.kid } ?: refs.find { it.kid == keyInfo.kid }
            } else {
                null
            }
        if (metadataMatch != null) {
            return KeyInfo<KeyType>(alias = metadataMatch.alias, kid = metadataMatch.kid, providerId = metadataMatch.providerId)
        }

        // Step 2: direct alias-shaped lookup — treat the kid value as an alias. Callers
        // regularly carry the provisioning alias in `kid` (e.g. GenerateMacArgs.keyId is
        // looked up as KeyInfo(kid = keyId)). The keystore supports direct alias gets, so
        // resolve against it without depending on the listKeys() metadata scan, which
        // skips entries it cannot decode and compares aliases with exact string equality
        // (PKCS12 alias lookups themselves are case-insensitive).
        val kid = keyInfo.kid
        if (kid != null) {
            val ks = currentKeyStore()
            if (ks.containsAlias(kid) && ks.isKeyEntry(kid)) {
                return KeyInfo<KeyType>(alias = kid, kid = kid, providerId = config.id)
            }
        }

        // Step 3: key-material comparison fallback (only when caller provided key material)
        if (keyInfo.key != null) {
            val allKeys = listKeysInternal()
            val materialMatch =
                allKeys.find {
                    when (keyInfo.key?.getKeyType()) {
                        KeyTypeMapping.EC -> {
                            val providedKey = keyInfo.key
                            val storedKey = it.key
                            val xMatches =
                                !providedKey?.getXAsString().isNullOrEmpty() &&
                                    !storedKey?.getXAsString().isNullOrEmpty() &&
                                    providedKey.getXAsString() == storedKey?.getXAsString()
                            val yMatches =
                                !providedKey?.getYAsString().isNullOrEmpty() &&
                                    !storedKey?.getYAsString().isNullOrEmpty() &&
                                    providedKey.getYAsString() == storedKey?.getYAsString()
                            xMatches && yMatches
                        }

                        KeyTypeMapping.RSA -> {
                            val providedKey = keyInfo.key?.let { toJoseJwk(it) }
                            val storedKey = it.key?.let { toJoseJwk(it) }
                            val nMatches =
                                !providedKey?.n.isNullOrEmpty() &&
                                    !storedKey?.n.isNullOrEmpty() &&
                                    providedKey.n == storedKey?.n
                            val eMatches =
                                !providedKey?.e.isNullOrEmpty() &&
                                    !storedKey?.e.isNullOrEmpty() &&
                                    providedKey.e == storedKey?.e
                            nMatches && eMatches
                        }

                        else -> {
                            false
                        }
                    }
                }
            if (materialMatch != null) {
                return materialMatch
            }
        }

        return keyInfo
    }

    /**
     * Waits for all pending persistence operations to complete to ensure data consistency.
     * This should be called before read operations to avoid phantom entries.
     */
    private suspend fun awaitPendingPersistence() {
        if (!config.persist) {
            return // No persistence configured, no need to wait
        }

        // Get the current persistence job if any
        val job = currentPersistenceJob

        // If there's an active job, wait for it
        job?.await()
    }

    /**
     * Schedules asynchronous persistence of the keystore to avoid blocking the calling thread.
     * This method uses an atomic counter to ensure no updates are lost, even when multiple
     * modifications happen during an ongoing persistence operation.
     */
    private fun scheduleAsyncPersistence() {
        // Increment the change counter atomically
        pendingChanges.incrementAndGet()

        // If persistence is already running, it will pick up this change
        if (isPersistenceRunning) {
            return
        }

        // Start persistence in background and track the job
        val job =
            backgroundScope.async {
                persistenceLoop()
            }
        currentPersistenceJob = job

        // Launch in background to handle cleanup
        backgroundScope.launch {
            job.await()
            // Clear the job reference when done
            if (currentPersistenceJob == job) {
                currentPersistenceJob = null
            }
        }
    }

    /**
     * Durably persists a pending write before returning.
     *
     * A write (store/delete) updates the in-memory [KeyStore] synchronously, but the on-disk
     * `.p12`/`.jks` file is only refreshed by the background persistence loop. That is fine for a
     * single keystore instance — read operations call [awaitPendingPersistence] for consistency —
     * but it is NOT durable across instances: a second [SoftwareKeyStoreService] built later (e.g. a
     * different session/scope) loads the file from disk and would miss an entry whose flush had not
     * yet completed. The platform `license` keystore is exactly this case: the import session
     * stores the recipient key, then a separate decrypt session reads the shared on-disk keystore.
     *
     * Scheduling the flush and awaiting it here makes a persisted write durable on disk by the time
     * the write call returns, so any later instance that loads the same file sees the entry. No-ops
     * when persistence is disabled (in-memory-only keystores).
     */
    private suspend fun persistDurably() {
        if (!config.persist) {
            return
        }
        // Record the version this write must reach disk at. scheduleAsyncPersistence() bumps
        // pendingChanges, so our change is at least the current pendingChanges value.
        scheduleAsyncPersistence()
        val target = pendingChanges.get()
        // Await the in-flight flush, then re-schedule until the persisted version covers our
        // change. The extra loop closes the race where the running loop completed (reading an
        // older pendingChanges) just before our increment landed, leaving currentPersistenceJob
        // cleared with our change unflushed.
        awaitPendingPersistence()
        while (lastPersistedVersion.get() < target) {
            scheduleAsyncPersistence()
            awaitPendingPersistence()
        }
    }

    /**
     * Persistence loop that continues until all pending changes are persisted.
     * This ensures that no updates are lost even if they occur during persistence.
     */
    private suspend fun persistenceLoop() {
        persistenceMutex.withLock {
            // Prevent multiple persistence loops from running simultaneously
            if (isPersistenceRunning) {
                return@withLock
            }

            isPersistenceRunning = true
            try {
                while (true) {
                    val currentChanges = pendingChanges.get()
                    val lastPersisted = lastPersistedVersion.get()

                    // No new changes since last persistence
                    if (currentChanges <= lastPersisted) {
                        break
                    }

                    // Persist the current state
                    persistKeyStoreAsync()

                    // Update the last persisted version to the changes we just handled
                    lastPersistedVersion.set(currentChanges)

                    // Check if new changes arrived during persistence
                    // If so, continue the loop to persist them
                }
            } finally {
                isPersistenceRunning = false
            }
        }
    }

    /**
     * Persists the current state of the keystore asynchronously on the IO dispatcher.
     *
     * This function waits for the keystore to be initialized, then writes its contents
     * to the file specified in the `source.path`, encrypting it using the configured password.
     *
     * This operation only occurs if the keystore source is of type [KeyStoreLoaderOpts.Source.File].
     */
    private suspend fun persistKeyStoreAsync() {
        withContext(Dispatchers.IO) {
            // Flush the ACTIVE keystore: when a disk reload has overlaid a newer on-disk state
            // (another instance's durable write), subsequent writes by this instance landed on that
            // overlay via currentKeyStore(). Persisting keyStoreData's base would drop those writes.
            val ks = currentKeyStore()
            val resolvedSource = keyStoreData.await().resolvedSource
            if (resolvedSource is KeyStoreLoaderOpts.Source.File) {
                val targetFile = java.io.File(resolvedSource.path)
                val dir = targetFile.parentFile ?: java.io.File(".")
                val tmpFile = java.io.File(dir, "${targetFile.name}.tmp")
                val bakFile = java.io.File(dir, "${targetFile.name}.bak")

                // Write to temp file first and fsync
                java.io.FileOutputStream(tmpFile).use { fos ->
                    val channel = fos.channel
                    ks.store(fos, password)
                    fos.flush()
                    try {
                        channel.force(true) // durability
                    } catch (_: Throwable) {
                        // Ignored: filesystem may not support force/fsync
                    }
                }

                // Keep a backup of previous good state, then atomically replace
                if (targetFile.exists()) {
                    // Best effort backup
                    if (bakFile.exists()) {
                        bakFile.delete()
                    }
                    targetFile.renameTo(bakFile)
                }

                // Move temp -> final atomically if possible
                val moved = tmpFile.renameTo(targetFile)
                if (!moved && tmpFile.exists()) {
                    // Fallback to NIO move only if tmp file still exists
                    try {
                        java.nio.file.Files.move(
                            tmpFile.toPath(),
                            targetFile.toPath(),
                            java.nio.file.StandardCopyOption.REPLACE_EXISTING,
                            java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        )
                    } catch (_: Throwable) {
                        // Ignored: atomic move failed, falling back to copy/replace
                        if (tmpFile.exists()) {
                            java.nio.file.Files
                                .copy(tmpFile.toPath(), targetFile.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING)
                            tmpFile.delete()
                        }
                    }
                }

                // Cleanup backup if final is present
                if (targetFile.exists() && bakFile.exists()) {
                    bakFile.delete()
                }
            }
        }
    }

    /**
     * Persists the current state of the keystore synchronously.
     *
     * This method is kept for backward compatibility but internally delegates to
     * the async version while ensuring it completes.
     *
     * @deprecated Use scheduleAsyncPersistence() for better performance
     */
    private suspend fun persistKeyStore() {
        persistKeyStoreAsync()
    }

    private fun getSignatureAlgorithm(entry: KeyStore.PrivateKeyEntry): String? {
        val chain: Array<java.security.cert.Certificate> = entry.certificateChain
        if (chain.isEmpty()) {
            return null
        }

        val cert = chain[0]
        if (cert !is X509Certificate) {
            return null
        }

        return cert.sigAlgName
    }

    private fun resolvedKeyInfoFromSecretEntry(
        alias: String,
        entry: KeyStore.SecretKeyEntry,
    ): ResolvedKeyInfoType<*> {
        val secretKey = entry.secretKey
        val keyBytes = secretKey.encoded
        val kValue = keyBytes.encodeToBase64Url()
        val algName = secretKey.algorithm // e.g. "HmacSHA256"
        val jwaAlg =
            when {
                algName.contains("256") -> JwaAlgorithm.HS256
                algName.contains("384") -> JwaAlgorithm.HS384
                algName.contains("512") -> JwaAlgorithm.HS512
                else -> null
            }
        val jwk =
            Jwk(
                kty = JwaKeyType.oct,
                k = kValue,
                alg = jwaAlg,
                kid = alias,
            )
        return ResolvedKeyInfo(
            kid = alias,
            key = jwk,
            alias = alias,
            providerId = config.id,
            keyVisibility = KeyVisibility.fromValue(config.keyVisibility),
            keyType = KeyTypeMapping.Symmetric,
            signatureAlgorithm = jwaAlg?.let { SignatureAlgorithm.fromJose(it) },
        )
    }

    private fun resolvedKeyInfoFrom(
        alias: String,
        entry: KeyStore.PrivateKeyEntry,
    ): ResolvedKeyInfoType<*> {
        var jwk = derPrivateKeyToJwk(entry.privateKey.encoded)
        val sigAlgName = getSignatureAlgorithm(entry)
        val jwaAlgorithm = JwaAlgorithm.fromValue(sigAlgName)
        val storageWrapper = isStorageWrapperChain(entry.certificateChain)
        val certChain =
            entry.certificateChain
                .takeUnless { storageWrapper }
                ?.map { cert -> certificateJwkEncode(cert.encoded) }
                ?.toTypedArray()
                ?: emptyArray()
        val certChainOrNull = certChain.takeIf { it.isNotEmpty() }

        // EC keys from PKCS#8 may lack the optional public key component.
        // Derive x/y from the certificate's public key when missing.
        if (jwk.kty == JwaKeyType.EC && jwk.x == null && entry.certificate != null) {
            val pubJwk = derPublicKeyToJwk(entry.certificate.publicKey.encoded)
            jwk =
                Jwk
                    .Builder()
                    .withKty(jwk.kty)
                    .withCrv(jwk.crv ?: pubJwk.crv)
                    .withD(jwk.d)
                    .withX(pubJwk.x)
                    .withY(pubJwk.y)
                    // Cert chain comes from the PKCS12 entry, not the private-key DER.
                    // `derPrivateKeyToJwk(entry.privateKey.encoded)` only sees the key
                    // material, so the original `jwk.x5c` is always null here.
                    .withX5c(certChainOrNull)
                    .build()
        } else if (jwk.kty == JwaKeyType.OKP && jwk.x == null && entry.certificate != null) {
            // RFC 8410 PKCS#8 commonly carries only the EdDSA seed. Recover the
            // public component from the storage wrapper so a cold reload returns
            // the same complete JWK that was originally stored.
            val pubJwk = derPublicKeyToJwk(entry.certificate.publicKey.encoded)
            jwk =
                Jwk
                    .Builder()
                    .withKty(jwk.kty)
                    .withCrv(jwk.crv ?: pubJwk.crv)
                    .withD(jwk.d)
                    .withX(pubJwk.x)
                    .withAlg(jwk.alg ?: pubJwk.alg)
                    .withX5c(certChainOrNull)
                    .build()
        } else if (jwk.x5c.isNullOrEmpty() && certChainOrNull != null) {
            // Same issue for non-EC and EC-with-x-already-present paths: the JWK derived
            // from the private-key DER carries no certificate chain. Consumers reading
            // `jwk.x5c` directly (OID4VP x509_san_dns / x509_hash signing,
            // CoseSign1 with `requireX5Chain=true`, etc.) need it on the JWK itself —
            // the outer `ResolvedKeyInfo.x5c` field isn't read by every consumer.
            jwk = jwk.copy(x5c = certChainOrNull)
        }

        return ResolvedKeyInfo(
            key = jwk,
            alias = alias,
            providerId = config.id,
            keyVisibility = KeyVisibility.fromValue(config.keyVisibility),
            // Derive the key type from the canonical JOSE `kty` of the JWK we just decoded
            // (e.g. EC/RSA/OKP) rather than the JCA `PrivateKey.algorithm` string. The JCA
            // string is provider-specific ("ECDSA", "EdDSA", ...) and does NOT match the
            // KeyTypeMapping class names that `fromValue` compares against, so it silently
            // resolves to null — which makes signing fail with "Key type null not supported"
            // whenever a key is reloaded from disk (cold keystore cache). `jwk.kty` is the
            // same value already used above to repair EC public coordinates, so it is reliable.
            keyType = KeyTypeMapping.tryFromJose(jwk.kty).let { if (it.isOk) it.value else KeyTypeMapping.fromValue(entry.privateKey.algorithm) },
            x5c = certChainOrNull,
            signatureAlgorithm = jwaAlgorithm?.let { SignatureAlgorithm.fromJose(it) },
        )
    }

    /**
     * Performance helper: Gets cached resolved key info or resolves it from the entry.
     * This avoids expensive DER->JWK conversions and certificate chain encoding when possible.
     *
     * @param alias The alias of the key
     * @param entry The private key entry from the keystore
     * @return The resolved key info, either from cache or freshly resolved
     */
    private suspend fun getCachedOrResolveKeyInfo(
        alias: String,
        entry: KeyStore.PrivateKeyEntry,
    ): ResolvedKeyInfoType<*> {
        // Check cache first (only if cache is valid)
        if (isCacheValid()) {
            val cached = cachedResolvedKey(alias)
            if (cached != null) {
                return cached
            }
        }

        // Cache miss or invalid - resolve and cache
        val resolved = resolvedKeyInfoFrom(alias, entry)
        sharedState().putResolved(alias, resolved)
        return resolved
    }

    /**
     * Performance helper: Invalidates the resolved key info cache.
     * Called on any write operation (store, delete) to ensure cache consistency.
     */
    private suspend fun invalidateCache() {
        sharedState().invalidate()
    }

    /**
     * Mints a minimal self-signed certificate that wraps [keyInfo]'s key so a PKCS12/JKS private-key
     * entry can be stored. Software keystores require every private-key entry to carry a certificate
     * chain; some keys (e.g. a bare EC encryption JWK used purely to unwrap a JWE) legitimately have
     * no certificate of their own. Rather than reject those, we attach a self-signed wrapper so the
     * keystore accepts the entry. The certificate plays no role in trust — it exists solely to satisfy
     * the keystore-storage constraint, and the original key material is preserved byte-for-byte.
     *
     * EC, RSA, and EdDSA private keys can be wrapped. Other key types retain the explicit storage error.
     */
    private suspend fun selfSignedWrapperCertificate(
        keyInfo: ResolvedKeyInfoType<*>,
        alias: String,
    ): Certificate {
        val jwk =
            (keyInfo.key as? Jwk)?.takeIf { it.kty == JwaKeyType.EC || it.kty == JwaKeyType.RSA || it.kty == JwaKeyType.OKP }
                ?: throw IllegalArgumentException(
                    "Either certChain or keyInfo.x5c must be present and contain at least one certificate (no self-signed wrapper available for key type ${keyInfo.keyType})",
                )
        if (jwk.kty == JwaKeyType.RSA) return selfSignedRsaWrapperCertificate(keyInfo, jwk, alias)

        if (jwk.kty == JwaKeyType.OKP) return selfSignedOkpWrapperCertificate(keyInfo, jwk, alias)

        val curve =
            jwk.crv?.let { Curve.fromJose(it) }
                ?: throw IllegalArgumentException("EC key for alias $alias is missing 'crv'; cannot mint a self-signed wrapper certificate")

        // Sign the TBS with the EC private key over the P-curve in raw (r||s) form. The key's own
        // declared `alg`/`use` (e.g. ECDH-ES enc) is irrelevant for this wrapper — we only need a
        // valid ECDSA self-signature so PKCS12 stores the entry, so we pin ES256/SHA-256.
        val signingKeyInfo =
            ResolvedKeyInfo(
                key = jwk,
                keyVisibility = KeyVisibility.PRIVATE,
                keyType = KeyTypeMapping.EC,
                alias = alias,
                providerId = config.id,
                kid = keyInfo.kid ?: alias,
                signatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
            )

        val ecdsaCurve = resolveEcdsaKmpCurve(curve)
        val provider = CryptographyProvider.Default
        val privateKey = jwk.toEcdsaPrivateKey(provider = provider, curve = ecdsaCurve)
        val signer = privateKey.signatureGenerator(digest = SHA256, format = ECDSA.SignatureFormat.RAW)

        val subject = X509DistinguishedNameElements(commonName = alias)
        val notBefore = LocalDateTimeKMP.now()
        val notAfter =
            LocalDateTimeKMP(
                year = notBefore.year + 10,
                month = notBefore.month,
                day = notBefore.day,
                hour = notBefore.hour,
                minute = notBefore.minute,
                second = notBefore.second,
            )
        val result =
            CertificateCreationUtils.createCertificate(
                issuerKeyInfo = signingKeyInfo,
                issuer = subject,
                subjectKeyInfo = signingKeyInfo,
                subject = subject,
                serialNumber = 1,
                extensions = listOf(X509CertificateExtensionSpec(STORAGE_WRAPPER_EXTENSION_OID, valueDer = STORAGE_WRAPPER_EXTENSION_VALUE)),
                notBefore = notBefore,
                notAfter = notAfter,
                signatureFunction = { tbs -> signer.generateSignature(tbs) },
            )
        return result.certificate
    }

    private suspend fun selfSignedRsaWrapperCertificate(
        keyInfo: ResolvedKeyInfoType<*>,
        jwk: Jwk,
        alias: String,
    ): Certificate {
        val signingKeyInfo =
            ResolvedKeyInfo(
                key = jwk,
                keyVisibility = KeyVisibility.PRIVATE,
                keyType = KeyTypeMapping.RSA,
                alias = alias,
                providerId = config.id,
                kid = keyInfo.kid ?: alias,
                signatureAlgorithm = SignatureAlgorithm.RSA_SHA256,
            )
        val signer = jwk.toRsaPkcs1PrivateKey(provider = CryptographyProvider.Default, digest = SHA256).signatureGenerator()
        val subject = X509DistinguishedNameElements(commonName = alias)
        val notBefore = LocalDateTimeKMP.now()
        val notAfter =
            LocalDateTimeKMP(
                year = notBefore.year + 10,
                month = notBefore.month,
                day = notBefore.day,
                hour = notBefore.hour,
                minute = notBefore.minute,
                second = notBefore.second,
            )
        return CertificateCreationUtils.createCertificate(
            issuerKeyInfo = signingKeyInfo,
            issuer = subject,
            subjectKeyInfo = signingKeyInfo,
            subject = subject,
            serialNumber = 1,
            extensions = listOf(X509CertificateExtensionSpec(STORAGE_WRAPPER_EXTENSION_OID, valueDer = STORAGE_WRAPPER_EXTENSION_VALUE)),
            notBefore = notBefore,
            notAfter = notAfter,
            signatureFunction = { tbs -> signer.generateSignature(tbs) },
        ).certificate
    }

    private suspend fun selfSignedOkpWrapperCertificate(
        keyInfo: ResolvedKeyInfoType<*>,
        jwk: Jwk,
        alias: String,
    ): Certificate {
        val curve =
            jwk.crv?.let { Curve.fromJose(it) }
                ?: throw IllegalArgumentException("OKP key for alias $alias is missing 'crv'; cannot mint a self-signed wrapper certificate")
        require(curve is Curve.Ed25519 || curve is Curve.Ed448) {
            "OKP key for alias $alias must use Ed25519 or Ed448; got $curve"
        }
        val signatureAlgorithm = if (curve is Curve.Ed25519) SignatureAlgorithm.ED25519 else SignatureAlgorithm.ED448
        val signingKeyInfo =
            ResolvedKeyInfo(
                key = jwk,
                keyVisibility = KeyVisibility.PRIVATE,
                keyType = KeyTypeMapping.OKP,
                alias = alias,
                providerId = config.id,
                kid = keyInfo.kid ?: alias,
                signatureAlgorithm = signatureAlgorithm,
            )
        val signer = jwk.toEdDsaPrivateKey(provider = CryptographyProvider.Default, curve = curve).signatureGenerator()
        val subject = X509DistinguishedNameElements(commonName = alias)
        val notBefore = LocalDateTimeKMP.now()
        val notAfter =
            LocalDateTimeKMP(
                year = notBefore.year + 10,
                month = notBefore.month,
                day = notBefore.day,
                hour = notBefore.hour,
                minute = notBefore.minute,
                second = notBefore.second,
            )
        return CertificateCreationUtils.createCertificate(
            issuerKeyInfo = signingKeyInfo,
            issuer = subject,
            subjectKeyInfo = signingKeyInfo,
            subject = subject,
            serialNumber = 1,
            extensions = listOf(X509CertificateExtensionSpec(STORAGE_WRAPPER_EXTENSION_OID, valueDer = STORAGE_WRAPPER_EXTENSION_VALUE)),
            notBefore = notBefore,
            notAfter = notAfter,
            signatureFunction = { tbs -> signer.generateSignature(tbs) },
        ).certificate
    }

    private fun isStorageWrapperChain(chain: Array<java.security.cert.Certificate>): Boolean =
        chain.size == 1 && (chain.singleOrNull() as? X509Certificate)?.getExtensionValue(STORAGE_WRAPPER_EXTENSION_OID) != null

    private companion object {
        /** Private extension marking a keystore-only wrapper, never a tenant certificate. */
        const val STORAGE_WRAPPER_EXTENSION_OID = "1.3.6.1.4.1.61026.1.1"
        val STORAGE_WRAPPER_EXTENSION_VALUE = byteArrayOf(0x05, 0x00)
    }

    /**
     * Waits for all pending persistence operations to complete.
     * This method is primarily intended for testing scenarios where you need to ensure
     * that all changes have been written to disk before verification.
     *
     * For production code, this should rarely be needed as read operations automatically
     * wait for consistency when required.
     */
    suspend fun awaitPendingPersistenceCompletion() {
        awaitPendingPersistence()
    }
}
