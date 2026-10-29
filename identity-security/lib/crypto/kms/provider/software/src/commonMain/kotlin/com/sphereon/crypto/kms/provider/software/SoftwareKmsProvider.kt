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

package com.sphereon.crypto.kms.provider.software

import com.sphereon.cbor.toCborByteString
import com.sphereon.core.api.Encoding
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFrom
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.crypto.core.CoseJoseKeyMappingService
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyInfo
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.ManagedKeyReference
import com.sphereon.crypto.core.ResolvedKeyInfo
import com.sphereon.crypto.core.ResolvedKeyInfoType
import com.sphereon.crypto.core.generic.CoseKeyPair
import com.sphereon.crypto.core.generic.CryptoAlg
import com.sphereon.crypto.core.generic.Curve
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.JoseKeyPair
import com.sphereon.crypto.core.generic.KeyOperations
import com.sphereon.crypto.core.generic.KeyTypeMapping
import com.sphereon.crypto.core.generic.ManagedKeyPair
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.generic.X509DistinguishedNameElements
import com.sphereon.crypto.core.generic.computeHmac
import com.sphereon.crypto.core.generic.generateHmacKey
import com.sphereon.crypto.core.interop.DerKmpKeyInfoContext
import com.sphereon.crypto.core.interop.checkSupportedEcdsaCurve
import com.sphereon.crypto.core.interop.expectedOkpKeyByteLength
import com.sphereon.crypto.core.interop.isOkpCurve
import com.sphereon.crypto.core.interop.keyInfoToEcdsaDerKmpContext
import com.sphereon.crypto.core.interop.keyInfoToRSADerKmpContext
import com.sphereon.crypto.core.interop.okpRawToJwk
import com.sphereon.crypto.core.interop.resolveEcdsaKmpCurve
import com.sphereon.crypto.core.interop.resolveEcdsaKmpDigest
import com.sphereon.crypto.core.interop.resolveEdDsaKmpCurve
import com.sphereon.crypto.core.interop.resolvePSSSaltSize
import com.sphereon.crypto.core.interop.resolveRSAKmpDigest
import com.sphereon.crypto.core.interop.resolveXdhKmpCurve
import com.sphereon.crypto.core.interop.toEcdsaPrivateKey
import com.sphereon.crypto.core.interop.toEcdsaPublicKey
import com.sphereon.crypto.core.interop.toEdDsaPrivateKey
import com.sphereon.crypto.core.interop.toEdDsaPublicKey
import com.sphereon.crypto.core.interop.toKeyInfoJwk
import com.sphereon.crypto.core.interop.toRsaPkcs1PrivateKey
import com.sphereon.crypto.core.interop.toRsaPkcs1PublicKey
import com.sphereon.crypto.core.interop.toRsaPssPrivateKey
import com.sphereon.crypto.core.interop.toRsaPssPublicKey
import com.sphereon.crypto.core.interop.toSphereonJwk
import com.sphereon.crypto.core.jose.JwaCurve
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkType
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.jose.generateJwkThumbprint
import com.sphereon.crypto.core.kms.CertificateOptions
import com.sphereon.crypto.core.kms.ConcatKdf
import com.sphereon.crypto.core.kms.ContentEncryptionAlgorithm
import com.sphereon.crypto.core.kms.EncryptionResult
import com.sphereon.crypto.core.kms.HasKeyStoreService
import com.sphereon.crypto.core.kms.KeyAgreementAlgorithm
import com.sphereon.crypto.core.kms.KeyStorageType
import com.sphereon.crypto.core.kms.KeyStoreConfig
import com.sphereon.crypto.core.kms.KeyStoreManager
import com.sphereon.crypto.core.kms.KeyStoreService
import com.sphereon.crypto.core.kms.KeyWrapAlgorithm
import com.sphereon.crypto.core.kms.KmsProvider
import com.sphereon.crypto.core.kms.KmsProviderCapabilities
import com.sphereon.crypto.core.kms.KmsProviderConfigBase
import com.sphereon.crypto.core.kms.KmsProviderOperation
import com.sphereon.crypto.core.kms.requireManagedSigningKeySelection
import com.sphereon.crypto.core.kms.OperationCapability
import com.sphereon.crypto.core.kms.command.EcPointMultiplyOutput
import com.sphereon.crypto.core.kms.command.EcPointMultiplyResult
import com.sphereon.crypto.core.kms.command.EcdhDeriveMode
import com.sphereon.crypto.core.kms.command.EcdhDeriveResult
import com.sphereon.crypto.core.kms.command.SignatureEncoding
import com.sphereon.crypto.core.kms.model.KeyProviderSettings
import com.sphereon.crypto.core.sign.model.SignInput
import com.sphereon.crypto.core.sign.model.SignOutput
import com.sphereon.crypto.core.sign.model.SignOutputData
import com.sphereon.crypto.core.sign.model.Signature
import com.sphereon.crypto.core.sign.model.SignatureLevel
import com.sphereon.crypto.core.sign.requireSigningKeyCompatible
import com.sphereon.crypto.core.sign.keyCompatibilityFailure
import com.sphereon.crypto.core.x509.Certificate
import com.sphereon.crypto.core.x509.CertificateCreationUtils
import com.sphereon.crypto.kms.keystore.memory.MemoryKeyStoreConfigType
import com.sphereon.crypto.kms.keystore.memory.MemoryKeyStoreFactory
import com.sphereon.crypto.kms.keystore.software.JksKeyStoreConfig
import com.sphereon.crypto.kms.keystore.software.EncryptedFileKeyStoreConfig
import com.sphereon.crypto.kms.keystore.software.BksKeyStoreConfig
import com.sphereon.crypto.kms.keystore.software.Pkcs12KeyStoreConfig
import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.CryptographyProviderApi
import dev.whyoleg.cryptography.CryptographySystem
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.EdDSA
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.algorithms.SHA384
import dev.whyoleg.cryptography.algorithms.SHA512
import dev.whyoleg.cryptography.algorithms.XDH
import dev.whyoleg.cryptography.operations.KeyGenerator
import dev.zacsweers.metro.Assisted
import dev.zacsweers.metro.AssistedInject
import dev.zacsweers.metro.Inject
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName
import kotlin.time.Clock

@OptIn(ExperimentalObjCName::class)
@ObjCName("SoftwareKmsProvider", exact = true)
interface SoftwareKmsProvider :
    KmsProvider,
    HasKeyStoreService {
//    override val keyStore: KeyStoreService?
}

/**
 * Non-Hardware-based CryptoProvider provides Elliptic Curve and RSA cryptographic operations delegating to well-known platform implementations like OpenSSL3, WebCrypto, Apple, Jdk,
 *
 * Warning: To be used for testing purposes. Use hardware-based crypto providers for production!
 * If you need ephemeral keys then you can use this provider together with the default in memory private key store and thus that is the exception to the above warning.
 *
 * @param cryptoProvider An instance of CryptographyProvider to use for cryptographic operations. Default is CryptographyProvider.Default.
 */
@JsExportCompat
@AssistedInject
@OptIn(ExperimentalObjCName::class)
@ObjCName("SoftwareKmsProviderImpl", exact = true)
class SoftwareKmsProviderImpl(
    @Assisted private val providerConfig: KmsProviderConfigBase,
    // Assisted because this comes from a factory in app scope
    @Assisted private val execution: SessionExecution,
    @Assisted val keyStoreManager: KeyStoreManager? = null,
    private val memoryKeyStoreFactory: MemoryKeyStoreFactory,
) : SoftwareKmsProvider {
    private val config: SoftwareKmsProviderConfigType = providerConfig as? SoftwareKmsProviderConfigType ?: throw IllegalArgumentException("Config must be ISoftwareKmsProviderConfig")
    private val log = execution.log.logManager.withTag("SoftwareKmsProvider")
    override val kmsProviderType = config.kmsProviderType
    override val id = config.id
    override val order = config.order
    override val enabled = config.enabled
    private var privateKeyStore: KeyStoreService? =
        this.config.keyStore?.withProviderScopedFileId(config.id)?.let {
            log.debug("KeyStore config type: ${it::class.simpleName}, keyStoreType: ${it.keyStoreType}, keyStoreManager: ${keyStoreManager != null}")
            keyStoreManager?.createFromKeyStoreConfig(config = it, execution = execution) ?: run {
                require(it is MemoryKeyStoreConfigType) {
                    "A key store manager is required when key store configuration is supplied and not of type MemoryKeyStoreConfig. Config: $config"
                }
                memoryKeyStoreFactory.create(it, execution)
            }
        }

    override val keyStore: KeyStoreService
        get() {
            val keyStore = privateKeyStore
            requireNotNull(keyStore) { "Key store is not initialized" }
            return keyStore
        }

    @OptIn(CryptographyProviderApi::class)
    private val cryptoProvider: CryptographyProvider =
        (config as? SoftwareKmsProviderConfigType)?.cryptographyProvider?.let { provId -> CryptographySystem.getRegisteredProviders().find { prov -> prov.name == provId } }
            ?: CryptographyProvider.Default

    /**
     * Provides ECDSA (Elliptic Curve Digital Signature Algorithm) cryptographic functions.
     * This variable holds an instance of the provider which is used to perform various cryptographic operations such as
     * key generation, signature generation, and signature verification.
     */
    private val ecdsa = lazy { cryptoProvider.get(ECDSA) }
    private val rsaPss = lazy { cryptoProvider.get(RSA.PSS) }
    private val rsaPkcs1 = lazy { cryptoProvider.get(RSA.PKCS1) }
    private val eddsa = lazy { cryptoProvider.get(EdDSA) }
    private val xdh = lazy { cryptoProvider.get(XDH) }
    override val settings: KeyProviderSettings? = null

    /**
     * Returns the full capabilities of this KMS provider.
     */
    override fun getCapabilities(): KmsProviderCapabilities =
        KmsProviderCapabilities(
            providerId = id,
            providerType = kmsProviderType,
            // Storage capabilities
            storageTypes = arrayOf(KeyStorageType.PERSISTENT, KeyStorageType.EPHEMERAL),
            supportsKeyImport = true,
            supportsKeyExport = true,
            exposePrivateKeys = config.exposePrivateKeysDuringGeneration,
            // Operations
            operations =
                arrayOf(
                    OperationCapability(
                        operation = KmsProviderOperation.GENERATE_KEY,
                        supported = true,
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.IMPORT_KEY,
                        supported = true,
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.EXPORT_KEY,
                        supported = true,
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.DELETE_KEY,
                        supported = true,
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.SIGN,
                        supported = true,
                        signatureAlgorithms =
                            arrayOf(
                                SignatureAlgorithm.ECDSA_SHA256,
                                SignatureAlgorithm.ECDSA_SHA384,
                                SignatureAlgorithm.ECDSA_SHA512,
                                SignatureAlgorithm.RSA_RAW,
                                SignatureAlgorithm.RSA_SHA256,
                                SignatureAlgorithm.RSA_SHA384,
                                SignatureAlgorithm.RSA_SHA512,
                                SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1,
                                SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1,
                                SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1,
                            ),
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.SIGN_DIGEST,
                        supported = true,
                        signatureAlgorithms =
                            arrayOf(
                                SignatureAlgorithm.ECDSA_SHA256,
                                SignatureAlgorithm.ECDSA_SHA384,
                                SignatureAlgorithm.ECDSA_SHA512,
                            ),
                        notes = "Signs caller-supplied digests/scalars without hashing again; currently supports ECDSA",
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.VERIFY,
                        supported = true,
                        signatureAlgorithms =
                            arrayOf(
                                SignatureAlgorithm.ECDSA_SHA256,
                                SignatureAlgorithm.ECDSA_SHA384,
                                SignatureAlgorithm.ECDSA_SHA512,
                                SignatureAlgorithm.RSA_RAW,
                                SignatureAlgorithm.RSA_SHA256,
                                SignatureAlgorithm.RSA_SHA384,
                                SignatureAlgorithm.RSA_SHA512,
                                SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1,
                                SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1,
                                SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1,
                            ),
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.VERIFY_DIGEST,
                        supported = true,
                        signatureAlgorithms =
                            arrayOf(
                                SignatureAlgorithm.ECDSA_SHA256,
                                SignatureAlgorithm.ECDSA_SHA384,
                                SignatureAlgorithm.ECDSA_SHA512,
                            ),
                        notes = "Verifies caller-supplied digests/scalars without hashing again; currently supports ECDSA",
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.ENCRYPT,
                        supported = true,
                        contentEncryptionAlgorithms =
                            arrayOf(
                                ContentEncryptionAlgorithm.A128GCM,
                                ContentEncryptionAlgorithm.A192GCM,
                                ContentEncryptionAlgorithm.A256GCM,
                            ),
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.DECRYPT,
                        supported = true,
                        contentEncryptionAlgorithms =
                            arrayOf(
                                ContentEncryptionAlgorithm.A128GCM,
                                ContentEncryptionAlgorithm.A192GCM,
                                ContentEncryptionAlgorithm.A256GCM,
                            ),
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.WRAP_KEY,
                        supported = true,
                        keyWrapAlgorithms =
                            arrayOf(
                                KeyWrapAlgorithm.RSA_OAEP,
                                KeyWrapAlgorithm.RSA_OAEP_256,
                                KeyWrapAlgorithm.RSA_OAEP_512,
                            ),
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.UNWRAP_KEY,
                        supported = true,
                        keyWrapAlgorithms =
                            arrayOf(
                                KeyWrapAlgorithm.RSA_OAEP,
                                KeyWrapAlgorithm.RSA_OAEP_256,
                                KeyWrapAlgorithm.RSA_OAEP_512,
                            ),
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.KEY_AGREEMENT,
                        supported = true,
                        keyAgreementAlgorithms =
                            arrayOf(
                                KeyAgreementAlgorithm.ECDH_ES,
                                KeyAgreementAlgorithm.ECDH_ES_A128KW,
                                KeyAgreementAlgorithm.ECDH_ES_A192KW,
                                KeyAgreementAlgorithm.ECDH_ES_A256KW,
                            ),
                        notes = "Supports ECDH key agreement with P-256, P-384, and P-521 curves",
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.ECDH_DERIVE_RAW_X,
                        supported = true,
                        keyAgreementAlgorithms =
                            arrayOf(
                                KeyAgreementAlgorithm.ECDH_ES,
                                KeyAgreementAlgorithm.ECDH_ES_A128KW,
                                KeyAgreementAlgorithm.ECDH_ES_A192KW,
                                KeyAgreementAlgorithm.ECDH_ES_A256KW,
                            ),
                        notes = "Returns the raw ECDH x-coordinate without exporting the private key to the caller",
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.ECDH_DERIVE_KDF,
                        supported = true,
                        keyAgreementAlgorithms =
                            arrayOf(
                                KeyAgreementAlgorithm.ECDH_ES,
                                KeyAgreementAlgorithm.ECDH_ES_A128KW,
                                KeyAgreementAlgorithm.ECDH_ES_A192KW,
                                KeyAgreementAlgorithm.ECDH_ES_A256KW,
                            ),
                        notes = "Applies Concat KDF to provider-derived ECDH output",
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.EC_POINT_MULTIPLY,
                        supported = true,
                        keyAgreementAlgorithms = arrayOf(KeyAgreementAlgorithm.ECDH_ES),
                        notes = "Provider-backed raw-X point multiplication equivalent to ECDH1_DERIVE with CKD_NULL",
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.GENERATE_CERTIFICATE,
                        supported = config.autoCreateCertificate,
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.IMPORT_CERTIFICATE,
                        supported = true,
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.X509_CHAIN_VALIDATION,
                        supported = false,
                        notes = "Not yet implemented",
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.HARDWARE_BACKED,
                        supported = false,
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.ATTESTATION,
                        supported = false,
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.KEY_ATTESTATION,
                        supported = false,
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.GENERATE_MAC,
                        supported = true,
                        signatureAlgorithms =
                            arrayOf(
                                SignatureAlgorithm.HMAC_SHA256,
                                SignatureAlgorithm.HMAC_SHA384,
                                SignatureAlgorithm.HMAC_SHA512,
                            ),
                    ),
                    OperationCapability(
                        operation = KmsProviderOperation.VERIFY_MAC,
                        supported = true,
                        signatureAlgorithms =
                            arrayOf(
                                SignatureAlgorithm.HMAC_SHA256,
                                SignatureAlgorithm.HMAC_SHA384,
                                SignatureAlgorithm.HMAC_SHA512,
                            ),
                    ),
                ),
            // Key type support
            supportedKeyTypes = arrayOf(KeyTypeMapping.EC, KeyTypeMapping.RSA, KeyTypeMapping.Symmetric, KeyTypeMapping.OKP),
            supportedCurves =
                arrayOf(
                    Curve.P_256,
                    Curve.P_384,
                    Curve.P_521,
                    Curve.Ed25519,
                    Curve.Ed448,
                    Curve.X25519,
                    Curve.X448,
                ),
            // Algorithm support - using generic crypto types
            supportedCryptoAlgorithms =
                arrayOf(CryptoAlg.ECDSA, CryptoAlg.RSA, CryptoAlg.HMAC, CryptoAlg.ED25519, CryptoAlg.ED448),
            supportedDigestAlgorithms = arrayOf(DigestAlg.SHA256, DigestAlg.SHA384, DigestAlg.SHA512),
            signatureAlgorithms =
                arrayOf(
                    SignatureAlgorithm.ECDSA_SHA256,
                    SignatureAlgorithm.ECDSA_SHA384,
                    SignatureAlgorithm.ECDSA_SHA512,
                    SignatureAlgorithm.RSA_RAW,
                    SignatureAlgorithm.RSA_SHA256,
                    SignatureAlgorithm.RSA_SHA384,
                    SignatureAlgorithm.RSA_SHA512,
                    SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1,
                    SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1,
                    SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1,
                    SignatureAlgorithm.HMAC_SHA256,
                    SignatureAlgorithm.HMAC_SHA384,
                    SignatureAlgorithm.HMAC_SHA512,
                    SignatureAlgorithm.ED25519,
                    SignatureAlgorithm.ED448,
                ),
            contentEncryptionAlgorithms =
                arrayOf(
                    ContentEncryptionAlgorithm.A128GCM,
                    ContentEncryptionAlgorithm.A192GCM,
                    ContentEncryptionAlgorithm.A256GCM,
                ),
            // Additional capabilities
            supportsX509 = true,
            supportsAttestation = false,
            supportsHardwareBacking = false,
            // Public key resolution
            supportsPublicKeyResolution = true,
            resolutionMethods = emptyArray(), // TODO: Need to determine available IIdentifierMethod instances
        )

    /**
     * Returns an array of supported elliptic curves for cryptographic operations.
     *
     * @return An array of CurveMapping objects representing the supported elliptic curves.
     */
    @Deprecated("Use getCapabilities().supportedCurves instead")
    override fun supportedCurves(): Array<Curve> = getCapabilities().supportedCurves

    /**
     * Checks if the provided elliptic curve is supported by the SoftwareKmsProviderImpl.
     *
     * @param curve The elliptic curve to be checked.
     * @return True if the curve is supported, false otherwise.
     */
    override fun isSupportedCurve(curve: Curve): Boolean = getCapabilities().supportedCurves.contains(curve)

    /**
     * Returns an array of supported hash algorithms.
     *
     * @return An array containing the supported HashAlgorithm values: SHA256, SHA384, and SHA512.
     */
    @Deprecated("Use getCapabilities().supportedDigestAlgorithms instead")
    override fun supportedDigests(): Array<DigestAlg> = getCapabilities().supportedDigestAlgorithms

    /**
     * Generates a cryptographic key pair based on the provided elliptic curve.
     *
     * @param curve The elliptic curve mapping used to generate the key pair.
     * @return A `CryptoProviderKeyPair` object containing the generated key pair
     *         with their respective JWK and COSE representations.
     */

    override suspend fun generateKeyAsync(
        alias: String?,
        use: JwkUse?,
        keyOperations: Array<out KeyOperations>?,
        alg: SignatureAlgorithm?,
        certificateOptions: CertificateOptions?,
    ): ManagedKeyPair {
        val keyUse = use ?: JwkUse.sig
        // For `use=enc` with no signature algorithm specified, mint a 256-bit
        // symmetric AES key. This is the natural shape for AES-KW key wrapping
        // (RFC 3394) and AES-GCM content encryption — the SignatureAlgorithm enum
        // (intentionally) doesn't carry an AES variant, so callers asking for a
        // "default encryption key" need this branch instead of being silently
        // upgraded to ECDSA_SHA256 (which then fails with
        // "Wrapping key must have raw bytes for AES-KW" downstream).
        if (keyUse == JwkUse.enc && alg == null) {
            return generateSymmetricEncKey(alias, keyOperations)
        }
        val algMapping = alg ?: SignatureAlgorithm.ECDSA_SHA256
        val curve = algMapping.curve
        val keyType =
            when (algMapping.cryptoAlgorithm) {
                CryptoAlg.RSA -> KeyTypeMapping.RSA
                CryptoAlg.HMAC -> KeyTypeMapping.Symmetric
                CryptoAlg.ED25519, CryptoAlg.ED448 -> KeyTypeMapping.OKP
                else -> KeyTypeMapping.EC
            }

        val keyOpsMapping = keyOperations ?: arrayOf(KeyOperations.SIGN, KeyOperations.VERIFY)

        // Try platform-specific native key generation first (iOS uses keychain)
        val finalAlias = alias ?: "key-${kotlin.random.Random.nextLong()}"
        val nativeKeyPair =
            generateKeyPairNative(
                alias = finalAlias,
                keyType = keyType,
                algorithm = algMapping,
                keyUse = keyUse,
                keyOperations = keyOpsMapping,
                overwriteAlias = this.config.keyStore?.overwriteAlias ?: true,
            )

        if (nativeKeyPair != null) {
            // Native generation succeeded (e.g., iOS keychain)
            // TODO: Handle certificates if requested (certificateOptions)
            return nativeKeyPair.copy(providerId = id)
        }

        // Symmetric key generation (HMAC/AES) - uses raw random bytes, no DER/certificate path
        if (keyType == KeyTypeMapping.Symmetric) {
            val digestAlg = algMapping.digestAlgorithm ?: DigestAlg.SHA256
            val keyBytes = generateHmacKey(digestAlg)
            val kValue = keyBytes.encodeToBase64Url()

            val kid = alias ?: "key-${kotlin.random.Random.nextLong()}"
            val keyOpsMapping = keyOperations ?: arrayOf(KeyOperations.MAC_CREATE, KeyOperations.MAC_VERIFY)
            val privateJwk =
                Jwk(
                    kty = JwaKeyType.oct,
                    k = kValue,
                    alg = algMapping.jose,
                    use = keyUse.value,
                    key_ops = null,
                    kid = kid,
                    generateKid = false,
                )
            // Public JWK omits the secret key material
            val publicJwk = privateJwk.copy(k = null)

            val publicCoseKey = CoseJoseKeyMappingService.toCoseKey(publicJwk)
            val managedKeyPair =
                ManagedKeyPair(
                    providerId = id,
                    kid = kid,
                    alias = alias ?: kid,
                    jose =
                        JoseKeyPair(
                            if (config.exposePrivateKeysDuringGeneration) {
                                privateJwk
                            } else {
                                null
                            },
                            publicJwk,
                        ),
                    cose =
                        CoseKeyPair(
                            if (config.exposePrivateKeysDuringGeneration) {
                                CoseJoseKeyMappingService.toCoseKey(privateJwk)
                            } else {
                                null
                            },
                            publicCoseKey,
                        ),
                )

            if (config.persistKeysDuringGeneration) {
                log.debug("Persisting symmetric key ${managedKeyPair.alias} to key store")
                val keyInfo =
                    ResolvedKeyInfo<Jwk>(
                        key = privateJwk,
                        keyVisibility = KeyVisibility.PRIVATE,
                        keyType = KeyTypeMapping.Symmetric,
                        alias = managedKeyPair.alias,
                        providerId = id,
                        kid = kid,
                        signatureAlgorithm = algMapping,
                    )
                keyStore.storeKey(
                    keyInfo,
                    alias = managedKeyPair.alias,
                    providerId = managedKeyPair.providerId,
                )
            }

            return managedKeyPair
        }

        // Fall back to software generation using cryptography library
        val privateJwk: Jwk
        val publicJwk: Jwk

        if (keyType === KeyTypeMapping.EC) {
            require(curve !== null) { "Curve must be provided for EC key type" }
            // Only EcDSA curves for now.
            checkSupportedEcdsaCurve(curve)
            val curveImpl = resolveEcdsaKmpCurve(curve)
            val keyPair = ecdsa.value.keyPairGenerator(curveImpl).generateKey()

            // Use native JWK encoding (cryptography-kotlin 0.6.0) — no signum roundtrip
            privateJwk =
                keyPair.privateKey
                    .toSphereonJwk()
                    .copy(use = keyUse.value, key_ops = null, alg = algMapping.jose)
            publicJwk =
                keyPair.publicKey
                    .toSphereonJwk()
                    .copy(use = keyUse.value, key_ops = null, alg = algMapping.jose)
        } else if (keyType === KeyTypeMapping.OKP) {
            require(curve !== null) { "Curve must be provided for OKP key type" }
            require(isOkpCurve(curve)) { "Curve $curve is not an OKP curve (expected Ed25519, Ed448, X25519, or X448)" }
            val expectedLen = expectedOkpKeyByteLength(curve)
            val isSigning = curve is Curve.Ed25519 || curve is Curve.Ed448
            val rawPublic: ByteArray
            val rawPrivate: ByteArray
            if (isSigning) {
                val keyPair = eddsa.value.keyPairGenerator(resolveEdDsaKmpCurve(curve)).generateKey()
                rawPublic = keyPair.publicKey.encodeToByteArray(EdDSA.PublicKey.Format.RAW)
                rawPrivate = keyPair.privateKey.encodeToByteArray(EdDSA.PrivateKey.Format.RAW)
            } else {
                val keyPair = xdh.value.keyPairGenerator(resolveXdhKmpCurve(curve)).generateKey()
                rawPublic = keyPair.publicKey.encodeToByteArray(XDH.PublicKey.Format.RAW)
                rawPrivate = keyPair.privateKey.encodeToByteArray(XDH.PrivateKey.Format.RAW)
            }
            check(rawPublic.size == expectedLen) { "Generated OKP public key length ${rawPublic.size} != expected $expectedLen for $curve" }
            check(rawPrivate.size == expectedLen) { "Generated OKP private key length ${rawPrivate.size} != expected $expectedLen for $curve" }
            privateJwk =
                okpRawToJwk(rawPublic = rawPublic, rawPrivate = rawPrivate, curve = curve)
                    .copy(use = keyUse.value, key_ops = null, alg = algMapping.jose)
            publicJwk = privateJwk.copy(d = null)
        } else {
            val (size, digest) =
                when (algMapping) {
                    SignatureAlgorithm.RSA_SHA384, SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1 -> 3072.bits to SHA384
                    SignatureAlgorithm.RSA_SHA512, SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1 -> 4096.bits to SHA512
                    else -> 2048.bits to SHA256
                }

            // Use PSS key generator for PSS algorithms to ensure compatibility
            val isPss =
                when (algMapping) {
                    SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1,
                    SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1,
                    SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1,
                    SignatureAlgorithm.RSA_SSA_PSS_RAW_MGF1,
                    -> true

                    else -> false
                }

            if (isPss) {
                val keyPair = rsaPss.value.keyPairGenerator(keySize = size, digest = digest).generateKey()
                privateJwk =
                    keyPair.privateKey
                        .toSphereonJwk()
                        .copy(use = keyUse.value, key_ops = null, alg = algMapping.jose)
                publicJwk =
                    keyPair.publicKey
                        .toSphereonJwk()
                        .copy(use = keyUse.value, key_ops = null, alg = algMapping.jose)
            } else {
                val keyPair = rsaPkcs1.value.keyPairGenerator(keySize = size, digest = digest).generateKey()
                privateJwk =
                    keyPair.privateKey
                        .toSphereonJwk()
                        .copy(use = keyUse.value, key_ops = null, alg = algMapping.jose)
                publicJwk =
                    keyPair.publicKey
                        .toSphereonJwk()
                        .copy(use = keyUse.value, key_ops = null, alg = algMapping.jose)
            }
        }

        val kid = privateJwk.kid ?: generateJwkThumbprint(publicJwk)
        val privateCoseKey = CoseJoseKeyMappingService.toCoseKey(privateJwk)
        val publicCoseKey = CoseJoseKeyMappingService.toCoseKey(publicJwk)

        var keyInfo: ResolvedKeyInfoType<JwkType> =
            ResolvedKeyInfo(
                key = privateJwk,
                keyVisibility = KeyVisibility.PRIVATE,
                keyType = keyType,
                alias = alias ?: kid,
                providerId = id,
                kid = kid,
                x5c = privateJwk.x5c,
                signatureAlgorithm = privateJwk.getSignatureAlgorithm() ?: alg,
            )
        var certChain: Array<Certificate>? = null

        // If certificate options are provided use them, otherwise see if we need to create a self signed cert and use the alias as CN
        val supportsCertificate = keyType == KeyTypeMapping.EC || keyType == KeyTypeMapping.RSA
        // Implicit certificates are self-signed. An encryption recipient must
        // never be used as a signer merely because automatic certificates are on.
        val supportsSelfSigning = keyUse == JwkUse.sig && KeyOperations.SIGN in keyOpsMapping
        val certOpts =
            certificateOptions ?: if (!config.autoCreateCertificate || !supportsCertificate || !supportsSelfSigning) {
                null
            } else {
                CertificateOptions(
                    subjectKeyInfo = keyInfo,
                    subject = X509DistinguishedNameElements(commonName = alias ?: kid),
                )
            }
        if (certOpts != null && keyInfo.x5c == null) {
            // Create a self-signed certificate if no cert chain is provided and the option is enabled
            val certResult =
                CertificateCreationUtils.createCertificate(
                    issuerKeyInfo = certOpts.issuerKeyInfo,
                    issuer = certOpts.issuer,
                    subjectKeyInfo = certOpts.subjectKeyInfo,
                    subject = certOpts.subject,
                    serialNumber = certOpts.serialNumber,
                    extensions = certOpts.extensions,
                    notBefore = certOpts.notBefore,
                    notAfter = certOpts.notAfter,
                    signatureFunction = {
                        this.createRawSignature(keyInfo = keyInfo, input = it, requireX5Chain = false)
                    },
                )
            // Let's populate the certchain and also update the keyInfo with the cert chain
            certChain = arrayOf(certResult.certificate)
            keyInfo = certResult.certificate.amendJwkKeyInfo(keyInfo)
        }

        // The certificate is persisted with the key above, but callers receive the generated
        // pair, not the internal key-info object. Keep the public return value coherent with the
        // persisted entry: downstream public-material caches must retain x5c rather than freezing
        // the bare JWK that existed before automatic certificate creation.
        val returnedPublicJwk = publicJwk.copy(kid = kid, x5c = keyInfo.x5c)
        val returnedPrivateJwk = privateJwk.copy(kid = kid, x5c = keyInfo.x5c)

        val managedKeyPair =
            ManagedKeyPair(
                providerId = id,
                kid = kid,
                alias = alias ?: kid,
                jose =
                    JoseKeyPair(
                        if (config.exposePrivateKeysDuringGeneration) {
                            returnedPrivateJwk
                        } else {
                            null
                        },
                        returnedPublicJwk,
                    ),
                cose =
                    CoseKeyPair(
                        if (config.exposePrivateKeysDuringGeneration) {
                            privateCoseKey.copy(kid = kid.toCborByteString(Encoding.UTF8))
                        } else {
                            null
                        },
                        publicCoseKey.copy(kid = kid.toCborByteString(Encoding.UTF8)),
                    ),
            )

        if (config.persistKeysDuringGeneration) {
            log.debug("Persisting key ${keyInfo.alias} to key store")
            keyStore.storeKey(
                ResolvedKeyInfo.fromKeyInfo(keyInfo, privateJwk),
                alias = managedKeyPair.alias,
                providerId = managedKeyPair.providerId,
                certChain = certChain,
            )
        }

        return managedKeyPair
    }

    private suspend fun keyInfoToBytesWithKeystoreLookup(
        keyInfo: KeyInfoType<*>,
        mangedKeyRequired: Boolean = false,
    ): DerKmpKeyInfoContext {
        val inlineKey =
            keyInfo.key?.let { suppliedKey ->
                runCatching { CoseJoseKeyMappingService.toJoseJwk(suppliedKey) }
                    .getOrElse { cause ->
                        throw IllegalArgumentException(
                            "Inline key material cannot be converted to a JWK; refusing keystore lookup",
                            cause,
                        )
                    }
            }
        if (inlineKey != null) {
            validateInlineKeySelection(keyInfo, inlineKey)
        } else {
            log.debug("[KEYSTORE-LOOKUP] Looking up key with alias=${keyInfo.alias}, kid=${keyInfo.kid}, signatureAlgorithm=${keyInfo.signatureAlgorithm}")
        }
        // When a managed (private) key is required (e.g., for signing) and the keystore exposes
        // private key material for signing, we must request PRIVATE visibility from the keystore.
        // Software keystores (memory, PKCS12, JKS, file-backed) store and expose private key bytes
        // for software signing. Hardware-backed keystores (e.g., iOS keychain, HSMs) delegate signing
        // to hardware without exposing private keys; those are handled by signWithNativeKey().
        val lookupKeyInfo =
            if (mangedKeyRequired && privateKeyStore?.exposesPrivateKeysForSigning() == true) {
                KeyInfo<Nothing>(
                    alias = keyInfo.alias,
                    kid = keyInfo.kid,
                    keyVisibility = KeyVisibility.PRIVATE,
                    signatureAlgorithm = keyInfo.signatureAlgorithm,
                    providerId = keyInfo.providerId,
                )
            } else {
                keyInfo
            }
        val resolvedKeyInfo =
            if (inlineKey != null) {
                // Supplied material is authoritative even when an alias/kid accompanies it. This
                // is required while an automatically generated certificate is signed before the
                // generated alias has been persisted. Public-only material must never borrow a
                // stored private key; callers selecting a stored signing key must omit material.
                if (keyInfo is ResolvedKeyInfoType<*>) {
                    keyInfo
                } else {
                    ResolvedKeyInfo(
                        key = inlineKey,
                        opts = keyInfo.opts,
                        keyVisibility = keyInfo.keyVisibility ?: KeyVisibility.PUBLIC,
                        keyType = keyInfo.keyType ?: inlineKey.getKeyType(),
                        alias = keyInfo.alias,
                        providerId = keyInfo.providerId,
                        kid = keyInfo.kid ?: inlineKey.kid,
                        signatureAlgorithm = keyInfo.signatureAlgorithm ?: inlineKey.getSignatureAlgorithm(),
                        x5c = keyInfo.x5c ?: inlineKey.x5c,
                        keyEncoding = keyInfo.keyEncoding,
                        noCache = keyInfo.noCache,
                    )
                }
            } else if (!mangedKeyRequired) {
                val resolved = privateKeyStore?.getKey(keyInfo)
                log.debug("[KEYSTORE-LOOKUP] Retrieved key: alias=${resolved?.alias}, signatureAlgorithm=${resolved?.signatureAlgorithm}")
                resolved
            } else {
                val resolved = privateKeyStore?.getKey(lookupKeyInfo)
                log.debug("[KEYSTORE-LOOKUP] Retrieved key: alias=${resolved?.alias}, signatureAlgorithm=${resolved?.signatureAlgorithm}")
                resolved
            }

        requireNotNull(resolvedKeyInfo) { "Key ${keyInfo.alias ?: "<none>"} was not resolved, or not found in keystore" }
        return when (resolvedKeyInfo.keyType) {
            KeyTypeMapping.EC -> {
                keyInfoToEcdsaDerKmpContext(keyInfo, resolvedKeyInfo)
            }

            KeyTypeMapping.RSA -> {
                keyInfoToRSADerKmpContext(keyInfo, resolver = { resolvedKeyInfo })
            }

            KeyTypeMapping.OKP -> {
                // OKP keys (Ed25519 / Ed448 / X25519 / X448) bypass the DER pipeline —
                // cryptography-kotlin's EdDSA / XDH algorithms decode raw key bytes from
                // the JWK directly. We populate `DerKmpKeyInfoContext` with the JWK and
                // empty/null bytes; the EdDSA/XDH branches in createRawSignature/
                // isValidRawSignature ignore the byte fields and `curveImpl`.
                val jwkInfo = toKeyInfoJwk(if (resolvedKeyInfo.key != null) resolvedKeyInfo else keyInfo)
                val key =
                    jwkInfo.key
                        ?: throw IllegalArgumentException("OKP key info is missing the JWK key material")
                DerKmpKeyInfoContext(
                    key = key,
                    publicKeyBytes = ByteArray(0),
                    privateKeyBytes = if (key.d != null) ByteArray(0) else null,
                    curveImpl = null,
                    algImpl = SHA256,
                )
            }

            else -> {
                throw IllegalArgumentException("Key type ${resolvedKeyInfo.keyType} not supported")
            }
        }
    }

    private fun validateInlineKeySelection(
        keyInfo: KeyInfoType<*>,
        inlineKey: JwkType,
    ) {
        require(keyInfo.providerId == null || keyInfo.providerId == id) {
            "Inline key provider '${keyInfo.providerId}' does not match software KMS provider '$id'"
        }
        // An alias does not override explicit key identity on supplied material.
        if (
            keyInfo.kid != null &&
            inlineKey.kid != null &&
            keyInfo.kid != inlineKey.kid
        ) {
            throw IllegalArgumentException(
                "Inline key kid '${inlineKey.kid}' does not match selected kid '${keyInfo.kid}'",
            )
        }
    }

    /**
     * Generates a signature for the given input data using the provided key information.
     *
     * @param keyInfo Information about the signing key.
     * @param input The data to be signed.
     * @return The generated signature as a byte array.
     * @throws IllegalArgumentException If the private key is not provided or not supported.
     */
    override fun rawSignatureEncoding(algorithm: SignatureAlgorithm): com.sphereon.crypto.core.kms.command.SignatureEncoding? =
        com.sphereon.crypto.core.kms.command.SignatureEncoding.RAW

    override suspend fun createRawSignature(
        keyInfo: KeyInfoType<*>,
        input: ByteArray,
        requireX5Chain: Boolean,
    ): ByteArray {
        requireManagedSigningKeySelection(keyInfo)
        // Resolve once with private visibility. Inline material is authoritative, while a
        // selector is looked up once and can then be used by native or software signing.
        val resolvedContext = keyInfoToBytesWithKeystoreLookup(keyInfo, mangedKeyRequired = true)
        val resolvedKey = resolvedContext.key
        val requestedAlgorithm = keyInfo.signatureAlgorithm ?: resolvedKey.getSignatureAlgorithm()
            ?: throw IllegalArgumentException("No signature algorithm found or supplied for $keyInfo")
        val policyInfo = if (keyInfo.key != null) keyInfo else resolvedSigningKeyInfo(keyInfo, resolvedKey, requestedAlgorithm)
        policyInfo.requireSigningKeyCompatible(requestedAlgorithm)

        // Inline material is authoritative and must never be redirected to a provider alias.
        // Native signing is reserved for selectors whose private material is not exportable.
        if (keyInfo.key == null) {
            val nativeSignature = signWithNativeKey(policyInfo, input)
            if (nativeSignature != null) return nativeSignature
        }

        // Fall back to software signing
        val (key, _, privateKeyBytes, curveImpl, algImpl) = resolvedContext

        val softwarePolicyInfo = if (keyInfo.key != null) keyInfo else resolvedSigningKeyInfo(keyInfo, key, requestedAlgorithm)
        softwarePolicyInfo.requireSigningKeyCompatible(requestedAlgorithm)

        return when {
            key.kty == JwaKeyType.EC && key.d != null -> {
                // Load private key from JWK directly (no DER/signum roundtrip).
                // Prefer the precomputed curveImpl; fall back to the JWK crv when the
                // ECDSA context builder left curveImpl null (alias-resolved PKCS12 keys).
                val curve =
                    curveImpl
                        ?: resolveEcdsaKmpCurve(Curve.fromJose(key.crv ?: JwaCurve.P_256))
                        ?: throw IllegalArgumentException(
                            "Unsupported EC curve '${key.crv}' for software signing of ${keyInfo.alias ?: keyInfo.kid}",
                        )
                val digest = algImpl ?: resolveEcdsaKmpDigest(requestedAlgorithm)
                val privateKey = key.toEcdsaPrivateKey(provider = cryptoProvider, curve = curve)
                return privateKey.signatureGenerator(digest = digest, format = ECDSA.SignatureFormat.RAW).generateSignature(input)
            }

            key.kty == JwaKeyType.OKP && key.d != null -> {
                // EdDSA (Ed25519 / Ed448): no digest or signature-format parameter — RFC 8032 fixes those.
                val jwaCurve = key.crv ?: throw IllegalArgumentException("OKP signing key is missing 'crv'")
                val sphCurve = Curve.fromJose(jwaCurve)
                require(sphCurve is Curve.Ed25519 || sphCurve is Curve.Ed448) {
                    "OKP signing curve must be Ed25519 or Ed448, was $sphCurve"
                }
                val privateKey = key.toEdDsaPrivateKey(provider = cryptoProvider, curve = sphCurve)
                return privateKey.signatureGenerator().generateSignature(input)
            }

            key.kty == JwaKeyType.RSA && key.n != null && key.d != null -> {
                val signatureAlgorithm = requestedAlgorithm
                log.debug("[SIGNING] RSA: keyInfo.signatureAlgorithm=${keyInfo.signatureAlgorithm}, key.getSignatureAlgorithm()=${key.getSignatureAlgorithm()}, resolved=$signatureAlgorithm")
                val digest = resolveRSAKmpDigest(signatureAlgorithm)
                when (signatureAlgorithm) {
                    SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1, SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, SignatureAlgorithm.RSA_SSA_PSS_RAW_MGF1 -> {
                        log.debug("[SIGNING] Using RSA-PSS with digest=$digest (using library default salt size = digest length)")
                        // Load private key from JWK directly (no DER/signum roundtrip)
                        val privateKey = key.toRsaPssPrivateKey(provider = cryptoProvider, digest = digest)
                        privateKey.signatureGenerator().generateSignature(input)
                    }

                    else -> {
                        log.debug("[SIGNING] Using RSA-PKCS1 with digest=$digest")
                        val privateKey = key.toRsaPkcs1PrivateKey(provider = cryptoProvider, digest = digest)
                        privateKey.signatureGenerator().generateSignature(input)
                    }
                }
            }

            else -> {
                throw IllegalArgumentException(
                    "Private key resolution or HSMs not supported yet. Please provide a private key " +
                        "(kty=${key.kty}, hasD=${key.d != null}, curveImpl=${curveImpl != null}, " +
                        "alias=${keyInfo.alias}, kid=${keyInfo.kid}, visibility=${keyInfo.keyVisibility})",
                )
            }
        }
    }

    /**
     * Verifies the signature of the input data using the provided key information.
     *
     * @param keyInfo Key information that includes the public key and other details.
     * @param input The original data which the signature is supposed to represent.
     * @param signature The signature that needs to be verified.
     * @return true if the signature is valid, false otherwise.
     * @throws IllegalArgumentException if a private key is used to verify the signature.
     */
    override suspend fun isValidRawSignature(
        keyInfo: KeyInfoType<*>,
        input: ByteArray,
        signature: ByteArray,
    ): Boolean {
        val (key, _, _, curveImpl, algImpl) = keyInfoToBytesWithKeystoreLookup(keyInfo)
        val signatureAlgorithm = keyInfo.signatureAlgorithm ?: key.getSignatureAlgorithm()
            ?: throw IllegalArgumentException("No signature algorithm found or supplied for $keyInfo")
        keyInfo.key?.let { keyInfo.requireVerificationKeyCompatible(signatureAlgorithm) }
        resolvedSigningKeyInfo(keyInfo, key).verificationPolicyInfo().requireVerificationKeyCompatible(signatureAlgorithm)
        return when {
            key.kty == JwaKeyType.OKP && key.x != null -> {
                // EdDSA (Ed25519 / Ed448): no digest parameter; signature length fixed.
                val jwaCurve = key.crv ?: throw IllegalArgumentException("OKP verification key is missing 'crv'")
                val sphCurve = Curve.fromJose(jwaCurve)
                require(sphCurve is Curve.Ed25519 || sphCurve is Curve.Ed448) {
                    "OKP verification curve must be Ed25519 or Ed448, was $sphCurve"
                }
                val publicKey = key.toEdDsaPublicKey(provider = cryptoProvider, curve = sphCurve)
                publicKey.signatureVerifier().tryVerifySignature(input, signature)
            }

            key.x != null && curveImpl != null -> {
                // Load public key from JWK directly (no DER/signum roundtrip)
                val publicKey = key.toEcdsaPublicKey(provider = cryptoProvider, curve = curveImpl)
                publicKey.signatureVerifier(digest = algImpl, format = ECDSA.SignatureFormat.RAW).tryVerifySignature(input, signature)
            }

            key.n != null -> {
                log.debug("[VERIFICATION] RSA: keyInfo.signatureAlgorithm=${keyInfo.signatureAlgorithm}, key.getSignatureAlgorithm()=${key.getSignatureAlgorithm()}, resolved=$signatureAlgorithm")
                val digest = resolveRSAKmpDigest(signatureAlgorithm)
                when (signatureAlgorithm) {
                    SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1, SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1, SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1, SignatureAlgorithm.RSA_SSA_PSS_RAW_MGF1 -> {
                        log.debug("[VERIFICATION] Using RSA-PSS with digest=$digest")
                        val publicKey = key.toRsaPssPublicKey(provider = cryptoProvider, digest = digest)
                        publicKey.signatureVerifier().tryVerifySignature(input, signature)
                    }

                    else -> {
                        log.debug("[VERIFICATION] Using RSA-PKCS1 with digest=$digest")
                        val publicKey = key.toRsaPkcs1PublicKey(provider = cryptoProvider, digest = digest)
                        publicKey.signatureVerifier().tryVerifySignature(input, signature)
                    }
                }
            }

            else -> {
                throw IllegalArgumentException("Private key resolution or HSMs not supported yet. Please provide a private key")
            }
        }
    }

    override suspend fun signDigest(
        keyInfo: KeyInfoType<*>,
        digest: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        signatureEncoding: SignatureEncoding,
        requireX5Chain: Boolean,
    ): ByteArray {
        requireManagedSigningKeySelection(keyInfo)
        require(digest.isNotEmpty()) { "digest is required" }
        val (key, _, _, curveImpl, _) = keyInfoToBytesWithKeystoreLookup(keyInfo, mangedKeyRequired = true)

        resolvedSigningKeyInfo(keyInfo, key).requireSigningKeyCompatible(signatureAlgorithm)

        require(signatureAlgorithm.cryptoAlgorithm == CryptoAlg.ECDSA) { "Digest signing currently supports ECDSA algorithms only, got: $signatureAlgorithm" }
        require(key.kty == JwaKeyType.EC) { "Digest signing with $signatureAlgorithm requires an EC key, got: ${key.kty}" }
        require(key.d != null) { "Digest signing with $signatureAlgorithm requires a private EC key" }
        require(curveImpl != null) { "Digest signing with $signatureAlgorithm requires a supported EC curve" }

        val privateKey = key.toEcdsaPrivateKey(provider = cryptoProvider, curve = curveImpl)
        return privateKey
            .signatureGenerator(digest = null, format = signatureEncoding.toKmpEcdsaSignatureFormat())
            .generateSignature(digest)
    }

    override suspend fun verifyDigest(
        keyInfo: KeyInfoType<*>,
        digest: ByteArray,
        signature: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        signatureEncoding: SignatureEncoding,
    ): Boolean {
        require(digest.isNotEmpty()) { "digest is required" }
        require(signature.isNotEmpty()) { "signature is required" }
        val (key, _, _, curveImpl, _) = keyInfoToBytesWithKeystoreLookup(keyInfo)

        keyInfo.key?.let { keyInfo.requireVerificationKeyCompatible(signatureAlgorithm) }
        resolvedSigningKeyInfo(keyInfo, key).verificationPolicyInfo().requireVerificationKeyCompatible(signatureAlgorithm)

        require(signatureAlgorithm.cryptoAlgorithm == CryptoAlg.ECDSA) { "Digest verification currently supports ECDSA algorithms only, got: $signatureAlgorithm" }
        require(key.kty == JwaKeyType.EC) { "Digest verification with $signatureAlgorithm requires an EC key, got: ${key.kty}" }
        require(key.x != null && key.y != null) { "Digest verification with $signatureAlgorithm requires a public EC key" }
        require(curveImpl != null) { "Digest verification with $signatureAlgorithm requires a supported EC curve" }

        val publicKey = key.toEcdsaPublicKey(provider = cryptoProvider, curve = curveImpl)
        return publicKey
            .signatureVerifier(digest = null, format = signatureEncoding.toKmpEcdsaSignatureFormat())
            .tryVerifySignature(digest, signature)
    }

    override suspend fun createSignature(
        signInput: SignInput,
        keyInfo: KeyInfoType<*>?,
        signatureAlgorithm: SignatureAlgorithm?,
    ): SignOutput {
        requireNotNull(keyInfo) { "keyInfo is required for SoftwareKmsProvider.createSignature" }
        val signatureBytes = createRawSignature(keyInfo, signInput.input, false)
        return SignOutputData(
            signedData = signatureBytes,
            signatureLevel = SignatureLevel.RAW,
            signingTime = Clock.System.now(),
            name = signInput.name,
            mimeType = signInput.mimeType,
        )
    }

    override suspend fun isValidSignature(
        signInput: SignInput,
        signature: Signature,
    ): Boolean = isValidRawSignature(signature.keyInfo, signInput.input, signature.value)

    private fun resolvedSigningKeyInfo(
        requestedKeyInfo: KeyInfoType<*>,
        resolvedKey: Jwk,
        requestedAlgorithm: SignatureAlgorithm? = requestedKeyInfo.signatureAlgorithm,
    ): KeyInfoType<*> {
        val kid = resolvedKey.kid ?: requestedKeyInfo.kid
        val x5c = requestedKeyInfo.x5c ?: resolvedKey.x5c
        return if (requestedKeyInfo is ResolvedKeyInfoType<*>) {
            ResolvedKeyInfo(
                kid = kid,
                key = resolvedKey,
                opts = requestedKeyInfo.opts,
                keyVisibility = requestedKeyInfo.keyVisibility,
                signatureAlgorithm = requestedAlgorithm,
                x5c = x5c,
                alias = requestedKeyInfo.alias,
                providerId = requestedKeyInfo.providerId,
                keyType = requestedKeyInfo.keyType,
                keyEncoding = requestedKeyInfo.keyEncoding,
                noCache = requestedKeyInfo.noCache,
            )
        } else {
            KeyInfo(
                kid = kid,
                key = resolvedKey,
                opts = requestedKeyInfo.opts,
                keyVisibility = requestedKeyInfo.keyVisibility,
                signatureAlgorithm = requestedAlgorithm,
                x5c = x5c,
                alias = requestedKeyInfo.alias,
                providerId = requestedKeyInfo.providerId,
                keyType = requestedKeyInfo.keyType,
                keyEncoding = requestedKeyInfo.keyEncoding,
                noCache = requestedKeyInfo.noCache,
            )
        }
    }

    private fun KeyInfoType<*>.requireVerificationKeyCompatible(requestedAlgorithm: SignatureAlgorithm) {
        val failure = keyCompatibilityFailure(requestedAlgorithm, KeyOperations.VERIFY)
        if (failure != null) {
            throw IllegalArgumentException(failure)
        }
    }

    private fun KeyInfoType<*>.verificationPolicyInfo(): KeyInfoType<*> = this

    // Encryption operations
    override suspend fun encrypt(
        keyInfo: KeyInfoType<*>,
        plaintext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        additionalAuthenticatedData: ByteArray?,
    ): EncryptionResult {
        val resolvedKeyInfo = resolveKeyIfNeeded(keyInfo)
        val result =
            encryptWithNativeKey(resolvedKeyInfo, plaintext, algorithm.identifier, additionalAuthenticatedData)
                ?: throw UnsupportedOperationException("Encryption algorithm '${algorithm.identifier}' not supported on this platform")

        return result
    }

    override suspend fun decrypt(
        keyInfo: KeyInfoType<*>,
        ciphertext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        iv: ByteArray,
        authTag: ByteArray,
        additionalAuthenticatedData: ByteArray?,
    ): ByteArray {
        val resolvedKeyInfo = resolveKeyIfNeeded(keyInfo)
        return decryptWithNativeKey(resolvedKeyInfo, ciphertext, algorithm.identifier, iv, authTag, additionalAuthenticatedData)
            ?: throw UnsupportedOperationException("Decryption algorithm '${algorithm.identifier}' not supported on this platform")
    }

    override suspend fun wrapKey(
        wrappingKeyInfo: KeyInfoType<*>,
        keyToWrap: ByteArray,
        algorithm: KeyWrapAlgorithm,
    ): ByteArray {
        val resolvedKeyInfo = resolveKeyIfNeeded(wrappingKeyInfo)
        return wrapKeyWithNativeKey(resolvedKeyInfo, keyToWrap, algorithm.identifier)
            ?: throw UnsupportedOperationException("Key wrapping algorithm '${algorithm.identifier}' not supported on this platform")
    }

    override suspend fun unwrapKey(
        unwrappingKeyInfo: KeyInfoType<*>,
        wrappedKey: ByteArray,
        algorithm: KeyWrapAlgorithm,
    ): ByteArray {
        val resolvedKeyInfo = resolveKeyIfNeeded(unwrappingKeyInfo)
        return unwrapKeyWithNativeKey(resolvedKeyInfo, wrappedKey, algorithm.identifier)
            ?: throw UnsupportedOperationException("Key unwrapping algorithm '${algorithm.identifier}' not supported on this platform")
    }

    override suspend fun performKeyAgreement(
        privateKeyInfo: KeyInfoType<*>,
        publicKeyInfo: KeyInfoType<*>,
        algorithm: KeyAgreementAlgorithm,
        keyDataLen: Int?,
    ): ByteArray {
        log.debug("Performing ECDH key agreement with algorithm: ${algorithm.identifier}")
        val resolvedPrivateKeyInfo = resolveKeyIfNeeded(privateKeyInfo)
        val resolvedPublicKeyInfo = resolvePublicKeyIfNeeded(publicKeyInfo)
        return performKeyAgreementWithNativeKey(resolvedPrivateKeyInfo, resolvedPublicKeyInfo, algorithm.identifier)
    }

    override suspend fun ecdhDerive(
        privateKeyInfo: KeyInfoType<*>,
        publicKeyInfo: KeyInfoType<*>,
        algorithm: KeyAgreementAlgorithm,
        mode: EcdhDeriveMode,
        keyDataLen: Int?,
        algorithmId: String?,
        partyUInfo: ByteArray?,
        partyVInfo: ByteArray?,
    ): EcdhDeriveResult {
        log.debug("Performing provider-backed ECDH derive with algorithm: ${algorithm.identifier}, mode: $mode")
        val resolvedPrivateKeyInfo = resolveKeyIfNeeded(privateKeyInfo)
        val resolvedPublicKeyInfo = resolvePublicKeyIfNeeded(publicKeyInfo)
        val rawSharedSecret = performKeyAgreementWithNativeKey(resolvedPrivateKeyInfo, resolvedPublicKeyInfo, algorithm.identifier)

        return when (mode) {
            EcdhDeriveMode.RAW_X -> {
                EcdhDeriveResult(derivedSecret = rawSharedSecret)
            }

            EcdhDeriveMode.CONCAT_KDF -> {
                val derived =
                    ConcatKdf.deriveKey(
                        sharedSecret = rawSharedSecret,
                        keyDataLen = requireNotNull(keyDataLen) { "keyDataLen is required when mode is CONCAT_KDF" },
                        algorithmId = requireNotNull(algorithmId) { "algorithmId is required when mode is CONCAT_KDF" },
                        apu = partyUInfo ?: ByteArray(0),
                        apv = partyVInfo ?: ByteArray(0),
                    )
                EcdhDeriveResult(derivedSecret = derived, rawSharedSecret = rawSharedSecret)
            }
        }
    }

    override suspend fun ecPointMultiply(
        privateKeyInfo: KeyInfoType<*>,
        publicKeyInfo: KeyInfoType<*>,
        output: EcPointMultiplyOutput,
    ): EcPointMultiplyResult {
        require(output == EcPointMultiplyOutput.RAW_X) { "Only RAW_X EC point multiplication output is supported" }
        val rawX =
            ecdhDerive(
                privateKeyInfo = privateKeyInfo,
                publicKeyInfo = publicKeyInfo,
                algorithm = KeyAgreementAlgorithm.ECDH_ES,
                mode = EcdhDeriveMode.RAW_X,
                keyDataLen = null,
                algorithmId = null,
                partyUInfo = null,
                partyVInfo = null,
            ).derivedSecret
        return EcPointMultiplyResult(rawX = rawX)
    }

    override suspend fun generateMac(
        keyId: String,
        message: ByteArray,
        digestAlgorithm: DigestAlg,
    ): ByteArray {
        val keyBytes = resolveHmacKeyBytes(keyId)
        return computeHmac(keyBytes, message, digestAlgorithm)
    }

    override suspend fun verifyMac(
        keyId: String,
        message: ByteArray,
        mac: ByteArray,
        digestAlgorithm: DigestAlg,
    ): Boolean {
        val keyBytes = resolveHmacKeyBytes(keyId)
        val computed = computeHmac(keyBytes, message, digestAlgorithm)
        return computed.contentEquals(mac)
    }

    /**
     * Resolves the key material from the keystore when keyInfo.key is null.
     * This is needed for encrypt/decrypt operations where a KeyInfo with only
     * an alias (no key material) is passed — the actual JWK must be fetched from the store.
     */
    private suspend fun resolveKeyIfNeeded(keyInfo: KeyInfoType<*>): KeyInfoType<*> {
        if (keyInfo.key != null) {
            return keyInfo
        }
        // Preserve which lookup mode the caller used. Aliases (operator-assigned
        // labels like `invitation-hmac-kek-default`) and kids (canonical key
        // identifiers, often JWK thumbprints) are NOT interchangeable: a stored
        // key with a thumbprint kid won't match an alias passed as kid, and
        // vice-versa. Forward the original `KeyInfo` so the keystore performs
        // the lookup against the same field the caller populated.
        //
        // Request PRIVATE visibility explicitly: every KMS operation that resolves through here
        // (sign, decrypt, unwrapKey, performKeyAgreement) needs the private key material. KeyInfo's
        // keyVisibility defaults to PUBLIC, which makes the keystore strip the private `d`/`k`
        // component and hand back a public-only key — the license JWE unwrap then fails because the
        // recipient key has no private scalar. Pinning PRIVATE here exports the private material.
        val lookup =
            when {
                keyInfo.alias != null -> KeyInfo<Jwk>(alias = keyInfo.alias, keyVisibility = KeyVisibility.PRIVATE)

                keyInfo.kid != null -> KeyInfo<Jwk>(kid = keyInfo.kid, keyVisibility = KeyVisibility.PRIVATE)

                else -> throw IllegalArgumentException(
                    "KeyInfo has no key material and no alias/kid to resolve from keystore",
                )
            }
        return keyStore.getKey(lookup)
    }

    private suspend fun resolvePublicKeyIfNeeded(keyInfo: KeyInfoType<*>): KeyInfoType<*> {
        if (keyInfo.key != null) {
            return keyInfo
        }
        val lookup =
            when {
                keyInfo.alias != null -> KeyInfo<Jwk>(alias = keyInfo.alias, keyVisibility = KeyVisibility.PUBLIC)

                keyInfo.kid != null -> KeyInfo<Jwk>(kid = keyInfo.kid, keyVisibility = KeyVisibility.PUBLIC)

                else -> throw IllegalArgumentException(
                    "KeyInfo has no key material and no alias/kid to resolve from keystore",
                )
            }
        return keyStore.getKey(lookup)
    }

    /**
     * Mints a 256-bit symmetric AES key suitable for AES-KW key wrapping (RFC 3394)
     * and AES-GCM content encryption. Persists it as an `oct` JWK with the `k`
     * parameter holding the raw bytes — the same shape `extractRawKeyBytes` in
     * `NativeEncryption` expects.
     *
     * Used when [generateKeyAsync] is called with `use=enc` and no `alg`. The
     * `SignatureAlgorithm` enum has no AES variant by design (AES isn't a
     * signature algorithm), so callers asking for a generic encryption key get
     * routed here instead of being silently upgraded to ECDSA, which would fail
     * later in the wrap path with "Wrapping key must have raw bytes for AES-KW".
     */
    private suspend fun generateSymmetricEncKey(
        alias: String?,
        keyOperations: Array<out KeyOperations>?,
    ): ManagedKeyPair {
        // 256 bits = 32 bytes. Matches NativeEncryption.AES_256_KEY_SIZE
        // (private const, inlined here to avoid widening its visibility).
        val keyBytes =
            dev.whyoleg.cryptography.random.CryptographyRandom
                .nextBytes(32)
        val kValue = keyBytes.encodeToBase64Url()
        val kid = alias ?: "key-${kotlin.random.Random.nextLong()}"
        // A symmetric KEK serves both wrap/unwrap (RFC 3394) and direct content
        // encryption (AES-GCM). Default to that full op set; honour caller
        // overrides verbatim so a deployment that wants e.g. wrap-only keys can
        // pin them.
        val keyOpsMapping =
            keyOperations ?: arrayOf(
                KeyOperations.WRAP_KEY,
                KeyOperations.UNWRAP_KEY,
                KeyOperations.ENCRYPT,
                KeyOperations.DECRYPT,
            )
        val joseKeyOps = keyOpsMapping.map { it.jose }.toTypedArray()
        val privateJwk =
            Jwk(
                kty = JwaKeyType.oct,
                k = kValue,
                // No `alg` — JWK `alg` is single-valued, but an oct key minted as a generic
                // KEK is used by both wrap (A256KW) and content encrypt (A256GCM) paths.
                // Leaving `alg` unset keeps the JWK valid for either use.
                alg = null,
                use = JwkUse.enc.value,
                key_ops = joseKeyOps,
                kid = kid,
                generateKid = false,
            )
        val publicJwk = privateJwk.copy(k = null)
        val publicCoseKey = CoseJoseKeyMappingService.toCoseKey(publicJwk)
        val managedKeyPair =
            ManagedKeyPair(
                providerId = id,
                kid = kid,
                alias = alias ?: kid,
                jose =
                    JoseKeyPair(
                        if (config.exposePrivateKeysDuringGeneration) privateJwk else null,
                        publicJwk,
                    ),
                cose =
                    CoseKeyPair(
                        if (config.exposePrivateKeysDuringGeneration) {
                            CoseJoseKeyMappingService.toCoseKey(privateJwk)
                        } else {
                            null
                        },
                        publicCoseKey,
                    ),
            )

        if (config.persistKeysDuringGeneration) {
            log.debug("Persisting symmetric AES key ${managedKeyPair.alias} to key store")
            val keyInfo =
                ResolvedKeyInfo<Jwk>(
                    key = privateJwk,
                    keyVisibility = KeyVisibility.PRIVATE,
                    keyType = KeyTypeMapping.Symmetric,
                    alias = managedKeyPair.alias,
                    providerId = id,
                    kid = kid,
                    signatureAlgorithm = null,
                )
            keyStore.storeKey(
                keyInfo,
                alias = managedKeyPair.alias,
                providerId = managedKeyPair.providerId,
            )
        }
        return managedKeyPair
    }

    private suspend fun resolveHmacKeyBytes(keyId: String): ByteArray {
        val managedKey =
            runCatching { keyStore.getKey(KeyInfo<Jwk>(alias = keyId)) }
                .getOrElse { aliasFailure ->
                    runCatching { keyStore.getKey(KeyInfo<Jwk>(kid = keyId)) }
                        .getOrElse { kidFailure ->
                            throw IllegalArgumentException(
                                "HMAC key '$keyId' could not be resolved by provider '$id': " +
                                    "alias lookup failed: ${aliasFailure.message}; " +
                                    "kid lookup failed: ${kidFailure.message}",
                                kidFailure,
                            ).also { it.addSuppressed(aliasFailure) }
                        }
                }
        val jwk =
            managedKey.key as? JwkType
                ?: throw IllegalArgumentException("Key '$keyId' cannot be resolved as JWK")
        val kValue =
            jwk.k
                ?: throw IllegalArgumentException("Key '$keyId' is not a symmetric key (missing 'k' field)")
        return kValue.decodeFrom(Encoding.BASE64URL)
    }

    @Deprecated("Use getCapabilities().supportedKeyTypes instead")
    override fun supportedKeyTypes(): Array<KeyTypeMapping> = getCapabilities().supportedKeyTypes

    /**
     * Returns an array of supported EcDSA and RSA algorithm mappings.
     *
     * @return An array containing AlgorithmMappings
     */
    @Deprecated("Use getCapabilities().signatureAlgorithms instead")
    override fun supportedSignatureAlgorithms(): Array<SignatureAlgorithm> = getCapabilities().signatureAlgorithms

    fun setPrivateKeyStore(keyStore: KeyStoreService) =
        apply {
            this.privateKeyStore = keyStore
        }

    override suspend fun listKeys(): Array<ManagedKeyReference> = keyStore.listKeys()

    override suspend fun getKey(keyInfo: KeyInfoType<*>): ManagedKeyInfoType<*> {
        // The underlying KeyStoreService stamps the returned ManagedKeyInfo's
        // `providerId` with the *keystore's* id (`config.id` inside the KeyStore
        // service) — which is fine for the keystore's internal scope, but the
        // keystore id is allowed to differ from the KMS provider id. Downstream
        // callers (e.g. SignatureCommandImpl) treat the resolved keyInfo's
        // `providerId` as a KMS provider id and look it up in the
        // KmsProviderRegistry; if those values differ, the lookup fails with
        // "Invalid KMS id <keystoreId> provider".
        //
        // We own the keystore here and we are the parent KMS provider, so swap
        // in our own id before returning. If the inner result is already tagged
        // for a different KMS provider (e.g. caller pre-set it on resolution),
        // preserve that tag.
        val managed = keyStore.getKey(keyInfo)
        if (managed.providerId == id) return managed
        // Wrap the resolved key with our provider id. ManagedKeyInfoType extends
        // ResolvedKeyInfoType, so the returned `managed` is itself a usable
        // resolvedKeyInfo for the new wrapper — alias/key/cert chain etc. are
        // delegated through it.
        return ManagedKeyInfo(
            alias = managed.alias,
            providerId = id,
            resolvedKeyInfo = managed,
        )
    }

    override suspend fun storeKey(
        keyInfo: ResolvedKeyInfoType<*>,
        providerId: String,
        alias: String,
        certChain: Array<Certificate>?,
    ): ManagedKeyInfoType<*> = keyStore.storeKey(keyInfo, providerId, alias, certChain)

    override suspend fun deleteKey(keyInfo: KeyInfoType<*>): Boolean = keyStore.deleteKey(keyInfo)

    override fun keyVisibility(): KeyVisibility = keyStore.keyVisibility()
}

internal fun KeyStoreConfig.withProviderScopedFileId(providerId: String): KeyStoreConfig =
    when (this) {
        is EncryptedFileKeyStoreConfig -> copy(id = providerId)
        is Pkcs12KeyStoreConfig -> copy(id = providerId)
        is BksKeyStoreConfig -> copy(id = providerId)
        is JksKeyStoreConfig -> copy(id = providerId)
        else -> this
    }

private fun SignatureEncoding.toKmpEcdsaSignatureFormat(): ECDSA.SignatureFormat =
    when (this) {
        SignatureEncoding.RAW -> ECDSA.SignatureFormat.RAW
        SignatureEncoding.DER -> ECDSA.SignatureFormat.DER
    }
