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

package com.sphereon.crypto.core.kms

import com.sphereon.core.api.conf.ConfigService
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.compat.JsExportCompat
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.SigningException
import com.sphereon.crypto.core.generic.Curve
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.KeyOperations
import com.sphereon.crypto.core.generic.KeyTypeMapping
import com.sphereon.crypto.core.generic.ManagedKeyPair
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.kms.command.EcPointMultiplyOutput
import com.sphereon.crypto.core.kms.command.EcPointMultiplyResult
import com.sphereon.crypto.core.kms.command.EcdhDeriveMode
import com.sphereon.crypto.core.kms.command.EcdhDeriveResult
import com.sphereon.crypto.core.kms.command.SignatureEncoding
import com.sphereon.crypto.core.sign.SimpleSignatureService
import com.sphereon.crypto.core.sign.model.SignInput
import com.sphereon.crypto.core.sign.model.SignOutput
import com.sphereon.crypto.core.sign.model.Signature
import com.sphereon.di.Order
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesTo
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlin.experimental.ExperimentalObjCName
import kotlin.js.JsStatic
import kotlin.jvm.JvmField
import kotlin.jvm.JvmOverloads
import kotlin.jvm.JvmStatic
import kotlin.native.ObjCName

@JsExportCompat
interface WithKmsProviderType {
    val kmsProviderType: String
}

@JsExportCompat
enum class PredefinedKmsProviderTypes : WithKmsProviderType {
    SOFTWARE,
    MOBILE,
    REST,
    AZURE_KEYVAULT,
    AWS_KMS,
    DIGIDENTITY,
    EPHEMERAL,
    ;

    override val kmsProviderType: String = name.lowercase()

    companion object {
        @JsStatic
        @JvmStatic
        fun fromValue(value: String): PredefinedKmsProviderTypes =
            entries.firstOrNull { it.kmsProviderType == value.lowercase() }
                ?: throw IllegalArgumentException("Unknown kms provider type: $value")
    }
}

@JsExportCompat
@Serializable
@SerialName("KmsProviderConfig")
@OptIn(ExperimentalObjCName::class)
@ObjCName("KmsProviderConfig", exact = true)
data class
KmsProviderConfig
    @JvmOverloads
    constructor(
        override val kmsProviderType: String,
        override val id: String,
        override val enabled: Boolean = true,
        override val order: Int = Order.MEDIUM.orderValue,
        override val exposePrivateKeysDuringGeneration: Boolean = false,
        override val persistKeysDuringGeneration: Boolean = true,
        override val defaultConfigValues: Map<String, String> = emptyMap(),
    ) : AbstractKmsProviderConfig(),
        KmsProviderConfigBase

@Serializable
@JsExportCompat
abstract class AbstractKmsProviderConfig {
    @SerialName("type")
    abstract val kmsProviderType: String
    abstract val id: String
    abstract val enabled: Boolean
    abstract val order: Int

    @SerialName("exposePrivateKeysDuringGeneration")
    abstract val exposePrivateKeysDuringGeneration: Boolean

    @SerialName("persistKeysDuringGeneration")
    abstract val persistKeysDuringGeneration: Boolean

    @SerialName("defaultConfigValues")
    abstract val defaultConfigValues: Map<String, String>
}

@JsExportCompat
@OptIn(ExperimentalObjCName::class)
@ObjCName("KmsProviderConfigBase", exact = true)
interface KmsProviderConfigBase {
    val kmsProviderType: String
    val id: String
    val enabled: Boolean
    val order: Int
    val exposePrivateKeysDuringGeneration: Boolean
    val persistKeysDuringGeneration: Boolean
    val defaultConfigValues: Map<String, String>
}

@JsExportCompat
interface KmsProviderFactory : WithKmsProviderType {
    fun create(
        config: KmsProviderConfigBase,
        execution: SessionExecution,
    ): KmsProvider
}

interface KmsProviderManager {
    /**
     * Creates a KMS provider from a config object (sync).
     */
    fun createFromProviderConfig(
        config: KmsProviderConfigBase,
        execution: SessionExecution,
    ): KmsProvider

    /**
     * Creates KMS providers from config properties (sync).
     * Requires sync cache to be warmed up if using external cache.
     */
    fun createFromProperties(
        configService: ConfigService,
        execution: SessionExecution,
    ): Set<KmsProvider>

    /**
     * Creates KMS providers from config properties (async).
     * Can access external caches (Redis, DB) directly without warmup.
     * Default implementation delegates to sync version.
     */
    suspend fun createFromPropertiesAsync(
        configService: ConfigService,
        execution: SessionExecution,
    ): Set<KmsProvider> = createFromProperties(configService, execution)

    @ContributesTo(AppScope::class)
    interface Graph {
        val kmsProviderManager: KmsProviderManager
    }
}

/**
 * Interface `KmsProvider` provides a blueprint for managing cryptographic keys, including their generation,
 * supported types, and cryptographic curves. Extends the `SimpleSignatureService` to offer functionalities for
 * generating and verifying cryptographic signatures, and `EncryptionService` for encryption/decryption operations.
 */
@JsExportCompat
interface KmsProvider :
    WithKmsProviderType,
    SimpleSignatureService,
    EncryptionService,
    KeyStoreService {
    /** Exact createRawSignature output of this implementation; null is undeclared and must never be guessed. */
    fun rawSignatureEncoding(algorithm: SignatureAlgorithm): SignatureEncoding? = null
    val order: Int
        get() = Order.MEDIUM.orderValue
    val id: String
    val enabled: Boolean
        get() = true

    /**
     * Whether this provider records the keys it creates in the managed key-reference index itself.
     *
     * A generic caller that generates or stores a key through a provider normally indexes the key
     * it gets back, under the provider id that key reports. A provider that already wrote the
     * authoritative row must not have that repeated: the same key would be indexed a second time,
     * and if the provider answers to more than one id, the second row lands under a different
     * provider id and becomes a duplicate of one key. Two rows for one key then drift apart on
     * every lifecycle operation, and a delete that removes one of them leaves the other pointing at
     * a backing key that is gone.
     *
     * Ordinary providers own key material and nothing else, so this is false for them and the
     * generic indexing stands.
     */
    val maintainsKeyReferenceIndex: Boolean
        get() = false

    /**
     * Releases provider-owned network clients when a session registry evicts or replaces this
     * provider. Local providers normally have nothing to release.
     */
    fun close() = Unit

    /**
     * Returns the full capabilities of this KMS provider.
     * This method provides a comprehensive view of what operations, algorithms, and features
     * the provider supports, making it easier to query provider capabilities programmatically.
     *
     * This replaces the need to call multiple supportedXXX() methods individually.
     *
     * @return A KmsProviderCapabilities object containing all provider capabilities
     */
    fun getCapabilities(): KmsProviderCapabilities

    /**
     * Retrieves an array of supported key type mappings.
     *
     * The supported key types represent the mappings between COSE (CBOR Object Signing and Encryption)
     * key types and their corresponding JWA (JSON Web Algorithms) key types. This method provides the
     * available key type mappings for cryptographic operations.
     *
     * @return An array of supported `KeyTypeMapping` objects.
     * @deprecated Use getCapabilities().supportedKeyTypes instead
     */
    @Deprecated(
        message = "Use getCapabilities().supportedKeyTypes instead. This method will be removed in a future release.",
        replaceWith = ReplaceWith("getCapabilities().supportedKeyTypes"),
        level = DeprecationLevel.WARNING,
    )
    fun supportedKeyTypes(): Array<KeyTypeMapping>

    /**
     * Provides a list of supported algorithms by the crypto provider.
     *
     * @return An array of AlgorithmMapping objects representing the supported algorithms.
     * @deprecated Use getCapabilities().signatureAlgorithms instead
     */
    @Deprecated(
        message = "Use getCapabilities().signatureAlgorithms instead. This method will be removed in a future release.",
        replaceWith = ReplaceWith("getCapabilities().signatureAlgorithms"),
        level = DeprecationLevel.WARNING,
    )
    fun supportedSignatureAlgorithms(): Array<SignatureAlgorithm>

    /**
     * @deprecated Use getCapabilities().signatureAlgorithms and extract digest algorithms instead
     */
    @Deprecated(
        message = "Use getCapabilities() instead. This method will be removed in a future release.",
        replaceWith = ReplaceWith("getCapabilities()"),
        level = DeprecationLevel.WARNING,
    )
    fun supportedDigests(): Array<DigestAlg> // convenience, derived from signature algos above

    /**
     * Retrieves an array of supported elliptic curve mappings.
     *
     * @return An array of `CurveMapping` instances representing the supported elliptic curves
     *         for cryptographic operations.
     * @deprecated Use getCapabilities().supportedCurves instead
     */
    @Deprecated(
        message = "Use getCapabilities().supportedCurves instead. This method will be removed in a future release.",
        replaceWith = ReplaceWith("getCapabilities().supportedCurves"),
        level = DeprecationLevel.WARNING,
    )
    fun supportedCurves(): Array<Curve>

    /**
     * Checks if the provided elliptic curve mapping is supported by the crypto provider.
     *
     * @param curve The curve mapping to be checked for support.
     * @return true if the curve is supported, false otherwise.
     */
    fun isSupportedCurve(curve: Curve): Boolean

    /**
     * Creates a digital signature based on the provided input and key information.
     *
     * @param signInput The input data and metadata required for creating the signature.
     * @param keyInfo Optional key information required for the signing operation.
     * @param signatureAlgorithm Optional signature algorithm to be used; defaults to the algorithm in keyInfo.
     * @return The generated signature output.
     * @throws SigningException If any error occurs during the signing process.
     */
    suspend fun createSignature(
        signInput: SignInput,
        keyInfo: KeyInfoType<*>? = null,
        signatureAlgorithm: SignatureAlgorithm? = keyInfo?.signatureAlgorithm,
    ): SignOutput

    /**
     * Validates a given cryptographic signature against the provided signing input.
     *
     * @param signInput The input required for signing operations.
     * @param signature The cryptographic signature to be validated.
     * @return `true` if the signature is valid; `false` otherwise.
     */
    suspend fun isValidSignature(
        signInput: SignInput,
        signature: Signature,
    ): Boolean

    /**
     * Asynchronously generates a cryptographic key pair based on the specified elliptic curve mapping.
     *
     * @param curve The elliptic curve mapping used to generate the key pair. This parameter defines the types of curves supported
     *              for cryptographic operations and includes mappings for both COSE and JOSE curves.
     * @return A `CryptoProviderKeyPair` containing both COSE and JOSE key pairs.
     */
    suspend fun generateKeyAsync(
        alias: String? = null,
        use: JwkUse? = null,
        keyOperations: Array<out KeyOperations>? = null,
        alg: SignatureAlgorithm? = null,
        certificateOptions: CertificateOptions? = null,
    ): ManagedKeyPair

    /**
     * Creates a signature over caller-supplied digest data.
     *
     * Providers that support this operation must sign [digest] directly and must not hash it again.
     */
    suspend fun signDigest(
        keyInfo: KeyInfoType<*>,
        digest: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        signatureEncoding: SignatureEncoding = SignatureEncoding.RAW,
        requireX5Chain: Boolean = false,
    ): ByteArray = throw UnsupportedOperationException("Provider $id does not support ${KmsProviderOperation.SIGN_DIGEST}")

    /**
     * Verifies a signature over caller-supplied digest data.
     *
     * Providers that support this operation must verify [digest] directly and must not hash it again.
     */
    suspend fun verifyDigest(
        keyInfo: KeyInfoType<*>,
        digest: ByteArray,
        signature: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        signatureEncoding: SignatureEncoding = SignatureEncoding.RAW,
    ): Boolean = throw UnsupportedOperationException("Provider $id does not support ${KmsProviderOperation.VERIFY_DIGEST}")

    /**
     * Derives an ECDH raw x-coordinate or KDF output without exporting the private key to the caller.
     */
    suspend fun ecdhDerive(
        privateKeyInfo: KeyInfoType<*>,
        publicKeyInfo: KeyInfoType<*>,
        algorithm: KeyAgreementAlgorithm = KeyAgreementAlgorithm.ECDH_ES,
        mode: EcdhDeriveMode = EcdhDeriveMode.RAW_X,
        keyDataLen: Int? = null,
        algorithmId: String? = null,
        partyUInfo: ByteArray? = null,
        partyVInfo: ByteArray? = null,
    ): EcdhDeriveResult =
        throw UnsupportedOperationException(
            "Provider $id does not support ${if (mode == EcdhDeriveMode.RAW_X) KmsProviderOperation.ECDH_DERIVE_RAW_X else KmsProviderOperation.ECDH_DERIVE_KDF}",
        )

    /**
     * Performs provider-backed EC point multiplication semantics. Phase 1 providers may expose raw-X output only.
     */
    suspend fun ecPointMultiply(
        privateKeyInfo: KeyInfoType<*>,
        publicKeyInfo: KeyInfoType<*>,
        output: EcPointMultiplyOutput = EcPointMultiplyOutput.RAW_X,
    ): EcPointMultiplyResult = throw UnsupportedOperationException("Provider $id does not support ${KmsProviderOperation.EC_POINT_MULTIPLY}")

    /**
     * Generate a MAC (Message Authentication Code) for the given message using the specified key.
     *
     * On cloud KMS providers (AWS, Azure), the HMAC key never leaves the HSM —
     * the computation happens server-side. On software providers, it uses local crypto.
     *
     * @param keyId The ID/alias of the HMAC key in this provider
     * @param message The data to compute the MAC over
     * @param digestAlgorithm The hash algorithm to use (SHA-256, SHA-384, SHA-512)
     * @return The raw HMAC digest bytes (NOT multihash-encoded — the command handles encoding)
     * @throws UnsupportedOperationException if this provider does not support MAC operations
     */
    suspend fun generateMac(
        keyId: String,
        message: ByteArray,
        digestAlgorithm: DigestAlg,
    ): ByteArray = throw UnsupportedOperationException("Provider $id does not support MAC operations")

    /**
     * Verify a MAC for the given message using the specified key.
     *
     * @param keyId The ID/alias of the HMAC key in this provider
     * @param message The original data
     * @param mac The expected MAC digest bytes to verify against
     * @param digestAlgorithm The hash algorithm to use
     * @return true if the MAC is valid
     * @throws UnsupportedOperationException if this provider does not support MAC operations
     */
    suspend fun verifyMac(
        keyId: String,
        message: ByteArray,
        mac: ByteArray,
        digestAlgorithm: DigestAlg,
    ): Boolean = throw UnsupportedOperationException("Provider $id does not support MAC operations")
}

interface KmsProviderConfigBinder {
    /**
     * Gets all KMS provider IDs from configuration (sync).
     * Requires sync cache to be warmed up if using external cache.
     */
    fun getKmsProviderIds(configService: ConfigService): Array<String>

    /**
     * Gets a specific KMS provider config (sync).
     * Requires sync cache to be warmed up if using external cache.
     */
    fun getKmsProviderConfig(
        configService: ConfigService,
        providerId: String,
    ): KmsProviderConfigBase

    /**
     * Gets all KMS provider configs (sync).
     * Requires sync cache to be warmed up if using external cache.
     */
    fun getKmsProviderConfigs(configService: ConfigService): Array<KmsProviderConfigBase>

    /**
     * Gets all KMS provider IDs from configuration (async).
     * Can access external caches (Redis, DB) directly without warmup.
     * Default implementation delegates to sync version.
     */
    suspend fun getKmsProviderIdsAsync(configService: ConfigService): Array<String> = getKmsProviderIds(configService)

    /**
     * Gets a specific KMS provider config (async).
     * Can access external caches (Redis, DB) directly without warmup.
     * Default implementation delegates to sync version.
     */
    suspend fun getKmsProviderConfigAsync(
        configService: ConfigService,
        providerId: String,
    ): KmsProviderConfigBase = getKmsProviderConfig(configService, providerId)

    /**
     * Gets all KMS provider configs (async).
     * Can access external caches (Redis, DB) directly without warmup.
     * Default implementation delegates to sync version.
     */
    suspend fun getKmsProviderConfigsAsync(configService: ConfigService): Array<KmsProviderConfigBase> = getKmsProviderConfigs(configService)

    @ContributesTo(AppScope::class)
    interface Graph {
        val kmsProviderConfigBinder: KmsProviderConfigBinder
    }

    companion object {
        const val KMS_PROVIDERS_PREFIX = "kms.providers"
    }
}
