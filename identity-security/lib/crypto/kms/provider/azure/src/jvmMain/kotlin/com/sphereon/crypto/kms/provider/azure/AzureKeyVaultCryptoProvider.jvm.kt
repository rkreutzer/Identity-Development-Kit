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

package com.sphereon.crypto.kms.provider.azure

/**
 * Azure Key Vault implementation of the CryptoProvider interface for JVM platforms.
 *
 * This class provides integration with Azure Key Vault services for cryptographic operations
 * including key generation, storage, retrieval, signing, and signature verification.
 * It supports both regular Azure Key Vault and Azure Managed HSM instances.
 *
 * The provider supports the following operations:
 * - Key generation (EC keys with various curves)
 * - Raw signature creation and verification
 * - Structured signature creation and verification
 * - Key listing, retrieval, storage, and deletion
 * - Certificate-based operations when using standard Key Vault
 *
 * The implementation uses Azure SDK for Java to communicate with Azure Key Vault
 * and supports various authentication methods including client credentials,
 * certificate-based authentication, interactive browser authentication,
 * and username/password authentication.
 *
 * @property config Configuration options for connecting to Azure Key Vault
 * @property settings Provider-specific settings
 *
 */

import com.azure.core.exception.ResourceNotFoundException
import com.azure.core.http.policy.RetryOptions
import com.azure.core.http.policy.RetryPolicy
import com.azure.security.keyvault.certificates.CertificateAsyncClient
import com.azure.security.keyvault.certificates.CertificateClientBuilder
import com.azure.security.keyvault.certificates.CertificateServiceVersion
import com.azure.security.keyvault.certificates.models.KeyVaultCertificate
import com.azure.security.keyvault.keys.KeyAsyncClient
import com.azure.security.keyvault.keys.KeyClientBuilder
import com.azure.security.keyvault.keys.KeyServiceVersion
import com.azure.security.keyvault.keys.models.CreateEcKeyOptions
import com.azure.security.keyvault.keys.models.CreateOctKeyOptions
import com.azure.security.keyvault.keys.models.CreateRsaKeyOptions
import com.azure.security.keyvault.keys.models.ImportKeyOptions
import com.azure.security.keyvault.keys.models.JsonWebKey
import com.azure.security.keyvault.keys.models.KeyCurveName
import com.azure.security.keyvault.keys.models.KeyOperation
import com.azure.security.keyvault.keys.models.KeyProperties
import com.azure.security.keyvault.keys.models.KeyType
import com.azure.security.keyvault.keys.models.KeyVaultKey
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm as AzureSignatureAlgorithm
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm as AzureKeyWrapAlgorithm
import com.azure.security.keyvault.keys.cryptography.models.EncryptParameters
import com.azure.security.keyvault.keys.cryptography.models.DecryptParameters
import com.sphereon.core.api.error.NotFoundException
import com.sphereon.crypto.core.kms.ContentEncryptionAlgorithm
import com.sphereon.crypto.core.kms.BackendKeyOperationProofProvider
import com.sphereon.crypto.core.kms.BackendKeyProvedDecryption
import com.sphereon.crypto.core.kms.BackendKeyProvedEncryption
import com.sphereon.crypto.core.kms.BackendSymmetricKmsKeyLifecycle
import com.sphereon.crypto.core.kms.ProviderCertificateIdCanonicalizer
import com.sphereon.crypto.core.kms.ProviderCertificateLookup
import com.sphereon.crypto.core.kms.ProviderCertificateReference
import com.sphereon.crypto.core.kms.ProviderCertificateReferenceService
import com.sphereon.crypto.core.kms.ProviderNativeObjectLookup
import com.sphereon.crypto.core.kms.ProviderNativeObjectType
import com.sphereon.crypto.core.kms.ProviderTenantAssignmentVerifier
import com.sphereon.crypto.core.ManagedKeyReference
import com.sphereon.crypto.core.toKeyReference
import com.sphereon.crypto.core.kms.EncryptionResult
import com.sphereon.crypto.core.kms.KeyWrapAlgorithm
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import java.security.SecureRandom
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.TimeoutException
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.reactor.awaitSingle
import kotlinx.coroutines.reactor.awaitSingleOrNull
import com.sphereon.core.compat.Uuid
import com.sphereon.core.api.decodeFromBase64
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.crypto.core.CoseJoseKeyMappingService
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.ManagedKeyInfo
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.ResolvedKeyInfoType
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.SignClientException
import com.sphereon.crypto.core.generic.CoseKeyPair
import com.sphereon.crypto.core.generic.CryptoAlg
import com.sphereon.crypto.core.generic.Curve
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.crypto.core.generic.JoseKeyPair
import com.sphereon.crypto.core.generic.KeyOperations
import com.sphereon.crypto.core.generic.ManagedKeyPair
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwkType
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.sign.requireSigningKeyCompatible
import com.sphereon.crypto.core.sign.keyCompatibilityFailure
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.jose.generateJwkThumbprint
import com.sphereon.crypto.core.kms.CertificateOptions
import com.sphereon.crypto.core.kms.PredefinedKmsProviderTypes
import com.sphereon.crypto.core.kms.command.SignatureEncoding
import com.sphereon.crypto.core.kms.command.SignatureEncodingCodec
import com.sphereon.crypto.core.kms.requireManagedSigningKeySelection
import com.sphereon.crypto.core.sign.model.SignInput
import com.sphereon.crypto.core.sign.model.SignOutput
import com.sphereon.crypto.core.sign.model.SignOutputData
import com.sphereon.crypto.core.sign.model.Signature
import com.sphereon.crypto.core.sign.model.SignatureLevel
import com.sphereon.crypto.core.sign.model.SigningMode
import com.sphereon.crypto.core.x509.Certificate
import com.sphereon.crypto.core.x509.certificateFromDer
import kotlinx.coroutines.CancellationException

/** Public-only snapshot returned by the internal Azure certificate-client seam. */
internal data class AzureCertificateClientRead(
    val certificateId: String?,
    val keyId: String?,
    val certificateDer: ByteArray,
    val tags: Map<String, String> = emptyMap(),
)

/** Public-only snapshot returned by the internal Azure key-client seam. */
internal data class AzureKeyClientRead(
    val keyId: String?,
    val name: String?,
    val version: String?,
    val tags: Map<String, String>,
)

/** JVM-internal boundary around the authenticated Azure key client. */
internal fun interface AzureKeyTenantAssignmentReader {
    suspend fun read(
        name: String,
        version: String?,
    ): AzureKeyClientRead
}

/**
 * JVM-internal boundary around the authenticated Azure certificate client.
 *
 * Keeping Azure SDK models behind this seam lets deterministic tests exercise the
 * public provider contract without exposing SDK types through common/public APIs.
 */
internal fun interface AzureCertificateClientReader {
    suspend fun read(
        alias: String,
        version: String?,
    ): AzureCertificateClientRead
}

private fun AzureKmsProviderConfig.retryPolicyOrNull(): RetryPolicy? =
    exponentialBackoffRetryOpts?.let { RetryPolicy(RetryOptions(it.toExponentialBackoffOptions())) }

/** Builds the Key Vault key client. HTTP logging never includes bodies, see [azureHttpLogOptions]. */
internal fun AzureKmsProviderConfig.buildKeyAsyncClient(): KeyAsyncClient =
    KeyClientBuilder()
        .serviceVersion(KeyServiceVersion.V7_3)
        .vaultUrl(keyvaultUrl)
        .clientOptions(toClientOptions())
        .httpLogOptions(azureHttpLogOptions())
        .retryPolicy(retryPolicyOrNull())
        .credential(credentialOpts.toTokenCredential(tenantId))
        .buildAsyncClient()

/** Builds the Key Vault certificate client. HTTP logging never includes bodies, see [azureHttpLogOptions]. */
internal fun AzureKmsProviderConfig.buildCertificateAsyncClient(): CertificateAsyncClient =
    CertificateClientBuilder()
        .serviceVersion(CertificateServiceVersion.V7_3)
        .vaultUrl(keyvaultUrl)
        .clientOptions(toClientOptions())
        .httpLogOptions(azureHttpLogOptions())
        .retryPolicy(retryPolicyOrNull())
        .credential(credentialOpts.toTokenCredential(tenantId))
        .buildAsyncClient()

/**
 * Implementation of the Azure Key Vault Crypto Provider for JVM environments.
 * Handles key creation, signature operations, key listing, and importing via the Azure SDK for JS.
 */
actual class AzureKeyVaultCryptoProvider actual constructor(
    config: AzureKmsProviderConfig,
//    settings: KeyProviderSettings
) : BaseAzureKeyvaultCryptoProvider(config/*, settings*/),
    ProviderCertificateReferenceService,
    ProviderCertificateIdCanonicalizer,
    ProviderTenantAssignmentVerifier,
    BackendKeyOperationProofProvider,
    BackendSymmetricKmsKeyLifecycle {

    private val keyClient: KeyAsyncClient = config.buildKeyAsyncClient()


    private val hasCertsApi = config.hsmType == HSMType.KEYVAULT

    private var keyTenantAssignmentReader: AzureKeyTenantAssignmentReader =
        AzureKeyTenantAssignmentReader { name, version ->
            val key =
                if (version == null) {
                    keyClient.getKey(name).awaitSingle()
                } else {
                    keyClient.getKey(name, version).awaitSingle()
                }
            AzureKeyClientRead(
                keyId = key.id,
                name = key.properties.name,
                version = key.properties.version,
                tags = key.properties.tags.orEmpty(),
            )
        }

    private val certClient = if (hasCertsApi) config.buildCertificateAsyncClient() else null

    private var certificateClientReader: AzureCertificateClientReader? =
        certClient?.let { client ->
            AzureCertificateClientReader { alias, version ->
                val certificate: KeyVaultCertificate =
                    if (version == null) {
                        client.getCertificate(alias).awaitSingle()
                    } else {
                        client.getCertificateVersion(alias, version).awaitSingle()
                    }
                AzureCertificateClientRead(
                    certificateId = certificate.id ?: certificate.properties?.id,
                    keyId = certificate.keyId,
                    certificateDer = certificate.cer.copyOf(),
                    tags = certificate.properties?.tags.orEmpty(),
                )
            }
        }

    internal constructor(
        config: AzureKmsProviderConfig,
        certificateClientReader: AzureCertificateClientReader,
    ) : this(config) {
        require(config.hsmType == HSMType.KEYVAULT) {
            "Azure certificate reads require a standard Key Vault configuration"
        }
        this.certificateClientReader = certificateClientReader
    }

    internal constructor(
        config: AzureKmsProviderConfig,
        keyTenantAssignmentReader: AzureKeyTenantAssignmentReader,
        certificateClientReader: AzureCertificateClientReader,
    ) : this(config, certificateClientReader) {
        this.keyTenantAssignmentReader = keyTenantAssignmentReader
    }

    override val supportsProviderCertificateReferenceReads: Boolean
        get() = hasCertsApi && certificateClientReader != null

    override suspend fun isAssignedToTenant(
        lookup: ProviderNativeObjectLookup,
        tenantId: String,
    ): Boolean {
        if (tenantId.isBlank()) {
            return false
        }
        if (lookup.type == ProviderNativeObjectType.CERTIFICATE && !hasCertsApi) {
            return false
        }

        return try {
            when (lookup.type) {
                ProviderNativeObjectType.KEY -> {
                    val (name, version) = parseAzureKeyLookup(config.keyvaultUrl, lookup)
                    val key = keyTenantAssignmentReader.read(name, version)
                    resolveAzureKeyIdentity(
                        configuredVaultUrl = config.keyvaultUrl,
                        lookup = lookup,
                        returnedKeyId = key.keyId,
                        returnedName = key.name,
                        returnedVersion = key.version,
                    )
                    azureTenantTagMatches(key.tags, tenantId)
                }

                ProviderNativeObjectType.CERTIFICATE -> {
                    val reader = certificateClientReader ?: return false
                    val certificateLookup =
                        ProviderCertificateLookup(
                            alias = lookup.alias,
                            id = lookup.id,
                        )
                    val (alias, version) = parseAzureCertificateLookup(certificateLookup)
                    val certificate = reader.read(alias, version)
                    resolveAzureCertificateIdentity(
                        configuredVaultUrl = config.keyvaultUrl,
                        lookup = certificateLookup,
                        returnedCertificateId = certificate.certificateId,
                        returnedKeyId = certificate.keyId,
                    )
                    azureTenantTagMatches(certificate.tags, tenantId)
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Generates a new key pair in Azure Key Vault.
     *
     * @param alias The key reference to use for the key pair. If null, a new key reference will be generated.
     * @param keyOperations The key operations that the key pair should support.
     * @param alg The signature algorithm to use for the key pair.
     * @return A ManagedKeyPair object containing the generated key pair.
     * @throws IllegalArgumentException if the curve is not supported by Azure Key Vault.
     * @throws SignClientException if the key pair could not be generated.
     */
    override suspend fun generateKeyAsync(
        alias: String?,
        use: JwkUse?,
        keyOperations: Array<out KeyOperations>?,
        alg: SignatureAlgorithm?,
        certificateOptions: CertificateOptions?
    ): ManagedKeyPair {
        require(certificateOptions == null) { "Certificate options are not yet supported for Azure Keyvault" }
        val signatureAlgorithm = alg ?: SignatureAlgorithm.ECDSA_SHA256

        require(isSupportedSignatureAlgorithm(signatureAlgorithm)) {
            "Signature algorithm ${signatureAlgorithm.cryptoAlgorithm.name} is not supported by Azure Key Vault"
        }

        val keyName = alias ?: "key-${Uuid.v4String()}"
        val operations: Array<KeyOperation> = (keyOperations ?: arrayOf(KeyOperations.SIGN, KeyOperations.VERIFY))
            .map {
                it.toAzureKeyOperation()
            }
            .toTypedArray()

        val keyVaultKey = when (signatureAlgorithm.cryptoAlgorithm) {
            CryptoAlg.RSA -> {
                // Create RSA key
                val createRsaKeyOptions = CreateRsaKeyOptions(keyName)
                    .setKeySize(2048) // Default RSA key size
                    .setKeyOperations(*operations)

                keyClient.createRsaKey(createRsaKeyOptions)
                    .timeout(Duration.ofSeconds(10))
                    .onErrorMap(TimeoutException::class.java) {
                        RuntimeException("Azure operation timed out, check your Azure env vars")
                    }
                    .awaitSingle()
            }
            else -> {
                // Create EC key (ECDSA)
                val curve = signatureAlgorithm.curve ?: Curve.P_256

                val createEcKeyOptions = CreateEcKeyOptions(keyName)
                    .setCurveName(curve.toAzureKeyCurveName())
                    .setKeyOperations(*operations)

                keyClient.createEcKey(createEcKeyOptions)
                    .timeout(Duration.ofSeconds(10))
                    .onErrorMap(TimeoutException::class.java) {
                        RuntimeException("Azure operation timed out, check your Azure env vars")
                    }
                    .awaitSingle()
            }
        }

        if (keyVaultKey == null) {
            throw SignClientException("Failed to create key in Azure Key Vault for reference $keyName in vault ${keyClient.vaultUrl}")
        }

        val keyVaultJwk = keyVaultKey.toJwk()
        val kid = keyVaultJwk.kid ?: generateJwkThumbprint(keyVaultJwk)
        val jwk = keyVaultJwk.copy(kid = kid)
        val publicCoseKey = CoseJoseKeyMappingService.toCoseKey(jwk)

        return ManagedKeyPair(
            providerId = id,
            alias = keyVaultKey.name,
            kid = kid,
            jose = JoseKeyPair(null, jwk),
            cose = CoseKeyPair(null, publicCoseKey)
        )

    }

    /**
     * Creates a raw digital signature using the specified key and input data.
     *
     * @param keyInfo Information about the key to use for signing
     * @param input The data to be signed
     * @param requireX5Chain Whether to require an X.509 certificate chain
     * @return The raw signature bytes
     * @throws SignClientException if the key cannot be found or signature creation fails
     */
    override fun rawSignatureEncoding(algorithm: SignatureAlgorithm): com.sphereon.crypto.core.kms.command.SignatureEncoding? =
        com.sphereon.crypto.core.kms.command.SignatureEncoding.RAW

    override suspend fun createRawSignature(
        keyInfo: KeyInfoType<*>,
        input: ByteArray,
        requireX5Chain: Boolean
    ): ByteArray {
        requireManagedSigningKeySelection(keyInfo)
        val keyVaultKey = fetchAzureKey(keyInfo)

        val resolved = keyVaultKey.toManagedKeyInfo()
        val algorithm = keyInfo.signatureAlgorithm ?: keyVaultKey.toSignatureAlgorithm()
            ?: throw SignClientException("Azure RSA keys require an explicit signing algorithm")
        keyInfo.key?.let { keyInfo.requireSigningKeyCompatible(algorithm) }
        resolved.signingPolicyInfo().requireSigningKeyCompatible(algorithm)
        val cryptoClient = cryptographyClientFor(keyInfo)
        val signResult = cryptoClient.sign(algorithm.toAzureSignatureAlgorithm(), hash(algorithm, input)).awaitSingleOrNull()
            ?: throw SignClientException("Failed to create raw signature for key: ${keyInfo.alias}")

        return signResult.signature
    }

    private fun hash(algorithm: SignatureAlgorithm, input: ByteArray): ByteArray =
        hash(
            DigestAlg.fromValue(
                algorithm.digestAlgorithm?.name
                    ?: throw IllegalArgumentException("Digest algorithm is required"),
            ),
            input,
        )

    private fun hash(digestAlg: com.sphereon.crypto.core.generic.DigestAlg, input: ByteArray): ByteArray {
        return hash(input, digestAlg)
    }

    /**
     * Verifies a raw signature against the provided input data using the specified key.
     *
     * @param keyInfo Information about the key to use for verification
     * @param input The original data that was signed
     * @param signature The signature bytes to verify
     * @return True if the signature is valid, false otherwise
     * @throws SignClientException if the key cannot be found or verification fails
     */
    override suspend fun isValidRawSignature(
        keyInfo: KeyInfoType<*>,
        input: ByteArray,
        signature: ByteArray
    ): Boolean {
        val keyVaultKey = fetchAzureKey(keyInfo)

        val cryptoClient = cryptographyClientFor(keyInfo)

        val algorithm = keyInfo.signatureAlgorithm ?: keyVaultKey.toSignatureAlgorithm()
            ?: throw SignClientException("Azure RSA keys require an explicit verification algorithm")
        val resolved = keyVaultKey.toManagedKeyInfo()
        keyInfo.key?.let { keyInfo.requireVerificationKeyCompatible(algorithm) }
        resolved.signingPolicyInfo().requireVerificationKeyCompatible(algorithm)
        val verifyResult = cryptoClient.verify(algorithm.toAzureSignatureAlgorithm(), hash(algorithm, input), signature).awaitSingleOrNull()
            ?: throw SignClientException("Failed to verify signature for key: ${keyInfo.alias}")

        return verifyResult.isValid
    }

    override suspend fun signDigest(
        keyInfo: KeyInfoType<*>,
        digest: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        signatureEncoding: SignatureEncoding,
        requireX5Chain: Boolean,
    ): ByteArray {
        requireManagedSigningKeySelection(keyInfo)
        val keyVaultKey = fetchAzureKey(keyInfo)
        requireDigestLength(signatureAlgorithm, digest)
        val resolved = keyVaultKey.toManagedKeyInfo()
        keyInfo.key?.let { keyInfo.requireSigningKeyCompatible(signatureAlgorithm) }
        resolved.signingPolicyInfo().requireSigningKeyCompatible(signatureAlgorithm)
        val cryptoClient = cryptographyClientFor(keyInfo)
        val signResult = cryptoClient.sign(signatureAlgorithm.toAzureSignatureAlgorithm(), digest).awaitSingleOrNull()
            ?: throw SignClientException("Failed to create digest signature for key: ${keyInfo.alias}")
        return normalizeAzureSignatureOutput(signResult.signature, signatureEncoding, signatureAlgorithm)
    }

    override suspend fun verifyDigest(
        keyInfo: KeyInfoType<*>,
        digest: ByteArray,
        signature: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        signatureEncoding: SignatureEncoding,
    ): Boolean {
        val keyVaultKey = fetchAzureKey(keyInfo)
        requireDigestLength(signatureAlgorithm, digest)
        val resolved = keyVaultKey.toManagedKeyInfo()
        keyInfo.key?.let { keyInfo.requireVerificationKeyCompatible(signatureAlgorithm) }
        resolved.signingPolicyInfo().requireVerificationKeyCompatible(signatureAlgorithm)
        val cryptoClient = cryptographyClientFor(keyInfo)
        val nativeSignature = normalizeAzureSignatureInput(signature, signatureEncoding, signatureAlgorithm)
        val verifyResult = cryptoClient.verify(signatureAlgorithm.toAzureSignatureAlgorithm(), digest, nativeSignature).awaitSingleOrNull()
            ?: throw SignClientException("Failed to verify digest signature for key: ${keyInfo.alias}")
        return verifyResult.isValid
    }

    /**
     * Creates a structured signature for the provided input using the specified key and algorithm.
     *
     * @param signInput The input data and parameters for the signing operation
     * @param keyInfo Information about the key to use for signing (required)
     * @param signatureAlgorithm The algorithm to use for signing (defaults to signInput.algorithm if null)
     * @return A SignOutput containing the signature and related metadata
     * @throws SignClientException if the key info is not provided or signing fails
     */
    override suspend fun createSignature(
        signInput: SignInput,
        keyInfo: KeyInfoType<*>?,
        signatureAlgorithm: SignatureAlgorithm?
    ): SignOutput {
        val actualKeyInfo = keyInfo ?: throw SignClientException("Key info must be provided for signature creation")
        val signatureValue = when (signInput.signMode) {
            SigningMode.DOCUMENT -> {
                // Raw document data — createRawSignature handles hashing internally
                val requestedKeyInfo = signatureAlgorithm?.let {
                    KeyInfo.fromDTO(actualKeyInfo).copy(signatureAlgorithm = it)
                } ?: actualKeyInfo
                createRawSignature(requestedKeyInfo, signInput.input, false)
            }
            SigningMode.DIGEST -> {
                // Input is already a digest — sign directly without additional hashing
                val cryptoClient = cryptographyClientFor(actualKeyInfo)
                val keyVaultKey = fetchAzureKey(actualKeyInfo)
                val actualAlgorithm = signatureAlgorithm ?: actualKeyInfo.signatureAlgorithm ?: keyVaultKey.toSignatureAlgorithm()
                    ?: throw SignClientException("Azure RSA keys require an explicit signing algorithm")
                val resolved = keyVaultKey.toManagedKeyInfo()
                actualKeyInfo.key?.let { actualKeyInfo.requireSigningKeyCompatible(actualAlgorithm) }
                resolved.signingPolicyInfo().requireSigningKeyCompatible(actualAlgorithm)
                val signResult = cryptoClient.sign(actualAlgorithm.toAzureSignatureAlgorithm(), signInput.input).awaitSingleOrNull()
                    ?: throw SignClientException("Failed to create signature for key: ${actualKeyInfo.alias}")
                signResult.signature
            }
        }

        return SignOutputData(
            signedData = signatureValue,
            signatureLevel = SignatureLevel.RAW,
            signingTime = kotlin.time.Clock.System.now(),
            name = signInput.name,
        )
    }

    /**
     * Verifies a structured signature against the provided input data.
     *
     * @param signInput The input data to verify against the signature
     * @param signature The signature object containing the signature value and metadata
     * @return True if the signature is valid, false otherwise
     * @throws SignClientException if verification fails or the digest algorithm is missing for DOCUMENT mode
     */
    override suspend fun isValidSignature(signInput: SignInput, signature: Signature): Boolean {
        return when (signature.signMode) {
            SigningMode.DOCUMENT -> {
                // Raw document data — isValidRawSignature handles hashing internally
                isValidRawSignature(signature.keyInfo, signInput.input, signature.value)
            }
            SigningMode.DIGEST -> {
                // Input is already a digest — verify directly without additional hashing
                val cryptoClient = cryptographyClientFor(signature.keyInfo)
                val keyVaultKey = fetchAzureKey(signature.keyInfo)
                val algorithm = signature.keyInfo.signatureAlgorithm ?: keyVaultKey.toSignatureAlgorithm()
                    ?: throw SignClientException("Azure RSA keys require an explicit verification algorithm")
                val resolved = keyVaultKey.toManagedKeyInfo()
                signature.keyInfo.key?.let { signature.keyInfo.requireVerificationKeyCompatible(algorithm) }
                resolved.signingPolicyInfo().requireVerificationKeyCompatible(algorithm)
                val verifyResult = cryptoClient.verify(algorithm.toAzureSignatureAlgorithm(), signInput.input, signature.value).awaitSingleOrNull()
                    ?: throw SignClientException("Failed to verify signature for key: ${signature.keyInfo.alias}")
                verifyResult.isValid
            }
        }
    }

    /**
     * Lists all available keys in the Azure Key Vault.
     *
     * @return An array of managed key information objects
     */
    override suspend fun listKeys(): Array<ManagedKeyReference> {
        val keyProperties = keyClient.listPropertiesOfKeys()
            .filter { it.isEnabled }
            .collectList()
            .awaitSingle()

        return coroutineScope {
            keyProperties.map { property: KeyProperties ->
                async {
                    getKey(KeyInfo<JwkType>(kid = property.toKid()))
                }
            }.awaitAll().map { it.toKeyReference() }.toTypedArray()
        }
    }

    /**
     * Retrieves key information from Azure Key Vault.
     * First attempts to get the key as a certificate if the certificate API is available,
     * then falls back to retrieving it as a key if necessary.
     *
     * @param keyInfo Information about the key to retrieve
     * @return Managed key information including the full key details
     * @throws SignClientException if the key cannot be found in Azure Key Vault
     */
    override suspend fun getKey(keyInfo: KeyInfoType<*>): ManagedKeyInfoType<*> {
        val reference = azureKeyReference(keyInfo)
        val kvNames = kidToKVKeyName(reference)
        // Try the certificate first if available
        val keyEntry = if (supportsProviderCertificateReferenceReads) {
            try {
                certificateClientReader!!.read(kvNames.first, kvNames.second.ifBlank { null })
                    .toManagedCertInfo()
                    .preserveAzurePublicJwkCertificateMetadata()
            } catch (_: ResourceNotFoundException) {
                null
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                throw cancelled
            } catch (expected: Exception) {
                throw SignClientException("certificateClient.getCertificate failed", expected)
            }
        } else null

        // A certificate read already contains the public key. Only use the keys API when no
        // certificate exists, so certificate-only access does not require backing-key read access.
        if (keyEntry != null) return keyEntry

        // Fall back to the key API if no certificate was found.
        val key = try {
            val key = if (kvNames.second.isBlank()) {
                keyClient.getKey(kvNames.first)
            } else {
                keyClient.getKey(kvNames.first, kvNames.second)
            }
            key.awaitSingleOrNull()
        } catch (_: ResourceNotFoundException) {
            null
        } catch (cancelled: kotlinx.coroutines.CancellationException) {
            throw cancelled
        } catch (expected: Exception) {
            throw SignClientException("keyClient.getKey failed", expected)
        }
        return key?.toManagedKeyInfo()
            ?: throw NotFoundException(resource = "Azure Key Vault key")
    }

    override suspend fun getCertificate(
        lookup: ProviderCertificateLookup,
    ): IdkResult<ProviderCertificateReference, IdkError> = readCertificateReference(lookup)

    override fun canonicalCertificateId(lookup: ProviderCertificateLookup): IdkResult<String?, IdkError> =
        try {
            Ok(canonicalAzureCertificateId(config.keyvaultUrl, lookup)).asResult()
        } catch (_: IllegalArgumentException) {
            certificateReadError(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Provider certificate lookup is invalid"))
        }

    private suspend fun readCertificateReference(
        lookup: ProviderCertificateLookup,
    ): IdkResult<ProviderCertificateReference, IdkError> {
        if (!supportsProviderCertificateReferenceReads) {
            return certificateReadError(
                IdkError.UNSUPPORTED_OPERATION_ERROR(operation = "provider certificate read"),
            )
        }
        if (lookup.alias.isBlank()) {
            return certificateReadError(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Provider certificate lookup is invalid"))
        }

        return try {
            val (alias, version) = parseAzureCertificateLookup(lookup)
            val certificate = certificateClientReader!!.read(alias, version)
            val identity =
                resolveAzureCertificateIdentity(
                    configuredVaultUrl = config.keyvaultUrl,
                    lookup = lookup,
                    returnedCertificateId = certificate.certificateId,
                    returnedKeyId = certificate.keyId,
                )
            val leaf = certificateFromDer(certificate.certificateDer)
            Ok(
                ProviderCertificateReference(
                    providerId = id,
                    alias = identity.alias,
                    id = identity.id,
                    certificate = leaf,
                ),
            ).asResult()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: ResourceNotFoundException) {
            certificateReadError(IdkError.NOT_FOUND_ERROR(message = "Provider certificate was not found"))
        } catch (_: IllegalArgumentException) {
            certificateReadError(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Provider certificate lookup is invalid"))
        } catch (_: Exception) {
            certificateReadError(IdkError.UNKNOWN_ERROR(message = "Provider certificate read failed"))
        }
    }

    /**
     * Stores a key in Azure Key Vault.
     *
     * @param keyInfo The resolved key information to store
     * @param providerId The key management system identifier
     * @param alias The reference to use for the key in the KMS
     * @return Managed key information for the stored key
     * @throws SignClientException if the key format is unsupported or storage fails
     */
    override suspend fun storeKey(keyInfo: ResolvedKeyInfoType<*>, providerId: String, alias: String, certChain: Array<Certificate>?): ManagedKeyInfoType<*> {
        val key = keyInfo.key

        // Handle Jwk keys
        val jsonWebKey = when (key) {
            is Jwk -> {
                with(key) {
                    val azureKey = JsonWebKey()
                        .setKeyType(KeyType.fromString(kty.value))

                    when (kty) {
                        JwaKeyType.EC -> {
                            azureKey.setCurveName(KeyCurveName.fromString(crv?.value ?: "P-256"))
                                .setX(x?.decodeFromBase64(true))
                                .setY(y?.decodeFromBase64(true))
                                .setD(d?.decodeFromBase64(true))
                        }

                        JwaKeyType.RSA -> {
                            azureKey.setN(n?.decodeFromBase64(true))
                                .setE(e?.decodeFromBase64(true))
                                .setD(d?.decodeFromBase64(true))
                        }

                        else -> throw SignClientException("Unsupported key type: ${kty.value}")
                    }

                    key_ops?.let { ops ->
                        azureKey.setKeyOps(ops.map {
                            KeyOperations.fromJose(it).toAzureKeyOperation()
                        }.toList())
                    }
                    azureKey
                }
            }

            else -> throw SignClientException("Unsupported key format: ${key::class.simpleName}")
        }

        val (name, version) = kidToKVKeyName(alias)
        val importedKey = keyClient.importKey(
            ImportKeyOptions(name, jsonWebKey)
                .setHardwareProtected(config.hsmType == HSMType.MANAGED_HSM)
        ).awaitSingle()


        return importedKey.toManagedKeyInfo()
    }

    /**
     * Deletes a key from Azure Key Vault.
     * Note: This only marks the key for deletion. Purging after the deletion period would require additional steps.
     *
     * @param keyInfo Information about the key to delete
     * @return True if deletion was successful, false otherwise
     * @throws SignClientException if the key ID is missing
     */
    override suspend fun deleteKey(keyInfo: KeyInfoType<*>): Boolean {
        if (keyInfo.kid == null) {
            throw SignClientException("Key ID is required to delete a key")
        }
        val (name, version) = kidToKVKeyName(keyInfo.kid!!)

        try {
            keyClient.beginDeleteKey(name).last().awaitSingle()
            return true
        } catch (cancellation: kotlinx.coroutines.CancellationException) {
            throw cancellation
        } catch (_: Exception) {
            return false
        }
    }

    /**
     * Gets the visibility level of keys managed by this provider.
     *
     * @return KeyVisibility.PUBLIC indicating that keys are publicly accessible
     */
    override fun keyVisibility(): KeyVisibility = KeyVisibility.PUBLIC
    actual override val kmsProviderType: String = PredefinedKmsProviderTypes.AZURE_KEYVAULT.kmsProviderType

    /**
     * Encrypts plaintext using the specified key and algorithm.
     *
     * Azure Key Vault supports AES-GCM and AES-CBC encryption algorithms.
     * The IV is automatically generated for GCM algorithms.
     *
     * @param keyInfo Information about the key to use for encryption
     * @param plaintext The data to encrypt
     * @param algorithm The content encryption algorithm to use
     * @param additionalAuthenticatedData Optional AAD for authenticated encryption
     * @return EncryptionResult containing ciphertext, IV, and authentication tag
     * @throws SignClientException if the key cannot be found or encryption fails
     */
    override suspend fun encrypt(
        keyInfo: KeyInfoType<*>,
        plaintext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        additionalAuthenticatedData: ByteArray?
    ): EncryptionResult {
        val cryptoClient = cryptographyClientFor(keyInfo)

        // Generate IV based on algorithm requirements
        val iv = ByteArray(algorithm.ivLength)
        SecureRandom().nextBytes(iv)

        val encryptParams = when (algorithm) {
            ContentEncryptionAlgorithm.A128GCM -> {
                if (additionalAuthenticatedData != null) {
                    EncryptParameters.createA128GcmParameters(plaintext, additionalAuthenticatedData)
                } else {
                    EncryptParameters.createA128GcmParameters(plaintext)
                }
            }
            ContentEncryptionAlgorithm.A192GCM -> {
                if (additionalAuthenticatedData != null) {
                    EncryptParameters.createA192GcmParameters(plaintext, additionalAuthenticatedData)
                } else {
                    EncryptParameters.createA192GcmParameters(plaintext)
                }
            }
            ContentEncryptionAlgorithm.A256GCM -> {
                if (additionalAuthenticatedData != null) {
                    EncryptParameters.createA256GcmParameters(plaintext, additionalAuthenticatedData)
                } else {
                    EncryptParameters.createA256GcmParameters(plaintext)
                }
            }
            ContentEncryptionAlgorithm.A128CBC_HS256 -> EncryptParameters.createA128CbcParameters(plaintext, iv)
            ContentEncryptionAlgorithm.A192CBC_HS384 -> EncryptParameters.createA192CbcParameters(plaintext, iv)
            ContentEncryptionAlgorithm.A256CBC_HS512 -> EncryptParameters.createA256CbcParameters(plaintext, iv)
        }

        val encryptResult = cryptoClient.encrypt(encryptParams).awaitSingleOrNull()
            ?: throw SignClientException("Failed to encrypt data with key: ${keyInfo.alias}")

        return EncryptionResult(
            ciphertext = encryptResult.cipherText,
            iv = encryptResult.iv ?: iv,
            authTag = encryptResult.authenticationTag ?: ByteArray(algorithm.tagLength)
        )
    }

    /**
     * Decrypts ciphertext using the specified key and algorithm.
     *
     * @param keyInfo Information about the key to use for decryption
     * @param ciphertext The encrypted data
     * @param algorithm The content encryption algorithm used for encryption
     * @param iv The initialization vector used during encryption
     * @param authTag The authentication tag for verification
     * @param additionalAuthenticatedData Optional AAD used during encryption
     * @return The decrypted plaintext
     * @throws SignClientException if the key cannot be found or decryption fails
     */
    override suspend fun decrypt(
        keyInfo: KeyInfoType<*>,
        ciphertext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        iv: ByteArray,
        authTag: ByteArray,
        additionalAuthenticatedData: ByteArray?
    ): ByteArray {
        val cryptoClient = cryptographyClientFor(keyInfo)

        val decryptParams = when (algorithm) {
            ContentEncryptionAlgorithm.A128GCM -> {
                if (additionalAuthenticatedData != null) {
                    DecryptParameters.createA128GcmParameters(ciphertext, iv, authTag, additionalAuthenticatedData)
                } else {
                    DecryptParameters.createA128GcmParameters(ciphertext, iv, authTag)
                }
            }
            ContentEncryptionAlgorithm.A192GCM -> {
                if (additionalAuthenticatedData != null) {
                    DecryptParameters.createA192GcmParameters(ciphertext, iv, authTag, additionalAuthenticatedData)
                } else {
                    DecryptParameters.createA192GcmParameters(ciphertext, iv, authTag)
                }
            }
            ContentEncryptionAlgorithm.A256GCM -> {
                if (additionalAuthenticatedData != null) {
                    DecryptParameters.createA256GcmParameters(ciphertext, iv, authTag, additionalAuthenticatedData)
                } else {
                    DecryptParameters.createA256GcmParameters(ciphertext, iv, authTag)
                }
            }
            ContentEncryptionAlgorithm.A128CBC_HS256 -> DecryptParameters.createA128CbcParameters(ciphertext, iv)
            ContentEncryptionAlgorithm.A192CBC_HS384 -> DecryptParameters.createA192CbcParameters(ciphertext, iv)
            ContentEncryptionAlgorithm.A256CBC_HS512 -> DecryptParameters.createA256CbcParameters(ciphertext, iv)
        }

        val decryptResult = cryptoClient.decrypt(decryptParams).awaitSingleOrNull()
            ?: throw SignClientException("Failed to decrypt data with key: ${keyInfo.alias}")

        return decryptResult.plainText
    }

    override suspend fun encryptWithBackendKeyProof(
        keyInfo: KeyInfoType<*>,
        plaintext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        additionalAuthenticatedData: ByteArray?,
    ): BackendKeyProvedEncryption {
        val immutableIdentity = requireImmutableAzureKeyIdentity(keyInfo)
        val metadata = getVersionedSymmetricNonExportableKey(immutableIdentity)
        val cryptoClient = cryptographyClientFor(keyInfo)
        val parameters = azureEncryptParameters(plaintext, algorithm, additionalAuthenticatedData)
        val result =
            cryptoClient.encrypt(parameters).awaitSingleOrNull()
                ?: throw SignClientException("Azure Key Vault encryption failed")
        require(result.keyId == metadata.id) { "Azure Key Vault encryption key identity mismatch" }
        return BackendKeyProvedEncryption(
            encryption =
                EncryptionResult(
                    ciphertext = result.cipherText,
                    iv = result.iv ?: ByteArray(algorithm.ivLength),
                    authTag = result.authenticationTag ?: ByteArray(algorithm.tagLength),
                ),
            backendKeyIdentityDigest = azureBackendKeyIdentityDigest(metadata.id),
        )
    }

    override suspend fun decryptWithBackendKeyProof(
        keyInfo: KeyInfoType<*>,
        ciphertext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        iv: ByteArray,
        authTag: ByteArray,
        additionalAuthenticatedData: ByteArray?,
        expectedBackendKeyIdentityDigest: String,
    ): BackendKeyProvedDecryption {
        val immutableIdentity = requireImmutableAzureKeyIdentity(keyInfo)
        val metadata = getVersionedSymmetricNonExportableKey(immutableIdentity)
        val digest = azureBackendKeyIdentityDigest(metadata.id)
        require(digest == expectedBackendKeyIdentityDigest) {
            "Azure Key Vault backend key identity digest mismatch"
        }
        val result =
            cryptographyClientFor(keyInfo)
                .decrypt(azureDecryptParameters(ciphertext, algorithm, iv, authTag, additionalAuthenticatedData))
                .awaitSingleOrNull()
                ?: throw SignClientException("Azure Key Vault decryption failed")
        require(result.keyId == metadata.id) { "Azure Key Vault decryption key identity mismatch" }
        return BackendKeyProvedDecryption(
            plaintext = result.plainText,
            backendKeyIdentityDigest = digest,
        )
    }

    override suspend fun resolveImmutableBackendKeyIdentity(bindingAlias: String): String? {
        val keyName = requireAzureBindingAlias(bindingAlias)
        return try {
            requireSymmetricNonExportableAzureKey(keyClient.getKey(keyName).awaitSingle()).id
        } catch (_: ResourceNotFoundException) {
            null
        }
    }

    override suspend fun createSymmetricNonExportableKey(bindingAlias: String): String {
        val keyName = requireAzureBindingAlias(bindingAlias)
        resolveImmutableBackendKeyIdentity(bindingAlias)?.let { return it }
        val key =
            keyClient.createOctKey(
                CreateOctKeyOptions(keyName)
                    .setHardwareProtected(true)
                    .setExportable(false)
                    .setEnabled(true)
                    .setKeyOperations(KeyOperation.ENCRYPT, KeyOperation.DECRYPT),
            ).awaitSingle()
        return requireSymmetricNonExportableAzureKey(key).id
    }

    override suspend fun revokeSymmetricNonExportableKey(bindingAlias: String) {
        val keyName = requireAzureBindingAlias(bindingAlias)
        val present =
            try {
                keyClient.getKey(keyName).awaitSingle()
                true
            } catch (_: ResourceNotFoundException) {
                false
            }
        if (!present) {
            try {
                keyClient.getDeletedKey(keyName).awaitSingle()
            } catch (_: ResourceNotFoundException) {
                // Exact binding is absent: revocation is already complete or creation never committed.
            }
            return
        }
        keyClient.beginDeleteKey(keyName).last().awaitSingle()
    }

    /**
     * Wraps (encrypts) a key using the specified wrapping key and algorithm.
     *
     * Supports RSA-OAEP and AES key wrap algorithms.
     *
     * @param wrappingKeyInfo Information about the key to use for wrapping
     * @param keyToWrap The key material to wrap
     * @param algorithm The key wrap algorithm to use
     * @return The wrapped key bytes
     * @throws SignClientException if wrapping fails
     */
    override suspend fun wrapKey(
        wrappingKeyInfo: KeyInfoType<*>,
        keyToWrap: ByteArray,
        algorithm: KeyWrapAlgorithm
    ): ByteArray {
        val cryptoClient = cryptographyClientFor(wrappingKeyInfo)
        val azureAlgorithm = algorithm.toAzureKeyWrapAlgorithm()

        val wrapResult = cryptoClient.wrapKey(azureAlgorithm, keyToWrap).awaitSingleOrNull()
            ?: throw SignClientException("Failed to wrap key with key: ${wrappingKeyInfo.alias}")

        return wrapResult.encryptedKey
    }

    /**
     * Unwraps (decrypts) a wrapped key using the specified unwrapping key and algorithm.
     *
     * @param unwrappingKeyInfo Information about the key to use for unwrapping
     * @param wrappedKey The wrapped key bytes
     * @param algorithm The key wrap algorithm used during wrapping
     * @return The unwrapped key material
     * @throws SignClientException if unwrapping fails
     */
    override suspend fun unwrapKey(
        unwrappingKeyInfo: KeyInfoType<*>,
        wrappedKey: ByteArray,
        algorithm: KeyWrapAlgorithm
    ): ByteArray {
        val cryptoClient = cryptographyClientFor(unwrappingKeyInfo)
        val azureAlgorithm = algorithm.toAzureKeyWrapAlgorithm()

        val unwrapResult = cryptoClient.unwrapKey(azureAlgorithm, wrappedKey).awaitSingleOrNull()
            ?: throw SignClientException("Failed to unwrap key with key: ${unwrappingKeyInfo.alias}")

        return unwrapResult.key
    }

    /**
     * Binds cryptographic operations to the immutable Azure key version when a kid is supplied.
     * Falling back to an unversioned alias is retained for legacy callers; envelope encryption
     * always persists and supplies the resolved kid.
     */
    private fun cryptographyClientFor(keyInfo: KeyInfoType<*>): com.azure.security.keyvault.keys.cryptography.CryptographyAsyncClient {
        val reference = azureKeyReference(keyInfo)
        val (name, version) = kidToKVKeyName(reference)
        return if (version.isBlank()) {
            keyClient.getCryptographyAsyncClient(name)
        } else {
            keyClient.getCryptographyAsyncClient(name, version)
        }
    }

    /**
     * Resolve operator aliases before canonical kids. A request carrying both fields is
     * intentionally bound to the alias; the kid is metadata and must not redirect the
     * cryptography client to a different Azure key/version.
     */
    private suspend fun fetchAzureKey(keyInfo: KeyInfoType<*>): KeyVaultKey {
        val (name, version) = kidToKVKeyName(azureKeyReference(keyInfo))
        return if (version.isBlank()) {
            keyClient.getKey(name).awaitSingleOrNull()
        } else {
            keyClient.getKey(name, version).awaitSingleOrNull()
        } ?: throw SignClientException("Key not found in Azure Key Vault for reference: ${azureKeyReference(keyInfo)}")
    }

    private fun requireImmutableAzureKeyIdentity(keyInfo: KeyInfoType<*>): String {
        val kid = keyInfo.kid ?: throw SignClientException("A versioned Azure key id is required")
        require(keyInfo.alias == null || keyInfo.alias == kid) {
            "Azure current-version aliases are not accepted for attested operations"
        }
        require(AZURE_VERSIONED_KEY_ID.matches(kid)) { "A versioned Azure key id is required" }
        val configuredVault = config.keyvaultUrl.trimEnd('/')
        require(kid.startsWith("$configuredVault/keys/")) {
            "Azure key identity does not belong to the configured provider"
        }
        return kid
    }

    private suspend fun getVersionedSymmetricNonExportableKey(immutableIdentity: String): KeyVaultKey {
        val (name, version) = kidToKVKeyName(immutableIdentity)
        require(version.isNotBlank()) { "A versioned Azure key id is required" }
        return requireSymmetricNonExportableAzureKey(keyClient.getKey(name, version).awaitSingle())
    }

    private fun SignatureAlgorithm.toAzureSignatureAlgorithm(): AzureSignatureAlgorithm =
        when (this) {
            SignatureAlgorithm.ECDSA_SHA256 -> AzureSignatureAlgorithm.ES256
            SignatureAlgorithm.ECDSA_SHA384 -> AzureSignatureAlgorithm.ES384
            SignatureAlgorithm.ECDSA_SHA512 -> AzureSignatureAlgorithm.ES512
            SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1 -> AzureSignatureAlgorithm.PS256
            SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1 -> AzureSignatureAlgorithm.PS384
            SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1 -> AzureSignatureAlgorithm.PS512
            SignatureAlgorithm.RSA_SHA256 -> AzureSignatureAlgorithm.RS256
            SignatureAlgorithm.RSA_SHA384 -> AzureSignatureAlgorithm.RS384
            SignatureAlgorithm.RSA_SHA512 -> AzureSignatureAlgorithm.RS512
            else -> throw SignClientException("Digest signing is not supported for $this")
        }

    private fun requireDigestLength(
        algorithm: SignatureAlgorithm,
        digest: ByteArray,
    ) {
        val expected =
            when (algorithm) {
                SignatureAlgorithm.ECDSA_SHA256,
                SignatureAlgorithm.RSA_SHA256,
                SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1 -> 32
                SignatureAlgorithm.ECDSA_SHA384,
                SignatureAlgorithm.RSA_SHA384,
                SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1 -> 48
                SignatureAlgorithm.ECDSA_SHA512,
                SignatureAlgorithm.RSA_SHA512,
                SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1 -> 64
                else -> throw SignClientException("Digest signing is not supported for $algorithm")
            }
        require(digest.size == expected) { "Digest for $algorithm must be $expected bytes, got ${digest.size}" }
    }

    private fun normalizeAzureSignatureOutput(
        signature: ByteArray,
        signatureEncoding: SignatureEncoding,
        algorithm: SignatureAlgorithm,
    ): ByteArray =
        when {
            algorithm.cryptoAlgorithm == CryptoAlg.ECDSA && signatureEncoding == SignatureEncoding.RAW ->
                if (SignatureEncodingCodec.isDer(signature)) {
                    SignatureEncodingCodec.derToRaw(signature, SignatureEncodingCodec.scalarLength(algorithm))
                } else {
                    signature
                }

            algorithm.cryptoAlgorithm == CryptoAlg.ECDSA && signatureEncoding == SignatureEncoding.DER ->
                if (SignatureEncodingCodec.isDer(signature)) {
                    signature
                } else {
                    SignatureEncodingCodec.rawToDer(signature, SignatureEncodingCodec.scalarLength(algorithm))
                }

            signatureEncoding == SignatureEncoding.RAW -> signature
            else -> throw SignClientException("DER signature encoding is only supported for ECDSA algorithms")
        }

    private fun normalizeAzureSignatureInput(
        signature: ByteArray,
        signatureEncoding: SignatureEncoding,
        algorithm: SignatureAlgorithm,
    ): ByteArray =
        when {
            algorithm.cryptoAlgorithm == CryptoAlg.ECDSA && signatureEncoding == SignatureEncoding.RAW -> signature
            algorithm.cryptoAlgorithm == CryptoAlg.ECDSA && signatureEncoding == SignatureEncoding.DER ->
                SignatureEncodingCodec.derToRaw(signature, SignatureEncodingCodec.scalarLength(algorithm))
            signatureEncoding == SignatureEncoding.RAW -> signature
            else -> throw SignClientException("DER signature encoding is only supported for ECDSA algorithms")
        }

    /**
     * Converts our KeyWrapAlgorithm to Azure's KeyWrapAlgorithm.
     */
    private fun KeyWrapAlgorithm.toAzureKeyWrapAlgorithm(): AzureKeyWrapAlgorithm = when (this) {
        KeyWrapAlgorithm.RSA1_5 -> AzureKeyWrapAlgorithm.RSA1_5
        KeyWrapAlgorithm.RSA_OAEP -> AzureKeyWrapAlgorithm.RSA_OAEP
        KeyWrapAlgorithm.RSA_OAEP_256 -> AzureKeyWrapAlgorithm.RSA_OAEP_256
        KeyWrapAlgorithm.RSA_OAEP_384 -> throw UnsupportedOperationException("RSA-OAEP-384 not supported by Azure Key Vault")
        KeyWrapAlgorithm.RSA_OAEP_512 -> throw UnsupportedOperationException("RSA-OAEP-512 not supported by Azure Key Vault")
        KeyWrapAlgorithm.A128KW -> AzureKeyWrapAlgorithm.A128KW
        KeyWrapAlgorithm.A192KW -> AzureKeyWrapAlgorithm.A192KW
        KeyWrapAlgorithm.A256KW -> AzureKeyWrapAlgorithm.A256KW
        KeyWrapAlgorithm.A128GCMKW -> throw UnsupportedOperationException("A128GCMKW not supported by Azure Key Vault")
        KeyWrapAlgorithm.A192GCMKW -> throw UnsupportedOperationException("A192GCMKW not supported by Azure Key Vault")
        KeyWrapAlgorithm.A256GCMKW -> throw UnsupportedOperationException("A256GCMKW not supported by Azure Key Vault")
        KeyWrapAlgorithm.DIR -> throw UnsupportedOperationException("Direct key agreement not supported for key wrapping")
    }

}

private fun ManagedKeyInfoType<*>.signingPolicyInfo(): KeyInfoType<*> {
    val dto = KeyInfo.fromDTO(this)
    return if ((dto.key as? JwkType)?.alg == null) dto.copy(signatureAlgorithm = null) else dto
}

/** Azure aliases are tenant-scoped operational references and take precedence over metadata kids. */
internal fun azureKeyReference(keyInfo: KeyInfoType<*>): String =
    keyInfo.alias ?: keyInfo.kid
    ?: throw SignClientException("A key id or alias is required for Azure Key Vault operations")

private fun KeyInfoType<*>.requireVerificationKeyCompatible(requestedAlgorithm: SignatureAlgorithm) {
    keyCompatibilityFailure(requestedAlgorithm, KeyOperations.VERIFY)?.let { throw IllegalArgumentException(it) }
}

private fun requireSymmetricNonExportableAzureKey(key: KeyVaultKey): KeyVaultKey {
    require(key.keyType == KeyType.OCT_HSM) { "Azure key is not hardware-protected symmetric key material" }
    require(key.properties.isEnabled == true && key.properties.isExportable != true) {
        "Azure key is disabled or exportable"
    }
    require(
        key.keyOperations?.containsAll(listOf(KeyOperation.ENCRYPT, KeyOperation.DECRYPT)) == true,
    ) {
        "Azure key does not permit encrypt/decrypt"
    }
    require(AZURE_VERSIONED_KEY_ID.matches(key.id)) { "Azure key metadata does not include a versioned identity" }
    return key
}

private fun requireAzureBindingAlias(bindingAlias: String): String {
    require(AZURE_BINDING_ALIAS.matches(bindingAlias)) { "Azure key binding alias is invalid" }
    return bindingAlias
}

private fun azureBackendKeyIdentityDigest(immutableIdentity: String): String =
    "sha256:" +
        MessageDigest.getInstance("SHA-256")
            .digest("azure-key-vault\u0000$immutableIdentity".encodeToByteArray())
            .joinToString(separator = "") { "%02x".format(it) }

private fun azureEncryptParameters(
    plaintext: ByteArray,
    algorithm: ContentEncryptionAlgorithm,
    additionalAuthenticatedData: ByteArray?,
): EncryptParameters =
    when (algorithm) {
        ContentEncryptionAlgorithm.A128GCM ->
            additionalAuthenticatedData?.let { EncryptParameters.createA128GcmParameters(plaintext, it) }
                ?: EncryptParameters.createA128GcmParameters(plaintext)
        ContentEncryptionAlgorithm.A192GCM ->
            additionalAuthenticatedData?.let { EncryptParameters.createA192GcmParameters(plaintext, it) }
                ?: EncryptParameters.createA192GcmParameters(plaintext)
        ContentEncryptionAlgorithm.A256GCM ->
            additionalAuthenticatedData?.let { EncryptParameters.createA256GcmParameters(plaintext, it) }
                ?: EncryptParameters.createA256GcmParameters(plaintext)
        else -> throw SignClientException("Attested Azure encryption requires an AES-GCM algorithm")
    }

private fun azureDecryptParameters(
    ciphertext: ByteArray,
    algorithm: ContentEncryptionAlgorithm,
    iv: ByteArray,
    authTag: ByteArray,
    additionalAuthenticatedData: ByteArray?,
): DecryptParameters =
    when (algorithm) {
        ContentEncryptionAlgorithm.A128GCM ->
            additionalAuthenticatedData?.let {
                DecryptParameters.createA128GcmParameters(ciphertext, iv, authTag, it)
            } ?: DecryptParameters.createA128GcmParameters(ciphertext, iv, authTag)
        ContentEncryptionAlgorithm.A192GCM ->
            additionalAuthenticatedData?.let {
                DecryptParameters.createA192GcmParameters(ciphertext, iv, authTag, it)
            } ?: DecryptParameters.createA192GcmParameters(ciphertext, iv, authTag)
        ContentEncryptionAlgorithm.A256GCM ->
            additionalAuthenticatedData?.let {
                DecryptParameters.createA256GcmParameters(ciphertext, iv, authTag, it)
            } ?: DecryptParameters.createA256GcmParameters(ciphertext, iv, authTag)
        else -> throw SignClientException("Attested Azure decryption requires an AES-GCM algorithm")
    }

internal data class AzureCertificateIdentity(
    val alias: String,
    val id: String,
)

internal data class AzureKeyIdentity(
    val alias: String,
    val id: String,
)

/**
 * Validates the identity returned by Azure before a tenant tag can be trusted.
 * The SDK response is deliberately reduced to the exact configured vault,
 * requested name, and requested version before its tags are inspected.
 */
internal fun resolveAzureKeyIdentity(
    configuredVaultUrl: String,
    lookup: ProviderNativeObjectLookup,
    returnedKeyId: String?,
    returnedName: String?,
    returnedVersion: String?,
): AzureKeyIdentity {
    rejectIf(lookup.type != ProviderNativeObjectType.KEY)
    val configuredVault = configuredVaultUrl.trimEnd('/')
    rejectIf(configuredVault.isBlank())
    val (requestedAlias, requestedVersion) = parseAzureKeyLookup(configuredVaultUrl, lookup)
    rejectIf(requestedAlias != lookup.alias)

    val keyMatch = returnedKeyId?.let { AZURE_KEY_ID.matchEntire(it) }
    rejectIf(keyMatch == null)
    rejectIf(!keyMatch!!.groupValues[1].equals(configuredVault, ignoreCase = true))
    rejectIf(keyMatch.groupValues[2] != requestedAlias)
    rejectIf(returnedName != requestedAlias || keyMatch.groupValues[2] != returnedName)

    val actualVersion = keyMatch.groupValues[3]
    rejectIf(returnedVersion != actualVersion)
    requestedVersion?.let { rejectIf(it != actualVersion) }

    lookup.id?.let { requestedId ->
        val requestedIdentity = parseRequestedKeyIdentity(requestedId, lookup.alias, configuredVault)
        rejectIf(requestedIdentity.first != requestedAlias || requestedIdentity.second != actualVersion)
    }

    return AzureKeyIdentity(
        alias = requestedAlias,
        id = "$requestedAlias:$actualVersion",
    )
}

/**
 * Validates the identities returned by Azure before any public result is built.
 *
 * Azure returns full vault URLs for certificate and key ids. Those URLs are
 * intentionally consumed only for validation; the public identity is the
 * provider's configured id plus the stable `name:version` certificate id.
 */
internal fun resolveAzureCertificateIdentity(
    configuredVaultUrl: String,
    lookup: ProviderCertificateLookup,
    returnedCertificateId: String?,
    returnedKeyId: String?,
): AzureCertificateIdentity {
    val configuredVault = configuredVaultUrl.trimEnd('/')
    rejectIf(configuredVault.isBlank())
    rejectIf(lookup.alias.isBlank() || !AZURE_CERTIFICATE_NAME.matches(lookup.alias))

    val certificateMatch = returnedCertificateId?.let { AZURE_CERTIFICATE_ID.matchEntire(it) }
    rejectIf(certificateMatch == null)
    val certificateVault = certificateMatch!!.groupValues[1]
    val certificateAlias = certificateMatch.groupValues[2]
    val certificateVersion = certificateMatch.groupValues[3]
    rejectIf(!certificateVault.equals(configuredVault, ignoreCase = true))
    rejectIf(certificateAlias != lookup.alias)

    val keyMatch = returnedKeyId?.let { AZURE_KEY_ID.matchEntire(it) }
    rejectIf(keyMatch == null)
    rejectIf(!keyMatch!!.groupValues[1].equals(configuredVault, ignoreCase = true))
    rejectIf(keyMatch.groupValues[2] != certificateAlias || keyMatch.groupValues[3] != certificateVersion)

    lookup.id?.let { requestedId ->
        val requestedIdentity = parseRequestedCertificateIdentity(requestedId, lookup.alias, configuredVault)
        rejectIf(requestedIdentity.first != certificateAlias || requestedIdentity.second != certificateVersion)
    }

    return AzureCertificateIdentity(
        alias = certificateAlias,
        id = "$certificateAlias:$certificateVersion",
    )
}

/**
 * Normalizes an accepted certificate id spelling (`alias:version`, a versioned certificate URL
 * in the configured vault, or a bare version) to the canonical `alias:version`. A URL for another
 * vault or an id naming another alias is rejected.
 */
internal fun canonicalAzureCertificateId(
    configuredVaultUrl: String,
    lookup: ProviderCertificateLookup,
): String? {
    val configuredVault = configuredVaultUrl.trimEnd('/')
    rejectIf(configuredVault.isBlank())
    rejectIf(lookup.alias.isBlank() || !AZURE_CERTIFICATE_NAME.matches(lookup.alias))
    val requestedId = lookup.id ?: return null
    val (alias, version) = parseRequestedCertificateIdentity(requestedId, lookup.alias, configuredVault)
    return "$alias:$version"
}

private fun parseAzureCertificateLookup(lookup: ProviderCertificateLookup): Pair<String, String?> {
    rejectIf(lookup.alias.isBlank() || !AZURE_CERTIFICATE_NAME.matches(lookup.alias))
    val requestedId = lookup.id ?: return lookup.alias to null
    val versionedUri = AZURE_CERTIFICATE_ID.matchEntire(requestedId)
    if (versionedUri != null) {
        rejectIf(versionedUri.groupValues[2] != lookup.alias)
        return lookup.alias to versionedUri.groupValues[3]
    }
    val canonical = AZURE_CERTIFICATE_CANONICAL_ID.matchEntire(requestedId)
    if (canonical == null) {
        rejectIf(!AZURE_CERTIFICATE_VERSION.matches(requestedId))
        return lookup.alias to requestedId
    }
    rejectIf(canonical.groupValues[1] != lookup.alias)
    return lookup.alias to canonical.groupValues[2]
}

private fun parseAzureKeyLookup(
    configuredVaultUrl: String,
    lookup: ProviderNativeObjectLookup,
): Pair<String, String?> {
    rejectIf(lookup.type != ProviderNativeObjectType.KEY)
    rejectIf(lookup.alias.isBlank() || !AZURE_CERTIFICATE_NAME.matches(lookup.alias))
    val requestedId = lookup.id ?: return lookup.alias to null
    val versionedUri = AZURE_KEY_ID.matchEntire(requestedId)
    if (versionedUri != null) {
        rejectIf(!versionedUri.groupValues[1].equals(configuredVaultUrl.trimEnd('/'), ignoreCase = true))
        rejectIf(versionedUri.groupValues[2] != lookup.alias)
        return lookup.alias to versionedUri.groupValues[3]
    }
    val canonical = AZURE_KEY_CANONICAL_ID.matchEntire(requestedId)
    if (canonical != null) {
        rejectIf(canonical.groupValues[1] != lookup.alias)
        return lookup.alias to canonical.groupValues[2]
    }
    rejectIf(!AZURE_CERTIFICATE_VERSION.matches(requestedId))
    return lookup.alias to requestedId
}

private fun parseRequestedKeyIdentity(
    requestedId: String,
    alias: String,
    configuredVaultUrl: String,
): Pair<String, String> {
    val versionedUri = AZURE_KEY_ID.matchEntire(requestedId)
    if (versionedUri != null) {
        rejectIf(!versionedUri.groupValues[1].equals(configuredVaultUrl, ignoreCase = true))
        rejectIf(versionedUri.groupValues[2] != alias)
        return versionedUri.groupValues[2] to versionedUri.groupValues[3]
    }
    val canonical = AZURE_KEY_CANONICAL_ID.matchEntire(requestedId)
    if (canonical != null) {
        rejectIf(canonical.groupValues[1] != alias)
        return canonical.groupValues[1] to canonical.groupValues[2]
    }
    rejectIf(!AZURE_CERTIFICATE_VERSION.matches(requestedId))
    return alias to requestedId
}

private fun parseRequestedCertificateIdentity(
    requestedId: String,
    alias: String,
    configuredVaultUrl: String,
): Pair<String, String> {
    val versionedUri = AZURE_CERTIFICATE_ID.matchEntire(requestedId)
    if (versionedUri != null) {
        rejectIf(!versionedUri.groupValues[1].equals(configuredVaultUrl, ignoreCase = true))
        rejectIf(versionedUri.groupValues[2] != alias)
        return versionedUri.groupValues[2] to versionedUri.groupValues[3]
    }
    val canonical = AZURE_CERTIFICATE_CANONICAL_ID.matchEntire(requestedId)
    if (canonical == null) {
        rejectIf(!AZURE_CERTIFICATE_VERSION.matches(requestedId))
        return alias to requestedId
    }
    rejectIf(canonical.groupValues[1] != alias)
    return canonical.groupValues[1] to canonical.groupValues[2]
}

private fun rejectIf(condition: Boolean) {
    if (condition) {
        throw IllegalArgumentException("Azure certificate identity rejected")
    }
}

private fun <V> certificateReadError(error: IdkError): IdkResult<V, IdkError> = Err(error).asResult()

private fun azureTenantTagMatches(
    tags: Map<String, String>,
    tenantId: String,
): Boolean {
    val expected = tenantId.encodeToByteArray()
    return tags.entries.any { (key, value) ->
        key == AZURE_TENANT_ASSIGNMENT_TAG_KEY &&
            MessageDigest.isEqual(value.encodeToByteArray(), expected)
    }
}

/**
 * Keeps public certificate metadata attached to provider JWKs.
 *
 * Azure's certificate mapper supplies x5c. If a provider JWK already supplies
 * x5t or x5t#S256, those values are authoritative and are preserved. When a
 * provider supplies the public chain without either thumbprint, derive the
 * standard base64url thumbprints from the exact leaf DER bytes.
 */
internal fun preserveAzurePublicJwkCertificateMetadata(jwk: Jwk): Jwk {
    val certificateDer = jwk.x5c?.firstOrNull()?.let { it.decodeFromBase64() } ?: return jwk
    val x5t = jwk.x5t ?: MessageDigest.getInstance("SHA-1").digest(certificateDer).encodeToBase64Url()
    val x5tS256 = jwk.x5t_S256 ?: MessageDigest.getInstance("SHA-256").digest(certificateDer).encodeToBase64Url()
    return jwk.copy(x5t = x5t, x5t_S256 = x5tS256)
}

private fun ManagedKeyInfoType<Jwk>.preserveAzurePublicJwkCertificateMetadata(): ManagedKeyInfoType<Jwk> {
    val preservedJwk = preserveAzurePublicJwkCertificateMetadata(key)
    if (preservedJwk == key) {
        return this
    }
    return ManagedKeyInfo.fromKeyInfo(KeyInfo.fromDTO(this).copy(key = preservedJwk))
}

private val AZURE_VERSIONED_KEY_ID =
    Regex("^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?/keys/[A-Za-z0-9-]{1,127}/[A-Za-z0-9]{1,128}$")
private val AZURE_BINDING_ALIAS = Regex("^[A-Za-z0-9][A-Za-z0-9-]{0,126}$")
private val AZURE_CERTIFICATE_NAME = Regex("^[A-Za-z0-9-]{1,127}$")
private val AZURE_CERTIFICATE_ID =
    Regex("^(https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?)/certificates/([A-Za-z0-9-]{1,127})/([A-Za-z0-9]{1,128})$")
private val AZURE_KEY_ID =
    Regex("^(https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?)/keys/([A-Za-z0-9-]{1,127})/([A-Za-z0-9]{1,128})$")
private val AZURE_CERTIFICATE_CANONICAL_ID =
    Regex("^([A-Za-z0-9-]{1,127}):([A-Za-z0-9]{1,128})$")
private val AZURE_KEY_CANONICAL_ID =
    Regex("^([A-Za-z0-9-]{1,127}):([A-Za-z0-9]{1,128})$")
private val AZURE_CERTIFICATE_VERSION = Regex("^[A-Za-z0-9]{1,128}$")
private const val AZURE_TENANT_ASSIGNMENT_TAG_KEY = "sphereon-tenant-id"
