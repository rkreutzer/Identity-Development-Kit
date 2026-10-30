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

package com.sphereon.crypto.kms.provider.aws

import aws.sdk.kotlin.services.kms.KmsClient
import aws.sdk.kotlin.services.kms.model.CreateAliasRequest
import aws.sdk.kotlin.services.kms.model.CreateKeyRequest
import aws.sdk.kotlin.services.kms.model.CreateKeyResponse
import aws.sdk.kotlin.services.kms.model.DeleteAliasRequest
import aws.sdk.kotlin.services.kms.model.DecryptRequest
import aws.sdk.kotlin.services.kms.model.DeriveSharedSecretRequest
import aws.sdk.kotlin.services.kms.model.DescribeKeyRequest
import aws.sdk.kotlin.services.kms.model.EncryptRequest
import aws.sdk.kotlin.services.kms.model.EncryptionAlgorithmSpec
import aws.sdk.kotlin.services.kms.model.GetPublicKeyRequest
import aws.sdk.kotlin.services.kms.model.KeyAgreementAlgorithmSpec
import aws.sdk.kotlin.services.kms.model.KeyListEntry
import aws.sdk.kotlin.services.kms.model.KeyManagerType
import aws.sdk.kotlin.services.kms.model.KeySpec
import aws.sdk.kotlin.services.kms.model.KeyState
import aws.sdk.kotlin.services.kms.model.KeyUsageType
import aws.sdk.kotlin.services.kms.model.KmsInvalidSignatureException
import aws.sdk.kotlin.services.kms.model.ListKeysRequest
import aws.sdk.kotlin.services.kms.model.ListResourceTagsRequest
import aws.sdk.kotlin.services.kms.model.MessageType
import aws.sdk.kotlin.services.kms.model.NotFoundException
import aws.sdk.kotlin.services.kms.model.OriginType
import aws.sdk.kotlin.services.kms.model.ScheduleKeyDeletionRequest
import aws.sdk.kotlin.services.kms.model.SignRequest
import aws.sdk.kotlin.services.kms.model.SigningAlgorithmSpec
import aws.sdk.kotlin.services.kms.model.Tag
import aws.sdk.kotlin.services.kms.model.VerifyRequest
import aws.sdk.kotlin.runtime.auth.credentials.EcsCredentialsProvider
import aws.sdk.kotlin.runtime.auth.credentials.DefaultChainCredentialsProvider
import aws.sdk.kotlin.runtime.auth.credentials.ImdsCredentialsProvider
import aws.sdk.kotlin.runtime.auth.credentials.ProfileCredentialsProvider
import aws.sdk.kotlin.runtime.auth.credentials.StaticCredentialsProvider
import aws.smithy.kotlin.runtime.auth.awscredentials.CredentialsProvider
import aws.smithy.kotlin.runtime.net.url.Url
import com.sphereon.crypto.core.ManagedKeyReference
import com.sphereon.crypto.core.kms.model.KeyProviderSettings
import com.sphereon.crypto.core.kms.model.AwsKmsClientConfig
import com.sphereon.crypto.core.kms.model.CredentialMode
import com.sphereon.crypto.core.toKeyReference
import kotlinx.coroutines.currentCoroutineContext
import com.sphereon.crypto.core.kms.ManagedKeyCreationAttempt
import com.sphereon.crypto.core.kms.ManagedKeyCreationAttemptState
import com.sphereon.crypto.core.kms.ManagedKeyCreationAttemptIntent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import com.sphereon.crypto.core.CoseJoseKeyMappingService
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.ResolvedKeyInfoType
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.generic.CryptoAlg
import com.sphereon.crypto.core.generic.CoseKeyPair
import com.sphereon.crypto.core.generic.Curve
import com.sphereon.crypto.core.generic.JoseKeyPair
import com.sphereon.crypto.core.generic.KeyOperations
import com.sphereon.crypto.core.generic.ManagedKeyPair
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwkType
import com.sphereon.crypto.core.jose.JoseKeyOperations
import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.JwaCurve
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.interop.toDerEcdsaPublicKeyBytes
import com.sphereon.crypto.core.kms.ConcatKdf
import com.sphereon.crypto.core.kms.BackendKeyOperationProofProvider
import com.sphereon.crypto.core.kms.BackendKeyProvedDecryption
import com.sphereon.crypto.core.kms.BackendKeyProvedEncryption
import com.sphereon.crypto.core.kms.BackendSymmetricKmsKeyLifecycle
import com.sphereon.crypto.core.kms.CertificateOptions
import com.sphereon.crypto.core.kms.ContentEncryptionAlgorithm
import com.sphereon.crypto.core.kms.EncryptionResult
import com.sphereon.crypto.core.kms.KeyAgreementAlgorithm
import com.sphereon.crypto.core.kms.KeyWrapAlgorithm
import com.sphereon.crypto.core.kms.PredefinedKmsProviderTypes
import com.sphereon.crypto.core.kms.ProviderTenantAssignmentVerifier
import com.sphereon.crypto.core.kms.ProviderNativeObjectLookup
import com.sphereon.crypto.core.kms.ProviderNativeObjectType
import com.sphereon.crypto.core.kms.requireManagedSigningKeySelection
import com.sphereon.crypto.core.kms.command.EcdhDeriveMode
import com.sphereon.crypto.core.kms.command.EcdhDeriveResult
import com.sphereon.crypto.core.kms.command.EcPointMultiplyOutput
import com.sphereon.crypto.core.kms.command.EcPointMultiplyResult
import com.sphereon.crypto.core.kms.command.SignatureEncoding
import com.sphereon.crypto.core.kms.command.SignatureEncodingCodec
import com.sphereon.crypto.core.x509.Certificate
import com.sphereon.crypto.core.sign.requireSigningKeyCompatible
import com.sphereon.crypto.core.sign.keyCompatibilityFailure
import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec
import com.sphereon.core.api.encodeToBase64Url
import kotlinx.coroutines.CancellationException

/** Internal SDK-neutral metadata used by tenant-assignment verification tests and adapter. */
internal data class AwsKmsKeyIdentity(
    val keyId: String,
    val arn: String,
)

/** Internal page returned by AWS KMS resource-tag reads. */
internal data class AwsKmsResourceTagPage(
    val tags: List<Pair<String, String>>,
    val truncated: Boolean,
    val nextMarker: String?,
)

/** Keeps AWS SDK models and credentials out of the public tenant-assignment capability. */
internal interface AwsKmsTenantAssignmentReader {
    suspend fun describeKey(keyReference: String): AwsKmsKeyIdentity

    suspend fun listResourceTags(keyId: String, marker: String?): AwsKmsResourceTagPage
}

actual class AwsKmsCryptoProvider actual constructor(
    settings: KeyProviderSettings
) : BaseAwsKmsCryptoProvider(settings),
    ProviderTenantAssignmentVerifier,
    BackendKeyOperationProofProvider,
    BackendSymmetricKmsKeyLifecycle {

    @Volatile
    private var sharedClient: KmsClient? = null
    private val clientMutex = Mutex()
    private var managedCreationCall: suspend (KmsClient, CreateKeyRequest) -> CreateKeyResponse = { client, request ->
        singleAttemptManagedCreationClient(client).use { it.createKey(request) }
    }
    private var tenantAssignmentReader: AwsKmsTenantAssignmentReader? = null

    override suspend fun isAssignedToTenant(
        lookup: ProviderNativeObjectLookup,
        tenantId: String,
    ): Boolean {
        if (lookup.type != ProviderNativeObjectType.KEY || tenantId.isBlank()) return false

        return try {
            val reader = tenantAssignmentReader ?: defaultTenantAssignmentReader()
            val aliasIdentity = reader.describeKey(requireAwsNativeAlias(lookup.alias))
            val requestedIdentity =
                lookup.id?.let {
                    requireAwsNativeKeyIdentity(it)
                    reader.describeKey(it)
                }
            if (requestedIdentity != null && requestedIdentity != aliasIdentity) return false
            reader.hasTenantAssignment(aliasIdentity.keyId, tenantId)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            false
        }
    }

    internal constructor(
        settings: KeyProviderSettings,
        tenantAssignmentReader: AwsKmsTenantAssignmentReader,
    ) : this(settings) {
        this.tenantAssignmentReader = tenantAssignmentReader
    }

    internal constructor(
        settings: KeyProviderSettings,
        client: KmsClient,
    ) : this(settings) {
        this.sharedClient = client
    }

    internal constructor(
        settings: KeyProviderSettings,
        client: KmsClient,
        managedCreationCall: suspend (KmsClient, CreateKeyRequest) -> CreateKeyResponse,
    ) : this(settings, client) {
        this.managedCreationCall = managedCreationCall
    }
    private suspend fun defaultTenantAssignmentReader(): AwsKmsTenantAssignmentReader {
        val client = getAWSKmsClient()
        return object : AwsKmsTenantAssignmentReader {
            override suspend fun describeKey(keyReference: String): AwsKmsKeyIdentity {
                val metadata = client.describeKey(DescribeKeyRequest { keyId = keyReference }).keyMetadata
                    ?: throw IllegalStateException("AWS KMS did not return key metadata")
                return AwsKmsKeyIdentity(
                    keyId = metadata.keyId ?: throw IllegalStateException("AWS KMS key identity is missing"),
                    arn = metadata.arn ?: throw IllegalStateException("AWS KMS key ARN is missing"),
                )
            }

            override suspend fun listResourceTags(keyId: String, marker: String?): AwsKmsResourceTagPage {
                val response =
                    client.listResourceTags(
                        ListResourceTagsRequest {
                            this.keyId = keyId
                            this.marker = marker
                            limit = AWS_LIST_TAGS_PAGE_SIZE
                        },
                    )
                return AwsKmsResourceTagPage(
                    tags =
                        response.tags.orEmpty().mapNotNull { tag ->
                            val key = tag.tagKey ?: return@mapNotNull null
                            val value = tag.tagValue ?: return@mapNotNull null
                            key to value
                        },
                    truncated = response.truncated,
                    nextMarker = response.nextMarker,
                )
            }
        }
    }

    private suspend fun getAWSKmsClient(): KmsClient {
        sharedClient?.let { return it }
        return clientMutex.withLock {
            sharedClient?.let { return@withLock it }
            withContext(Dispatchers.IO) {
                KmsClient {
                    region = awsConfig.region
                    awsConfig.endpointUrl?.let { endpointUrl = Url.parse(it) }
                    credentialsProvider = awsKmsCredentialsProvider(awsConfig)
                }
            }.also { sharedClient = it }
        }
    }

    override fun close() {
        val client = sharedClient
        sharedClient = null
        if (client != null) {
            runBlocking {
                client.close()
            }
        }
    }

    override suspend fun generateKeyAsync(
        alias: String?,
        use: JwkUse?,
        keyOperations: Array<out KeyOperations>?,
        alg: SignatureAlgorithm?,
        certificateOptions: CertificateOptions?
    ): ManagedKeyPair {
        require(certificateOptions == null) { "Certificate options are not yet supported by AWS KMS" }
        val signingAlgorithm = alg ?: SignatureAlgorithm.ECDSA_SHA256
        val keyAgreementKey =
            keyOperations?.any { operation ->
                operation == KeyOperations.DERIVE_KEY || operation == KeyOperations.DERIVE_BITS
            } == true

        if (!isSupportedSignatureAlgorithm(signingAlgorithm)) {
            val algName = when (signingAlgorithm) {
                SignatureAlgorithm.ED25519 -> "Ed25519"
                else -> signingAlgorithm.toString()
            }
            throw IllegalArgumentException("Signature algorithm $algName is not supported by AWS KMS")
        }

        // Map signature algorithm to key spec
        val keySpec = when (signingAlgorithm) {
            SignatureAlgorithm.ECDSA_SHA256 -> KeySpec.EccNistP256
            SignatureAlgorithm.ECDSA_SHA384 -> KeySpec.EccNistP384
            SignatureAlgorithm.ECDSA_SHA512 -> KeySpec.EccNistP521
            // RSA PSS algorithms
            SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1,
            SignatureAlgorithm.RSA_SHA256 -> KeySpec.Rsa2048
            SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1,
            SignatureAlgorithm.RSA_SHA384 -> KeySpec.Rsa3072
            SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1,
            SignatureAlgorithm.RSA_SHA512 -> KeySpec.Rsa4096
            else -> throw IllegalArgumentException("Unsupported signature algorithm: $signingAlgorithm")
        }
        require(
            !keyAgreementKey ||
                keySpec == KeySpec.EccNistP256 ||
                keySpec == KeySpec.EccNistP384 ||
                keySpec == KeySpec.EccNistP521,
        ) { "AWS KMS KEY_AGREEMENT keys must be EC NIST keys" }

        // Create key in AWS KMS
        val client = getAWSKmsClient()
        val attempt = currentCoroutineContext()[ManagedKeyCreationAttempt]
        if (attempt != null) {
            require(attempt.providerId == id && attempt.backingAlias == alias && !keyAgreementKey) { "Managed creation scope does not match the provider" }
            when (attempt.state()) {
                ManagedKeyCreationAttemptState.REVOKED -> error("Managed creation authority was revoked")
                ManagedKeyCreationAttemptState.CLAIMED -> return recoverCreationPair(client, attempt, signingAlgorithm)
                ManagedKeyCreationAttemptState.UNCLAIMED -> {
                    check(attempt.intent == ManagedKeyCreationAttemptIntent.CREATE_OR_RECOVER) { "Recovery authority cannot create a key" }
                    if (!attempt.claimCreateOnce()) return recoverCreationPair(client, attempt, signingAlgorithm)
                }
            }
        }
        val createRequest = CreateKeyRequest {
            if (attempt != null) tags = managedCreationTags(attempt)
            this.keyUsage = if (keyAgreementKey) KeyUsageType.KeyAgreement else KeyUsageType.SignVerify
            this.keySpec = keySpec
        }
        val createKeyResponse = if (attempt == null) client.createKey(createRequest) else managedCreationCall(client, createRequest)
        val kid = createKeyResponse.keyMetadata?.keyId?.let(::awsCanonicalKeyId)
            ?: throw IllegalStateException("Failed to retrieve key ID after creation")

        if (alias != null && (createKeyResponse.keyMetadata?.arn != null || createKeyResponse.keyMetadata?.keyId != null)) {
            // We cannot set the alias right from the start, so we are doing it afterward
            client.createAlias(
                CreateAliasRequest {
                    aliasName = if (alias.startsWith("alias/")) alias else "alias/$alias"
                    targetKeyId = createKeyResponse.keyMetadata?.keyId ?: createKeyResponse.keyMetadata?.arn
                })
        }


        // Get public key in DER format
        val getPublicKeyResponse = client.getPublicKey(GetPublicKeyRequest {
            keyId = kid
        })
        val publicKeyDer: ByteArray = getPublicKeyResponse.publicKey
            ?: throw IllegalStateException("Public key not found")

        val joseKeyOperations =
            if (keyAgreementKey) {
                arrayOf(JoseKeyOperations.DERIVE_KEY, JoseKeyOperations.DERIVE_BITS)
            } else {
                arrayOf(JoseKeyOperations.SIGN, JoseKeyOperations.VERIFY)
            }
        return toManagedKeyPair(publicKeyDer, kid, alias ?: kid, signingAlgorithm, joseKeyOperations)
    }

    private fun toManagedKeyPair(
        publicKeyDer: ByteArray,
        kid: String,
        alias: String,
        signatureAlgorithm: SignatureAlgorithm? = null,
        joseKeyOperations: Array<JoseKeyOperations> = arrayOf(JoseKeyOperations.SIGN, JoseKeyOperations.VERIFY),
    ): ManagedKeyPair {
        // Create JWK from public key
        val jwk = createJwkFromPublicKey(publicKeyDer, kid, signatureAlgorithm, joseKeyOperations)
        val joseKeyPair = JoseKeyPair(null, jwk)

        return ManagedKeyPair(
            providerId = id,
            alias = alias,
            kid = kid,
            jose = joseKeyPair,
            cose = CoseKeyPair(null, CoseJoseKeyMappingService.toCoseKey(jwk))
        )
    }

    override fun rawSignatureEncoding(algorithm: SignatureAlgorithm): com.sphereon.crypto.core.kms.command.SignatureEncoding? =
        if (algorithm.jose?.value?.startsWith("ES") == true) com.sphereon.crypto.core.kms.command.SignatureEncoding.DER else com.sphereon.crypto.core.kms.command.SignatureEncoding.RAW

    override suspend fun createRawSignature(
        keyInfo: KeyInfoType<*>,
        input: ByteArray,
        requireX5Chain: Boolean
    ): ByteArray {
        requireManagedSigningKeySelection(keyInfo)
        // The selector (alias/kid/providerId) is not a signing policy. Resolve the actual
        // AWS public key first and validate the requested algorithm against that metadata before
        // handing any bytes to KMS. This also prevents an inline key from changing the key that
        // an explicit provider selector addresses.
        val resolved = getKey(keyInfo)
        val algorithm = keyInfo.signatureAlgorithm ?: resolved.signatureAlgorithm
            ?: throw IllegalArgumentException("Key does not have a signature algorithm set")
        keyInfo.key?.let { keyInfo.requireSigningKeyCompatible(algorithm) }
        resolved.signingPolicyInfo().requireSigningKeyCompatible(algorithm)

        val client = getAWSKmsClient()
        val signResponse = client.sign(SignRequest {
            this.keyId = determineAwsKeyId(keyInfo)
            message = input
            this.signingAlgorithm = algorithm.toSigningAlgorithmSpec()
        })

        return signResponse.signature!!
    }

    /**
     * Verifies a raw signature using a key stored in Azure Key Vault.
     */
    override suspend fun isValidRawSignature(
        keyInfo: KeyInfoType<*>,
        input: ByteArray,
        signature: ByteArray
    ): Boolean {
        val resolved = getKey(keyInfo)
        val algorithm = keyInfo.signatureAlgorithm ?: resolved.signatureAlgorithm
            ?: throw IllegalArgumentException("Key does not have a signature algorithm set")
        keyInfo.key?.let { keyInfo.requireVerificationKeyCompatible(algorithm) }
        resolved.verificationPolicyInfo().requireVerificationKeyCompatible(algorithm)

        val client = getAWSKmsClient()
        try {
            val verifyResponse = client.verify(VerifyRequest {
                this.keyId = determineAwsKeyId(keyInfo)
                message = input
                this.signature = signature
                this.signingAlgorithm = algorithm?.toSigningAlgorithmSpec()
            })
            return verifyResponse.signatureValid
        } catch (_: KmsInvalidSignatureException) {
            // Signature validation failed
            return false
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
        requireDigestLength(signatureAlgorithm, digest)
        val resolved = getKey(keyInfo)
        keyInfo.key?.let { keyInfo.requireSigningKeyCompatible(signatureAlgorithm) }
        resolved.signingPolicyInfo().requireSigningKeyCompatible(signatureAlgorithm)
        val signResponse =
            getAWSKmsClient().sign(
                SignRequest {
                    keyId = determineAwsKeyId(keyInfo)
                    message = digest
                    messageType = MessageType.fromValue("DIGEST")
                    signingAlgorithm = signatureAlgorithm.toSigningAlgorithmSpec()
                },
            )
        val nativeSignature = signResponse.signature ?: throw IllegalStateException("AWS KMS did not return a signature")
        return normalizeAwsSignatureOutput(nativeSignature, signatureEncoding, signatureAlgorithm)
    }

    override suspend fun verifyDigest(
        keyInfo: KeyInfoType<*>,
        digest: ByteArray,
        signature: ByteArray,
        signatureAlgorithm: SignatureAlgorithm,
        signatureEncoding: SignatureEncoding,
    ): Boolean {
        requireDigestLength(signatureAlgorithm, digest)
        val resolved = getKey(keyInfo)
        keyInfo.key?.let { keyInfo.requireVerificationKeyCompatible(signatureAlgorithm) }
        resolved.verificationPolicyInfo().requireVerificationKeyCompatible(signatureAlgorithm)
        val nativeSignature = normalizeAwsSignatureInput(signature, signatureEncoding, signatureAlgorithm)
        return try {
            getAWSKmsClient()
                .verify(
                    VerifyRequest {
                        keyId = determineAwsKeyId(keyInfo)
                        message = digest
                        this.signature = nativeSignature
                        messageType = MessageType.fromValue("DIGEST")
                        signingAlgorithm = signatureAlgorithm.toSigningAlgorithmSpec()
                    },
                ).signatureValid
        } catch (_: KmsInvalidSignatureException) {
            false
        }
    }

    private fun SignatureAlgorithm.toSigningAlgorithmSpec(): SigningAlgorithmSpec {
        return when (this) {
            SignatureAlgorithm.ECDSA_SHA256 -> SigningAlgorithmSpec.EcdsaSha256
            SignatureAlgorithm.ECDSA_SHA384 -> SigningAlgorithmSpec.EcdsaSha384
            SignatureAlgorithm.ECDSA_SHA512 -> SigningAlgorithmSpec.EcdsaSha512
            // RSA PSS (RSASSA-PSS)
            SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1 -> SigningAlgorithmSpec.RsassaPssSha256
            SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1 -> SigningAlgorithmSpec.RsassaPssSha384
            SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1 -> SigningAlgorithmSpec.RsassaPssSha512
            // RSA PKCS#1 v1.5 - use fromValue as enum names vary by SDK version
            SignatureAlgorithm.RSA_SHA256 -> SigningAlgorithmSpec.fromValue("RSASSA_PKCS1_V1_5_SHA_256")
            SignatureAlgorithm.RSA_SHA384 -> SigningAlgorithmSpec.fromValue("RSASSA_PKCS1_V1_5_SHA_384")
            SignatureAlgorithm.RSA_SHA512 -> SigningAlgorithmSpec.fromValue("RSASSA_PKCS1_V1_5_SHA_512")
            else -> throw IllegalArgumentException("Unsupported signature algorithm: $this")
        }
    }

    private fun requireDigestLength(
        algorithm: SignatureAlgorithm,
        digest: ByteArray,
    ) {
        val expected =
            when (algorithm) {
                SignatureAlgorithm.ECDSA_SHA256 -> 32
                SignatureAlgorithm.ECDSA_SHA384 -> 48
                SignatureAlgorithm.ECDSA_SHA512 -> 64
                SignatureAlgorithm.RSA_SHA256,
                SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1 -> 32
                SignatureAlgorithm.RSA_SHA384,
                SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1 -> 48
                SignatureAlgorithm.RSA_SHA512,
                SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1 -> 64
                else -> throw IllegalArgumentException("Digest signing is not supported for $algorithm")
            }
        require(digest.size == expected) { "Digest for $algorithm must be $expected bytes, got ${digest.size}" }
    }

    private fun normalizeAwsSignatureOutput(
        signature: ByteArray,
        signatureEncoding: SignatureEncoding,
        algorithm: SignatureAlgorithm,
    ): ByteArray =
        when {
            algorithm.cryptoAlgorithm == CryptoAlg.ECDSA && signatureEncoding == SignatureEncoding.RAW ->
                SignatureEncodingCodec.derToRaw(signature, SignatureEncodingCodec.scalarLength(algorithm))
            algorithm.cryptoAlgorithm == CryptoAlg.ECDSA && signatureEncoding == SignatureEncoding.DER -> signature
            signatureEncoding == SignatureEncoding.RAW -> signature
            else -> throw IllegalArgumentException("DER signature encoding is only supported for ECDSA algorithms")
        }

    private fun normalizeAwsSignatureInput(
        signature: ByteArray,
        signatureEncoding: SignatureEncoding,
        algorithm: SignatureAlgorithm,
    ): ByteArray =
        when {
            algorithm.cryptoAlgorithm == CryptoAlg.ECDSA && signatureEncoding == SignatureEncoding.RAW ->
                SignatureEncodingCodec.rawToDer(signature, SignatureEncodingCodec.scalarLength(algorithm))
            algorithm.cryptoAlgorithm == CryptoAlg.ECDSA && signatureEncoding == SignatureEncoding.DER -> signature
            signatureEncoding == SignatureEncoding.RAW -> signature
            else -> throw IllegalArgumentException("DER signature encoding is only supported for ECDSA algorithms")
        }

    /**
     * Creates a JWK (JSON Web Key) representation from the DER-encoded public key.
     *
     * This implementation supports EC curves P-256, P-384, P-521 and RSA keys.
     *
     * @param publicKeyDer DER-encoded public key bytes.
     * @param keyId The key identifier to embed in the JWK.
     * @param signatureAlgorithm Optional signature algorithm hint for RSA keys.
     * @return A Jwk representing the public key.
     * @throws IllegalArgumentException if the key is not a valid EC or RSA key.
     */
    fun createJwkFromPublicKey(
        publicKeyDer: ByteArray,
        keyId: String,
        signatureAlgorithm: SignatureAlgorithm? = null,
        joseKeyOperations: Array<JoseKeyOperations> = arrayOf(JoseKeyOperations.SIGN, JoseKeyOperations.VERIFY),
    ): Jwk {
        val keySpec = X509EncodedKeySpec(publicKeyDer)

        // Convert BigInteger to a fixed-length byte array (unsigned representation)
        fun bigIntToFixedLengthBytes(value: BigInteger, length: Int): ByteArray {
            val bytes = value.toByteArray()
            return when {
                bytes.size == length -> bytes
                bytes.size == length + 1 && bytes[0].toInt() == 0 -> bytes.copyOfRange(1, bytes.size)
                bytes.size < length -> {
                    // Left pad with zeros if necessary
                    ByteArray(length).apply {
                        System.arraycopy(bytes, 0, this, length - bytes.size, bytes.size)
                    }
                }
                else -> bytes.copyOfRange(bytes.size - length, bytes.size)
            }
        }

        // Try EC first, then RSA
        return try {
            val keyFactory = KeyFactory.getInstance("EC")
            val publicKey = keyFactory.generatePublic(keySpec) as ECPublicKey

            // Extract the affine coordinates (x and y)
            val ecPoint = publicKey.w
            val params = publicKey.params
            val fieldSize = params.curve.field.fieldSize
            val coordinateLength = (fieldSize + 7) / 8

            val xBytes = bigIntToFixedLengthBytes(ecPoint.affineX, coordinateLength)
            val yBytes = bigIntToFixedLengthBytes(ecPoint.affineY, coordinateLength)

            val xEncoded = xBytes.encodeToBase64Url()
            val yEncoded = yBytes.encodeToBase64Url()

            // Map the field size to the corresponding JWK "crv" value
            val (crv, alg) = when (fieldSize) {
                256 -> JwaCurve.P_256 to JwaAlgorithm.ES256
                384 -> JwaCurve.P_384 to JwaAlgorithm.ES384
                521 -> JwaCurve.P_521 to JwaAlgorithm.ES512
                else -> throw IllegalArgumentException("Unsupported EC curve with field size $fieldSize")
            }

            Jwk.Builder()
                .withKid(keyId)
                .withKty(JwaKeyType.EC)
                .withAlg(alg)
                .withCrv(crv)
                .withX(xEncoded)
                .withY(yEncoded)
                .withKeyOps(joseKeyOperations)
                .build()
        } catch (_: Exception) {
            // Try RSA
            val keyFactory = KeyFactory.getInstance("RSA")
            val publicKey = keyFactory.generatePublic(keySpec) as java.security.interfaces.RSAPublicKey

            val modulusBytes = publicKey.modulus.toByteArray().let {
                if (it[0].toInt() == 0) it.copyOfRange(1, it.size) else it
            }
            val exponentBytes = publicKey.publicExponent.toByteArray()

            val nEncoded = modulusBytes.encodeToBase64Url()
            val eEncoded = exponentBytes.encodeToBase64Url()

            // Determine RSA algorithm only from an explicit signature hint. AWS KMS lookup
            // metadata is algorithm-neutral across RS*/PS*.
            val alg = when (signatureAlgorithm) {
                SignatureAlgorithm.RSA_SSA_PSS_SHA256_MGF1 -> JwaAlgorithm.PS256
                SignatureAlgorithm.RSA_SSA_PSS_SHA384_MGF1 -> JwaAlgorithm.PS384
                SignatureAlgorithm.RSA_SSA_PSS_SHA512_MGF1 -> JwaAlgorithm.PS512
                SignatureAlgorithm.RSA_SHA256 -> JwaAlgorithm.RS256
                SignatureAlgorithm.RSA_SHA384 -> JwaAlgorithm.RS384
                SignatureAlgorithm.RSA_SHA512 -> JwaAlgorithm.RS512
                // AWS KMS RSA keys support both PKCS#1 and PSS. A lookup has no algorithm
                // restriction, so do not fabricate one into the returned JWK. The caller's
                // requested algorithm is validated and supplied to the Sign API above.
                else -> null
            }

            Jwk.Builder()
                .withKid(keyId)
                .withKty(JwaKeyType.RSA)
                .withAlg(alg)
                .withN(nEncoded)
                .withE(eEncoded)
                .withKeyOps(joseKeyOperations)
                .build()
        }
    }


    override suspend fun listKeys(): Array<ManagedKeyReference> {
        return run {
            val client = getAWSKmsClient()
            client.listKeys().keys?.map { entry: KeyListEntry ->
                getKey(KeyInfo<JwkType>(kid = awsCanonicalKeyId(entry.keyId!!)))
            }
        }.orEmpty().map { it.toKeyReference() }.toTypedArray()


    }

    override suspend fun getKey(keyInfo: KeyInfoType<*>): ManagedKeyInfoType<*> {
        return getAWSKmsClient().let { client ->
            val attempt = currentCoroutineContext()[ManagedKeyCreationAttempt]
            if (attempt != null) {
                require(attempt.providerId == id && keyInfo.alias == attempt.backingAlias) { "Managed creation scope does not match key lookup" }
                check(attempt.authorizeRecovery()) { "Managed creation recovery is not authorized" }
                when (attempt.state()) {
                    ManagedKeyCreationAttemptState.REVOKED -> error("Managed creation authority was revoked")
                    ManagedKeyCreationAttemptState.CLAIMED -> return@let recoverCreationPair(client, attempt,
                        requireNotNull(keyInfo.signatureAlgorithm)).joseToManagedKeyInfo()
                    ManagedKeyCreationAttemptState.UNCLAIMED -> Unit
                }
                // The journal has not granted any physical creation. Probe its exact server
                // alias, independently of an optional key selector carried by the caller.
                try {
                    client.getPublicKey(GetPublicKeyRequest {
                        keyId = if (attempt.backingAlias.startsWith("alias/")) attempt.backingAlias else "alias/${attempt.backingAlias}"
                    })
                } catch (missing: NotFoundException) {
                    if (attempt.intent == ManagedKeyCreationAttemptIntent.RECOVER_FOR_REVOCATION) {
                        check(attempt.authorizeRecovery() && attempt.state() == ManagedKeyCreationAttemptState.UNCLAIMED) {
                            "Unclaimed managed creation authority changed"
                        }
                        attempt.reportRevoked()
                    }
                    throw com.sphereon.core.api.error.NotFoundException(resource = "AWS KMS key", cause = missing)
                }
                error("An unclaimed managed creation alias already exists")
            }
            val resolvedKeyId = determineAwsKeyId(keyInfo)
            val resolvedAlias = keyInfo.alias ?: keyInfo.kid ?: resolvedKeyId
            val response = try {
                client.getPublicKey(GetPublicKeyRequest { keyId = resolvedKeyId })
            } catch (missing: NotFoundException) {
                throw com.sphereon.core.api.error.NotFoundException(resource = "AWS KMS key", cause = missing)
            }
            response.publicKey?.let {

                toManagedKeyPair(
                    it,
                    awsCanonicalKeyId(response.keyId ?: resolvedKeyId),
                    resolvedAlias,
                ).joseToManagedKeyInfo()
            }
                ?: throw IllegalArgumentException(
                    "Key with ID ${keyInfo.alias} not found in AWS KMS"
                )
        }
    }

    private suspend fun recoverCreationPair(client: KmsClient, attempt: ManagedKeyCreationAttempt, algorithm: SignatureAlgorithm): ManagedKeyPair {
        val keyId = recoverManagedCreationKey(client, attempt, algorithm)
        val response = client.getPublicKey(GetPublicKeyRequest { this.keyId = keyId })
        require(response.keyId?.let(::awsCanonicalKeyId) == keyId && response.publicKey != null) { "Managed creation public receipt is inconsistent" }
        check(attempt.authorizeRecovery()) { "Managed creation authority changed" }
        return toManagedKeyPair(requireNotNull(response.publicKey), keyId, attempt.backingAlias, algorithm)
    }
    override suspend fun storeKey(keyInfo: ResolvedKeyInfoType<*>, providerId: String, alias: String, certChain: Array<Certificate>?): ManagedKeyInfoType<*> {
        throw UnsupportedOperationException("AWS KMS does not support storing keys, it generates them only")
    }

    override suspend fun deleteKey(keyInfo: KeyInfoType<*>): Boolean {
        return getAWSKmsClient().let { client ->
            val attempt = currentCoroutineContext()[ManagedKeyCreationAttempt]
            if (attempt != null) {
                require(attempt.intent == ManagedKeyCreationAttemptIntent.RECOVER_FOR_REVOCATION &&
                    attempt.providerId == id && attempt.backingAlias == keyInfo.alias &&
                    attempt.state() == ManagedKeyCreationAttemptState.CLAIMED && attempt.authorizeRecovery()) { "Managed deletion is not authorized" }
                val physicalId = awsCanonicalKeyId(requireNotNull(keyInfo.kid))
                val metadata = try { client.describeKey(DescribeKeyRequest { this.keyId = physicalId }).keyMetadata }
                    catch (missing: NotFoundException) { throw com.sphereon.core.api.error.NotFoundException("AWS KMS key", cause = missing) }
                    ?: error("Managed deletion metadata is missing")
                require(metadata.keyId == physicalId && metadata.keySpec == expectedManagedKeySpec(requireNotNull(keyInfo.signatureAlgorithm)) &&
                    metadata.keyUsage == KeyUsageType.SignVerify && metadata.origin == OriginType.AwsKms && metadata.keyManager == KeyManagerType.Customer &&
                    metadata.keyState in setOf(KeyState.Enabled, KeyState.Disabled, KeyState.PendingDeletion) &&
                    hasManagedCreationTags(client, physicalId, attempt)) { "Managed deletion receipt is inconsistent" }
                check(attempt.authorizeRecovery()) { "Managed deletion authority changed" }
                if (metadata.keyState == KeyState.PendingDeletion) return@let true
                val removed = client.scheduleKeyDeletion(ScheduleKeyDeletionRequest { this.keyId = physicalId; pendingWindowInDays = 7 }).keyState == KeyState.PendingDeletion
                check(attempt.authorizeRecovery()) { "Managed deletion authority changed" }
                return@let removed
            }
            val keyId = if (keyInfo.kid != null) keyInfo.kid else getKey(keyInfo).kid ?: determineAwsKeyId(keyInfo)  // We fetch the key first, since deletion can only happen via kid and not an alias!
            client.scheduleKeyDeletion(ScheduleKeyDeletionRequest {
                this.keyId = keyId
                pendingWindowInDays = 7
            }).keyState == KeyState.PendingDeletion
        }
    }

    override fun keyVisibility(): KeyVisibility {
        return KeyVisibility.PUBLIC
    }

    override val kmsProviderType: String
        get() = PredefinedKmsProviderTypes.AWS_KMS.kmsProviderType

    /**
     * Encrypts plaintext using the specified key and algorithm.
     *
     * AWS KMS supports symmetric encryption (AES-256-GCM) for symmetric keys
     * and asymmetric encryption (RSA-OAEP) for RSA keys.
     *
     * @param keyInfo Information about the key to use for encryption
     * @param plaintext The data to encrypt
     * @param algorithm The content encryption algorithm to use
     * @param additionalAuthenticatedData Optional AAD for authenticated encryption (not supported by AWS KMS directly)
     * @return EncryptionResult containing ciphertext, IV, and authentication tag
     */
    override suspend fun encrypt(
        keyInfo: KeyInfoType<*>,
        plaintext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        additionalAuthenticatedData: ByteArray?
    ): EncryptionResult {
        val client = getAWSKmsClient()

        // AWS KMS encrypt operation - uses symmetric key encryption
        val encryptResponse = client.encrypt(EncryptRequest {
            this.keyId = determineAwsKeyId(keyInfo)
            this.plaintext = plaintext
            this.encryptionContext = awsKmsEncryptionContext(additionalAuthenticatedData)
            // AWS KMS uses symmetric encryption by default (AES-256-GCM)
            // The algorithm parameter maps to the key's encryption algorithm
            this.encryptionAlgorithm = algorithm.toAwsEncryptionAlgorithm()
        })

        return EncryptionResult(
            ciphertext = encryptResponse.ciphertextBlob ?: throw IllegalStateException("Encryption failed - no ciphertext returned"),
            iv = ByteArray(algorithm.ivLength), // AWS KMS handles IV internally
            authTag = ByteArray(algorithm.tagLength) // AWS KMS handles auth tag internally
        )
    }

    /**
     * Decrypts ciphertext using the specified key and algorithm.
     *
     * @param keyInfo Information about the key to use for decryption
     * @param ciphertext The encrypted data
     * @param algorithm The content encryption algorithm used for encryption
     * @param iv The initialization vector used during encryption (not used by AWS KMS - handled internally)
     * @param authTag The authentication tag for verification (not used by AWS KMS - handled internally)
     * @param additionalAuthenticatedData Optional AAD used during encryption
     * @return The decrypted plaintext
     */
    override suspend fun decrypt(
        keyInfo: KeyInfoType<*>,
        ciphertext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        iv: ByteArray,
        authTag: ByteArray,
        additionalAuthenticatedData: ByteArray?
    ): ByteArray {
        val client = getAWSKmsClient()

        val decryptResponse = client.decrypt(DecryptRequest {
            this.keyId = determineAwsKeyId(keyInfo)
            this.ciphertextBlob = ciphertext
            this.encryptionContext = awsKmsEncryptionContext(additionalAuthenticatedData)
            this.encryptionAlgorithm = algorithm.toAwsEncryptionAlgorithm()
        })

        return decryptResponse.plaintext ?: throw IllegalStateException("Decryption failed - no plaintext returned")
    }

    override suspend fun encryptWithBackendKeyProof(
        keyInfo: KeyInfoType<*>,
        plaintext: ByteArray,
        algorithm: ContentEncryptionAlgorithm,
        additionalAuthenticatedData: ByteArray?,
    ): BackendKeyProvedEncryption {
        val immutableIdentity = requireImmutableAwsKmsKeyArn(keyInfo)
        val client = getAWSKmsClient()
        val metadata = describeSymmetricNonExportableKey(client, immutableIdentity)
        val response =
            client.encrypt(
                EncryptRequest {
                    keyId = immutableIdentity
                    this.plaintext = plaintext
                    encryptionContext = awsKmsEncryptionContext(additionalAuthenticatedData)
                    encryptionAlgorithm = algorithm.toAwsEncryptionAlgorithm()
                },
            )
        val responseIdentity =
            response.keyId ?: throw IllegalStateException("AWS KMS did not authenticate an encryption key identity")
        require(responseIdentity == metadata.arn) { "AWS KMS encryption key identity mismatch" }
        val digest = awsBackendKeyIdentityDigest(metadata.arn!!, metadata.keyId!!)
        return BackendKeyProvedEncryption(
            encryption =
                EncryptionResult(
                    ciphertext = response.ciphertextBlob
                        ?: throw IllegalStateException("Encryption failed - no ciphertext returned"),
                    iv = ByteArray(algorithm.ivLength),
                    authTag = ByteArray(algorithm.tagLength),
                ),
            backendKeyIdentityDigest = digest,
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
        val immutableIdentity = requireImmutableAwsKmsKeyArn(keyInfo)
        val client = getAWSKmsClient()
        val metadata = describeSymmetricNonExportableKey(client, immutableIdentity)
        val digest = awsBackendKeyIdentityDigest(metadata.arn!!, metadata.keyId!!)
        require(digest == expectedBackendKeyIdentityDigest) { "AWS KMS backend key identity digest mismatch" }
        val response =
            client.decrypt(
                DecryptRequest {
                    keyId = immutableIdentity
                    ciphertextBlob = ciphertext
                    encryptionContext = awsKmsEncryptionContext(additionalAuthenticatedData)
                    encryptionAlgorithm = algorithm.toAwsEncryptionAlgorithm()
                },
            )
        val responseIdentity =
            response.keyId ?: throw IllegalStateException("AWS KMS did not authenticate a decryption key identity")
        require(responseIdentity == metadata.arn) { "AWS KMS decryption key identity mismatch" }
        return BackendKeyProvedDecryption(
            plaintext = response.plaintext ?: throw IllegalStateException("Decryption failed - no plaintext returned"),
            backendKeyIdentityDigest = digest,
        )
    }

    override suspend fun resolveImmutableBackendKeyIdentity(bindingAlias: String): String? {
        val alias = requireAwsBindingAlias(bindingAlias)
        val client = getAWSKmsClient()
        val bindingDigest = awsBindingJournalDigest(bindingAlias)
        val aliasMetadata =
            try {
                describeSymmetricNonExportableKey(client, alias)
            } catch (_: NotFoundException) {
                null
            }
        if (aliasMetadata != null) {
            require(
                keyHasBindingJournalTag(client, aliasMetadata.keyId!!, bindingDigest),
            ) {
                "AWS KMS binding alias is not owned by the secret-management lifecycle"
            }
            return aliasMetadata.arn
        }
        val taggedKeys = findActiveKeysByBindingJournalTag(client, bindingDigest)
        return when (val plan = awsSymmetricKeyCreationReconciliationPlan(null, taggedKeys.mapNotNull { it.arn })) {
            AwsSymmetricKeyCreationReconciliationPlan.Create -> null
            is AwsSymmetricKeyCreationReconciliationPlan.Reuse -> plan.immutableKeyIdentity
            is AwsSymmetricKeyCreationReconciliationPlan.Reattach -> {
                val taggedKey =
                    taggedKeys.singleOrNull { it.arn == plan.immutableKeyIdentity }
                        ?: throw IllegalStateException("AWS KMS key reconciliation state is inconsistent")
                client.createAlias(
                    CreateAliasRequest {
                        aliasName = alias
                        targetKeyId = taggedKey.keyId
                    },
                )
                plan.immutableKeyIdentity
            }
        }
    }

    override suspend fun createSymmetricNonExportableKey(bindingAlias: String): String {
        val alias = requireAwsBindingAlias(bindingAlias)
        resolveImmutableBackendKeyIdentity(bindingAlias)?.let { return it }
        val client = getAWSKmsClient()
        val bindingDigest = awsBindingJournalDigest(bindingAlias)
        val created =
            client.createKey(
                CreateKeyRequest {
                    keySpec = KeySpec.SymmetricDefault
                    keyUsage = KeyUsageType.EncryptDecrypt
                    description = "Sphereon isolated secret-management encryption key"
                    tags =
                        listOf(
                            Tag {
                                tagKey = AWS_BINDING_JOURNAL_TAG_KEY
                                tagValue = bindingDigest
                            },
                        )
                },
            ).keyMetadata ?: throw IllegalStateException("AWS KMS did not return created key metadata")
        val metadata = requireSymmetricNonExportableKeyMetadata(created)
        try {
            client.createAlias(
                CreateAliasRequest {
                    aliasName = alias
                    targetKeyId = metadata.keyId
                },
            )
        } catch (failure: Throwable) {
            client.scheduleKeyDeletion(
                ScheduleKeyDeletionRequest {
                    keyId = metadata.keyId
                    pendingWindowInDays = AWS_MINIMUM_DELETION_WINDOW_DAYS
                },
            )
            throw failure
        }
        return metadata.arn!!
    }

    override suspend fun revokeSymmetricNonExportableKey(bindingAlias: String) {
        val alias = requireAwsBindingAlias(bindingAlias)
        val client = getAWSKmsClient()
        val bindingDigest = awsBindingJournalDigest(bindingAlias)
        val metadata =
            try {
                describeSymmetricKeyForRevocation(client, alias)
            } catch (_: NotFoundException) {
                val tagged = findRevocableKeysByBindingJournalTag(client, bindingDigest)
                when {
                    tagged.isEmpty() -> return
                    tagged.size == 1 -> tagged.single()
                    else -> throw IllegalStateException("AWS KMS binding journal is ambiguous")
                }
            }
        val plan = awsSymmetricKeyRevocationPlan(metadata.keyState)
        if (plan.scheduleDeletion) {
            client.scheduleKeyDeletion(
                ScheduleKeyDeletionRequest {
                    keyId = metadata.arn
                    pendingWindowInDays = AWS_MINIMUM_DELETION_WINDOW_DAYS
                },
            )
        }
        check(plan.deleteAlias) { "AWS KMS alias deletion cannot precede key deletion scheduling" }
        try {
            client.deleteAlias(DeleteAliasRequest { aliasName = alias })
        } catch (_: NotFoundException) {
            // A hard crash can leave only the atomically tagged key and no alias.
        }
    }

    /**
     * Wraps (encrypts) a key using the specified wrapping key and algorithm.
     *
     * AWS KMS uses the encrypt operation for key wrapping with RSA-OAEP algorithms.
     *
     * @param wrappingKeyInfo Information about the key to use for wrapping
     * @param keyToWrap The key material to wrap
     * @param algorithm The key wrap algorithm to use
     * @return The wrapped key bytes
     */
    override suspend fun wrapKey(
        wrappingKeyInfo: KeyInfoType<*>,
        keyToWrap: ByteArray,
        algorithm: KeyWrapAlgorithm
    ): ByteArray {
        val client = getAWSKmsClient()

        // AWS KMS uses encrypt operation for key wrapping
        val encryptResponse = client.encrypt(EncryptRequest {
            this.keyId = determineAwsKeyId(wrappingKeyInfo)
            this.plaintext = keyToWrap
            this.encryptionAlgorithm = algorithm.toAwsEncryptionAlgorithm()
        })

        return encryptResponse.ciphertextBlob ?: throw IllegalStateException("Key wrapping failed - no ciphertext returned")
    }

    /**
     * Unwraps (decrypts) a wrapped key using the specified unwrapping key and algorithm.
     *
     * @param unwrappingKeyInfo Information about the key to use for unwrapping
     * @param wrappedKey The wrapped key bytes
     * @param algorithm The key wrap algorithm used during wrapping
     * @return The unwrapped key material
     */
    override suspend fun unwrapKey(
        unwrappingKeyInfo: KeyInfoType<*>,
        wrappedKey: ByteArray,
        algorithm: KeyWrapAlgorithm
    ): ByteArray {
        val client = getAWSKmsClient()

        val decryptResponse = client.decrypt(DecryptRequest {
            this.keyId = determineAwsKeyId(unwrappingKeyInfo)
            this.ciphertextBlob = wrappedKey
            this.encryptionAlgorithm = algorithm.toAwsEncryptionAlgorithm()
        })

        return decryptResponse.plaintext ?: throw IllegalStateException("Key unwrapping failed - no plaintext returned")
    }

    /**
     * Performs ECDH key agreement using AWS KMS DeriveSharedSecret API.
     *
     * AWS KMS supports ECDH key agreement (as of June 2024) via the DeriveSharedSecret API.
     * Note: This requires EC keys created with KeyUsage of KEY_AGREEMENT in AWS KMS.
     * Keys created by generateKeyAsync() are for signing (SIGN_VERIFY) and cannot be used here.
     * You need to create KEY_AGREEMENT keys via AWS Console or SDK directly.
     *
     * @param privateKeyInfo Information about the KMS key to use as the private key (must have KEY_AGREEMENT usage)
     * @param publicKeyInfo Information about the public key (must be a JWK with EC key type)
     * @param algorithm The key agreement algorithm to use (ECDH_ES)
     * @param keyDataLen Optional length for the derived key data (not used by AWS KMS raw derivation)
     * @return The derived shared secret bytes
     */
    override suspend fun performKeyAgreement(
        privateKeyInfo: KeyInfoType<*>,
        publicKeyInfo: KeyInfoType<*>,
        algorithm: KeyAgreementAlgorithm,
        keyDataLen: Int?
    ): ByteArray {
        if (algorithm != KeyAgreementAlgorithm.ECDH_ES) {
            throw UnsupportedOperationException("AWS KMS only supports ECDH key agreement, not $algorithm")
        }

        // Get the public key and convert to DER format
        val publicKey = publicKeyInfo.key
            ?: throw IllegalArgumentException("Public key is required for key agreement")

        // Convert JWK to DER-encoded public key bytes
        val publicKeyDer = when (publicKey) {
            is JwkType -> toDerEcdsaPublicKeyBytes(publicKey)
            else -> throw IllegalArgumentException("Public key must be a JWK for AWS KMS key agreement")
        }

        val client = getAWSKmsClient()

        val deriveResponse = client.deriveSharedSecret(DeriveSharedSecretRequest {
            this.keyId = determineAwsKeyId(privateKeyInfo)
            this.publicKey = publicKeyDer
            this.keyAgreementAlgorithm = KeyAgreementAlgorithmSpec.fromValue("ECDH")
        })

        return deriveResponse.sharedSecret
            ?: throw IllegalStateException("Key agreement failed - no shared secret returned")
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
        val rawSharedSecret =
            performKeyAgreement(
                privateKeyInfo = privateKeyInfo,
                publicKeyInfo = publicKeyInfo,
                algorithm = algorithm,
                keyDataLen = null,
            )
        return when (mode) {
            EcdhDeriveMode.RAW_X -> EcdhDeriveResult(derivedSecret = rawSharedSecret)
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
        require(output == EcPointMultiplyOutput.RAW_X) { "AWS KMS EC point multiplication supports RAW_X output only" }
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

    /**
     * Converts ContentEncryptionAlgorithm to AWS KMS EncryptionAlgorithmSpec.
     * AWS KMS symmetric keys use SYMMETRIC_DEFAULT (AES-256-GCM).
     */
    private fun ContentEncryptionAlgorithm.toAwsEncryptionAlgorithm(): EncryptionAlgorithmSpec = when (this) {
        ContentEncryptionAlgorithm.A128GCM,
        ContentEncryptionAlgorithm.A192GCM,
        ContentEncryptionAlgorithm.A256GCM,
        ContentEncryptionAlgorithm.A128CBC_HS256,
        ContentEncryptionAlgorithm.A192CBC_HS384,
        ContentEncryptionAlgorithm.A256CBC_HS512 -> EncryptionAlgorithmSpec.SymmetricDefault
    }

    /**
     * Converts KeyWrapAlgorithm to AWS KMS EncryptionAlgorithmSpec.
     */
    private fun KeyWrapAlgorithm.toAwsEncryptionAlgorithm(): EncryptionAlgorithmSpec = when (this) {
        KeyWrapAlgorithm.RSA_OAEP -> EncryptionAlgorithmSpec.RsaesOaepSha1
        KeyWrapAlgorithm.RSA_OAEP_256 -> EncryptionAlgorithmSpec.RsaesOaepSha256
        KeyWrapAlgorithm.RSA1_5 -> throw UnsupportedOperationException("RSA1_5 not supported by AWS KMS - use RSA_OAEP instead")
        KeyWrapAlgorithm.RSA_OAEP_384,
        KeyWrapAlgorithm.RSA_OAEP_512 -> throw UnsupportedOperationException("RSA-OAEP-384/512 not supported by AWS KMS")
        KeyWrapAlgorithm.A128KW,
        KeyWrapAlgorithm.A192KW,
        KeyWrapAlgorithm.A256KW -> EncryptionAlgorithmSpec.SymmetricDefault
        KeyWrapAlgorithm.A128GCMKW,
        KeyWrapAlgorithm.A192GCMKW,
        KeyWrapAlgorithm.A256GCMKW -> throw UnsupportedOperationException("AES-GCM key wrap not supported by AWS KMS")
        KeyWrapAlgorithm.DIR -> throw UnsupportedOperationException("Direct key agreement not supported for key wrapping")
    }
}

internal fun awsKmsCredentialsProvider(config: AwsKmsClientConfig): CredentialsProvider =
    when (config.credentialOpts.credentialMode) {
        CredentialMode.DEFAULT_CHAIN -> DefaultChainCredentialsProvider(region = config.region)
        CredentialMode.ACCESS_KEY -> {
            val options = requireNotNull(config.credentialOpts.accessKeyCredentialOpts) {
                "AWS ACCESS_KEY credential options are required"
            }
            require(options.credentialsSecretId.isNotBlank()) {
                "AWS ACCESS_KEY credential source identity is required"
            }
            val accessKeyId = options.accessKeyId?.takeIf(String::isNotBlank)
                ?: throw IllegalArgumentException("AWS ACCESS_KEY material is not staged")
            val secretAccessKey = options.secretAccessKey?.takeIf(String::isNotBlank)
                ?: throw IllegalArgumentException("AWS ACCESS_KEY material is not staged")
            StaticCredentialsProvider {
                this.accessKeyId = accessKeyId
                this.secretAccessKey = secretAccessKey
                this.sessionToken = options.sessionToken?.takeIf(String::isNotBlank)
            }
        }
        CredentialMode.PROFILE -> {
            val profileName = config.credentialOpts.profileCredentialOpts?.profileName?.takeIf(String::isNotBlank)
                ?: throw IllegalArgumentException("AWS PROFILE credential options are required")
            ProfileCredentialsProvider(profileName = profileName, region = config.region)
        }
        CredentialMode.CONTAINER -> EcsCredentialsProvider()
        CredentialMode.INSTANCE -> ImdsCredentialsProvider()
    }

private suspend fun describeSymmetricNonExportableKey(
    client: KmsClient,
    keyReference: String,
) =
    client.describeKey(DescribeKeyRequest { keyId = keyReference }).keyMetadata
        ?.let(::requireSymmetricNonExportableKeyMetadata)
        ?: throw IllegalStateException("AWS KMS did not return key metadata")

private suspend fun describeSymmetricKeyForRevocation(
    client: KmsClient,
    keyReference: String,
): aws.sdk.kotlin.services.kms.model.KeyMetadata {
    val metadata =
        client.describeKey(DescribeKeyRequest { keyId = keyReference }).keyMetadata
            ?: throw IllegalStateException("AWS KMS did not return key metadata")
    return requireRevocableSymmetricKeyMetadata(metadata)
}

private fun requireRevocableSymmetricKeyMetadata(
    metadata: aws.sdk.kotlin.services.kms.model.KeyMetadata,
): aws.sdk.kotlin.services.kms.model.KeyMetadata {
    require(metadata.keyState == KeyState.Enabled || metadata.keyState == KeyState.Disabled ||
        metadata.keyState == KeyState.PendingDeletion
    ) {
        "AWS KMS key is not in a revocable lifecycle state"
    }
    require(metadata.keySpec == KeySpec.SymmetricDefault && metadata.keyUsage == KeyUsageType.EncryptDecrypt) {
        "AWS KMS key is not a symmetric encryption key"
    }
    require(metadata.origin == OriginType.AwsKms && metadata.keyManager == KeyManagerType.Customer) {
        "AWS KMS key custody is not customer-controlled hardware"
    }
    require(!metadata.arn.isNullOrBlank() && !metadata.keyId.isNullOrBlank()) {
        "AWS KMS key metadata is incomplete"
    }
    return metadata
}

private fun requireSymmetricNonExportableKeyMetadata(
    metadata: aws.sdk.kotlin.services.kms.model.KeyMetadata,
): aws.sdk.kotlin.services.kms.model.KeyMetadata {
    require(metadata.enabled == true && metadata.keyState == KeyState.Enabled) { "AWS KMS key is not enabled" }
    require(metadata.keySpec == KeySpec.SymmetricDefault && metadata.keyUsage == KeyUsageType.EncryptDecrypt) {
        "AWS KMS key is not a symmetric encryption key"
    }
    require(metadata.origin == OriginType.AwsKms && metadata.keyManager == KeyManagerType.Customer) {
        "AWS KMS key custody is not customer-controlled hardware"
    }
    require(!metadata.arn.isNullOrBlank() && !metadata.keyId.isNullOrBlank()) {
        "AWS KMS key metadata is incomplete"
    }
    return metadata
}

private suspend fun findActiveKeysByBindingJournalTag(
    client: KmsClient,
    bindingDigest: String,
): List<aws.sdk.kotlin.services.kms.model.KeyMetadata> =
    findKeysByBindingJournalTag(client, bindingDigest)
        .filter { it.keyState == KeyState.Enabled }
        .map(::requireSymmetricNonExportableKeyMetadata)

private suspend fun findRevocableKeysByBindingJournalTag(
    client: KmsClient,
    bindingDigest: String,
): List<aws.sdk.kotlin.services.kms.model.KeyMetadata> =
    findKeysByBindingJournalTag(client, bindingDigest)
        .map(::requireRevocableSymmetricKeyMetadata)

private suspend fun findKeysByBindingJournalTag(
    client: KmsClient,
    bindingDigest: String,
): List<aws.sdk.kotlin.services.kms.model.KeyMetadata> {
    val matches = mutableListOf<aws.sdk.kotlin.services.kms.model.KeyMetadata>()
    var marker: String? = null
    var pages = 0
    do {
        check(++pages <= AWS_MAX_RECONCILIATION_PAGES) { "AWS KMS key reconciliation exceeded its bounded scan" }
        val response =
            client.listKeys(
                ListKeysRequest {
                    this.marker = marker
                    limit = AWS_LIST_KEYS_PAGE_SIZE
                },
            )
        response.keys.orEmpty().forEach { entry ->
            val keyId = entry.keyId ?: return@forEach
            if (keyHasBindingJournalTag(client, keyId, bindingDigest)) {
                val metadata =
                    try {
                        describeSymmetricKeyForRevocation(client, keyId)
                    } catch (_: NotFoundException) {
                        null
                    }
                if (metadata != null) matches += metadata
            }
        }
        marker =
            if (response.truncated) {
                response.nextMarker
                    ?: throw IllegalStateException("AWS KMS key reconciliation pagination is invalid")
            } else {
                null
            }
    } while (marker != null)
    return matches.distinctBy { it.arn }
}

private suspend fun keyHasBindingJournalTag(
    client: KmsClient,
    keyId: String,
    expectedBindingDigest: String,
): Boolean {
    var marker: String? = null
    var pages = 0
    do {
        check(++pages <= AWS_MAX_TAG_PAGES) { "AWS KMS tag reconciliation exceeded its bounded scan" }
        val response =
            client.listResourceTags(
                ListResourceTagsRequest {
                    this.keyId = keyId
                    this.marker = marker
                    limit = AWS_LIST_TAGS_PAGE_SIZE
                },
            )
        if (
            response.tags.orEmpty().any {
                it.tagKey == AWS_BINDING_JOURNAL_TAG_KEY &&
                    MessageDigest.isEqual(it.tagValue.encodeToByteArray(), expectedBindingDigest.encodeToByteArray())
            }
        ) {
            return true
        }
        marker =
            if (response.truncated) {
                response.nextMarker
                    ?: throw IllegalStateException("AWS KMS tag reconciliation pagination is invalid")
            } else {
                null
            }
    } while (marker != null)
    return false
}

private fun awsBindingJournalDigest(bindingAlias: String): String =
    canonicalBackendKeyIdentityDigest(
        "secret-management:aws-kms-binding-journal:v1\u0000$bindingAlias",
    )

private fun requireImmutableAwsKmsKeyArn(keyInfo: KeyInfoType<*>): String {
    val kid = keyInfo.kid ?: throw IllegalArgumentException("An immutable AWS KMS key ARN is required")
    require(keyInfo.alias == null || keyInfo.alias == kid) { "AWS KMS aliases are not accepted for attested operations" }
    require(AWS_KMS_KEY_ARN.matches(kid)) { "An immutable AWS KMS key ARN is required" }
    return kid
}

private fun requireAwsBindingAlias(bindingAlias: String): String {
    require(AWS_KMS_BINDING_ALIAS.matches(bindingAlias)) { "AWS KMS binding alias is invalid" }
    return "alias/$bindingAlias"
}

private fun awsBackendKeyIdentityDigest(
    arn: String,
    keyId: String,
): String =
    canonicalBackendKeyIdentityDigest(
        "aws-kms\u0000$arn\u0000$keyId",
    )

private fun canonicalBackendKeyIdentityDigest(value: String): String =
    "sha256:" +
        MessageDigest.getInstance("SHA-256")
            .digest(value.encodeToByteArray())
            .joinToString(separator = "") { "%02x".format(it) }

/**
 * AWS KMS does not expose an RSA PKCS#1-v1.5 versus PSS restriction in GetPublicKey. A JWK
 * synthesized from that response therefore has no authoritative `alg`; remove the historical
 * RSA inference from the policy DTO while retaining all actual family/curve/use/key_ops data.
 */
private fun ManagedKeyInfoType<*>.signingPolicyInfo(): KeyInfoType<*> {
    val dto = KeyInfo.fromDTO(this)
    return if ((dto.key as? JwkType)?.alg == null) dto.copy(signatureAlgorithm = null) else dto
}

private fun ManagedKeyInfoType<*>.verificationPolicyInfo(): KeyInfoType<*> = signingPolicyInfo()

private fun KeyInfoType<*>.requireVerificationKeyCompatible(requestedAlgorithm: SignatureAlgorithm) {
    keyCompatibilityFailure(requestedAlgorithm, KeyOperations.VERIFY)?.let { failure ->
        throw IllegalArgumentException(failure)
    }
}

internal data class AwsSymmetricKeyRevocationPlan(
    val scheduleDeletion: Boolean,
    val deleteAlias: Boolean,
)

internal fun awsSymmetricKeyRevocationPlan(state: KeyState?): AwsSymmetricKeyRevocationPlan =
    when (state) {
        KeyState.Enabled,
        KeyState.Disabled,
        -> AwsSymmetricKeyRevocationPlan(scheduleDeletion = true, deleteAlias = true)

        KeyState.PendingDeletion -> AwsSymmetricKeyRevocationPlan(scheduleDeletion = false, deleteAlias = true)
        else -> throw IllegalStateException("AWS KMS key is not in a revocable lifecycle state")
    }

internal sealed interface AwsSymmetricKeyCreationReconciliationPlan {
    data object Create : AwsSymmetricKeyCreationReconciliationPlan

    data class Reuse(
        val immutableKeyIdentity: String,
    ) : AwsSymmetricKeyCreationReconciliationPlan

    data class Reattach(
        val immutableKeyIdentity: String,
    ) : AwsSymmetricKeyCreationReconciliationPlan
}

internal fun awsSymmetricKeyCreationReconciliationPlan(
    aliasIdentity: String?,
    taggedKeyIdentities: List<String>,
): AwsSymmetricKeyCreationReconciliationPlan {
    val uniqueTaggedIdentities = taggedKeyIdentities.toSet()
    if (aliasIdentity != null) {
        require(aliasIdentity in uniqueTaggedIdentities) {
            "AWS KMS binding alias is not owned by the secret-management lifecycle"
        }
        return AwsSymmetricKeyCreationReconciliationPlan.Reuse(aliasIdentity)
    }
    return when (uniqueTaggedIdentities.size) {
        0 -> AwsSymmetricKeyCreationReconciliationPlan.Create
        1 -> AwsSymmetricKeyCreationReconciliationPlan.Reattach(uniqueTaggedIdentities.single())
        else -> throw IllegalStateException("AWS KMS binding journal is ambiguous")
    }
}

fun determineAwsKeyId(keyInfo: KeyInfoType<*>): String {
    val keyIdArg = keyInfo.alias ?: keyInfo.kid ?: throw IllegalArgumentException("KMS key reference is required")
    return if (keyInfo.alias == keyInfo.kid || keyInfo.alias == null || keyIdArg.startsWith("alias/")) keyIdArg else "alias/$keyIdArg"
}

private suspend fun AwsKmsTenantAssignmentReader.hasTenantAssignment(
    keyId: String,
    tenantId: String,
): Boolean {
    var marker: String? = null
    repeat(AWS_MAX_TENANT_ASSIGNMENT_TAG_PAGES) {
        val page = listResourceTags(keyId, marker)
        if (
            page.tags.any { (key, value) ->
                key == AWS_TENANT_ASSIGNMENT_TAG_KEY &&
                    MessageDigest.isEqual(value.encodeToByteArray(), tenantId.encodeToByteArray())
            }
        ) {
            return true
        }
        marker =
            if (page.truncated) {
                page.nextMarker ?: throw IllegalStateException("AWS KMS tag pagination is invalid")
            } else {
                null
            }
        if (marker == null) return false
    }
    throw IllegalStateException("AWS KMS tag pagination exceeded its bounded scan")
}

private fun requireAwsNativeAlias(alias: String): String {
    val normalized = if (alias.startsWith("alias/")) alias else "alias/$alias"
    require(AWS_NATIVE_ALIAS.matches(normalized)) { "AWS KMS alias is invalid" }
    return normalized
}

/**
 * AWS reports the same key as a bare key id (CreateKey, ListKeys) or as its ARN (GetPublicKey,
 * Sign). The bare key id is the kid callers persist and publish, so every path reduces to it.
 */
internal fun awsCanonicalKeyId(identity: String): String =
    if (AWS_KMS_KEY_ARN.matches(identity)) identity.substringAfterLast("key/") else identity

private fun requireAwsNativeKeyIdentity(identity: String) {
    require(AWS_KMS_KEY_ARN.matches(identity) || AWS_KMS_KEY_ID.matches(identity)) {
        "AWS KMS key identity is invalid"
    }
}

/**
 * Binds the caller's opaque AAD to AWS KMS ciphertext without disclosing the AAD itself in
 * CloudTrail or provider diagnostics. AWS authenticates the complete encryption-context map and
 * rejects decrypt requests whose digest differs.
 */
internal fun awsKmsEncryptionContext(additionalAuthenticatedData: ByteArray?): Map<String, String>? {
    if (additionalAuthenticatedData == null) return null
    val digest = MessageDigest.getInstance("SHA-256").digest(additionalAuthenticatedData)
    return try {
        mapOf(AWS_KMS_AAD_CONTEXT_KEY to "sha256:${digest.encodeToBase64Url()}")
    } finally {
        digest.fill(0)
    }
}

private const val AWS_KMS_AAD_CONTEXT_KEY: String = "sphereon-aad-digest"
private const val AWS_BINDING_JOURNAL_TAG_KEY: String = "sphereon-secret-management-binding"
private const val AWS_MINIMUM_DELETION_WINDOW_DAYS: Int = 7
private const val AWS_LIST_KEYS_PAGE_SIZE: Int = 1_000
private const val AWS_LIST_TAGS_PAGE_SIZE: Int = 50
private const val AWS_MAX_RECONCILIATION_PAGES: Int = 1_000
private const val AWS_MAX_TAG_PAGES: Int = 100
private const val AWS_MAX_TENANT_ASSIGNMENT_TAG_PAGES: Int = 100
private const val AWS_TENANT_ASSIGNMENT_TAG_KEY: String = "sphereon-tenant-id"
private val AWS_KMS_KEY_ARN =
    Regex("^arn:aws(?:-[a-z0-9-]+)?:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-fA-F-]{36}$")
private val AWS_KMS_KEY_ID = Regex("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
private val AWS_KMS_BINDING_ALIAS = Regex("^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")
private val AWS_NATIVE_ALIAS = Regex("^alias/[A-Za-z0-9/_-]{1,255}$")
