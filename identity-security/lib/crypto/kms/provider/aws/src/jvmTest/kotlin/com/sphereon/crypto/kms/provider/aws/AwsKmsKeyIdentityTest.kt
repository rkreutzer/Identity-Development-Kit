package com.sphereon.crypto.kms.provider.aws

import aws.sdk.kotlin.services.kms.KmsClient
import aws.sdk.kotlin.services.kms.model.CreateAliasRequest
import aws.sdk.kotlin.services.kms.model.CreateAliasResponse
import aws.sdk.kotlin.services.kms.model.CreateKeyRequest
import aws.sdk.kotlin.services.kms.model.CreateKeyResponse
import aws.sdk.kotlin.services.kms.model.GetPublicKeyRequest
import aws.sdk.kotlin.services.kms.model.GetPublicKeyResponse
import aws.sdk.kotlin.services.kms.model.KeyMetadata
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.kms.model.AccessKeyCredentialOpts
import com.sphereon.crypto.core.kms.model.AwsKmsClientConfig
import com.sphereon.crypto.core.kms.model.CredentialMode
import com.sphereon.crypto.core.kms.model.CredentialOpts
import com.sphereon.crypto.core.kms.model.KeyProviderConfig
import com.sphereon.crypto.core.kms.model.KeyProviderSettings
import com.sphereon.crypto.core.kms.model.KeyProviderType
import com.sphereon.crypto.core.kms.resolveManagedSigningKeySelection
import java.lang.reflect.Proxy
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class AwsKmsKeyIdentityTest {
    private val keyId = "79da999a-1b2c-4d5e-8f90-a1b2c3d4e5f6"
    private val keyArn = "arn:aws:kms:eu-central-1:123456789012:key/$keyId"
    private val alias = "tenant-aws-live-1"

    @Test
    fun canonicalKeyIdReducesArnToBareKeyId() {
        assertEquals(keyId, awsCanonicalKeyId(keyArn))
        assertEquals(keyId, awsCanonicalKeyId(keyId))
        assertEquals("alias/$alias", awsCanonicalKeyId("alias/$alias"))
    }

    @Test
    fun createdKidMatchesGetKeyAndAliasSelection() =
        runTest {
            val provider = AwsKmsCryptoProvider(settings(), fakeKmsClient())
            try {
                val created = provider.generateKeyAsync(alias, null, null, SignatureAlgorithm.ECDSA_SHA256, null)
                assertEquals(keyId, created.kid)

                assertEquals(created.kid, provider.getKey(KeyInfo<KeyType>(kid = created.kid)).kid)
                assertEquals(created.kid, provider.getKey(KeyInfo<KeyType>(kid = keyArn)).kid)
                assertEquals(created.kid, provider.getKey(KeyInfo<KeyType>(alias = alias)).kid)

                val selected =
                    provider.resolveManagedSigningKeySelection(
                        KeyInfo<KeyType>(alias = alias, kid = created.kid, providerId = provider.id),
                    )
                assertEquals(created.kid, selected.kid)
            } finally {
                provider.close()
            }
        }

    @Test fun onlyTypedMissingPublicKeyBecomesPortableAbsence() = runTest {
        val missing = aws.sdk.kotlin.services.kms.model.NotFoundException { message = "missing" }
        val provider = AwsKmsCryptoProvider(settings(), fakeKmsClient(missing))
        try {
            val error = kotlin.test.assertFailsWith<com.sphereon.core.api.error.NotFoundException> {
                provider.getKey(KeyInfo<KeyType>(alias = alias))
            }
            kotlin.test.assertSame(missing, error.cause)
        } finally { provider.close() }
    }
    @Test fun publicKeyPermissionAndTransportFailuresKeepTheirIdentity() = runTest {
        val failure = IllegalStateException("permission denied")
        val provider = AwsKmsCryptoProvider(settings(), fakeKmsClient(failure))
        try {
            val error = kotlin.test.assertFailsWith<IllegalStateException> { provider.getKey(KeyInfo<KeyType>(alias = alias)) }
            kotlin.test.assertSame(failure, error)
        } finally { provider.close() }
    }
    private fun fakeKmsClient(readFailure: RuntimeException? = null): KmsClient {
        val publicKeyDer =
            KeyPairGenerator.getInstance("EC")
                .apply { initialize(ECGenParameterSpec("secp256r1")) }
                .generateKeyPair()
                .public
                .encoded
        val aliases = mutableMapOf<String, String>()
        return Proxy.newProxyInstance(KmsClient::class.java.classLoader, arrayOf(KmsClient::class.java)) { _, method, args ->
            when (val request = args?.firstOrNull()) {
                is CreateKeyRequest -> CreateKeyResponse { keyMetadata = KeyMetadata { keyId = this@AwsKmsKeyIdentityTest.keyId; arn = keyArn } }
                is CreateAliasRequest -> {
                    aliases[request.aliasName!!] = request.targetKeyId!!
                    CreateAliasResponse {}
                }
                is GetPublicKeyRequest -> {
                    readFailure?.let { throw it }
                    val reference = request.keyId!!
                    require(reference == keyId || reference == keyArn || aliases[reference] == keyId) { "Unknown key $reference" }
                    GetPublicKeyResponse {
                        keyId = keyArn
                        publicKey = publicKeyDer
                    }
                }
                else ->
                    when (method.name) {
                        "close" -> Unit
                        "toString" -> "FakeKmsClient"
                        "hashCode" -> 0
                        "equals" -> false
                        else -> throw UnsupportedOperationException(method.name)
                    }
            }
        } as KmsClient
    }

    private fun settings() =
        KeyProviderSettings(
            id = "aws-identity-test",
            config =
                KeyProviderConfig(
                    type = KeyProviderType.AWS_KMS,
                    aws =
                        AwsKmsClientConfig(
                            region = "eu-central-1",
                            credentialOpts =
                                CredentialOpts(
                                    credentialMode = CredentialMode.ACCESS_KEY,
                                    accessKeyCredentialOpts =
                                        AccessKeyCredentialOpts(
                                            credentialsSecretId = "test-credentials",
                                            accessKeyId = "test-access-key",
                                            secretAccessKey = "test-secret-key",
                                        ),
                                ),
                        ),
                ),
        )
}
