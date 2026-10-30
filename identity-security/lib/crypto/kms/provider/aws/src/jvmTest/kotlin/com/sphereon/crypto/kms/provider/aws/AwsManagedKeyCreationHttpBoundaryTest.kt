package com.sphereon.crypto.kms.provider.aws

import aws.sdk.kotlin.runtime.auth.credentials.StaticCredentialsProvider
import aws.sdk.kotlin.services.kms.KmsClient
import aws.smithy.kotlin.runtime.net.url.Url
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.kms.*
import com.sphereon.crypto.core.kms.model.*
import com.sun.net.httpserver.HttpServer
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.*
import java.net.InetSocketAddress
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.*

/** Actual SDK serialization, SigV4, HTTP transport and retry pipeline against a bounded local fixture. */
class AwsManagedKeyCreationHttpBoundaryTest {
    @Test fun transientCreateResponseIsNeverRetriedAndScopedClosePreservesTheOwningClient() = runBlocking {
        withTimeout(30_000) {
            val creates = AtomicInteger(); val claimCalls = AtomicInteger()
            val operations = CopyOnWriteArrayList<String>(); val errors = CopyOnWriteArrayList<String>()
            var state = ManagedKeyCreationAttemptState.UNCLAIMED
            var creationTags: JsonArray? = null
            val publicDer = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair().public.encoded
            val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
            server.createContext("/") { exchange ->
                try {
                    val authorization = exchange.requestHeaders.getFirst("Authorization") ?: error("Unsigned SDK request")
                    check(authorization.contains("Credential=test/") && authorization.contains("/eu-central-1/kms/"))
                    val operation = exchange.requestHeaders.getFirst("X-Amz-Target")?.substringAfterLast('.') ?: error("Missing SDK target")
                    operations += operation
                    val input = Json.parseToJsonElement(exchange.requestBody.use { it.readBytes().toString(Charsets.UTF_8) }).jsonObject
                    val response: JsonObject = when (operation) {
                        "CreateKey" -> {
                            creates.incrementAndGet(); creationTags = input["Tags"]!!.jsonArray
                            buildJsonObject { put("__type", "KMSInternalException"); put("message", "persisted before transient response") }
                        }
                        "ListKeys" -> buildJsonObject { put("Keys", buildJsonArray { add(buildJsonObject { put("KeyId", KEY); put("KeyArn", ARN) }) }); put("Truncated", false) }
                        "ListResourceTags" -> buildJsonObject { put("Tags", requireNotNull(creationTags)); put("Truncated", false) }
                        "DescribeKey" -> buildJsonObject { put("KeyMetadata", buildJsonObject {
                            put("KeyId", KEY); put("Arn", ARN); put("Enabled", true); put("KeyState", "Enabled"); put("KeySpec", "ECC_NIST_P256")
                            put("KeyUsage", "SIGN_VERIFY"); put("Origin", "AWS_KMS"); put("KeyManager", "CUSTOMER")
                        }) }
                        "GetPublicKey" -> buildJsonObject {
                            put("KeyId", ARN); put("PublicKey", Base64.getEncoder().encodeToString(publicDer)); put("KeySpec", "ECC_NIST_P256"); put("KeyUsage", "SIGN_VERIFY")
                        }
                        else -> error("Unexpected SDK operation")
                    }
                    val output = response.toString().encodeToByteArray()
                    exchange.responseHeaders.add("Content-Type", "application/x-amz-json-1.1")
                    exchange.responseHeaders.add("x-amzn-RequestId", "durable-http-fixture")
                    exchange.sendResponseHeaders(if (operation == "CreateKey") 503 else 200, output.size.toLong())
                    exchange.responseBody.use { it.write(output) }
                } catch (failure: Throwable) {
                    errors += failure::class.simpleName + ":" + failure.message
                    runCatching { exchange.sendResponseHeaders(500, -1) }
                } finally { exchange.close() }
            }
            server.start()
            try {
            val credentials = StaticCredentialsProvider { accessKeyId = "test"; secretAccessKey = "test" }
            val client = KmsClient {
                region = "eu-central-1"; credentialsProvider = credentials
                endpointUrl = Url.parse("http://127.0.0.1:${server.address.port}")
                retryStrategy { maxAttempts = 3 }
            }
            val provider = AwsKmsCryptoProvider(settings(), client)
            fun attempt() = ManagedKeyCreationAttempt(PROVIDER, ALIAS, TOKEN, readState = { state }, claim = {
                claimCalls.incrementAndGet()
                if (state != ManagedKeyCreationAttemptState.UNCLAIMED) false else { state = ManagedKeyCreationAttemptState.CLAIMED; true }
            }, recover = { state == ManagedKeyCreationAttemptState.CLAIMED })
            try {
                assertEquals(3, client.config.retryStrategy.config.maxAttempts)
                assertFails { withContext(attempt()) { provider.generateKeyAsync(ALIAS, null, null, ALG, null) } }
                assertEquals(1, creates.get(), "The actual SDK must not retry the claimed CreateKey on HTTP503")
                assertEquals(1, claimCalls.get())
                assertEquals(TOKEN, creationTags!!.single { it.jsonObject["TagKey"]?.jsonPrimitive?.content == MANAGED_OPERATION_TAG }.jsonObject["TagValue"]!!.jsonPrimitive.content)
                val receipt = withContext(attempt()) { provider.generateKeyAsync(ALIAS, null, null, ALG, null) }
                assertEquals(KEY, receipt.kid); assertEquals(1, creates.get()); assertEquals(1, claimCalls.get())
                assertTrue(operations.containsAll(listOf("ListKeys", "ListResourceTags", "DescribeKey", "GetPublicKey")))
                // The single-attempt clone has already closed. This still uses the original
                // client's credentials, endpoint, signer and shared HTTP engine successfully.
                assertEquals(KEY, provider.getKey(KeyInfo<KeyType>(kid = KEY)).kid)
                assertEquals(emptyList(), errors.toList())
            } finally { provider.close() }
            } finally { server.stop(0) }
        }
    }
    private fun settings() = KeyProviderSettings(id = PROVIDER, config = KeyProviderConfig(type = KeyProviderType.AWS_KMS,
        aws = AwsKmsClientConfig(region = "eu-central-1", credentialOpts = CredentialOpts(credentialMode = CredentialMode.ACCESS_KEY,
            accessKeyCredentialOpts = AccessKeyCredentialOpts(credentialsSecretId = "test", accessKeyId = "test", secretAccessKey = "test")))))
    private companion object {
        const val PROVIDER = "aws-managed-http-test"; const val ALIAS = "durable-http-operation"
        const val KEY = "79da999a-1b2c-4d5e-8f90-a1b2c3d4e5f6"
        const val ARN = "arn:aws:kms:eu-central-1:123456789012:key/$KEY"
        const val TOKEN = "7da57c97-ec4c-43c1-8b9c-4d2b51822cd6"
        val ALG = SignatureAlgorithm.ECDSA_SHA256
    }
}
