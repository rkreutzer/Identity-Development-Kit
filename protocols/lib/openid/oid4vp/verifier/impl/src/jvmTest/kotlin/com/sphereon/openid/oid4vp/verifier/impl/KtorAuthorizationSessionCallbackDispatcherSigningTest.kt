package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.OpaqueSecretResolver
import com.sphereon.core.api.http.callback.CallbackSigning
import com.sphereon.core.api.http.callback.CallbackSigningAlgorithm
import com.sphereon.ktor.http.client.provider.HttpClientEngineType
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.verifier.callback.AuthorizationSessionCallbackSigning
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import kotlinx.coroutines.test.runTest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Signed delivery through the real dispatcher, checked by a receiver-side HMAC computed with the
 * JDK rather than with the production primitive. The signed overload is not used by the session
 * store, which sends callbacks unsigned; it stays covered for implementers that call it directly.
 */
class KtorAuthorizationSessionCallbackDispatcherSigningTest {
    private val status = GetAuthorizationRequestStatusOutput(
        correlationId = "callback-signing-correlation",
        status = AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED,
        lastUpdated = 1_800_000_000_000L,
    )

    @Test
    fun shouldSignTheSentBytesWithAnHmacAnIndependentReceiverCanVerify() = runTest {
        val secret = "callback-hmac-test-secret"
        var sentBody: ByteArray? = null
        var signature: String? = null
        val engine = MockEngine { request ->
            sentBody = (request.body as OutgoingContent.ByteArrayContent).bytes()
            signature = request.headers[CallbackSigning.SIGNATURE_HEADER]
            respond("", HttpStatusCode.OK)
        }
        try {
            val result = KtorAuthorizationSessionCallbackDispatcher(MockTransport(engine), OpaqueSecretResolver { Ok(secret) }).dispatch(
                "https://receiver.example.com/oid4vp",
                status,
                AuthorizationSessionCallbackSigning("secret-ref", CallbackSigningAlgorithm.HMAC_SHA256),
            )
            assertTrue(result.isOk)
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(secret.encodeToByteArray(), "HmacSHA256"))
            val expected = mac.doFinal(sentBody).joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
            assertEquals("${CallbackSigning.HMAC_SHA256_PREFIX}$expected", signature)
        } finally {
            engine.close()
        }
    }

    @Test
    fun shouldFailBeforeHttpWhenTheSecretResolverThrows() = runTest {
        var requests = 0
        val engine = MockEngine {
            requests++
            respond("", HttpStatusCode.OK)
        }
        try {
            val result = KtorAuthorizationSessionCallbackDispatcher(
                MockTransport(engine),
                OpaqueSecretResolver { throw IllegalStateException("secret resolver detail") },
            ).dispatch(
                "https://receiver.example.com/oid4vp",
                status,
                AuthorizationSessionCallbackSigning("secret-ref", CallbackSigningAlgorithm.HMAC_SHA256),
            )
            assertTrue(result.isErr)
            assertEquals(0, requests)
        } finally {
            engine.close()
        }
    }

    @Test
    fun shouldReportAFailingClientFactoryAsAFailedDeliveryWithoutItsDetail() = runTest {
        val factory = object : HttpClientFactory {
            override fun createClient(options: HttpClientOptions): HttpClient = throw IllegalStateException("factory detail")
            override fun isSupportedOptions(options: HttpClientOptions): Boolean = true
            override fun getEngineTypesSupported(): List<HttpClientEngineType> = emptyList()
            override fun getEngineTypeDefault(): HttpClientEngineType = error("Engine metadata is not used by this test")
        }
        val result = KtorAuthorizationSessionCallbackDispatcher(factory).dispatch("https://receiver.example.com/oid4vp", status)

        assertTrue(result.isErr)
        result.getOrElse { error -> assertFalse(error.message.defaultMessage.contains("factory detail")) }
    }

    private class MockTransport(private val engine: MockEngine) : HttpClientFactory {
        override fun createClient(options: HttpClientOptions): HttpClient = HttpClient(engine) {
            expectSuccess = false
            followRedirects = options.followRedirects
            if (options.enableContentNegotiation) {
                install(ContentNegotiation) { options.contentNegotiationConfig?.invoke(this) }
            }
            options.additionalConfig?.invoke(this)
        }

        override fun isSupportedOptions(options: HttpClientOptions): Boolean = true
        override fun getEngineTypesSupported(): List<HttpClientEngineType> = emptyList()
        override fun getEngineTypeDefault(): HttpClientEngineType = error("Engine metadata is not used by this test")
    }
}
