package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.ktor.http.client.provider.HttpClientEngineType
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.core.api.conf.OpaqueSecretResolver
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.universal.VerifiedClaimsValue
import com.sphereon.openid.oid4vp.universal.VerifiedData
import com.sphereon.openid.oid4vp.verifier.callback.AuthorizationSessionCallbackSigning
import com.sphereon.openid.oid4vp.verifier.callback.AuthorizationSessionCallbackDispatcher
import com.sphereon.core.api.Ok
import com.sphereon.core.api.http.callback.CallbackSigningAlgorithm
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.core.api.http.callback.CallbackSigning
import com.sphereon.openid.oid4vc.common.SessionError
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import io.ktor.http.headersOf
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Real callback dispatcher with only the remote HTTP transport replaced. */
class KtorAuthorizationSessionCallbackDispatcherTest {
    private val update = GetAuthorizationRequestStatusOutput(
        correlationId = "callback-correlation-42",
        status = AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED,
        lastUpdated = 1_800_000_000_000L,
    )

    @Test
    fun successfulHttpAcknowledgementIsRequiredForDeliverySuccess() = runTest {
        for (code in listOf(200, 202, 204)) {
            var requests = 0
            val factory = TransportFactory(MockEngine { request ->
                requests++
                assertEquals(HttpMethod.Post, request.method)
                assertEquals("https://receiver.example.com/oid4vp", request.url.toString())
                respond("", HttpStatusCode.fromValue(code))
            })
            try {
                val result = KtorAuthorizationSessionCallbackDispatcher(factory)
                    .dispatch("https://receiver.example.com/oid4vp", update)
                assertTrue(result.isOk, "HTTP $code must acknowledge the delivery")
                assertEquals(1, requests)
            } finally {
                factory.close()
            }
        }
    }

    @Test
    fun shouldPostTheStatusResponseUnderTheSpecificationFieldNames() = runTest {
        val body = postedBody(update.copy(sessionId = "session-1", createdAt = 1L, expiresAt = 9L))

        assertEquals("callback-correlation-42", body.getValue("correlation_id").jsonPrimitive.content)
        assertEquals("authorization_response_verified", body.getValue("status").jsonPrimitive.content)
        assertEquals(1_800_000_000_000L, body.getValue("last_updated").jsonPrimitive.long)
        assertEquals("session-1", body.getValue("session_id").jsonPrimitive.content)
        for (legacyKey in listOf("correlationId", "updatedAt", "errorCode", "errorMessage")) {
            assertFalse(body.containsKey(legacyKey), "the previous camelCase body key $legacyKey must not be sent")
        }
    }

    @Test
    fun shouldOmitVerifiedDataWhenTheStatusCarriesNone() = runTest {
        assertFalse(postedBody(update).containsKey("verified_data"))
    }

    @Test
    fun shouldOmitTheVerifiedDataMembersThatWereNotSelected() = runTest {
        val claims = VerifiedClaimsValue(id = "passport", type = "urn:test:passport")
        val claimsOnly = postedBody(update.copy(verifiedData = VerifiedData(credentialClaims = listOf(claims))))
            .getValue("verified_data").jsonObject
        assertEquals(setOf("credential_claims"), claimsOnly.keys)

        val responseOnly = postedBody(
            update.copy(verifiedData = VerifiedData(authorizationResponse = JsonObject(mapOf("state" to JsonPrimitive("s"))))),
        ).getValue("verified_data").jsonObject
        assertEquals(setOf("authorization_response"), responseOnly.keys)

        val both = postedBody(
            update.copy(
                verifiedData = VerifiedData(
                    credentialClaims = listOf(claims),
                    authorizationResponse = JsonObject(mapOf("state" to JsonPrimitive("s"))),
                ),
            ),
        ).getValue("verified_data").jsonObject
        assertEquals(setOf("credential_claims", "authorization_response"), both.keys)
    }

    @Test
    fun shouldSendTheStructuredErrorTheStatusApiShows() = runTest {
        val error = SessionError(code = "invalid_request", message = "bad response")
        val body = postedBody(update.copy(status = AuthorizationSessionStatus.ERROR, error = error))

        assertEquals("error", body.getValue("status").jsonPrimitive.content)
        assertEquals("invalid_request", body.getValue("error").jsonObject.getValue("code").jsonPrimitive.content)
        assertEquals("bad response", body.getValue("error").jsonObject.getValue("message").jsonPrimitive.content)
    }

    @Test
    fun shouldPostJsonWithoutSigningHeadersWhenUnsigned() = runTest {
        var contentType: String? = null
        var signature: String? = null
        val factory = TransportFactory(MockEngine { request ->
            contentType = request.body.contentType?.withoutParameters()?.toString()
            signature = request.headers[CallbackSigning.SIGNATURE_HEADER]
            respond("", HttpStatusCode.OK)
        })
        try {
            KtorAuthorizationSessionCallbackDispatcher(factory).dispatch("https://receiver.example.com/oid4vp", update)
            assertEquals("application/json", contentType)
            assertEquals(null, signature)
        } finally {
            factory.close()
        }
    }

    @Test
    fun receiverHttpErrorsAreNotReportedAsSuccessfulDelivery() = runTest {
        for (code in listOf(400, 401, 403, 429, 500, 503)) {
            val factory = TransportFactory(MockEngine { respond("not accepted", HttpStatusCode.fromValue(code)) })
            try {
                val result = KtorAuthorizationSessionCallbackDispatcher(factory)
                    .dispatch("https://receiver.example.com/oid4vp", update)
                assertTrue(result.isErr, "HTTP $code must not become CALLBACK_DISPATCHED")
            } finally {
                factory.close()
            }
        }
    }

    @Test
    fun redirectIsNotAnAcknowledgementAndCannotForwardTheCallback() = runTest {
        val destinations = mutableListOf<String>()
        val factory = TransportFactory(MockEngine { request ->
            destinations += request.url.toString()
            if (request.url.host == "receiver.example.com") {
                respond("", HttpStatusCode.TemporaryRedirect, headersOf("Location", "https://unexpected.example.com/collect"))
            } else {
                respond("", HttpStatusCode.OK)
            }
        })
        try {
            val result = KtorAuthorizationSessionCallbackDispatcher(factory)
                .dispatch("https://receiver.example.com/oid4vp", update)
            assertTrue(result.isErr, "redirects must not count as destination acknowledgement")
            assertEquals(listOf("https://receiver.example.com/oid4vp"), destinations)
        } finally {
            factory.close()
        }
    }

    @Test
    fun coroutineCancellationIsNotConvertedIntoCallbackFailure() = runTest {
        val factory = TransportFactory(MockEngine { throw CancellationException("cancel callback delivery") })
        try {
            assertFailsWith<CancellationException> {
                KtorAuthorizationSessionCallbackDispatcher(factory)
                    .dispatch("https://receiver.example.com/oid4vp", update)
            }
        } finally {
            factory.close()
        }
    }

    @Test
    fun transportFailureDoesNotExposeTransportSecretsInThePublicErrorMessage() = runTest {
        val marker = "transport-secret-do-not-publish"
        val factory = TransportFactory(MockEngine { throw IllegalStateException(marker) })
        try {
            val result = KtorAuthorizationSessionCallbackDispatcher(factory)
                .dispatch("https://receiver.example.com/oid4vp", update)
            assertTrue(result.isErr)
            result.getOrElse { error ->
                assertFalse(error.message.defaultMessage.contains(marker))
            }
        } finally {
            factory.close()
        }
    }

    @Test
    fun signedDeliveryWithoutSecretFailsBeforeHttp() = runTest {
        var requests = 0
        val factory = TransportFactory(MockEngine {
            requests++
            respond("", HttpStatusCode.OK)
        })
        try {
            for (secretRef in listOf<String?>(null, "   ")) {
                val result = KtorAuthorizationSessionCallbackDispatcher(factory).dispatch(
                    "https://receiver.example.com/oid4vp",
                    update,
                    AuthorizationSessionCallbackSigning(
                        secretRef = secretRef,
                        algorithm = CallbackSigningAlgorithm.HMAC_SHA256,
                    ),
                )
                assertTrue(result.isErr)
            }
            assertEquals(0, requests)
            assertEquals(0, factory.createdClients.size)
        } finally {
            factory.close()
        }
    }

    @Test
    fun resolvedEmptySecretFailsBeforeHttp() = runTest {
        var requests = 0
        val factory = TransportFactory(MockEngine {
            requests++
            respond("", HttpStatusCode.OK)
        })
        try {
            val result = KtorAuthorizationSessionCallbackDispatcher(
                factory,
                OpaqueSecretResolver { Ok("") },
            ).dispatch(
                "https://receiver.example.com/oid4vp",
                update,
                AuthorizationSessionCallbackSigning("secret-ref", CallbackSigningAlgorithm.HMAC_SHA256),
            )
            assertTrue(result.isErr)
            assertEquals(0, requests)
            assertEquals(0, factory.createdClients.size)
        } finally {
            factory.close()
        }
    }

    @Test
    fun legacyDispatcherDelegatesUnsignedAndRejectsSignedOverload() = runTest {
        var legacyCalls = 0
        val legacy = object : AuthorizationSessionCallbackDispatcher {
            override suspend fun dispatch(
                url: String,
                update: GetAuthorizationRequestStatusOutput,
            ) = Ok(Unit).also { legacyCalls++ }
        }

        val signed = legacy.dispatch(
            "https://receiver.example.com/oid4vp",
            update,
            AuthorizationSessionCallbackSigning("secret-ref", CallbackSigningAlgorithm.HMAC_SHA256),
        )
        assertTrue(signed.isErr)
        assertEquals(0, legacyCalls)

        val unsigned = legacy.dispatch("https://receiver.example.com/oid4vp", update, null)
        assertTrue(unsigned.isOk)
        assertEquals(1, legacyCalls)
    }

    @Test
    fun factoryCreatedClientIsClosedAfterCompletionFailureAndCancellation() = runTest {
        data class OwnershipCase(
            val name: String,
            val cancellation: Boolean,
        )

        for (case in listOf(
            OwnershipCase("normal completion", cancellation = false),
            OwnershipCase("transport failure", cancellation = false),
            OwnershipCase("cancellation", cancellation = true),
        )) {
            val engine = MockEngine {
                if (case.cancellation) {
                    throw CancellationException("cancel callback delivery")
                }
                if (case.name == "transport failure") {
                    throw IllegalStateException("transport failure")
                }
                respond("", HttpStatusCode.OK)
            }
            val factory = TransportFactory(engine)
            try {
                if (case.cancellation) {
                    assertFailsWith<CancellationException> {
                        KtorAuthorizationSessionCallbackDispatcher(factory)
                            .dispatch("https://receiver.example.com/oid4vp", update)
                    }
                } else {
                    val result = KtorAuthorizationSessionCallbackDispatcher(factory)
                        .dispatch("https://receiver.example.com/oid4vp", update)
                    if (case.name == "normal completion") {
                        assertTrue(result.isOk)
                    } else {
                        assertTrue(result.isErr)
                    }
                }

                val client = factory.createdClients.single()
                assertFalse(
                    client.coroutineContext[Job]!!.isActive,
                    "the factory-created client must be closed after ${case.name}",
                )
            } finally {
                // Deliberately leave clients untouched: this test observes dispatcher ownership.
                factory.closeEngineOnly()
            }
        }
    }

    private suspend fun postedBody(status: GetAuthorizationRequestStatusOutput): JsonObject {
        var posted: ByteArray? = null
        val factory = TransportFactory(MockEngine { request ->
            posted = (request.body as OutgoingContent.ByteArrayContent).bytes()
            respond("", HttpStatusCode.OK)
        })
        try {
            val result = KtorAuthorizationSessionCallbackDispatcher(factory)
                .dispatch("https://receiver.example.com/oid4vp", status)
            assertTrue(result.isOk)
        } finally {
            factory.close()
        }
        return Json.parseToJsonElement(posted!!.decodeToString()).jsonObject
    }

    private class TransportFactory(private val engine: MockEngine) : HttpClientFactory {
        private val clients = mutableListOf<HttpClient>()

        val createdClients: List<HttpClient>
            get() = clients.toList()

        override fun createClient(options: HttpClientOptions): HttpClient = HttpClient(engine) {
            // Deliberately do not throw for HTTP errors: the dispatcher owns acknowledgement.
            expectSuccess = false
            followRedirects = options.followRedirects
            if (options.enableContentNegotiation) {
                install(ContentNegotiation) { options.contentNegotiationConfig?.invoke(this) }
            }
            options.additionalConfig?.invoke(this)
            followRedirects = options.followRedirects
        }.also(clients::add)

        override fun isSupportedOptions(options: HttpClientOptions): Boolean = true
        override fun getEngineTypesSupported(): List<HttpClientEngineType> = emptyList()
        override fun getEngineTypeDefault(): HttpClientEngineType = error("Engine metadata is not used by this test")

        fun close() {
            clients.forEach(HttpClient::close)
            engine.close()
        }

        fun closeEngineOnly() {
            engine.close()
        }
    }
}
