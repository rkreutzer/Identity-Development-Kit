package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.ktor.http.client.provider.HttpClientEngineType
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vc.common.CredentialFormat
import com.sphereon.openid.oid4vp.common.vpTokenOf
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.universal.VerifiedDataMode
import com.sphereon.openid.oid4vp.universal.VerifiedDataOpts
import com.sphereon.openid.oid4vp.universal.universalOid4vpResponseJson
import com.sphereon.openid.oid4vp.verifier.MatchedCredential
import com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse
import com.sphereon.openid.oid4vp.verifier.ValidationResult
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionCallbackConfig
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionError
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.http.HttpStatusCode
import io.ktor.http.content.OutgoingContent
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * The real session store, mapper and HTTP dispatcher with only the receiver replaced. Every posted
 * body is compared with the status response the status API builds for the same persisted session,
 * and the wire keys are asserted by hand so that a defect shared by the callback and the status
 * response cannot make the two agree on a wrong answer.
 */
class AuthorizationSessionCallbackParityTest {
    private val wire = universalOid4vpResponseJson
    private val mapper = AuthorizationSessionStatusResponseMapperImpl()

    @Test
    fun shouldPostTheStatusResponseOfEachTransitionAndNothingMore() = runTest {
        val rig = Rig()
        try {
            val id = "parity-lifecycle"
            val claimsOnly = VerifiedDataOpts(listOf(VerifiedDataMode.CREDENTIAL_CLAIMS_DESERIALIZED))
            rig.store.put(id, callbackSession(id, claimsOnly), 600)
            rig.store.updateStatus(id, AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED)
            rig.store.storeResponse(id, parsedResponse(id))
            val storedVerified = rig.store.storeValidationResult(id, validResult()).getOrElse { error("validation failed: $it") }

            assertEquals(4, rig.posted.size)
            rig.posted.dropLast(1).forEach { body -> assertFalse(body.containsKey("verified_data")) }
            val verified = rig.posted.last()
            assertEquals("authorization_response_verified", verified.getValue("status").toString().trim('"'))
            assertEquals(setOf("credential_claims"), verified.getValue("verified_data").jsonObject.keys)
            for (legacyKey in listOf("correlationId", "updatedAt", "errorCode", "errorMessage")) {
                assertFalse(verified.containsKey(legacyKey))
            }
            assertEquals(id, verified.getValue("correlation_id").toString().trim('"'))
            assertEquals(storedVerified.updatedAt.toString(), verified.getValue("last_updated").toString())

            val polled = pollingBody(rig, id)
            assertEquals(polled - "verified_data", verified - "verified_data", "everything but verified data equals the status API body")
            val polledData = polled.getValue("verified_data").jsonObject
            assertEquals(setOf("credential_claims", "authorization_response"), polledData.keys, "polling offers both representations")
            assertEquals(polledData.getValue("credential_claims"), verified.getValue("verified_data").jsonObject.getValue("credential_claims"))
        } finally {
            rig.close()
        }
    }

    @Test
    fun shouldSelectTheRepresentationsOfEveryModeSubsetOnTheWire() = runTest {
        for (mask in 0 until (1 shl VerifiedDataMode.entries.size)) {
            val modes = VerifiedDataMode.entries.filterIndexed { index, _ -> mask and (1 shl index) != 0 }
            val rig = Rig()
            try {
                val id = "parity-modes-$mask"
                rig.store.put(id, callbackSession(id, VerifiedDataOpts(modes)).withStatuses(AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED), 600)
                rig.store.updateStatus(id, AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED)
                rig.store.storeResponse(id, parsedResponse(id))
                rig.store.storeValidationResult(id, validResult())

                val body = rig.posted.single()
                val keys = (body["verified_data"] as? JsonObject)?.keys.orEmpty()
                val expected = buildSet {
                    if (VerifiedDataMode.CREDENTIAL_CLAIMS_DESERIALIZED in modes) add("credential_claims")
                    if (VerifiedDataMode.AUTHORIZATION_RESPONSE in modes || VerifiedDataMode.VP_TOKEN in modes) add("authorization_response")
                }
                assertEquals(expected, keys, "modes $modes")
                assertEquals(expected.isNotEmpty(), body.containsKey("verified_data"), "modes $modes")
                assertFalse(body["verified_data"] is JsonNull)
            } finally {
                rig.close()
            }
        }
    }

    @Test
    fun shouldPostTheErrorTheStatusApiShowsAndNoVerifiedData() = runTest {
        val rig = Rig()
        try {
            val id = "parity-error"
            rig.store.put(id, callbackSession(id, VerifiedDataOpts(VerifiedDataMode.entries.toList())).withStatuses(AuthorizationSessionStatus.ERROR), 600)
            rig.store.updateStatus(id, AuthorizationSessionStatus.ERROR, AuthorizationSessionError("invalid_request", "bad response"))

            val body = rig.posted.single()
            assertEquals("error", body.getValue("status").toString().trim('"'))
            assertEquals("invalid_request", body.getValue("error").jsonObject.getValue("code").toString().trim('"'))
            assertEquals(id, body.getValue("correlation_id").toString().trim('"'))
            assertTrue(body.containsKey("last_updated"))
            assertFalse(body.containsKey("verified_data"))
            assertEquals(pollingBody(rig, id) - "verified_data", body - "verified_data")
        } finally {
            rig.close()
        }
    }

    private suspend fun pollingBody(rig: Rig, id: String): JsonObject {
        val session = rig.store.get(id).getOrElse { error("read failed: $it") }!!
        val status = mapper.build(session, VerifiedDataMode.entries.toList())
        return wire.encodeToJsonElement(GetAuthorizationRequestStatusOutput.serializer(), status).jsonObject
    }

    private fun AuthorizationSession.withStatuses(vararg statuses: AuthorizationSessionStatus) =
        copy(callback = callback!!.copy(statuses = statuses.toList()))

    private fun callbackSession(id: String, options: VerifiedDataOpts?): AuthorizationSession {
        val now = Clock.System.now().toEpochMilliseconds()
        return AuthorizationSession(
            instanceId = "parity-instance",
            sessionId = "parity-session-$id",
            correlationId = id,
            queryId = "parity-query",
            dcqlQuery = DcqlQuery(
                credentials = listOf(DcqlCredentialQuery(id = "identity_credential", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
            ),
            authorizationRequest = AuthorizationRequest(
                clientId = "https://verifier.example.com",
                redirectUri = "https://verifier.example.com/callback",
                state = id,
            ),
            status = AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED,
            callback = AuthorizationSessionCallbackConfig(url = "https://receiver.example.com/cb", verifiedData = options),
            createdAt = now,
            updatedAt = now,
            expiresAt = now + 600_000,
        )
    }

    private fun parsedResponse(id: String) =
        ParsedAuthorizationResponse(
            vpToken = vpTokenOf("identity_credential", "presentation"),
            rawVpToken = "{\"identity_credential\":[\"presentation\"]}",
            state = id,
        )

    private fun validResult() =
        ValidationResult(
            valid = true,
            matchedCredentials = listOf(
                MatchedCredential(
                    credentialQueryId = "identity_credential",
                    credentialFormat = CredentialFormat.SD_JWT_VC,
                    presentation = "presentation",
                    disclosedClaims = mapOf("given_name" to "Ada"),
                ),
            ),
        )

    private inner class Rig {
        val posted = mutableListOf<JsonObject>()
        private val engine = MockEngine { request ->
            posted += Json.parseToJsonElement((request.body as OutgoingContent.ByteArrayContent).bytes().decodeToString()).jsonObject
            respond("", HttpStatusCode.OK)
        }
        private val transport = object : HttpClientFactory {
            override fun createClient(options: HttpClientOptions): HttpClient = HttpClient(engine) {
                expectSuccess = false
                followRedirects = options.followRedirects
                if (options.enableContentNegotiation) {
                    install(ContentNegotiation) { options.contentNegotiationConfig?.invoke(this) }
                }
            }

            override fun isSupportedOptions(options: HttpClientOptions): Boolean = true
            override fun getEngineTypesSupported(): List<HttpClientEngineType> = emptyList()
            override fun getEngineTypeDefault(): HttpClientEngineType = error("Engine metadata is not used by this test")
        }
        val store = KvAuthorizationSessionStore(
            kvStoreManager = KvStoreTestKvStoreManager(Clock.System),
            kvStoreService = KvStoreTestNoOpKvStoreService(),
            dcqlQueryConfigurationStore = KvStoreTestNoOpDcqlQueryConfigurationStore(),
            callbackDispatcher = KtorAuthorizationSessionCallbackDispatcher(transport),
            statusResponseMapper = mapper,
            appLogManager = KvStoreTestAppLogManager(),
            execution = KvStoreTestSessionExecution(),
            clock = Clock.System,
        )

        fun close() = engine.close()
    }
}
