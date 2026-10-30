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
 */

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.openid.oid4vp.verifier.store.AuthorizationSessionStore

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.ConfigService
import com.sphereon.core.api.context.ContextConfig
import com.sphereon.core.api.context.IdkScope
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.log.AbstractLogManager
import com.sphereon.core.api.log.AppLogManager
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.data.store.kv.InMemoryKvStoreConfig
import com.sphereon.data.store.kv.KvEntry
import com.sphereon.data.store.kv.KvEntryMetadata
import com.sphereon.data.store.kv.KvNamespace
import com.sphereon.data.store.kv.KvNamespaceId
import com.sphereon.data.store.kv.KvPutResult
import com.sphereon.data.store.kv.KvStore
import com.sphereon.data.store.kv.KvStoreVersioning
import com.sphereon.data.store.kv.KvVersionAppendResult
import com.sphereon.data.store.kv.KvVersionedEntry
import com.sphereon.data.store.kv.KvStoreConfigBase
import com.sphereon.data.store.kv.KvStoreScopeBinding
import com.sphereon.data.store.kv.impl.KvStoreManager
import com.sphereon.data.store.kv.impl.KvStoreService
import com.sphereon.data.store.kv.memory.InMemoryKvBackingStorageImpl
import com.sphereon.data.store.kv.memory.InMemoryKvStoreFactoryImpl
import com.sphereon.di.context.NoOpSessionContext
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionContextManager
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.openid.oid4vp.common.store.StoredEntry
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.dcql.store.DcqlQueryConfigurationStore
import com.sphereon.openid.oid4vp.dcql.store.model.DcqlQueryConfiguration
import com.sphereon.openid.oid4vp.verifier.callback.AuthorizationSessionCallbackDispatcher
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.universal.VerifiedDataMode
import com.sphereon.openid.oid4vp.universal.VerifiedDataOpts
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionCallbackConfig
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejection
import com.sphereon.openid.oid4vp.verifier.CredentialValidationRejectionReason
import com.sphereon.openid.oid4vp.verifier.ValidationResult
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.time.Clock
import kotlin.time.Duration
import kotlin.time.Instant

/**
 * Regression coverage for [KvAuthorizationSessionStore]: unlike [TestAuthorizationSessionStore]
 * (an in-memory map that stores the [AuthorizationSession] object BY REFERENCE and therefore
 * cannot catch a missing field in the persistence entry's mapping), this drives the REAL store
 * through its internal [KvAuthorizationSessionStore.AuthorizationSessionEntry] DTO — a genuine
 * encode/decode round trip via the same [com.sphereon.data.store.kv.KotlinxSerializationJsonKvCodec]
 * production code uses. It exists specifically to catch the class of bug where a new
 * [AuthorizationSession] field is added but never threaded through the entry's constructor,
 * `toPublic()`, or `put()` mapping.
 */
class KvAuthorizationSessionStoreTest {
    @Test
    fun nestedDisclosedClaimsSurviveThePersistedValidationRoundTrip() = runTest {
        val store = createStore()
        val correlation = "structured-claims-roundtrip"
        assertEquals(true, store.put(correlation, session(null, correlation), 600).isOk)
        val objectClaim = Json.parseToJsonElement("""{"personal_care":true,"detail":{"level":1}}""")
        val arrayClaim = Json.parseToJsonElement("""[1,false,null]""")
        val matched = com.sphereon.openid.oid4vp.verifier.MatchedCredential(
            credentialQueryId = "achievement", credentialFormat = com.sphereon.openid.oid4vc.common.CredentialFormat.SD_JWT_VC,
            presentation = "verified-presentation", disclosedClaims = mapOf("outcomes" to objectClaim, "items" to arrayClaim, "reference" to "001", "text" to "true"),
        )
        assertEquals(true, store.storeValidationResult(correlation, ValidationResult(true, listOf(matched))).isOk)
        val reloaded = store.getByCorrelationId(correlation).value!!.validationResult!!.matchedCredentials.single().disclosedClaims
        assertEquals(objectClaim, reloaded["outcomes"])
        assertEquals(arrayClaim, reloaded["items"])
        assertEquals("001", reloaded["reference"])
        assertEquals("true", reloaded["text"])
    }

    @Test
    fun `server verification evidence survives persistence without promotion of skipped checks`() = runTest {
        val store = createStore()
        val evidence = com.sphereon.openid.oid4vp.verifier.VerifiedCredentialEvidence(
            presentationSha256 = "actual-digest",
            temporalFacts = com.sphereon.openid.oid4vp.verifier.VerifiedCredentialTemporalFacts(1000, 2000, 3000),
            verifiedAtEpochMillis = 123L,
            issuer = com.sphereon.openid.oid4vp.verifier.CredentialIssuerRef(issuer = "did:example:issuer"),
            trust = com.sphereon.openid.oid4vp.verifier.CredentialTrustValidation(
                enabled = true, trusted = false,
                mode = com.sphereon.openid.oid4vp.verifier.CredentialTrustValidationMode.AUDIT,
            ),
            status = com.sphereon.openid.oid4vp.verifier.VerifiedCredentialStatus(
                com.sphereon.openid.oid4vp.verifier.VerifiedCredentialStatusOutcome.SKIPPED,
                required = false, rejectOnUnresolvable = true,
            ),
        )
        val correlation = "verification-evidence-roundtrip"
        assertEquals(true, store.put(correlation, session(null, correlation), 600).isOk)
        val matched = com.sphereon.openid.oid4vp.verifier.MatchedCredential(
            credentialQueryId = "identity_credential",
            credentialFormat = com.sphereon.openid.oid4vc.common.CredentialFormat.SD_JWT_VC,
            presentation = "verified-presentation",
            verificationEvidence = evidence,
        )
        assertEquals(true, store.storeValidationResult(correlation,
            com.sphereon.openid.oid4vp.verifier.ValidationResult(true, listOf(matched))).isOk)
        assertEquals(evidence, store.get(correlation).value?.validationResult?.matchedCredentials?.single()?.verificationEvidence)
    }

    @Test
    fun shouldKeepClaimJsonTypesWhenAFreshStoreReadsTheSameBacking() = runTest {
        val manager = KvStoreTestKvStoreManager(Clock.System)
        val correlation = "claim-types-roundtrip"
        val address = Json.parseToJsonElement("""{"street":"Main","geo":[1,2.5],"unit":null}""")
        val tags = Json.parseToJsonElement("""["a","0612"]""")
        val written = linkedMapOf<String, Any?>(
            "phone" to "0612345678",
            "flag_text" to "true",
            "nan_text" to "NaN",
            "json_text" to "{\"x\":1}",
            "age" to 30L,
            "score" to 1.5,
            "active" to true,
            "none" to null,
            "address" to address,
            "tags" to tags,
        )
        val writer = createStore(manager = manager)
        assertEquals(true, writer.put(correlation, session(null, correlation), 600).isOk)
        val matched = com.sphereon.openid.oid4vp.verifier.MatchedCredential(
            credentialQueryId = "identity_credential",
            credentialFormat = com.sphereon.openid.oid4vc.common.CredentialFormat.SD_JWT_VC,
            presentation = "verified-presentation",
            disclosedClaims = written,
        )
        assertEquals(true, writer.storeValidationResult(correlation, ValidationResult(true, listOf(matched))).isOk)

        val read = createStore(manager = manager).get(correlation).value?.validationResult?.matchedCredentials?.single()?.disclosedClaims

        assertEquals(written, read)
        assertEquals(written.keys.toList(), read?.keys?.toList())
    }

    @Test
    fun shouldReadStoredClaimsAsTheyWereStoredWithoutRepairingHistory() {
        val entry = KvAuthorizationSessionStore.MatchedCredentialEntry(
            credentialQueryId = "q",
            credentialFormat = "dc+sd-jwt",
            presentation = "p",
            disclosedClaims = mapOf(
                "object_as_text" to kotlinx.serialization.json.JsonPrimitive("{\"x\":1}"),
                "number" to kotlinx.serialization.json.JsonPrimitive(7),
                "text_that_looks_numeric" to kotlinx.serialization.json.JsonPrimitive("7"),
                "object" to Json.parseToJsonElement("""{"x":1}"""),
            ),
        )

        val claims = entry.toPublic().disclosedClaims

        assertEquals("{\"x\":1}", claims["object_as_text"])
        assertEquals(7L, claims["number"])
        assertEquals("7", claims["text_that_looks_numeric"])
        assertEquals(Json.parseToJsonElement("""{"x":1}"""), claims["object"])
    }

    // The status endpoint reports VerifiedClaimsValue.type from the persisted session, so the credential
    // type must survive the session store; an untyped match stays untyped.
    @Test
    fun `the matched credential type survives persistence and stays absent when unknown`() = runTest {
        val store = createStore()
        for ((correlation, type) in listOf("credential-type-roundtrip" to "UniversityDegreeCredential", "credential-type-absent" to null)) {
            assertEquals(true, store.put(correlation, session(null, correlation), 600).isOk)
            val matched = com.sphereon.openid.oid4vp.verifier.MatchedCredential(
                credentialQueryId = "vcdm11",
                credentialFormat = com.sphereon.openid.oid4vc.common.CredentialFormat.JWT_VC_JSON,
                presentation = "verified-presentation",
                credentialType = type,
            )
            assertEquals(true, store.storeValidationResult(correlation,
                com.sphereon.openid.oid4vp.verifier.ValidationResult(true, listOf(matched))).isOk)
            assertEquals(type, store.get(correlation).value?.validationResult?.matchedCredentials?.single()?.credentialType)
        }
    }

    /**
     * A credential-status rejection is only useful to a relying party if it is still there after the
     * session has been written to the key-value store and read back. The public
     * [ValidationResult] is not `@Serializable`, so the rejection has to travel through
     * [KvAuthorizationSessionStore.ValidationResultEntry]; this drives the real store to prove the
     * entry actually carries it in both directions.
     */
    @Test
    fun rejectionsSurviveAStoreRoundTrip() =
        runTest {
            val store = createStore()
            val correlation = "credential-status-rejection-roundtrip"
            assertEquals(true, store.put(correlation, session(null, correlation), 600).isOk)
            val rejection =
                CredentialValidationRejection(
                    credentialQueryId = "identity_credential",
                    reason = CredentialValidationRejectionReason.REVOKED,
                    checkedAtEpochMillis = 1_764_000_000_000L,
                    statusValue = 1,
                )

            val stored =
                store.storeValidationResult(
                    correlation,
                    ValidationResult(
                        valid = false,
                        errors = listOf("Credential status asserts revocation"),
                        rejections = listOf(rejection),
                    ),
                )

            assertEquals(true, stored.isOk)
            assertEquals(listOf(rejection), store.get(correlation).value?.validationResult?.rejections)
        }

    /**
     * Sessions written before rejections existed carry no `rejections` key at all. Decoding one must
     * still succeed and yield an empty list rather than failing the whole session read.
     */
    @Test
    fun storedValidationResultWithoutRejectionsStillDecodes() {
        val storedBeforeRejectionsExisted = """{"valid":true,"matchedCredentials":[],"errors":[]}"""

        val decoded =
            Json.decodeFromString(
                KvAuthorizationSessionStore.ValidationResultEntry.serializer(),
                storedBeforeRejectionsExisted,
            )

        assertEquals(emptyList(), decoded.rejections)
        assertEquals(emptyList(), decoded.toPublic().rejections)
        assertEquals(true, decoded.toPublic().valid)
    }

    @Test
    fun ordinaryVerifiedSessionRejectsResponseReplay() =
        runTest {
            assertOrdinaryTerminalStateIsImmutable(valid = true)
        }

    @Test
    fun ordinaryFailedSessionCannotBeReopened() =
        runTest {
            assertOrdinaryTerminalStateIsImmutable(valid = false)
        }

    private suspend fun assertOrdinaryTerminalStateIsImmutable(valid: Boolean) {
        val store = createOrdinaryStoreWithRealBackend()
        val key = "ordinary-terminal-$valid"
        val response =
            com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse(
                vpToken = com.sphereon.openid.oid4vp.common.vpTokenOf("identity_credential", "presentation"),
                rawVpToken = "{\"identity_credential\":[\"presentation\"]}",
                state = key,
            )
        val validation = ValidationResult(valid, errors = if (valid) emptyList() else listOf("verification failed"))
        assertEquals(true, store.put(key, session(null, key), 600).isOk)
        assertEquals(true, store.storeResponse(key, response).isOk)
        assertEquals(true, store.storeValidationResultDeferred(key, validation).isOk)
        val completed = requireNotNull(store.getEntry(key).getOrElse { error(it.toString()) })
        assertEquals(
            if (valid) AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED else AuthorizationSessionStatus.ERROR,
            completed.value.status,
        )

        // Even identical received response bytes would rewind the completed session's status.
        val rejected =
            listOf(
                store.storeResponse(key, response),
                store.storeResponse(key, response.copy(rawVpToken = "changed")),
                store.storeValidationResult(key, ValidationResult(!valid)),
                store.updateStatus(key, AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED),
            )
        rejected.forEach { result ->
            assertEquals(
                IdkError.INVALID_STATE(message = "completed").code,
                assertIs<Err<IdkError>>(result).error.code,
            )
        }
        assertEquals(true, store.storeValidationResultDeferred(key, validation).isOk)
        assertEquals(completed, store.getEntry(key).getOrElse { error(it.toString()) })
    }

    private fun createOrdinaryStoreWithRealBackend(): KvAuthorizationSessionStore {
        val execution =
            object : SessionExecution by KvStoreTestSessionExecution() {
                override val sessionContext: SessionContext = NoOpSessionContext
            }
        val factory = InMemoryKvStoreFactoryImpl(InMemoryKvBackingStorageImpl())
        val manager =
            object : KvStoreManager {
                override fun createFromKvStoreConfig(config: KvStoreConfigBase): KvStore = factory.create(config, null)

                override fun createFromKvStoreConfig(
                    config: KvStoreConfigBase,
                    execution: SessionExecution?,
                ): KvStore = factory.create(config, execution)

                override fun createFromProperties(
                    configService: ConfigService,
                    execution: SessionExecution?,
                ): Set<KvStore> = error("Configuration enumeration is not used by this store")
            }
        return KvAuthorizationSessionStore(
            kvStoreManager = manager,
            kvStoreService = KvStoreTestNoOpKvStoreService(),
            dcqlQueryConfigurationStore = KvStoreTestNoOpDcqlQueryConfigurationStore(),
            callbackDispatcher = KvStoreTestNoOpCallbackDispatcher(),
            statusResponseMapper = AuthorizationSessionStatusResponseMapperImpl(),
            appLogManager = KvStoreTestAppLogManager(),
            execution = execution,
            clock = Clock.System,
        )
    }

    private fun createStore(
        clock: Clock = Clock.System,
        claimed: Boolean = false,
        dispatcher: AuthorizationSessionCallbackDispatcher = KvStoreTestNoOpCallbackDispatcher(),
        manager: KvStoreManager = KvStoreTestKvStoreManager(clock),
    ): KvAuthorizationSessionStore =
        KvAuthorizationSessionStore(
            kvStoreManager = manager,
            kvStoreService = KvStoreTestNoOpKvStoreService(claimed),
            dcqlQueryConfigurationStore = KvStoreTestNoOpDcqlQueryConfigurationStore(),
            callbackDispatcher = dispatcher,
            statusResponseMapper = AuthorizationSessionStatusResponseMapperImpl(),
            appLogManager = KvStoreTestAppLogManager(),
            execution = KvStoreTestSessionExecution(),
            clock = clock,
        )

    @Test
    fun shouldPersistTheCallbackVerifiedDataOptionsThroughTheStore() =
        runTest {
            val store = createStore()
            val cases =
                listOf(
                    "absent" to null,
                    "empty" to VerifiedDataOpts(),
                    "claims" to VerifiedDataOpts(listOf(VerifiedDataMode.CREDENTIAL_CLAIMS_DESERIALIZED)),
                    "mixed" to VerifiedDataOpts(VerifiedDataMode.entries.toList() + VerifiedDataMode.VP_TOKEN),
                )
            for ((name, options) in cases) {
                val correlationId = "callback-options-$name"
                assertEquals(true, store.put(correlationId, callbackSession(correlationId, options), 600).isOk)
                assertEquals(options, store.get(correlationId).value?.callback?.verifiedData, name)
            }
        }

    @Test
    fun shouldDecodeAStoredCallbackWithoutVerifiedDataAsHavingNone() {
        val legacy = """{"url":"https://receiver.example.com/cb","statuses":["ERROR"]}"""
        val entry = Json.decodeFromString(KvAuthorizationSessionStore.AuthorizationSessionCallbackEntry.serializer(), legacy)
        assertNull(entry.toPublic().verifiedData)
    }

    @Test
    fun shouldDispatchOneMappedStatusResponsePerPersistedTransition() =
        runTest {
            val dispatcher = KvStoreTestRecordingCallbackDispatcher()
            val store = createStore(dispatcher = dispatcher)
            val id = "callback-lifecycle"
            val options = VerifiedDataOpts(listOf(VerifiedDataMode.CREDENTIAL_CLAIMS_DESERIALIZED))

            assertEquals(true, store.put(id, callbackSession(id, options), 600).isOk)
            assertEquals(1, dispatcher.delivered.size)
            val retrieved = store.updateStatus(id, AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED).value!!
            assertEquals(2, dispatcher.delivered.size)
            store.storeResponse(id, parsedResponse(id))
            assertEquals(3, dispatcher.delivered.size)
            val verified = store.storeValidationResult(id, validResult()).value!!
            assertEquals(4, dispatcher.delivered.size)

            assertEquals(
                listOf(
                    AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED,
                    AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED,
                    AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_RECEIVED,
                    AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED,
                ),
                dispatcher.delivered.map { it.second.status },
            )
            assertEquals(retrieved.updatedAt, dispatcher.delivered[1].second.lastUpdated)
            assertEquals(verified.updatedAt, dispatcher.delivered[3].second.lastUpdated)
            assertEquals(listOf(null, null, null), dispatcher.delivered.take(3).map { it.second.verifiedData })
            val data = dispatcher.delivered[3].second.verifiedData!!
            assertEquals(true, data.credentialClaims != null)
            assertNull(data.authorizationResponse)
        }

    @Test
    fun shouldDispatchOnlyForTheStatusesTheCallbackLists() =
        runTest {
            val dispatcher = KvStoreTestRecordingCallbackDispatcher()
            val store = createStore(dispatcher = dispatcher)
            val id = "callback-status-filter"
            val session = callbackSession(id, VerifiedDataOpts(VerifiedDataMode.entries.toList()))
            val filtered = session.copy(callback = session.callback!!.copy(statuses = listOf(AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED)))

            assertEquals(true, store.put(id, filtered, 600).isOk)
            store.updateStatus(id, AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED)
            store.storeResponse(id, parsedResponse(id))
            assertEquals(0, dispatcher.delivered.size)
            store.storeValidationResult(id, validResult())

            assertEquals(listOf(AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED), dispatcher.delivered.map { it.second.status })
        }

    @Test
    fun shouldCarryNoVerifiedDataWithoutRequestedModes() =
        runTest {
            for ((name, options) in listOf("absent" to null, "empty" to VerifiedDataOpts())) {
                val dispatcher = KvStoreTestRecordingCallbackDispatcher()
                val store = createStore(dispatcher = dispatcher)
                val id = "callback-no-modes-$name"
                store.put(id, callbackSession(id, options), 600)
                store.updateStatus(id, AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED)
                store.storeResponse(id, parsedResponse(id))
                store.storeValidationResult(id, validResult())

                assertEquals(4, dispatcher.delivered.size, name)
                assertEquals(emptyList(), dispatcher.delivered.mapNotNull { it.second.verifiedData }, name)
            }
        }

    @Test
    fun shouldSendNoCallbackWhenTheSessionConfiguresNone() =
        runTest {
            val dispatcher = KvStoreTestRecordingCallbackDispatcher()
            val store = createStore(dispatcher = dispatcher)
            store.put("no-callback", session(null, "no-callback"), 600)
            store.updateStatus("no-callback", AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED)

            assertEquals(0, dispatcher.delivered.size)
        }

    @Test
    fun shouldKeepThePersistedTransitionAndAttemptOnceWhenDeliveryFails() =
        runTest {
            val dispatcher = KvStoreTestRecordingCallbackDispatcher(Err(IdkError.fromString(message = "receiver unavailable")))
            val store = createStore(dispatcher = dispatcher)
            val id = "callback-delivery-failure"
            store.put(id, callbackSession(id, null), 600)
            dispatcher.delivered.clear()

            val updated = store.updateStatus(id, AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED)

            assertEquals(true, updated.isOk)
            assertEquals(1, dispatcher.delivered.size)
            assertEquals(AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED, store.get(id).value?.status)
        }

    @Test
    fun shouldNotRepeatTheCallbackWhenAWriteLeavesTheStatusUnchanged() =
        runTest {
            val dispatcher = KvStoreTestRecordingCallbackDispatcher()
            val store = createStore(dispatcher = dispatcher)
            val id = "callback-same-status"
            store.put(id, callbackSession(id, null), 600)
            store.updateStatus(id, AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED)
            store.storeResponse(id, parsedResponse(id))
            val delivered = dispatcher.delivered.size

            store.storeResponse(id, parsedResponse(id))
            store.updateStatus(id, AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_RECEIVED)

            assertEquals(delivered, dispatcher.delivered.size)
        }

    @Test
    fun shouldDispatchADeferredValidationOnceWhenItIsDelivered() =
        runTest {
            val dispatcher = KvStoreTestRecordingCallbackDispatcher()
            val store = createStore(dispatcher = dispatcher)
            val id = "callback-deferred"
            store.put(id, callbackSession(id, VerifiedDataOpts(listOf(VerifiedDataMode.VP_TOKEN))), 600)
            store.updateStatus(id, AuthorizationSessionStatus.AUTHORIZATION_REQUEST_RETRIEVED)
            store.storeResponse(id, parsedResponse(id))
            val before = dispatcher.delivered.size

            store.storeValidationResultDeferred(id, validResult())
            assertEquals(before, dispatcher.delivered.size)

            store.dispatchDeferredValidation(id)
            assertEquals(before + 1, dispatcher.delivered.size)
            val data = dispatcher.delivered.last().second.verifiedData!!
            assertNull(data.credentialClaims)
            assertEquals(true, data.authorizationResponse != null)
        }

    private fun callbackSession(correlationId: String, options: VerifiedDataOpts?): AuthorizationSession =
        session(null, correlationId).copy(
            callback = AuthorizationSessionCallbackConfig(
                url = "https://receiver.example.com/cb",
                verifiedData = options,
                secretRef = "secret-ref-never-used",
            ),
        )

    private fun parsedResponse(correlationId: String) =
        com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse(
            vpToken = com.sphereon.openid.oid4vp.common.vpTokenOf("identity_credential", "presentation"),
            rawVpToken = "{\"identity_credential\":[\"presentation\"]}",
            state = correlationId,
        )

    private fun validResult() =
        ValidationResult(
            valid = true,
            matchedCredentials = listOf(
                com.sphereon.openid.oid4vp.verifier.MatchedCredential(
                    credentialQueryId = "identity_credential",
                    credentialFormat = com.sphereon.openid.oid4vc.common.CredentialFormat.SD_JWT_VC,
                    presentation = "presentation",
                    disclosedClaims = mapOf("given_name" to "Ada"),
                ),
            ),
        )

    private fun session(
        templateId: String?,
        correlationId: String,
    ): AuthorizationSession {
        val now = Clock.System.now().toEpochMilliseconds()
        return AuthorizationSession(
            instanceId = "verifier-instance-kv-store-templateid",
            sessionId = "kv-store-session-$correlationId",
            correlationId = correlationId,
            dcqlQuery = DcqlQuery(credentials = listOf(DcqlCredentialQuery(id = "identity_credential", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity")))),
            verifierId = "verifier-a",
            templateId = templateId,
            authorizationRequest =
                AuthorizationRequest(
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    state = correlationId,
                ),
            status = AuthorizationSessionStatus.AUTHORIZATION_REQUEST_CREATED,
            createdAt = now,
            updatedAt = now,
            expiresAt = now + 600_000,
        )
    }

    @Test
    fun `claimed creation replays original and rejects conflicts and terminal overwrite`() = runTest {
        val store = createStore(claimed = true)
        val key = AuthorizationSessionStore.CLAIMED_CORRELATION_PREFIX + "atomic-operation"
        val proposal = session("template-a", key)
        val first = store.createClaimedSession(proposal, "fingerprint", 600).getOrElse { error(it.toString()) }
        val replay = store.createClaimedSession(proposal.copy(sessionId = "losing-concurrent-session"), "fingerprint", 600)
        assertEquals(first, replay.value)
        assertIs<Err<*>>(store.createClaimedSession(proposal, "changed-fingerprint", 600))
        assertIs<Err<*>>(store.createClaimedSession(proposal.copy(templateId = "another-template"), "fingerprint", 600))
        val response = com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse(
            vpToken = com.sphereon.openid.oid4vp.common.vpTokenOf("identity_credential", "presentation"),
            rawVpToken = "{\"identity_credential\":[\"presentation\"]}", state = key,
        )
        assertEquals(true, store.storeResponse(key, response).isOk)
        assertIs<Err<*>>(store.storeResponse(key, response.copy(rawVpToken = "changed")))
        val validated = store.storeValidationResult(key, com.sphereon.openid.oid4vp.verifier.ValidationResult(true))
        assertEquals(true, validated.isOk)
        assertIs<Err<*>>(store.put(key, first, 600))
        assertIs<Err<*>>(store.storeValidationResult(key, com.sphereon.openid.oid4vp.verifier.ValidationResult(false, errors = listOf("changed"))))
        assertEquals(true, store.get(key).value?.validationResult?.valid)
        assertIs<Err<*>>(store.touch(key, 1200))
        assertIs<Err<*>>(store.delete(key))
        assertEquals(first.authorizationRequest, store.createClaimedSession(proposal, "fingerprint", 600).value.authorizationRequest)
    }

    @Test
    fun `claimed creation refuses implicit memory and ordinary put cannot reserve operation`() = runTest {
        val key = "oid4vp-claim:no-fallback"
        assertIs<Err<*>>(createStore().createClaimedSession(session(null, key), "fingerprint", 600))
        assertIs<Err<*>>(createStore(claimed = true).put(key, session(null, key), 600))
    }

    @Test
    fun legacyClaimReplaysThroughUrlSafeStateWithoutReplacingNonceOrTerminalHistory() = runTest {
        val manager = KvStoreTestKvStoreManager(Clock.System)
        val oldStore = createStore(claimed = true, manager = manager)
        val newStore = createStore(claimed = true, manager = manager)
        val legacyKey = AuthorizationSessionStore.LEGACY_CLAIMED_CORRELATION_PREFIX + "persisted-operation"
        val publicKey = AuthorizationSessionStore.CLAIMED_CORRELATION_PREFIX + "persisted-operation"
        val original = session("template", legacyKey).let {
            it.copy(authorizationRequest = it.authorizationRequest.copy(nonce = "original-nonce"))
        }
        val created = oldStore.createClaimedSession(original, "fingerprint", 600).value
        val proposal = session("template", publicKey).let {
            it.copy(authorizationRequest = it.authorizationRequest.copy(nonce = "replacement-nonce"))
        }
        assertEquals(created, newStore.createClaimedSession(proposal, "fingerprint", 600).value)
        assertEquals(created, newStore.get(publicKey).value)
        val response = com.sphereon.openid.oid4vp.verifier.ParsedAuthorizationResponse(
            vpToken = com.sphereon.openid.oid4vp.common.vpTokenOf("identity_credential", "presentation"),
            rawVpToken = "{\"identity_credential\":[\"presentation\"]}", state = legacyKey,
        )
        assertEquals(true, newStore.storeResponse(publicKey, response).isOk)
        val completed = newStore.storeValidationResult(publicKey, ValidationResult(true)).value
        assertEquals(completed, oldStore.get(legacyKey).value)
        assertEquals(completed, newStore.createClaimedSession(proposal, "fingerprint", 600).value)
        assertEquals("original-nonce", completed.authorizationRequest.nonce)
        assertEquals(legacyKey, completed.authorizationRequest.state)
        assertIs<Err<*>>(newStore.createClaimedSession(proposal, "changed", 600))
        assertIs<Err<*>>(newStore.put(publicKey, created, 600))
    }

    @Test
    fun legacyEncryptedClaimReplaysCorrelationKidButKeepsEncryptionMaterialPinned() = runTest {
        val store = createStore(claimed = true)
        val legacy = AuthorizationSessionStore.LEGACY_CLAIMED_CORRELATION_PREFIX + "encrypted-operation"
        val urlSafe = AuthorizationSessionStore.CLAIMED_CORRELATION_PREFIX + "encrypted-operation"
        fun metadata(kid: String, x: String = "public-x", alg: String = "ECDH-ES", use: String = "enc", enc: String = "A256GCM") =
            JsonObject(mapOf(
                "jwks" to JsonObject(mapOf("keys" to JsonArray(listOf(JsonObject(mapOf(
                    "kty" to JsonPrimitive("EC"), "crv" to JsonPrimitive("P-256"),
                    "x" to JsonPrimitive(x), "y" to JsonPrimitive("public-y"),
                    "kid" to JsonPrimitive(kid), "alg" to JsonPrimitive(alg), "use" to JsonPrimitive(use),
                )))))),
                "encrypted_response_enc_values_supported" to JsonArray(listOf(JsonPrimitive(enc))),
            ))
        val original = session("template", legacy).let { it.copy(authorizationRequest = it.authorizationRequest.copy(
            nonce = "original-encrypted-nonce", responseMode = "direct_post.jwt",
            additionalParameters = mapOf("client_metadata" to metadata(legacy)),
        )) }
        val created = store.createClaimedSession(original, "fingerprint", 600).value
        val proposal = original.copy(correlationId = urlSafe, authorizationRequest = original.authorizationRequest.copy(
            state = urlSafe, nonce = "replacement-encrypted-nonce",
            additionalParameters = mapOf("client_metadata" to metadata(urlSafe)),
        ))
        assertEquals(created, store.createClaimedSession(proposal, "fingerprint", 600).value)
        for (altered in listOf(
            metadata(urlSafe, x = "different-public-x"), metadata(urlSafe, alg = "ECDH-ES+A256KW"),
            metadata(urlSafe, use = "sig"), metadata(urlSafe, enc = "A128GCM"),
            metadata(AuthorizationSessionStore.CLAIMED_CORRELATION_PREFIX + "another-operation"),
        )) {
            assertIs<Err<*>>(store.createClaimedSession(proposal.copy(authorizationRequest = proposal.authorizationRequest.copy(
                additionalParameters = mapOf("client_metadata" to altered),
            )), "fingerprint", 600))
        }
        assertEquals(original.authorizationRequest, store.get(urlSafe).value?.authorizationRequest)

        val unrelatedKidOriginal = original.copy(correlationId = "$legacy-custom",
            authorizationRequest = original.authorizationRequest.copy(state = "$legacy-custom",
                additionalParameters = mapOf("client_metadata" to metadata("$legacy-unrelated"))))
        assertEquals(true, store.createClaimedSession(unrelatedKidOriginal, "custom-fingerprint", 600).isOk)
        val unrelatedKidProposal = unrelatedKidOriginal.copy(correlationId = "$urlSafe-custom",
            authorizationRequest = unrelatedKidOriginal.authorizationRequest.copy(state = "$urlSafe-custom",
                additionalParameters = mapOf("client_metadata" to metadata("$urlSafe-unrelated"))))
        assertIs<Err<*>>(store.createClaimedSession(unrelatedKidProposal, "custom-fingerprint", 600))
    }

    @Test
    fun competingClaimPrefixesShareOneAtomicOperationAcrossStoreInstances() = runTest {
        for (matchingFingerprint in listOf(true, false)) {
            val manager = KvStoreTestKvStoreManager(Clock.System)
            val stores = List(2) { createStore(claimed = true, manager = manager) }
            val start = CompletableDeferred<Unit>()
            val keys = listOf(AuthorizationSessionStore.CLAIMED_CORRELATION_PREFIX,
                AuthorizationSessionStore.LEGACY_CLAIMED_CORRELATION_PREFIX).map { it + "concurrent-operation" }
            val proposals = keys.mapIndexed { index, key -> session("template", key).let {
                it.copy(authorizationRequest = it.authorizationRequest.copy(nonce = "nonce-$index"))
            } }
            val pending = stores.mapIndexed { index, store -> async {
                start.await()
                store.createClaimedSession(proposals[index], if (matchingFingerprint) "same" else "fingerprint-$index", 600)
            } }
            start.complete(Unit)
            val results = pending.awaitAll()
            assertEquals(if (matchingFingerprint) 2 else 1, results.count { it.isOk })
            if (matchingFingerprint) assertEquals(results[0].value, results[1].value)
            val persisted = stores[0].get(keys[0]).value
            assertEquals(persisted, stores[1].get(keys[1]).value)
            assertEquals(true, results.filter { it.isOk }.all { it.value == persisted })
            assertIs<Err<*>>(stores[0].createClaimedSession(proposals[0].copy(templateId = "altered"), "same", 600))
        }
    }

    @Test
    fun ordinaryPutCannotReplaceEitherClaimNamespace() = runTest {
        for (prefix in listOf(AuthorizationSessionStore.CLAIMED_CORRELATION_PREFIX, AuthorizationSessionStore.LEGACY_CLAIMED_CORRELATION_PREFIX)) {
            val key = prefix + "reserved-operation"
            assertIs<Err<*>>(createStore(claimed = true).put(key, session(null, key), 600))
        }
    }

    @Test
    fun `templateId survives a real put then get round trip`() =
        runTest {
            val store = createStore()
            val correlationId = "kv-store-round-trip-with-template"

            assertEquals(true, store.put(correlationId, session(templateId = "template-a", correlationId = correlationId), ttlSeconds = 600).isOk)

            val fetched = store.get(correlationId)
            assertEquals(true, fetched.isOk)
            assertEquals("template-a", fetched.value?.templateId)
        }

    @Test
    fun `templateId survives a real put then getByCorrelationId round trip`() =
        runTest {
            val store = createStore()
            val correlationId = "kv-store-round-trip-by-correlation-id"

            assertEquals(true, store.put(correlationId, session(templateId = "template-b", correlationId = correlationId), ttlSeconds = 600).isOk)

            val fetched = store.getByCorrelationId(correlationId)
            assertEquals(true, fetched.isOk)
            assertEquals("template-b", fetched.value?.templateId)
        }

    /**
     * A stored authorization session must not be able to name key material. The verifier resolves
     * its response-encryption key from the session's verifier instance plus its own server-side
     * binding, so an entry that carried an alias, a provider id, or any other key locator would put
     * that selection back within reach of whatever can write the session store.
     */
    @Test
    fun `the persisted session entry carries no key selector`() {
        val descriptor = KvAuthorizationSessionStore.AuthorizationSessionEntry.serializer().descriptor
        val fields = (0 until descriptor.elementsCount).map { descriptor.getElementName(it) }

        val selectors = fields.filter { field -> KEY_SELECTOR_MARKERS.any { field.contains(it, ignoreCase = true) } }
        assertEquals(emptyList(), selectors, "a persisted session must not carry a key selector")
    }

    @Test
    fun `absent templateId round trips as null through the real store`() =
        runTest {
            val store = createStore()
            val correlationId = "kv-store-round-trip-no-template"

            assertEquals(true, store.put(correlationId, session(templateId = null, correlationId = correlationId), ttlSeconds = 600).isOk)

            val fetched = store.get(correlationId)
            assertEquals(true, fetched.isOk)
            assertNull(fetched.value?.templateId)
        }

    @Test
    fun `real store keeps caller ttl aligned across session and kv metadata`() =
        runTest {
            val now = Instant.parse("2026-08-24T12:00:00Z")
            val clock = FixedClock(now)
            val store = createStore(clock)
            val correlationId = "kv-store-caller-ttl"
            val value =
                session(templateId = null, correlationId = correlationId).copy(
                    createdAt = now.toEpochMilliseconds(),
                    updatedAt = now.toEpochMilliseconds(),
                    expiresAt = 0L,
                )

            val metadata = store.put(correlationId, value, ttlSeconds = 42)
            val storedMetadata = metadata.getOrNull()
            requireNotNull(storedMetadata)
            assertEquals(now.toEpochMilliseconds() + 42_000L, storedMetadata.expiresAt)
            val stored = store.getEntry(correlationId).getOrNull()
            requireNotNull(stored)
            assertEquals(now.toEpochMilliseconds() + 42_000L, stored.expiresAt)
            assertEquals(stored.expiresAt, stored.value.expiresAt)
        }

    @Test
    fun `real store rejects invalid ttl values`() =
        runTest {
            val store = createStore(FixedClock(Instant.parse("2026-08-24T12:00:00Z")))
            listOf(0L, -1L, Long.MAX_VALUE).forEachIndexed { index, ttlSeconds ->
                val result = store.put("invalid-ttl-$index", session(null, "invalid-ttl-$index"), ttlSeconds)
                assertEquals("ILLEGAL_ARGUMENT_ERROR", assertIs<Err<IdkError>>(result).error.code)
            }
        }

    private companion object {
        /** Anything that could name key material, however it is spelled. */
        val KEY_SELECTOR_MARKERS = listOf("alias", "providerId", "keyId", "kid", "locator", "jarm")
    }
}

// ---------------------------------------------------------------------------
// Minimal, byte-encoding-faithful test support (mirrors ResponseCodeProtectionTest /
// KvCredentialOfferSessionStoreTest in sibling modules: a real in-memory KvStore that
// round-trips through namespace.codec.encode/decode, not a pass-through-by-reference fake).
// ---------------------------------------------------------------------------

internal class KvStoreTestKvStore(
    private val clock: Clock,
) : KvStoreVersioning {
    override val config: KvStoreConfigBase =
        InMemoryKvStoreConfig(id = "test-auth-sessions", scopeBinding = KvStoreScopeBinding.TENANT)

    private data class Stored(
        val bytes: ByteArray,
        val createdAt: Long,
        val expiresAt: Long,
    )

    private val entries = mutableMapOf<String, Stored>()
    private val versions = mutableMapOf<String, MutableList<Pair<String, Stored>>>()
    private val versionMutex = kotlinx.coroutines.sync.Mutex()

    override suspend fun <V : Any> getHead(namespace: KvNamespace<V>, key: String): IdkResult<KvVersionedEntry<V>?, IdkError> {
        val chain = versions[compositeKey(namespace, key)] ?: return Ok(null)
        val (id, stored) = chain.last()
        return Ok(KvVersionedEntry(id, chain.dropLast(1).lastOrNull()?.first, namespace.codec.decode(stored.bytes), KvEntryMetadata(stored.createdAt, stored.expiresAt)))
    }

    override suspend fun <V : Any> getVersion(namespace: KvNamespace<V>, key: String, versionId: String): IdkResult<KvVersionedEntry<V>?, IdkError> {
        val chain = versions[compositeKey(namespace, key)] ?: return Ok(null)
        val index = chain.indexOfFirst { it.first == versionId }
        if (index < 0) return Ok(null)
        val (id, stored) = chain[index]
        return Ok(KvVersionedEntry(id, chain.getOrNull(index - 1)?.first, namespace.codec.decode(stored.bytes), KvEntryMetadata(stored.createdAt, stored.expiresAt)))
    }

    override suspend fun <V : Any> append(namespace: KvNamespace<V>, key: String, expectedPreviousVersionId: String?, value: V, ttl: Duration): IdkResult<KvVersionAppendResult<V>, IdkError> {
        // Let competing proposals reach the storage boundary before taking its atomic lock.
        kotlinx.coroutines.yield()
        versionMutex.lock()
        try {
            val head = getHead(namespace, key).value
            if (head?.versionId != expectedPreviousVersionId) return Ok(KvVersionAppendResult.Conflict(head))
            val chain = versions.getOrPut(compositeKey(namespace, key)) { mutableListOf() }
            val now = clock.now().toEpochMilliseconds()
            chain += (chain.size + 1).toString() to Stored(namespace.codec.encode(value), now, now + ttl.inWholeMilliseconds)
            return Ok(KvVersionAppendResult.Applied(getHead(namespace, key).value!!))
        } finally { versionMutex.unlock() }
    }

    override suspend fun deleteVersioned(namespace: KvNamespaceId, key: String): IdkResult<Boolean, IdkError> = Ok(versions.remove(compositeKey(namespace, key)) != null)

    private fun compositeKey(
        namespace: KvNamespaceId,
        key: String,
    ) = "${namespace.name}:$key"

    override suspend fun <V : Any> put(
        namespace: KvNamespace<V>,
        key: String,
        value: V,
        ttl: Duration,
    ): IdkResult<KvPutResult, IdkError> {
        val now = clock.now().toEpochMilliseconds()
        val expiresAt = if (ttl.isInfinite()) Long.MAX_VALUE else now + ttl.inWholeMilliseconds
        entries[compositeKey(namespace, key)] = Stored(bytes = namespace.codec.encode(value), createdAt = now, expiresAt = expiresAt)
        return Ok(KvPutResult(metadata = KvEntryMetadata(createdAtEpochMillis = now, expiresAtEpochMillis = expiresAt)))
    }

    override suspend fun <V : Any> get(
        namespace: KvNamespace<V>,
        key: String,
    ): IdkResult<V?, IdkError> = getEntry(namespace, key).map { it?.value }

    override suspend fun <V : Any> getEntry(
        namespace: KvNamespace<V>,
        key: String,
    ): IdkResult<KvEntry<V>?, IdkError> {
        val now = clock.now().toEpochMilliseconds()
        val stored = entries[compositeKey(namespace, key)] ?: return Ok(null)
        if (stored.expiresAt <= now) {
            entries.remove(compositeKey(namespace, key))
            return Ok(null)
        }
        val value = namespace.codec.decode(stored.bytes)
        return Ok(KvEntry(value = value, metadata = KvEntryMetadata(createdAtEpochMillis = stored.createdAt, expiresAtEpochMillis = stored.expiresAt)))
    }

    override suspend fun delete(
        namespace: KvNamespaceId,
        key: String,
    ): IdkResult<Boolean, IdkError> = Ok(entries.remove(compositeKey(namespace, key)) != null)

    override suspend fun exists(
        namespace: KvNamespaceId,
        key: String,
    ): IdkResult<Boolean, IdkError> {
        val now = clock.now().toEpochMilliseconds()
        val stored = entries[compositeKey(namespace, key)] ?: return Ok(false)
        if (stored.expiresAt <= now) {
            entries.remove(compositeKey(namespace, key))
            return Ok(false)
        }
        return Ok(true)
    }

    override suspend fun touch(
        namespace: KvNamespaceId,
        key: String,
        ttl: Duration,
    ): IdkResult<Boolean, IdkError> {
        val now = clock.now().toEpochMilliseconds()
        val stored = entries[compositeKey(namespace, key)] ?: return Ok(false)
        if (stored.expiresAt <= now) {
            entries.remove(compositeKey(namespace, key))
            return Ok(false)
        }
        val newExpiresAt = if (ttl.isInfinite()) Long.MAX_VALUE else now + ttl.inWholeMilliseconds
        entries[compositeKey(namespace, key)] = stored.copy(expiresAt = newExpiresAt)
        return Ok(true)
    }

    override suspend fun cleanupExpired(namespace: KvNamespaceId?): IdkResult<Int, IdkError> {
        val now = Clock.System.now().toEpochMilliseconds()
        val keysToRemove =
            entries
                .filter { (k, stored) ->
                    (namespace == null || k.startsWith("${namespace.name}:")) && stored.expiresAt <= now
                }.keys
                .toList()
        keysToRemove.forEach { entries.remove(it) }
        return Ok(keysToRemove.size)
    }
}

internal class KvStoreTestKvStoreManager(
    clock: Clock,
) : KvStoreManager {
    private val store = KvStoreTestKvStore(clock)

    override fun createFromKvStoreConfig(config: KvStoreConfigBase): KvStore = store

    override fun createFromKvStoreConfig(
        config: KvStoreConfigBase,
        execution: SessionExecution?,
    ): KvStore = store

    override fun createFromProperties(
        configService: ConfigService,
        execution: SessionExecution?,
    ): Set<KvStore> = setOf(store)
}

private class FixedClock(
    private val instant: Instant,
) : Clock {
    override fun now(): Instant = instant
}

internal class KvStoreTestNoOpKvStoreService(private val claimed: Boolean = false) : KvStoreService {
    override fun getStoreIds(): Array<String> = emptyArray()

    override fun getStoreConfig(storeId: String): KvStoreConfigBase = if (claimed)
        com.sphereon.data.store.kv.KvStoreConfig(storeId, backendId = "test-atomic-persistence")
        else throw UnsupportedOperationException("no store config in test")

    override fun getStore(storeId: String): KvStore = throw UnsupportedOperationException("no store in test")
}

internal class KvStoreTestSessionExecution : SessionExecution {
    override val sessionContextManager: SessionContextManager
        get() = throw UnsupportedOperationException("not used in store tests")
    override val sessionContext: SessionContext
        get() = throw UnsupportedOperationException("not used in store tests")
    override val log: SessionLogService
        get() = throw UnsupportedOperationException("not used in store tests")
    override val conf: ContextConfig
        get() = throw UnsupportedOperationException("not used in store tests")
}

internal class KvStoreTestAppLogManager :
    AbstractLogManager(scope = IdkScope.APP, loggers = emptySet()),
    AppLogManager

private class KvStoreTestNoOpCallbackDispatcher : AuthorizationSessionCallbackDispatcher {
    override suspend fun dispatch(
        url: String,
        status: GetAuthorizationRequestStatusOutput,
    ): IdkResult<Unit, IdkError> = Ok(Unit)
}

private class KvStoreTestRecordingCallbackDispatcher(
    private val outcome: IdkResult<Unit, IdkError> = Ok(Unit),
) : AuthorizationSessionCallbackDispatcher {
    val delivered = mutableListOf<Pair<String, GetAuthorizationRequestStatusOutput>>()

    override suspend fun dispatch(
        url: String,
        status: GetAuthorizationRequestStatusOutput,
    ): IdkResult<Unit, IdkError> {
        delivered += url to status
        return outcome
    }
}

/**
 * Never exercised by put/get/getByCorrelationId (only [KvAuthorizationSessionStore.createSession]
 * reads it, which this test does not call) — every member throws to make that explicit.
 */
internal class KvStoreTestNoOpDcqlQueryConfigurationStore : DcqlQueryConfigurationStore {
    private fun notUsed(): Nothing = throw UnsupportedOperationException("not used in store tests")

    override suspend fun getByQueryId(queryId: String): IdkResult<DcqlQueryConfiguration?, IdkError> = notUsed()

    override suspend fun put(
        key: String,
        value: DcqlQueryConfiguration,
        ttlSeconds: Long,
    ): IdkResult<com.sphereon.openid.oid4vp.common.store.StoreMetadata, IdkError> = notUsed()

    override suspend fun get(key: String): IdkResult<DcqlQueryConfiguration?, IdkError> = notUsed()

    override suspend fun getEntry(key: String): IdkResult<StoredEntry<DcqlQueryConfiguration>?, IdkError> = notUsed()

    override suspend fun delete(key: String): IdkResult<Boolean, IdkError> = notUsed()

    override suspend fun exists(key: String): IdkResult<Boolean, IdkError> = notUsed()

    override suspend fun touch(
        key: String,
        ttlSeconds: Long,
    ): IdkResult<Boolean, IdkError> = notUsed()

    override suspend fun cleanupExpired(): IdkResult<Int, IdkError> = notUsed()

    override suspend fun putPersistent(
        key: String,
        value: DcqlQueryConfiguration,
    ): IdkResult<com.sphereon.openid.oid4vp.common.store.StoreMetadata, IdkError> = notUsed()

    override suspend fun listIds(): IdkResult<List<String>, IdkError> = notUsed()

    override suspend fun getAll(): IdkResult<Map<String, DcqlQueryConfiguration>, IdkError> = notUsed()
}
