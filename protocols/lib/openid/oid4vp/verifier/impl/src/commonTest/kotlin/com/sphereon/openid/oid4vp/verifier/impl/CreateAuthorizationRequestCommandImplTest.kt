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

import com.sphereon.core.api.IdkResult
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSession
import com.sphereon.openid.oid4vp.verifier.store.AuthorizationSessionStore
import com.sphereon.core.api.Err
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.common.dcqlQuery
import com.sphereon.openid.oid4vp.dcql.ClaimsPathPointer
import com.sphereon.openid.oid4vp.dcql.DcqlClaimQuery
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.mdocMeta
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.verifier.CreateAuthorizationRequestArgs
import com.sphereon.openid.oid4vp.verifier.impl.testutil.Oid4vpVerifierTestContext
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Unit tests for CreateAuthorizationRequestCommandImpl
 */
class CreateAuthorizationRequestCommandImplTest {
    private val testContext = Oid4vpVerifierTestContext("create-auth-req-test", this)
    private val sessionStore = TestAuthorizationSessionStore()
    private val command = createTestCommand(sessionStore)

    @Test
    fun claimedReplayReturnsPersistedCorrelationAndOriginalRequest() = runTest {
        val legacy = AuthorizationSessionStore.LEGACY_CLAIMED_CORRELATION_PREFIX + "operation"
        val urlSafe = AuthorizationSessionStore.CLAIMED_CORRELATION_PREFIX + "operation"
        val replayStore = object : AuthorizationSessionStore by sessionStore {
            override suspend fun createClaimedSession(
                session: AuthorizationSession,
                fingerprint: String,
                ttlSeconds: Long,
            ): IdkResult<AuthorizationSession, IdkError> {
                assertEquals(urlSafe, session.correlationId)
                assertEquals(urlSafe, session.authorizationRequest.state)
                return Ok(session.copy(correlationId = legacy,
                    authorizationRequest = session.authorizationRequest.copy(state = legacy, nonce = "originalNonce123")))
            }
        }
        val result = createTestCommand(replayStore).createAuthorizationRequest(CreateAuthorizationRequestArgs(
            instanceId = "verifier-claimed-replay",
            dcqlQuery = DcqlQuery(credentials = listOf(DcqlCredentialQuery(
                id = "identity", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"),
            ))),
            clientId = "https://verifier.example.com",
            responseUri = "https://verifier.example.com/response",
            responseMode = ResponseMode.DIRECT_POST,
            nonce = "replacementNonce123",
            state = urlSafe,
            operationFingerprint = "fingerprint",
        ))
        assertIs<Ok<*>>(result)
        assertEquals(legacy, result.value.sessionId)
        assertEquals(legacy, result.value.request.state)
        assertEquals("originalNonce123", result.value.request.nonce)
    }

    @Test
    fun digitalCredentialsSignedRequestKeepsCorrelationOffTheWire() = runTest {
        val result = command.createAuthorizationRequest(
            CreateAuthorizationRequestArgs(
                instanceId = "dc-api-verifier",
                dcqlQuery = DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "identity", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
                ),
                clientId = "x509_hash:verifier-key",
                responseMode = ResponseMode.DC_API_JWT,
                expectedOrigins = listOf("https://verifier.example.com"),
                nonce = "nonce12345678",
                state = "private-correlation-id",
            ),
        )

        assertIs<Ok<*>>(result)
        val request = result.value.request
        assertEquals("dc_api.jwt", request.responseMode)
        assertNull(request.state)
        assertNull(request.redirectUri)
        assertNull(request.additionalParameters["response_uri"])
        assertEquals("[\"https://verifier.example.com\"]", request.additionalParameters["expected_origins"].toString())
        assertEquals("origin:https://verifier.example.com", holderBindingClientId(request))
        assertEquals(
            "origin:https://verifier.example.com",
            holderBindingClientId(request.copy(responseMode = ResponseMode.DC_API.value)),
        )
        assertNull(
            holderBindingClientId(
                request.copy(
                    responseMode = ResponseMode.DC_API.value,
                    additionalParameters = request.additionalParameters - "expected_origins",
                ),
            ),
        )
        assertEquals("private-correlation-id", result.value.sessionId)
        assertNotNull(sessionStore.get("private-correlation-id").getOrNull())
    }

    @Test
    fun `test create basic authorization request`() =
        runTest {
            // Given: Basic DCQL query requesting identity credential
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "identity_credential",
                                format = "dc+sd-jwt",
                                meta = sdJwtVcMeta("urn:test:identity"),
                                claims =
                                    listOf(
                                        DcqlClaimQuery(path = ClaimsPathPointer(listOf(JsonPrimitive("first_name")))),
                                        DcqlClaimQuery(path = ClaimsPathPointer(listOf(JsonPrimitive("last_name")))),
                                    ),
                            ),
                        ),
                )

            val args =
                CreateAuthorizationRequestArgs(
                    instanceId = "verifier-instance-basic-authorization-request",
                    dcqlQuery = dcqlQuery,
                    clientId = "https://verifier.example.com",
                    responseUri = "https://verifier.example.com/response",
                    responseMode = ResponseMode.DIRECT_POST,
                    nonce = "nonce12345678",
                    state = "state123",
                )

            // When: Creating the authorization request
            val result = command.createAuthorizationRequest(args)

            // Then: Request should be created successfully
            assertIs<Ok<*>>(result)
            val createdRequest = result.value

            assertEquals("https://verifier.example.com", createdRequest.request.clientId)
            assertEquals("vp_token", createdRequest.request.responseType)
            assertEquals("nonce12345678", createdRequest.request.nonce)
            assertEquals("direct_post", createdRequest.request.responseMode)
            assertEquals("state123", createdRequest.request.state)
            val createdSessionId = assertNotNull(createdRequest.sessionId)
            assertNotNull(createdRequest.request.dcqlQuery)

            val storedSession = sessionStore.get(createdSessionId)
            assertIs<Ok<*>>(storedSession)
            assertEquals(args.instanceId, storedSession.value?.instanceId)
        }

    @Test
    fun `test create authorization request persists templateId onto the session`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "identity_credential", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
                )

            val args =
                CreateAuthorizationRequestArgs(
                    instanceId = "verifier-instance-template-id-request",
                    dcqlQuery = dcqlQuery,
                    clientId = "https://verifier.example.com",
                    responseUri = "https://verifier.example.com/response",
                    responseMode = ResponseMode.DIRECT_POST,
                    nonce = "nonce12345678",
                    state = "state-template-a",
                    verifierId = "verifier-a",
                    templateId = "template-a",
                )

            val result = command.createAuthorizationRequest(args)

            assertIs<Ok<*>>(result)
            val createdSessionId = assertNotNull(result.value.sessionId)
            val storedSession = sessionStore.get(createdSessionId)
            assertIs<Ok<*>>(storedSession)
            assertEquals("template-a", storedSession.value?.templateId)
        }

    @Test
    fun `test create authorization request without templateId leaves session templateId null`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "identity_credential", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
                )

            val args =
                CreateAuthorizationRequestArgs(
                    instanceId = "verifier-instance-no-template-id-request",
                    dcqlQuery = dcqlQuery,
                    clientId = "https://verifier.example.com",
                    responseUri = "https://verifier.example.com/response",
                    responseMode = ResponseMode.DIRECT_POST,
                    nonce = "nonce12345678",
                    state = "state-no-template",
                )

            val result = command.createAuthorizationRequest(args)

            assertIs<Ok<*>>(result)
            val createdSessionId = assertNotNull(result.value.sessionId)
            val storedSession = sessionStore.get(createdSessionId)
            assertIs<Ok<*>>(storedSession)
            assertNull(storedSession.value?.templateId)
        }

    @Test
    fun `test create authorization request with client metadata`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials =
                        listOf(
                            DcqlCredentialQuery(
                                id = "mdoc_credential",
                                format = "mso_mdoc",
                                meta = mdocMeta("org.iso.18013.5.1.mDL"),
                            ),
                        ),
                )

            val args =
                CreateAuthorizationRequestArgs(
                    instanceId = "verifier-instance-client-metadata-request",
                    dcqlQuery = dcqlQuery,
                    clientId = "https://verifier.example.com",
                    responseUri = "https://verifier.example.com/response",
                    responseMode = ResponseMode.DIRECT_POST,
                    nonce = "nonce12345678",
                    clientIdScheme = ClientIdScheme.REDIRECT_URI,
                )

            val result = command.createAuthorizationRequest(args)

            assertIs<Ok<*>>(result)
            val request = result.value.request
            assertEquals("redirect_uri", request.additionalParameters["client_id_scheme"]?.toString()?.replace("\"", ""))
        }

    @Test
    fun `test validation fails without nonce`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "test", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential"))),
                )

            val args =
                CreateAuthorizationRequestArgs(
                    instanceId = "verifier-instance-empty-nonce-validation",
                    dcqlQuery = dcqlQuery,
                    clientId = "https://verifier.example.com",
                    responseUri = "https://verifier.example.com/response",
                    responseMode = ResponseMode.DIRECT_POST,
                    nonce = "", // Empty nonce
                )

            val result = command.createAuthorizationRequest(args)

            assertIs<Err<*>>(result)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("nonce"),
            )
        }

    @Test
    fun `test validation fails with short nonce`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "test", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential"))),
                )

            val args =
                CreateAuthorizationRequestArgs(
                    instanceId = "verifier-instance-short-nonce-validation",
                    dcqlQuery = dcqlQuery,
                    clientId = "https://verifier.example.com",
                    responseUri = "https://verifier.example.com/response",
                    responseMode = ResponseMode.DIRECT_POST,
                    nonce = "short", // Too short (< 8 chars)
                )

            val result = command.createAuthorizationRequest(args)

            assertIs<Err<*>>(result)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("8 characters"),
            )
        }

    @Test
    fun `test validation fails without response_uri for direct_post`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "test", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential"))),
                )

            val args =
                CreateAuthorizationRequestArgs(
                    instanceId = "verifier-instance-missing-response-uri-validation",
                    dcqlQuery = dcqlQuery,
                    clientId = "https://verifier.example.com",
                    responseUri = null, // Missing response_uri
                    responseMode = ResponseMode.DIRECT_POST,
                    nonce = "nonce12345678",
                )

            val result = command.createAuthorizationRequest(args)

            assertIs<Err<*>>(result)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("response_uri"),
            )
        }

    @Test
    fun `test fragment response mode`() =
        runTest {
            val dcqlQuery =
                DcqlQuery(
                    credentials = listOf(DcqlCredentialQuery(id = "test", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential"))),
                )

            val args =
                CreateAuthorizationRequestArgs(
                    instanceId = "verifier-instance-fragment-response-request",
                    dcqlQuery = dcqlQuery,
                    clientId = "https://verifier.example.com",
                    redirectUri = "https://verifier.example.com/callback",
                    responseMode = ResponseMode.FRAGMENT,
                    nonce = "nonce12345678",
                )

            val result = command.createAuthorizationRequest(args)

            assertIs<Ok<*>>(result)
            val request = result.value.request
            assertEquals("fragment", request.responseMode)
        }

    @Test
    fun `test empty DCQL query is rejected by the model`() {
        val exception =
            assertFailsWith<IllegalArgumentException> {
                DcqlQuery(
                    credentials = emptyList(),
                    credential_sets = null,
                )
            }
        assertTrue(exception.message.orEmpty().contains("credential"))
    }

    @Test
    fun `JAR signing DID binding rewrites client_id to decentralized_identifier prefix`() =
        runTest {
            // Per OID4VP §5.9.3: when signing under did:jwk the outer client_id MUST be
            // `decentralized_identifier:<did>` — the prefix is part of the value.
            val bindingConfig =
                StubSigningConfig(
                    enabled = true,
                    binding =
                        com.sphereon.openid.oid4vp.verifier.requesturi.VerifierSignerBinding.Did(
                            did = "did:jwk:eyJhbGciOiJFUzI1NiJ9",
                            verificationMethodId = "did:jwk:eyJhbGciOiJFUzI1NiJ9#0",
                        ),
                )
            val command =
                CreateAuthorizationRequestCommandImpl(
                    execution = testContext.execution,
                    authorizationSessionStore = TestAuthorizationSessionStore(),
                    requestObjectSigningConfig = bindingConfig,
                )

            val result =
                command.createAuthorizationRequest(
                    CreateAuthorizationRequestArgs(
                        instanceId = "verifier-instance-did-signer-binding",
                        dcqlQuery = DcqlQuery(credentials = listOf(DcqlCredentialQuery(id = "c", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential")))),
                        clientId = "https://verifier.example.com",
                        responseUri = "https://verifier.example.com/response",
                        responseMode = ResponseMode.DIRECT_POST,
                        nonce = "nonce12345678",
                    ),
                )

            assertIs<Ok<*>>(result)
            assertEquals(
                "decentralized_identifier:did:jwk:eyJhbGciOiJFUzI1NiJ9",
                result.value.request.clientId,
            )
            // OID4VP 1.0 §5.9.1 carries the scheme inside the client_id prefix; we do not
            // emit the legacy `client_id_scheme` parameter (it would break credo-ts whose
            // legacy enum doesn't include `decentralized_identifier`).
            assertEquals(
                ClientIdScheme.PRE_REGISTERED,
                result.value.request.clientIdScheme(),
            )
        }

    @Test
    fun `JAR signing x509_san_dns binding rewrites client_id to x509_san_dns prefix`() =
        runTest {
            val bindingConfig =
                StubSigningConfig(
                    enabled = true,
                    binding =
                        com.sphereon.openid.oid4vp.verifier.requesturi.VerifierSignerBinding.X509SanDns(
                            dnsName = "verifier.example.com",
                            certificateChain = listOf("MIIBdTCCARugAw...=="),
                        ),
                )
            val command =
                CreateAuthorizationRequestCommandImpl(
                    execution = testContext.execution,
                    authorizationSessionStore = TestAuthorizationSessionStore(),
                    requestObjectSigningConfig = bindingConfig,
                )

            val result =
                command.createAuthorizationRequest(
                    CreateAuthorizationRequestArgs(
                        instanceId = "verifier-instance-x509-signer-binding",
                        dcqlQuery = DcqlQuery(credentials = listOf(DcqlCredentialQuery(id = "c", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential")))),
                        clientId = "https://verifier.example.com",
                        responseUri = "https://verifier.example.com/response",
                        responseMode = ResponseMode.DIRECT_POST,
                        nonce = "nonce12345678",
                    ),
                )

            assertIs<Ok<*>>(result)
            assertEquals("x509_san_dns:verifier.example.com", result.value.request.clientId)
        }

    @Test
    fun `JAR signing enabled but binding resolution returns null surfaces Err`() =
        runTest {
            // No fallback to the HTTPS client_id when signing is configured but incomplete.
            val bindingConfig = StubSigningConfig(enabled = true, binding = null)
            val command =
                CreateAuthorizationRequestCommandImpl(
                    execution = testContext.execution,
                    authorizationSessionStore = TestAuthorizationSessionStore(),
                    requestObjectSigningConfig = bindingConfig,
                )

            val result =
                command.createAuthorizationRequest(
                    CreateAuthorizationRequestArgs(
                        instanceId = "verifier-instance-missing-signer-binding",
                        dcqlQuery = DcqlQuery(credentials = listOf(DcqlCredentialQuery(id = "c", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential")))),
                        clientId = "https://verifier.example.com",
                        responseUri = "https://verifier.example.com/response",
                        responseMode = ResponseMode.DIRECT_POST,
                        nonce = "nonce12345678",
                    ),
                )

            assertIs<Err<*>>(result)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("signing", ignoreCase = true) &&
                    result.error.message.defaultMessage
                        .contains("signer binding", ignoreCase = true),
                "Expected error about request-object signing / signer binding, got: ${result.error.message.defaultMessage}",
            )
        }

    @Test
    fun `caller-provided prefixed client_id is left untouched`() =
        runTest {
            // When the caller already supplies a §5.9.3 prefixed client_id (e.g. because
            // they manage x5c out-of-band), the command must not substitute a different
            // binding — the caller has spoken.
            val bindingConfig =
                StubSigningConfig(
                    enabled = true,
                    binding =
                        com.sphereon.openid.oid4vp.verifier.requesturi.VerifierSignerBinding.Did(
                            did = "did:jwk:SHOULD_NOT_BE_USED",
                            verificationMethodId = "did:jwk:SHOULD_NOT_BE_USED#0",
                        ),
                )
            val command =
                CreateAuthorizationRequestCommandImpl(
                    execution = testContext.execution,
                    authorizationSessionStore = TestAuthorizationSessionStore(),
                    requestObjectSigningConfig = bindingConfig,
                )

            val result =
                command.createAuthorizationRequest(
                    CreateAuthorizationRequestArgs(
                        instanceId = "verifier-instance-caller-supplied-binding",
                        dcqlQuery = DcqlQuery(credentials = listOf(DcqlCredentialQuery(id = "c", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential")))),
                        clientId = "x509_san_dns:caller.example.com",
                        clientIdScheme = ClientIdScheme.X509_SAN_DNS,
                        responseUri = "https://verifier.example.com/response",
                        responseMode = ResponseMode.DIRECT_POST,
                        nonce = "nonce12345678",
                    ),
                )

            assertIs<Ok<*>>(result)
            assertEquals("x509_san_dns:caller.example.com", result.value.request.clientId)
        }

    /**
     * The direct_post post-completion destination is pinned on the session, not on the request:
     * `redirect_uri` and `response_uri` are mutually exclusive on the wire, so the request object
     * must stay free of it while the value still has to survive to response time.
     */
    @Test
    fun directPostResponseRedirectUriIsPinnedOnTheSessionAndKeptOutOfTheRequest() =
        runTest {
            val store = TestAuthorizationSessionStore()
            val command =
                CreateAuthorizationRequestCommandImpl(
                    execution = testContext.execution,
                    authorizationSessionStore = store,
                    requestObjectSigningConfig =
                        com.sphereon.openid.oid4vp.verifier.requesturi.RequestObjectSigningConfig
                            .disabled(),
                )

            val result =
                command.createAuthorizationRequest(
                    CreateAuthorizationRequestArgs(
                        instanceId = "verifier-instance-direct-post-redirect",
                        dcqlQuery =
                            DcqlQuery(
                                credentials = listOf(DcqlCredentialQuery(id = "c", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential"))),
                            ),
                        clientId = "https://verifier.example.com",
                        responseUri = "https://verifier.example.com/response",
                        responseMode = ResponseMode.DIRECT_POST,
                        nonce = "nonce12345678",
                        directPostResponseRedirectUri = "https://app.example.com/done",
                    ),
                )

            assertIs<Ok<*>>(result)
            assertEquals(null, result.value.request.redirectUri)
            val session = store.get(result.value.sessionId!!).getOrNull()
            assertNotNull(session)
            assertEquals("https://app.example.com/done", session.directPostResponseRedirectUri)
        }

    /** A caller TTL decides the session lifetime; without one the store default applies. */
    @Test
    fun callerTtlDrivesTheStoredSessionExpiry() =
        runTest {
            val store = TestAuthorizationSessionStore()
            val command =
                CreateAuthorizationRequestCommandImpl(
                    execution = testContext.execution,
                    authorizationSessionStore = store,
                    requestObjectSigningConfig =
                        com.sphereon.openid.oid4vp.verifier.requesturi.RequestObjectSigningConfig
                            .disabled(),
                )

            val result =
                command.createAuthorizationRequest(
                    CreateAuthorizationRequestArgs(
                        instanceId = "verifier-instance-caller-ttl",
                        dcqlQuery =
                            DcqlQuery(
                                credentials = listOf(DcqlCredentialQuery(id = "c", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential"))),
                            ),
                        clientId = "https://verifier.example.com",
                        responseUri = "https://verifier.example.com/response",
                        responseMode = ResponseMode.DIRECT_POST,
                        nonce = "nonce12345678",
                        ttlSeconds = 42,
                    ),
                )

            assertIs<Ok<*>>(result)
            val entry = store.getEntry(result.value.sessionId!!).getOrNull()
            assertNotNull(entry)
            // The store TTL and the session's own expiresAt must agree — both derived from the
            // caller value, so a TTL no longer depends on whether a callback was configured.
            assertEquals(42_000L, entry.expiresAt - entry.createdAt)
            assertEquals(42_000L, entry.value.expiresAt - entry.value.createdAt)
        }

    @Test
    fun invalidCallerTtlsAreRejectedBeforePersistence() =
        runTest {
            listOf(0L, -1L, Long.MAX_VALUE).forEachIndexed { index, ttlSeconds ->
                val store = TestAuthorizationSessionStore()
                val command = createTestCommand(store)
                val result =
                    command.createAuthorizationRequest(
                        CreateAuthorizationRequestArgs(
                            instanceId = "verifier-instance-invalid-ttl-$index",
                            dcqlQuery =
                                DcqlQuery(
                                    credentials = listOf(DcqlCredentialQuery(id = "c", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:credential"))),
                                ),
                            clientId = "https://verifier.example.com",
                            responseUri = "https://verifier.example.com/response",
                            responseMode = ResponseMode.DIRECT_POST,
                            nonce = "nonce12345678",
                            state = "invalid-ttl-$index",
                            ttlSeconds = ttlSeconds,
                        ),
                    )

                assertEquals("ILLEGAL_ARGUMENT_ERROR", assertIs<Err<IdkError>>(result).error.code)
                assertEquals(false, store.exists("invalid-ttl-$index").getOrNull())
            }
        }

    @Test
    fun duplicateCallerStateCannotOverwriteAnExistingSession() =
        runTest {
            val store = TestAuthorizationSessionStore()
            val command = createTestCommand(store)
            val firstArgs =
                CreateAuthorizationRequestArgs(
                    instanceId = "verifier-instance-duplicate-state",
                    dcqlQuery =
                        DcqlQuery(
                            credentials = listOf(DcqlCredentialQuery(id = "first", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:first"))),
                        ),
                    clientId = "https://verifier.example.com",
                    responseUri = "https://verifier.example.com/response",
                    responseMode = ResponseMode.DIRECT_POST,
                    nonce = "firstNonce123",
                    state = "shared-business-key",
                )

            assertIs<Ok<*>>(command.createAuthorizationRequest(firstArgs))
            val duplicate =
                command.createAuthorizationRequest(
                    firstArgs.copy(
                        dcqlQuery =
                            DcqlQuery(
                                credentials = listOf(DcqlCredentialQuery(id = "second", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:second"))),
                            ),
                        nonce = "secondNonce123",
                    ),
                )

            assertEquals("ALREADY_EXISTS_ERROR", assertIs<Err<IdkError>>(duplicate).error.code)
            val persisted = store.get("shared-business-key").getOrNull()
            assertNotNull(persisted)
            assertEquals("firstNonce123", persisted.authorizationRequest.nonce)
            assertEquals(
                "first",
                persisted.dcqlQuery.credentials
                    .single()
                    .id,
            )
        }

    /** Helper: read client_id_scheme back out of the serialised request, because the
     *  AuthorizationRequest data class doesn't expose the enum directly. */
    private fun com.sphereon.oauth2.common.model.AuthorizationRequest.clientIdScheme(): ClientIdScheme {
        val scheme =
            additionalParameters["client_id_scheme"]?.let {
                (it as? kotlinx.serialization.json.JsonPrimitive)?.content
            } ?: return ClientIdScheme.PRE_REGISTERED
        return ClientIdScheme.entries.first { it.prefix == scheme }
    }

    private fun createTestCommand(sessionStore: AuthorizationSessionStore): CreateAuthorizationRequestCommandImpl =
        CreateAuthorizationRequestCommandImpl(
            execution = testContext.execution,
            authorizationSessionStore = sessionStore,
            requestObjectSigningConfig =
                com.sphereon.openid.oid4vp.verifier.requesturi.RequestObjectSigningConfig
                    .disabled(),
        )

    /** Stub config that returns a preset binding without touching KMS or DID providers. */
    private class StubSigningConfig(
        override val enabled: Boolean,
        private val binding: com.sphereon.openid.oid4vp.verifier.requesturi.VerifierSignerBinding?,
    ) : com.sphereon.openid.oid4vp.verifier.requesturi.RequestObjectSigningConfig {
        override val audience: String = "https://wallet.example.com"
        override val expirationSeconds: Long = 60

        override suspend fun resolveSigningKey(): com.sphereon.crypto.core.KeyInfoType<*> =
            com.sphereon.crypto.core
                .KeyInfo<Nothing>(alias = "stub")

        override suspend fun resolveSignerBinding(scheme: com.sphereon.openid.oid4vp.common.ClientIdScheme?) = binding
    }
}
