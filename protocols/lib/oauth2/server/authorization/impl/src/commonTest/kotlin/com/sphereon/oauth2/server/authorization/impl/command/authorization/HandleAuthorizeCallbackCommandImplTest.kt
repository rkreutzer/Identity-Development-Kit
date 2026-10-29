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

package com.sphereon.oauth2.server.authorization.impl.command.authorization

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.StringResult
import com.sphereon.oauth2.common.model.OAuth2ResponseMode
import com.sphereon.oauth2.server.authorization.command.AuthorizationResponseData
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationCodeArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationCodeCommand
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationResponseCommand
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeCallbackArgs
import com.sphereon.oauth2.server.authorization.impl.command.orchestration.StubAuthorizationServerService
import com.sphereon.oauth2.server.authorization.impl.storage.DefaultOidcLoginSessionIdProvider
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryOidcLoginSessionStore
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.model.AuthorizationSession
import com.sphereon.oauth2.server.authorization.provider.AuthenticatedUser
import com.sphereon.oauth2.server.authorization.provider.AuthenticationContext
import com.sphereon.oauth2.server.authorization.provider.AuthenticationError
import com.sphereon.oauth2.server.authorization.provider.AuthenticationHint
import com.sphereon.oauth2.server.authorization.provider.AuthenticationMethod
import com.sphereon.oauth2.server.authorization.provider.UserAuthenticationProvider
import com.sphereon.oauth2.server.authorization.provider.UserCredentials
import com.sphereon.oauth2.server.authorization.provider.UserInfo
import com.sphereon.oauth2.server.authorization.service.AuthorizationServerService
import com.sphereon.oauth2.server.authorization.storage.OidcLoginSession
import com.sphereon.oauth2.server.authorization.storage.PendingAuthorizationSessionStore
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

class HandleAuthorizeCallbackCommandImplTest {
    private val ctx = OAuth2ServerTestContext("handle-authorize-callback-test", this)

    @Test
    fun atomicConsumeFailureStopsCodeIssuanceEvenWhenLegacyPeekSucceeds() = runTest {
        val pending = session("atomic-consume-failure")
        var issuanceCalls = 0
        var consumeCalls = 0
        val store = object : PendingAuthorizationSessionStore {
            override suspend fun create(session: AuthorizationSession) = Ok(session)
            override suspend fun findById(sessionId: String) = Ok(pending)
            override suspend fun remove(sessionId: String) = Ok(Unit)
            override suspend fun consume(sessionId: String): IdkResult<AuthorizationSession?, IdkError> {
                consumeCalls++
                return Err(IdkError.fromString(code = "storage_error", message = "atomic write unavailable"))
            }
        }
        val service = service(
            stubCreateAuthorizationCode { issuanceCalls++; Ok(StringResult(value = "must-not-be-issued")) },
            stubCreateAuthorizationResponse { args -> Ok(AuthorizationResponseData(args.code, args.state, args.redirectUri)) },
        )
        val auth = FakeUserAuthenticationProvider(AuthenticatedUser(userId = "user-1", authenticatedAt = Clock.System.now(), authenticationMethod = AuthenticationMethod.PASSWORD))
        val command = HandleAuthorizeCallbackCommandImpl(ctx.execution, service, store, auth, DefaultOidcLoginSessionIdProvider(), InMemoryOidcLoginSessionStore(Clock.System))
        val result = command.execute(HandleAuthorizeCallbackArgs(sessionId = pending.sessionId))
        assertTrue(result.isErr)
        assertEquals("storage_error", result.error.code)
        assertEquals(1, consumeCalls)
        assertEquals(0, issuanceCalls)
    }

    private fun stubCreateAuthorizationCode(handler: suspend (CreateAuthorizationCodeArgs) -> IdkResult<StringResult, IdkError>): CreateAuthorizationCodeCommand =
        object : CreateAuthorizationCodeCommand {
            override val inputTypeToken = typeToken<CreateAuthorizationCodeArgs>()
            override val outputTypeToken = typeToken<StringResult>()
            override val isEnabled = true

            override suspend fun execute(args: CreateAuthorizationCodeArgs) = handler(args)
        }

    private fun stubCreateAuthorizationResponse(handler: suspend (CreateAuthorizationResponseArgs) -> IdkResult<AuthorizationResponseData, IdkError>): CreateAuthorizationResponseCommand =
        object : CreateAuthorizationResponseCommand {
            override val inputTypeToken = typeToken<CreateAuthorizationResponseArgs>()
            override val outputTypeToken = typeToken<AuthorizationResponseData>()
            override val isEnabled = true

            override suspend fun execute(args: CreateAuthorizationResponseArgs) = handler(args)
        }

    private fun service(
        codeStub: CreateAuthorizationCodeCommand,
        responseStub: CreateAuthorizationResponseCommand,
    ): AuthorizationServerService =
        object : StubAuthorizationServerService() {
            override val commands: AuthorizationServerService.Commands = TestCommands(codeStub, responseStub)
        }

    private class TestCommands(
        private val codeStub: CreateAuthorizationCodeCommand,
        private val responseStub: CreateAuthorizationResponseCommand,
    ) : AuthorizationServerService.Commands {
        override val parseTokenRequest get(): com.sphereon.oauth2.server.authorization.command.ParseTokenRequestCommand = throw NotImplementedError()
        override val verifyAuthorizationCodeGrant get(): com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantCommand = throw NotImplementedError()
        override val verifyRefreshTokenGrant get(): com.sphereon.oauth2.server.authorization.command.VerifyRefreshTokenGrantCommand = throw NotImplementedError()
        override val verifyClientCredentialsGrant get(): com.sphereon.oauth2.server.authorization.command.VerifyClientCredentialsGrantCommand = throw NotImplementedError()
        override val verifyPreAuthorizedCodeGrant get(): com.sphereon.oauth2.server.authorization.command.VerifyPreAuthorizedCodeGrantCommand = throw NotImplementedError()
        override val createAccessToken get(): com.sphereon.oauth2.server.authorization.command.CreateAccessTokenCommand = throw NotImplementedError()
        override val createRefreshToken get(): com.sphereon.oauth2.server.authorization.command.CreateRefreshTokenCommand = throw NotImplementedError()
        override val createTokenResponse get(): com.sphereon.oauth2.server.authorization.command.CreateTokenResponseCommand = throw NotImplementedError()
        override val parseAuthorizationRequest get(): com.sphereon.oauth2.server.authorization.command.ParseAuthorizationRequestCommand = throw NotImplementedError()
        override val verifyAuthorizationRequest get(): com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationRequestCommand = throw NotImplementedError()
        override val createAuthorizationSession get(): com.sphereon.oauth2.server.authorization.command.CreateAuthorizationSessionCommand = throw NotImplementedError()
        override val createAuthorizationCode get() = codeStub
        override val createAuthorizationResponse get() = responseStub
        override val createAuthorizationErrorResponse get(): com.sphereon.oauth2.server.authorization.command.CreateAuthorizationErrorResponseCommand = throw NotImplementedError()
        override val parsePushedAuthorizationRequest get(): com.sphereon.oauth2.server.authorization.command.ParsePushedAuthorizationRequestCommand = throw NotImplementedError()
        override val verifyPushedAuthorizationRequest get(): com.sphereon.oauth2.server.authorization.command.VerifyPushedAuthorizationRequestCommand = throw NotImplementedError()
        override val createRequestUri get(): com.sphereon.oauth2.server.authorization.command.CreateRequestUriCommand = throw NotImplementedError()
        override val createPushedAuthorizationResponse get(): com.sphereon.oauth2.server.authorization.command.CreatePushedAuthorizationResponseCommand = throw NotImplementedError()
        override val retrieveAuthorizationRequestByUri get(): com.sphereon.oauth2.server.authorization.command.RetrieveAuthorizationRequestByUriCommand = throw NotImplementedError()
        override val parseIntrospectionRequest get(): com.sphereon.oauth2.server.authorization.command.ParseIntrospectionRequestCommand = throw NotImplementedError()
        override val introspectToken get(): com.sphereon.oauth2.server.authorization.command.IntrospectTokenCommand = throw NotImplementedError()
        override val parseRevocationRequest get(): com.sphereon.oauth2.server.authorization.command.ParseRevocationRequestCommand = throw NotImplementedError()
        override val revokeToken get(): com.sphereon.oauth2.server.authorization.command.RevokeTokenCommand = throw NotImplementedError()
        override val buildServerMetadata get(): com.sphereon.oauth2.server.authorization.command.BuildServerMetadataCommand = throw NotImplementedError()
        override val verifyClientAuthentication get(): com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand = throw NotImplementedError()
        override val createAttestationChallenge get(): com.sphereon.oauth2.server.authorization.command.CreateAttestationChallengeCommand = throw NotImplementedError()
        override val createIdToken get(): com.sphereon.oauth2.server.authorization.command.CreateIdTokenCommand = throw NotImplementedError()
        override val getUserInfo get(): com.sphereon.oauth2.server.authorization.command.GetUserInfoCommand = throw NotImplementedError()
        override val getJwks get(): com.sphereon.oauth2.server.authorization.command.GetJwksCommand = throw NotImplementedError()
    }

    /**
     * In-memory pending session store seeded with the given sessions.
     */
    private class FakePendingAuthorizationSessionStore(
        seed: Map<String, AuthorizationSession> = emptyMap(),
    ) : PendingAuthorizationSessionStore {
        val map = seed.toMutableMap()
        var removeCalls = 0

        override suspend fun create(session: AuthorizationSession): IdkResult<AuthorizationSession, IdkError> {
            map[session.sessionId] = session
            return Ok(session)
        }

        override suspend fun findById(sessionId: String): IdkResult<AuthorizationSession?, IdkError> = Ok(map[sessionId])

        override suspend fun consume(sessionId: String): IdkResult<AuthorizationSession?, IdkError> {
            removeCalls += 1
            return Ok(map.remove(sessionId))
        }

        override suspend fun remove(sessionId: String): IdkResult<Unit, IdkError> {
            removeCalls += 1
            map.remove(sessionId)
            return Ok(Unit)
        }
    }

    private class FakeUserAuthenticationProvider(
        private val authenticatedUser: AuthenticatedUser? = null,
        private val authError: AuthenticationError? = null,
    ) : UserAuthenticationProvider {
        val requestedSessionIds = mutableListOf<String>()

        override suspend fun getAuthenticatedUser(sessionId: String): IdkResult<AuthenticatedUser?, AuthenticationError> {
            requestedSessionIds += sessionId
            authError?.let { return Err(it) }
            return Ok(authenticatedUser)
        }

        override suspend fun initiateAuthentication(
            sessionId: String,
            returnUrl: String,
            hint: AuthenticationHint?,
            context: AuthenticationContext?
        ): IdkResult<String, AuthenticationError> = Err(AuthenticationError.Generic(description = "unused"))

        override suspend fun authenticateWithCredentials(
            credentials: UserCredentials,
            context: AuthenticationContext?
        ): IdkResult<String?, AuthenticationError> = Ok(null)

        override suspend fun logout(userId: String): IdkResult<Unit, AuthenticationError> = Ok(Unit)

        override suspend fun getUserInfo(userId: String): IdkResult<UserInfo, AuthenticationError> = Ok(UserInfo(userId = userId))

        override suspend fun isAuthenticationMethodAvailable(method: AuthenticationMethod): IdkResult<Boolean, AuthenticationError> = Ok(false)
    }

    @Test
    fun successPathThreadsThroughCreateCodeAndCreateResponse() =
        runTest {
            var seenCodeArgs: CreateAuthorizationCodeArgs? = null
            val service =
                service(
                    codeStub =
                        stubCreateAuthorizationCode { args ->
                            seenCodeArgs = args
                            Ok(StringResult(value = "AC-1"))
                        },
                    responseStub =
                        stubCreateAuthorizationResponse { args ->
                            Ok(
                                AuthorizationResponseData(
                                    redirectUri = "${args.redirectUri}?code=${args.code}&state=${args.state}",
                                    code = args.code,
                                    state = args.state,
                                    responseMode = args.responseMode,
                                ),
                            )
                        },
                )
            val session = session("sess-1", state = "s-42")
            val store = FakePendingAuthorizationSessionStore(mapOf(session.sessionId to session))
            val authProvider =
                FakeUserAuthenticationProvider(
                    authenticatedUser =
                        AuthenticatedUser(
                            userId = "user-1",
                            authenticatedAt = Clock.System.now(),
                            authenticationMethod = AuthenticationMethod.PASSWORD,
                        ),
                )
            val command =
                HandleAuthorizeCallbackCommandImpl(
                    ctx.execution,
                    service,
                    store,
                    authProvider,
                    DefaultOidcLoginSessionIdProvider(),
                    InMemoryOidcLoginSessionStore(Clock.System),
                )

            val result =
                command.execute(
                    HandleAuthorizeCallbackArgs(
                        sessionId = session.sessionId,
                        authenticationSessionId = "wallet-session-1",
                    ),
                )

            assertTrue(result.isOk)
            assertEquals("AC-1", result.value.code)
            assertEquals("s-42", result.value.state)
            val captured = seenCodeArgs
            assertTrue(captured != null)
            assertEquals(session.sessionId, captured.session.sessionId)
            assertEquals("user-1", captured.userId)
            assertEquals(1, store.removeCalls)
            assertEquals(listOf("wallet-session-1"), authProvider.requestedSessionIds)
        }

    @Test
    fun firstPartyLoginSessionClaimsReachAuthorizationCode() =
        runTest {
            var seenCodeArgs: CreateAuthorizationCodeArgs? = null
            val service =
                service(
                    codeStub =
                        stubCreateAuthorizationCode { args ->
                            seenCodeArgs = args
                            Ok(StringResult(value = "AC-FIRST-PARTY"))
                        },
                    responseStub =
                        stubCreateAuthorizationResponse { args ->
                            Ok(
                                AuthorizationResponseData(
                                    redirectUri = "${args.redirectUri}?code=${args.code}",
                                    code = args.code,
                                    state = args.state,
                                    responseMode = args.responseMode,
                                ),
                            )
                        },
                )
            val pending = session("pending-first-party")
            val pendingStore = FakePendingAuthorizationSessionStore(mapOf(pending.sessionId to pending))
            val loginSessionIdProvider = DefaultOidcLoginSessionIdProvider()
            loginSessionIdProvider.setCurrentLoginSessionId("login-first-party")
            val loginSessionStore = InMemoryOidcLoginSessionStore(Clock.System)
            val now = Clock.System.now()
            loginSessionStore.create(
                OidcLoginSession(
                    sessionId = "login-first-party",
                    sub = "tenant-owner-1",
                    authTime = now,
                    authMethod = AuthenticationMethod.PASSWORD,
                    claims =
                        mapOf(
                            "roles" to JsonArray(listOf(JsonPrimitive("tenant-admin"))),
                        ),
                    createdAt = now,
                    absoluteExpiresAt = now + 10.minutes,
                    idleExpiresAt = now + 10.minutes,
                ),
            )
            val command =
                HandleAuthorizeCallbackCommandImpl(
                    ctx.execution,
                    service,
                    pendingStore,
                    FakeUserAuthenticationProvider(),
                    loginSessionIdProvider,
                    loginSessionStore,
                )

            val result = command.execute(HandleAuthorizeCallbackArgs(sessionId = pending.sessionId))

            assertTrue(result.isOk)
            assertEquals(
                JsonArray(listOf(JsonPrimitive("tenant-admin"))),
                seenCodeArgs?.userClaims?.get("roles"),
                "server-authenticated first-party session roles must survive the callback path",
            )
        }

    @Test
    fun missingPendingSessionReturnsInvalidRequest() =
        runTest {
            val service =
                service(
                    codeStub = stubCreateAuthorizationCode { error("not invoked") },
                    responseStub = stubCreateAuthorizationResponse { error("not invoked") },
                )
            val command =
                HandleAuthorizeCallbackCommandImpl(
                    ctx.execution,
                    service,
                    FakePendingAuthorizationSessionStore(),
                    FakeUserAuthenticationProvider(),
                    DefaultOidcLoginSessionIdProvider(),
                    InMemoryOidcLoginSessionStore(Clock.System),
                )

            val result = command.execute(HandleAuthorizeCallbackArgs(sessionId = "missing"))

            assertTrue(result.isErr)
            assertEquals("invalid_request", result.error.code)
        }

    @Test
    fun createCodeFailureSurfacesError() =
        runTest {
            val service =
                service(
                    codeStub = stubCreateAuthorizationCode { Err(IdkError.fromString(code = "server_error", message = "code-issue-fail")) },
                    responseStub = stubCreateAuthorizationResponse { error("createAuthorizationResponse should not be called when code creation fails") },
                )
            val session = session("sess-2")
            val store = FakePendingAuthorizationSessionStore(mapOf(session.sessionId to session))
            val authProvider =
                FakeUserAuthenticationProvider(
                    authenticatedUser =
                        AuthenticatedUser(
                            userId = "user-2",
                            authenticatedAt = Clock.System.now(),
                            authenticationMethod = AuthenticationMethod.PASSWORD,
                        ),
                )
            val command =
                HandleAuthorizeCallbackCommandImpl(
                    ctx.execution,
                    service,
                    store,
                    authProvider,
                    DefaultOidcLoginSessionIdProvider(),
                    InMemoryOidcLoginSessionStore(Clock.System),
                )

            val result = command.execute(HandleAuthorizeCallbackArgs(sessionId = session.sessionId))

            assertTrue(result.isErr)
            assertEquals("server_error", result.error.code)
        }

    private fun session(
        id: String,
        state: String? = null,
    ): AuthorizationSession {
        val now = Clock.System.now()
        return AuthorizationSession(
            sessionId = id,
            clientId = "client-$id",
            state = state,
            responseType = "code",
            responseMode = OAuth2ResponseMode.QUERY,
            redirectUri = "https://rp.example/callback",
            createdAt = now,
            expiresAt = now + 10.minutes,
        )
    }
}
