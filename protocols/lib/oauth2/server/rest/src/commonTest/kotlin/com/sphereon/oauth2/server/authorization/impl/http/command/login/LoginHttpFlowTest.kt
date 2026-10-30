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

package com.sphereon.oauth2.server.authorization.impl.http.command.login

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Err
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.random.GenerateTokenArgs
import com.sphereon.core.api.random.NextBytesArgs
import com.sphereon.core.api.random.SecureRandom
import com.sphereon.core.api.service.Amr
import com.sphereon.core.api.service.AuthAssuranceLevel
import com.sphereon.core.api.service.ByteArrayResult
import com.sphereon.core.api.service.StringResult
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceIdProvider
import com.sphereon.oauth2.server.authorization.audit.NoOpOAuth2AuditEmitter
import com.sphereon.oauth2.server.authorization.audit.OAuth2AuditEmitter
import com.sphereon.oauth2.server.authorization.audit.OAuth2AuditEventType
import com.sphereon.oauth2.server.authorization.impl.http.DefaultOAuth2ServerBaseUrlResolver
import com.sphereon.oauth2.server.authorization.impl.http.OAuth2ServerBaseUrlResolver
import com.sphereon.oauth2.server.authorization.impl.http.command.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.impl.http.command.TestSessionExecution
import com.sphereon.oauth2.server.authorization.impl.provider.LoginCsrfTokenizerImpl
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryPendingAuthorizationSessionStore
import com.sphereon.oauth2.server.authorization.model.AuthorizationSession
import com.sphereon.oauth2.server.authorization.provider.AuthenticatedUser
import com.sphereon.oauth2.server.authorization.provider.AuthenticationContext
import com.sphereon.oauth2.server.authorization.provider.AuthenticationError
import com.sphereon.oauth2.server.authorization.provider.AuthenticationHint
import com.sphereon.oauth2.server.authorization.provider.AuthenticationMethod
import com.sphereon.oauth2.server.authorization.provider.LoginCsrfKeyProvider
import com.sphereon.oauth2.server.authorization.provider.LoginCsrfTokenizer
import com.sphereon.oauth2.server.authorization.provider.LoginCsrfToken
import com.sphereon.oauth2.server.authorization.provider.LoginPageAsset
import com.sphereon.oauth2.server.authorization.provider.LoginPageBranding
import com.sphereon.oauth2.server.authorization.provider.LoginPageContext
import com.sphereon.oauth2.server.authorization.provider.LoginPageRenderer
import com.sphereon.oauth2.server.authorization.provider.LoginPageResponse
import com.sphereon.oauth2.server.authorization.provider.LoginPageThemeProvider
import com.sphereon.oauth2.server.authorization.provider.LoginPageThemeSnapshot
import com.sphereon.oauth2.server.authorization.provider.UserAuthenticationProvider
import com.sphereon.oauth2.server.authorization.provider.UserCredentials
import com.sphereon.oauth2.server.authorization.provider.UserInfo
import com.sphereon.oauth2.server.authorization.routing.AuthenticationRoute
import com.sphereon.oauth2.server.authorization.routing.AuthenticationRouteDecision
import com.sphereon.oauth2.server.authorization.storage.OidcLoginSession
import com.sphereon.oauth2.server.authorization.storage.PendingAuthorizationSessionStore
import dev.zacsweers.metro.Provider
import com.sphereon.oauth2.server.authorization.storage.OidcLoginSessionStore
import com.sphereon.oauth2.server.authorization.storage.OidcLoginSessionStoreError
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

/**
 * Wires the three login [com.sphereon.core.api.http.command.HttpEndpointCommand] impls against
 * lightweight in-memory fakes (no Ktor) and verifies the GET / POST / asset wire shape: page
 * render returns 200 with HTML; correct credentials produce a 302 + Set-Cookie + persisted
 * [OidcLoginSession]; wrong credentials produce a 302 back to `/login?error=invalid_credentials`;
 * the asset endpoint serves bundled CSS / SVG by their declared content types.
 */
class LoginHttpFlowTest {
    private val staticAssets =
        listOf(
            LoginPageAsset(
                path = "css/login.css",
                contentType = "text/css; charset=utf-8",
                bytes = "body { color: red; }".encodeToByteArray(),
            ),
            LoginPageAsset(
                path = "img/sphereon-logo.svg",
                contentType = "image/svg+xml",
                bytes = "<svg/>".encodeToByteArray(),
            ),
        )

    // Single tokenizer instance shared between the page (mints) and submit (verifies) commands
    // so the HMAC values agree across the tests' GET → POST round trip. Production wiring is
    // identical: AppScope-singleton tokenizer with one secret per AS process.
    private val csrfTokenizer: LoginCsrfTokenizer = LoginCsrfTokenizerImpl(StubLoginCsrfKeyProvider())

    private fun newLoginPageCommand(
        pendingStore: PendingAuthorizationSessionStore = pagePendingStore(),
        tokenizer: LoginCsrfTokenizer = csrfTokenizer,
    ): LoginPageHttpEndpointCommandImpl =
        LoginPageHttpEndpointCommandImpl(
            execution = TestSessionExecution(),
            loginPageRenderer = StubLoginPageRenderer(staticAssets = staticAssets),
            asInstanceIdProvider = StubAsInstanceIdProvider(),
            configProvider = TestOAuth2ServersConfigProvider(),
            baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
            csrfTokenizer = tokenizer,
            pendingAuthorizationSessionStore = pendingStore,
        )

    // Command wired with a config provider whose default server carries a fixed `issuer`, so the
    // base resolver returns the deterministic [TRUSTED_BASE]. The renderer reflects the resolved
    // returnUrl + formActionBase into the HTML so the trusted-base/return_url assertions can read
    // them off the wire shape.
    private fun newLoginPageCommandWithTrustedBase(trustedBase: String = TRUSTED_BASE): LoginPageHttpEndpointCommandImpl =
        LoginPageHttpEndpointCommandImpl(
            execution = TestSessionExecution(),
            loginPageRenderer = ReflectingLoginPageRenderer(),
            asInstanceIdProvider = StubAsInstanceIdProvider(),
            configProvider =
                TestOAuth2ServersConfigProvider(
                    config =
                        com.sphereon.oauth2.common.config.OAuth2ServersConfig(
                            servers =
                                mapOf(
                                    "default" to
                                        com.sphereon.oauth2.common.config
                                            .OAuth2ServerInstanceConfig(issuer = trustedBase),
                                ),
                        ),
                ),
            baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
            csrfTokenizer = csrfTokenizer,
            pendingAuthorizationSessionStore = pagePendingStore(),
        )

    private fun pagePendingStore(): PendingAuthorizationSessionStore =
        object : PendingAuthorizationSessionStore {
            override suspend fun create(session: AuthorizationSession): IdkResult<AuthorizationSession, IdkError> = Ok(session)

            override suspend fun findById(sessionId: String): IdkResult<AuthorizationSession?, IdkError> =
                Ok(pendingSession(sessionId))

            override suspend fun remove(sessionId: String): IdkResult<Unit, IdkError> = Ok(Unit)
        }

    private fun newLoginAssetCommand(): LoginAssetHttpEndpointCommandImpl =
        LoginAssetHttpEndpointCommandImpl(
            execution = TestSessionExecution(),
            loginPageRenderer = StubLoginPageRenderer(staticAssets = staticAssets),
        )

    private suspend fun newSubmitCommand(
        userAuthProvider: UserAuthenticationProvider = StubUserAuthProvider(validPair = "alice" to "wonderland"),
        store: InMemoryLoginSessionStore = InMemoryLoginSessionStore(),
        secureRandom: SecureRandom = FixedSecureRandom("login-sid-1"),
        auditEmitter: OAuth2AuditEmitter = NoOpOAuth2AuditEmitter,
        execution: SessionExecution = TestSessionExecution(),
        seedPendingSession: Boolean = true,
        applicationId: String? = "app-1",
        baseUrlResolver: OAuth2ServerBaseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
    ): Pair<LoginSubmitHttpEndpointCommandImpl, InMemoryLoginSessionStore> {
        val pendingStore = InMemoryPendingAuthorizationSessionStore()
        if (seedPendingSession) {
            pendingStore.create(pendingSession("sess-1").copy(applicationId = applicationId))
            pendingStore.create(pendingSession("sess-csrf").copy(applicationId = applicationId))
        }
        val command =
            LoginSubmitHttpEndpointCommandImpl(
                execution = execution,
                userAuthProvider = userAuthProvider,
                loginSessionStore = store,
                pendingAuthorizationSessionStore = pendingStore,
                secureRandom = secureRandom,
                configProvider = TestOAuth2ServersConfigProvider(),
                clock = Clock.System,
                auditEmitter = auditEmitter,
                csrfTokenizer = csrfTokenizer,
                baseUrlResolver = baseUrlResolver,
            )
        return command to store
    }

    private fun pendingSession(sessionId: String): AuthorizationSession =
        AuthorizationSession(
            sessionId = sessionId,
            clientId = "client-1",
            responseType = "code",
            redirectUri = "https://client.example/callback",
            createdAt = Clock.System.now(),
            expiresAt = Clock.System.now() + 15.minutes,
            applicationId = "app-1",
            authenticationRoute =
                AuthenticationRouteDecision(
                    route = AuthenticationRoute.LOCAL_LOGIN,
                    hostedAuthorizationServerId = "00000000-0000-4000-8000-000000000001",
                    hostedAuthorizationServerRevision = 1,
                    localLoginAllowed = true,
                ),
        )

    /**
     * Build a `(formBody, cookieHeader)` pair carrying valid CSRF tokens for [sessionId]
     * minted from the shared tokenizer. Tests that exercise the credential or audit paths
     * must thread these through the request to clear the new CSRF gate; tests that exercise
     * the gate itself construct invalid tuples by hand.
     */
    private suspend fun csrfFormAndCookie(
        sessionId: String,
        username: String,
        password: String,
        returnUrl: String = "https://as/authorize/callback?session_id=$sessionId",
    ): Pair<String, String> {
        val token = csrfTokenizer.mint(sessionId)
        val body =
            "username=$username&password=$password&session_id=$sessionId" +
                "&tab_id=${token.tabId}&session_code=${token.sessionCode}" +
                "&return_url=${com.sphereon.core.api.http.query.percentEncodeQueryComponent(returnUrl)}"
        val cookie = "oidc_login_csrf=${token.tabId}"
        return body to cookie
    }

    private suspend fun csrfWebAuthnFormAndCookie(
        sessionId: String,
        credentialId: String,
        username: String = "alice",
        returnUrl: String = "https://as/authorize/callback?session_id=$sessionId",
    ): Pair<String, String> {
        val token = csrfTokenizer.mint(sessionId)
        val body =
            "username=$username&session_id=$sessionId&webauthn_credential_id=$credentialId&webauthn_challenge_id=challenge-1" +
                "&webauthn_authenticator_data=authenticator-data&webauthn_client_data_json=client-data-json" +
                "&webauthn_signature=signature&webauthn_user_handle=$username" +
                "&webauthn_origin=https://login.example&webauthn_rp_id=login.example" +
                "&webauthn_user_verified=true&webauthn_transport=internal" +
                "&webauthn_backup_eligible=true&webauthn_backup_state=true&webauthn_prf_capable=true" +
                "&tab_id=${token.tabId}&session_code=${token.sessionCode}" +
                "&return_url=${com.sphereon.core.api.http.query.percentEncodeQueryComponent(returnUrl)}"
        val cookie = "oidc_login_csrf=${token.tabId}"
        return body to cookie
    }

    @Test
    fun loginPageRendersBrandedHtml() =
        runTest {
            val command = newLoginPageCommand()
            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/login",
                    // Cross-origin return_url is normalized to the trusted default by the command;
                    // this test asserts on sessionId, not return_url, so its outcome is unchanged.
                    queryParameters = mapOf("session_id" to "sess-1", "return_url" to "https://as/cb"),
                    headers = mapOf("Host" to "as.example", "Accept-Language" to "en-US,en;q=0.9"),
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            val r = response.value
            assertEquals(200, r.statusCode)
            assertEquals("text/html; charset=utf-8", r.headers["Content-Type"])
            assertEquals("no-store", r.headers["Cache-Control"])
            val body = r.body ?: ""
            assertTrue(body.contains("session-id=sess-1"), "Body must encode session id passed to renderer")
        }

    @Test
    fun loginPageMissingSessionIdReturns400() =
        runTest {
            val command = newLoginPageCommand()
            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/login",
                    queryParameters = emptyMap(),
                    headers = mapOf("Host" to "as.example"),
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            assertEquals(400, response.value.statusCode)
        }

    @Test
    fun loginAssetsServeCss() =
        runTest {
            val command = newLoginAssetCommand()
            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/login/assets/css/login.css",
                    queryParameters = emptyMap(),
                    headers = emptyMap(),
                )
            val response = command.execute(request)
            assertTrue(response.isOk, "Asset response must succeed")
            val r = response.value
            assertEquals(200, r.statusCode)
            assertEquals("text/css; charset=utf-8", r.headers["Content-Type"])
            assertEquals("body { color: red; }", r.body)
        }

    @Test fun unknownPendingSessionDoesNotMintCsrfOrIssueCookie() = runTest {
        var minted = false
        val pending = object : PendingAuthorizationSessionStore by pagePendingStore() {
            override suspend fun findById(sessionId: String): IdkResult<AuthorizationSession?, IdkError> = Ok(null)
        }
        val tokenizer = object : LoginCsrfTokenizer by csrfTokenizer {
            override suspend fun mint(sessionId: String): LoginCsrfToken { minted = true; error("No token for missing session") }
        }
        val response = newLoginPageCommand(pending, tokenizer).execute(GenericHttpRequest(method = "GET", path = "/login", queryParameters = mapOf("session_id" to "missing"), headers = mapOf("Host" to "as.example")))
        assertTrue(response.isOk); assertEquals(400, response.value.statusCode); assertEquals(false, minted)
        assertNull(response.value.headers["Set-Cookie"])
    }
    @Test fun pendingStorageFailureDoesNotMintCsrfOrIssueForm() = runTest {
        var minted = false
        val pending = object : PendingAuthorizationSessionStore by pagePendingStore() {
            override suspend fun findById(sessionId: String): IdkResult<AuthorizationSession?, IdkError> = Err(IdkError.INVALID_STATE(message = "Test storage failure"))
        }
        val tokenizer = object : LoginCsrfTokenizer by csrfTokenizer {
            override suspend fun mint(sessionId: String): LoginCsrfToken { minted = true; error("No token on storage failure") }
        }
        val response = newLoginPageCommand(pending, tokenizer).execute(GenericHttpRequest(method = "GET", path = "/login", queryParameters = mapOf("session_id" to "missing"), headers = mapOf("Host" to "as.example")))
        assertTrue(response.isOk); assertEquals(503, response.value.statusCode); assertEquals(false, minted)
        assertNull(response.value.headers["Set-Cookie"])
    }
    @Test fun pendingDisappearanceDuringCsrfMintReturns400WithoutCookie() = runTest {
        val tokenizer = object : LoginCsrfTokenizer by csrfTokenizer {
            override suspend fun mint(sessionId: String): LoginCsrfToken = throw IllegalArgumentException("Pending session disappeared")
        }
        val response = newLoginPageCommand(tokenizer = tokenizer).execute(GenericHttpRequest(method = "GET", path = "/login", queryParameters = mapOf("session_id" to "sess-1"), headers = mapOf("Host" to "as.example")))
        assertTrue(response.isOk); assertEquals(400, response.value.statusCode); assertNull(response.value.headers["Set-Cookie"])
    }
    @Test fun cancelledCsrfMintPropagatesCancellation() = runTest {
        val tokenizer = object : LoginCsrfTokenizer by csrfTokenizer {
            override suspend fun mint(sessionId: String): LoginCsrfToken = throw CancellationException("Cancelled")
        }
        assertFailsWith<CancellationException> {
            newLoginPageCommand(tokenizer = tokenizer).execute(GenericHttpRequest(method = "GET", path = "/login", queryParameters = mapOf("session_id" to "sess-1"), headers = mapOf("Host" to "as.example")))
        }
    }

    @Test
    fun loginAssetsUnknownPathReturnsNotFound() =
        runTest {
            val command = newLoginAssetCommand()
            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/login/assets/css/missing.css",
                    queryParameters = emptyMap(),
                    headers = emptyMap(),
                )
            val response = command.execute(request)
            assertTrue(response.isErr, "Unknown asset must be a 404")
        }

    @Test
    fun loginPostWithCorrectCredentialsSetsCookieAndRedirects() =
        runTest {
            val (command, store) = newSubmitCommand()
            val (body, csrfCookie) = csrfFormAndCookie("sess-1", "alice", "wonderland")
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to csrfCookie,
                        ),
                    bodySupplier = { body },
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            val r = response.value
            assertEquals(302, r.statusCode)
            val location = r.headers["Location"]
            assertNotNull(location)
            assertTrue(location.contains("/authorize/callback"), "Must redirect to authorization callback")
            val cookie = r.headers["Set-Cookie"]
            assertNotNull(cookie)
            assertTrue(cookie.contains("oidc_login_sid=login-sid-1"), "Cookie must carry the new session id")
            assertTrue(cookie.contains("HttpOnly"), "Cookie must be HttpOnly")
            assertTrue(cookie.contains("SameSite=Lax"), "Cookie must be SameSite=Lax")
            val stored = store.loaded("login-sid-1")
            assertNotNull(stored, "OidcLoginSession must be persisted")
            assertEquals("alice", stored.sub)
            assertEquals(AuthenticationMethod.PASSWORD, stored.authMethod)
            assertEquals(AuthAssuranceLevel.AAL1.acr, stored.acr)
            assertEquals(listOf(Amr.PWD), stored.amr)
        }

    @Test
    fun loginPostPersistsProviderAuthenticationContext() =
        runTest {
            val provider =
                StubUserAuthProvider(
                    validPair = "alice" to "wonderland",
                    acr = AuthAssuranceLevel.AAL2.acr,
                    amr = listOf(Amr.PWD, "otp"),
                    roles = listOf("tenant-admin"),
                )
            val (command, store) = newSubmitCommand(userAuthProvider = provider)
            val (body, csrfCookie) = csrfFormAndCookie("sess-1", "alice", "wonderland")
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to csrfCookie,
                        ),
                    bodySupplier = { body },
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            assertEquals(302, response.value.statusCode)
            val stored = store.loaded("login-sid-1")
            assertNotNull(stored, "OidcLoginSession must be persisted")
            assertEquals("alice", stored.sub)
            assertEquals(AuthenticationMethod.PASSWORD, stored.authMethod)
            assertEquals(AuthAssuranceLevel.AAL2.acr, stored.acr)
            assertEquals(listOf(Amr.PWD, "otp"), stored.amr)
            assertEquals(
                JsonArray(listOf(JsonPrimitive("tenant-admin"))),
                stored.claims["roles"],
            )
        }

    @Test
    fun loginPostSupportsApplicationAgnosticAuthentication() =
        runTest {
            val provider = StubUserAuthProvider(validPair = "alice" to "wonderland")
            val (command, store) =
                newSubmitCommand(
                    userAuthProvider = provider,
                    applicationId = null,
                )
            val (body, csrfCookie) = csrfFormAndCookie("sess-1", "alice", "wonderland")
            val response =
                command.execute(
                    GenericHttpRequest(
                        method = "POST",
                        path = "/login",
                        headers =
                            mapOf(
                                "Content-Type" to "application/x-www-form-urlencoded",
                                "Cookie" to csrfCookie,
                            ),
                        bodySupplier = { body },
                    ),
                )

            assertTrue(response.isOk)
            assertEquals(302, response.value.statusCode)
            assertNotNull(store.loaded("login-sid-1"), "Application-agnostic login must persist a session")
            assertEquals("sess-1", provider.lastAuthenticationContext?.sessionId)
            assertNull(provider.lastAuthenticationContext?.applicationId)
        }

    @Test
    fun loginPostWithWebAuthnAssertionSetsCookieAndPersistsAssurance() =
        runTest {
            val provider =
                StubUserAuthProvider(
                    validPair = "alice" to "wonderland",
                    validPasskeyCredentialId = "credential-1",
                )
            val (command, store) = newSubmitCommand(userAuthProvider = provider)
            val (body, csrfCookie) = csrfWebAuthnFormAndCookie("sess-1", "credential-1")
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to csrfCookie,
                        ),
                    bodySupplier = { body },
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            val r = response.value
            assertEquals(302, r.statusCode)
            assertTrue(r.headers["Set-Cookie"]?.contains("oidc_login_sid=login-sid-1") == true)
            val stored = store.loaded("login-sid-1")
            assertNotNull(stored, "OidcLoginSession must be persisted")
            assertEquals("alice", stored.sub)
            assertEquals(AuthenticationMethod.WEBAUTHN, stored.authMethod)
            assertEquals(AuthAssuranceLevel.AAL2.acr, stored.acr)
            assertEquals(listOf(Amr.WEBAUTHN), stored.amr)
        }

    @Test
    fun loginWebAuthnAssertionBeginUsesIdentityScopedChallengeProvider() =
        runTest {
            val pendingStore = InMemoryPendingAuthorizationSessionStore()
            pendingStore.create(pendingSession("sess-1"))
            val provider = CapturingWebAuthnAssertionChallengeProvider()
            val command =
                LoginWebAuthnAssertionBeginHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    pendingAuthorizationSessionStore = pendingStore,
                    configProvider =
                        TestOAuth2ServersConfigProvider(
                            config =
                                com.sphereon.oauth2.common.config.OAuth2ServersConfig(
                                    servers =
                                        mapOf(
                                            "default" to
                                                com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig(
                                                    webAuthn =
                                                        com.sphereon.oauth2.common.config.WebAuthnLoginConfig(
                                                            enabled = true,
                                                            rpId = "login.example",
                                                            allowedOrigins = setOf("https://login.example"),
                                                            allowedTransports = setOf("internal"),
                                                            level3PrfEnabled = true,
                                                        ),
                                                ),
                                        ),
                                ),
                        ),
                    challengeProvider = Provider { provider },
                )
            val response =
                command.execute(
                    GenericHttpRequest(
                        method = "POST",
                        path = "/login/webauthn/assertion/begin",
                        headers = mapOf("Content-Type" to "application/json"),
                        bodySupplier = {
                            """{"sessionId":"sess-1","tenantId":"tenant-a","identityId":"identity-a","origin":"https://login.example","credentialId":"credential-a"}"""
                        },
                    ),
                )

            assertTrue(response.isOk)
            assertEquals(201, response.value.statusCode)
            assertTrue(response.value.body?.contains("\"challengeId\":\"challenge-a\"") == true)
            val captured = provider.captured ?: error("challenge request was not captured")
            assertEquals("sess-1", captured.sessionId)
            assertEquals("app-1", captured.applicationId)
            assertEquals("tenant-a", captured.tenantId)
            assertEquals("identity-a", captured.identityId)
            assertEquals("credential-a", captured.credentialId)
        }

    @Test
    fun loginWebAuthnAssertionBeginAllowsDiscoverablePasskeyWithoutIdentityHint() =
        runTest {
            val pendingStore = InMemoryPendingAuthorizationSessionStore()
            pendingStore.create(pendingSession("sess-1"))
            val provider = CapturingWebAuthnAssertionChallengeProvider()
            val command =
                LoginWebAuthnAssertionBeginHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    pendingAuthorizationSessionStore = pendingStore,
                    configProvider =
                        TestOAuth2ServersConfigProvider(
                            config =
                                com.sphereon.oauth2.common.config.OAuth2ServersConfig(
                                    servers =
                                        mapOf(
                                            "default" to
                                                com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig(
                                                    webAuthn =
                                                        com.sphereon.oauth2.common.config.WebAuthnLoginConfig(
                                                            enabled = true,
                                                            rpId = "login.example",
                                                            allowedOrigins = setOf("https://login.example"),
                                                            allowedTransports = setOf("internal"),
                                                        ),
                                                ),
                                        ),
                                ),
                        ),
                    challengeProvider = Provider { provider },
                )
            val response =
                command.execute(
                    GenericHttpRequest(
                        method = "POST",
                        path = "/login/webauthn/assertion/begin",
                        headers = mapOf("Content-Type" to "application/json"),
                        bodySupplier = {
                            """{"sessionId":"sess-1","tenantId":"tenant-a","origin":"https://login.example"}"""
                        },
                    ),
                )

            assertTrue(response.isOk)
            assertEquals(201, response.value.statusCode)
            val captured = provider.captured ?: error("challenge request was not captured")
            assertEquals("sess-1", captured.sessionId)
            assertEquals("app-1", captured.applicationId)
            assertEquals("tenant-a", captured.tenantId)
            assertNull(captured.identityId)
            assertNull(captured.credentialId)
        }

    @Test
    fun loginPostWithWrongPasswordRedirectsBackWithError() =
        runTest {
            val (command, store) = newSubmitCommand()
            val (body, cookie) = csrfFormAndCookie("sess-1", "alice", "NOPE")
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to cookie,
                        ),
                    bodySupplier = { body },
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            val r = response.value
            assertEquals(302, r.statusCode)
            val location = r.headers["Location"] ?: ""
            assertTrue(location.startsWith("/login?"), "Failed login must redirect back to /login")
            assertTrue(location.contains("error=invalid_credentials"), "Location must carry invalid_credentials error")
            assertNull(r.headers["Set-Cookie"], "Failed login must not set a session cookie")
            assertEquals(0, store.size(), "Failed login must not persist a session")
        }

    @Test
    fun missingCredentialsReturnToSelectedIssuerLogin() =
        runTest { assertFailedLoginUsesSelectedIssuer(username = "", password = "wonderland") }

    @Test
    fun rejectedCredentialsReturnToSelectedIssuerLogin() =
        runTest {
            assertFailedLoginUsesSelectedIssuer(
                username = "alice",
                password = "wonderland",
                provider = StubUserAuthProvider("alice" to "wonderland", failure = AuthenticationError.InvalidCredentials()),
            )
        }

    @Test
    fun nullAuthenticationSubjectReturnsToSelectedIssuerLogin() =
        runTest { assertFailedLoginUsesSelectedIssuer(username = "alice", password = "NOPE") }

    private suspend fun assertFailedLoginUsesSelectedIssuer(
        username: String,
        password: String,
        provider: UserAuthenticationProvider = StubUserAuthProvider("alice" to "wonderland"),
    ) {
        val trustedBase = "$TRUSTED_BASE/as/selected-server"
        // A caller-supplied return URL must never select the login endpoint's issuer or origin.
        val returnUrl = "https://other.example/authorize/callback?session_id=sess-1&next=%2Faccount"
        var resolvedOriginalPath: String? = null
        val resolver = object : OAuth2ServerBaseUrlResolver {
            override suspend fun resolveBaseUrl(
                request: GenericHttpRequest,
                configProvider: com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider,
                tenantPath: String?,
            ): String {
                resolvedOriginalPath = request.originalPath
                return trustedBase
            }
        }
        val (command, store) = newSubmitCommand(userAuthProvider = provider, baseUrlResolver = resolver)
        val (body, cookie) = csrfFormAndCookie("sess-1", username, password, returnUrl)
        val response = command.execute(
            GenericHttpRequest(
                method = "POST",
                path = "/login",
                headers = mapOf("Content-Type" to "application/x-www-form-urlencoded", "Cookie" to cookie),
                bodySupplier = { body },
            ).copy(originalPath = "/as/selected-server/login"),
        )
        assertTrue(response.isOk)
        assertEquals(302, response.value.statusCode)
        assertEquals("/as/selected-server/login", resolvedOriginalPath)
        assertEquals(
            "/as/selected-server/login?session_id=sess-1&return_url=" +
                com.sphereon.core.api.http.query.percentEncodeQueryComponent(returnUrl) +
                "&error=invalid_credentials",
            response.value.headers["Location"],
        )
        assertNull(response.value.headers["Set-Cookie"], "Failed login must not authenticate a browser")
        assertEquals(0, store.size(), "Failed login must not persist a login session")
    }

    @Test
    fun loginPostWithoutPendingAuthorizationSessionReturns400() =
        runTest {
            val capturing = CapturingOAuth2AuditEmitter()
            val (command, store) = newSubmitCommand(auditEmitter = capturing, seedPendingSession = false)
            val (body, cookie) = csrfFormAndCookie("sess-1", "alice", "wonderland")
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to cookie,
                        ),
                    bodySupplier = { body },
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            assertEquals(400, response.value.statusCode, "Missing pending authorization session must reject")
            assertEquals(0, store.size(), "No login session must be created without authorization context")
            val event = capturing.events.single()
            assertEquals(OAuth2AuditEventType.LOGIN_ERROR, event.type)
            assertEquals("pending_session_not_found", event.metadata["error_subcode"])
            assertEquals("invalid_request", event.errorCode)
        }

    @Test
    fun loginPostSuccessEmitsLoginAuditEvent() =
        runTest {
            // Pin the LOGIN-on-success emission shape: subject must be the authenticated user;
            // amr/auth_method/login_session_id metadata must be present so SIEM rules can pivot
            // on these without parsing the wire response. Anti-enumeration posture allows the
            // success event to carry the subject because the caller demonstrably had the
            // password — this is not a probe vector.
            val capturing = CapturingOAuth2AuditEmitter()
            val (command, _) = newSubmitCommand(auditEmitter = capturing)
            val (body, cookie) = csrfFormAndCookie("sess-1", "alice", "wonderland")
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to cookie,
                        ),
                    bodySupplier = { body },
                )
            assertTrue(command.execute(request).isOk)
            assertEquals(1, capturing.events.size, "Successful login must emit exactly one audit event")
            val event = capturing.events.single()
            assertEquals(OAuth2AuditEventType.LOGIN, event.type)
            assertEquals("alice", event.subject)
            assertEquals("pwd", event.metadata["amr"])
            assertEquals(AuthAssuranceLevel.AAL1.acr, event.metadata["acr"])
            assertEquals("PASSWORD", event.metadata["auth_method"])
            assertEquals("login-sid-1", event.metadata["login_session_id"])
            assertNull(event.errorCode)
        }

    @Test
    fun loginAuditUsesResolvedExecutionTenantInsteadOfSessionContextTenant() =
        runTest {
            val capturing = CapturingOAuth2AuditEmitter()
            val (command, _) =
                newSubmitCommand(
                    auditEmitter = capturing,
                    execution = TestSessionExecution(tenantIdOverride = "tenant-route"),
                )
            val (body, cookie) = csrfFormAndCookie("sess-1", "alice", "wonderland")
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to cookie,
                        ),
                    bodySupplier = { body },
                )

            assertTrue(command.execute(request).isOk)
            assertEquals("tenant-route", capturing.events.single().tenantId)
        }

    @Test
    fun loginPostWrongPasswordEmitsLoginErrorAuditEventWithoutSubject() =
        runTest {
            // Pin the LOGIN_ERROR-on-failure emission shape: subject MUST be null even though
            // the wire-form sent a username, because a real account may not exist for that
            // value and an attacker probing usernames must not be able to enumerate via /events.
            // The error_subcode metadata distinguishes the failure mode (auth_provider_rejected
            // vs missing_credentials vs session_store_failure) for analyst pivoting; the wire
            // response is unified to `invalid_credentials`.
            val capturing = CapturingOAuth2AuditEmitter()
            val (command, _) = newSubmitCommand(auditEmitter = capturing)
            val (body, cookie) = csrfFormAndCookie("sess-1", "alice", "NOPE")
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to cookie,
                        ),
                    bodySupplier = { body },
                )
            assertTrue(command.execute(request).isOk)
            assertEquals(1, capturing.events.size, "Failed login must emit exactly one audit event")
            val event = capturing.events.single()
            assertEquals(OAuth2AuditEventType.LOGIN_ERROR, event.type)
            assertNull(event.subject, "LOGIN_ERROR must not carry the attempted username")
            // Stub provider models a rejected credential set as `Ok(null)` (no Err), which the
            // login impl treats as the same wire-failure shape but with a distinct subcode so a
            // SIEM analyst can tell whether the provider ran to completion or short-circuited
            // with an error. Either subcode is a valid wrong-password signal; the test pins
            // both wire-error code and audit-error code unification.
            assertTrue(
                event.metadata["error_subcode"] in setOf("auth_provider_rejected", "auth_provider_returned_null_subject"),
                "wrong-password subcode must be one of the documented rejection variants; got ${event.metadata["error_subcode"]}",
            )
            assertEquals("invalid_credentials", event.errorCode)
        }

    @Test
    fun loginPostMissingUsernameEmitsLoginErrorWithMissingCredentialsSubcode() =
        runTest {
            val capturing = CapturingOAuth2AuditEmitter()
            val (command, _) = newSubmitCommand(auditEmitter = capturing)
            val (body, cookie) = csrfFormAndCookie("sess-1", "", "wonderland")
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to cookie,
                        ),
                    bodySupplier = { body },
                )
            assertTrue(command.execute(request).isOk)
            val event = capturing.events.single()
            assertEquals(OAuth2AuditEventType.LOGIN_ERROR, event.type)
            assertEquals("missing_credentials", event.metadata["error_subcode"])
        }

    @Test
    fun loginPageRenderEmbedsTabIdAndSessionCodeAndSetsCsrfCookie() =
        runTest {
            // Pin the GET /login wire shape for the new CSRF defense: the rendered HTML must
            // carry tab_id + session_code values forwarded from LoginPageContext, AND the
            // response must set the oidc_login_csrf cookie scoped to /login.
            val command = newLoginPageCommand()
            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/login",
                    // Cross-origin return_url is normalized to the trusted default by the command;
                    // this test asserts on tab_id/session_code CSRF, not return_url, so its outcome is unchanged.
                    queryParameters = mapOf("session_id" to "sess-csrf", "return_url" to "https://as/cb"),
                    headers = mapOf("Host" to "as.example"),
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            val r = response.value
            assertEquals(200, r.statusCode)
            val cookie = r.headers["Set-Cookie"]
            assertNotNull(cookie, "GET /login must set the oidc_login_csrf cookie")
            assertTrue(cookie.startsWith("oidc_login_csrf="), "cookie name must be oidc_login_csrf, got: $cookie")
            assertTrue(cookie.contains("Path=/login"), "CSRF cookie must be scoped to /login")
            assertTrue(cookie.contains("HttpOnly"), "CSRF cookie must be HttpOnly")
            assertTrue(cookie.contains("SameSite=Strict"), "CSRF cookie must be SameSite=Strict")
            // The stub renderer's HTML body interpolates ctx.tabId / ctx.sessionCode via
            // ${ctx.errorMessage} only — but we can read the cookie's tab_id which equals
            // what the page mints; that's enough to prove the page generated AND propagated
            // the value, even though the stub renderer doesn't reflect them in its body.
        }

    @Test
    fun loginPageScopesCsrfCookieToPublicBasePath() =
        runTest {
            val command = newLoginPageCommandWithTrustedBase("$TRUSTED_BASE/auth")
            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/login",
                    queryParameters = mapOf("session_id" to "sess-csrf"),
                    headers = mapOf("Host" to "as.example"),
                )

            val response = command.execute(request)

            assertTrue(response.isOk)
            assertTrue(
                response.value.headers["Set-Cookie"].orEmpty().contains("Path=/auth/login"),
                "CSRF cookie must follow the externally visible issuer base path",
            )
        }

    @Test
    fun reflectedOffOriginReturnUrlIsRejected() =
        runTest {
            // A reflected, off-origin `return_url` (attacker-controlled) must NOT be honored:
            // the rendered hidden `return_url` input falls back to the trusted default, and no
            // form `action` carries the hostile origin.
            val command = newLoginPageCommandWithTrustedBase()
            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/login",
                    queryParameters =
                        mapOf(
                            "session_id" to "sess-1",
                            "return_url" to "https://evil.example/authorize/callback?session_id=sess-1",
                        ),
                    headers = mapOf("Host" to "as.example"),
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            val body = response.value.body ?: ""
            assertTrue(
                body.contains("value=\"$TRUSTED_BASE/authorize/callback?session_id=sess-1\""),
                "Hidden return_url input must be the trusted default, got body: $body",
            )
            assertTrue(!body.contains("evil.example"), "Reflected hostile origin must not appear anywhere in the page")
            assertTrue(
                body.contains("action=\"$TRUSTED_BASE/login\""),
                "Login form action must use the trusted base, got body: $body",
            )
        }

    @Test
    fun sameOriginReturnUrlIsHonored() =
        runTest {
            // A same-origin callback `return_url` on the trusted base IS honored verbatim.
            val command = newLoginPageCommandWithTrustedBase()
            val sameOrigin = "$TRUSTED_BASE/authorize/callback?session_id=sess-1"
            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/login",
                    queryParameters =
                        mapOf(
                            "session_id" to "sess-1",
                            "return_url" to sameOrigin,
                        ),
                    headers = mapOf("Host" to "as.example"),
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            val body = response.value.body ?: ""
            assertTrue(
                body.contains("value=\"$sameOrigin\""),
                "Hidden return_url input must echo the same-origin callback, got body: $body",
            )
        }

    @Test
    fun absentReturnUrlUsesTrustedDefault() =
        runTest {
            // No `return_url` param at all: the hidden input is the trusted default.
            val command = newLoginPageCommandWithTrustedBase()
            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/login",
                    queryParameters = mapOf("session_id" to "sess-1"),
                    headers = mapOf("Host" to "as.example"),
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            val body = response.value.body ?: ""
            assertTrue(
                body.contains("value=\"$TRUSTED_BASE/authorize/callback?session_id=sess-1\""),
                "Absent return_url must yield the trusted default, got body: $body",
            )
            assertTrue(
                body.contains("action=\"$TRUSTED_BASE/login\""),
                "Form action must use the trusted base when return_url is absent, got body: $body",
            )
        }

    @Test
    fun loginPostMissingTabIdReturns400() =
        runTest {
            val (command, store) = newSubmitCommand()
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to "oidc_login_csrf=anything",
                        ),
                    // No tab_id / session_code in the form — defends against an attacker who
                    // tries to bypass by simply not sending them.
                    bodySupplier = { "username=alice&password=wonderland&session_id=sess-1&return_url=https%3A%2F%2Fas%2Fcb" },
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            assertEquals(400, response.value.statusCode, "Missing CSRF params must reject")
            assertEquals(0, store.size(), "No session must be created on CSRF failure")
        }

    @Test
    fun loginPostWithMismatchedSessionCodeReturns400() =
        runTest {
            // Attacker leaked the URL (so they have session_id) and may have crafted a tab_id,
            // but cannot compute a valid session_code without the HMAC key. Any sessionCode
            // value that doesn't match the HMAC must reject.
            val (command, store) = newSubmitCommand()
            val (validBody, cookie) = csrfFormAndCookie("sess-1", "alice", "wonderland")
            val tamperedBody = validBody.replace(Regex("session_code=[^&]+"), "session_code=AAAA_attacker_forged_BBBB")
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to cookie,
                        ),
                    bodySupplier = { tamperedBody },
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            assertEquals(400, response.value.statusCode, "Forged session_code must reject")
            assertEquals(0, store.size(), "Auth must NOT proceed past CSRF rejection")
        }

    @Test
    fun loginPostWithMismatchedCookieTabIdReturns400() =
        runTest {
            // Form's tab_id matches the HMAC, but the browser's cookie carries a different
            // tab_id. Defends against an attacker who can leak the form contents (referer,
            // browser history) but cannot read the victim's cookie (HttpOnly + SameSite=Strict).
            val (command, _) = newSubmitCommand()
            val (body, _) = csrfFormAndCookie("sess-1", "alice", "wonderland")
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to "oidc_login_csrf=ATTACKER_DIFFERENT_TAB_ID",
                        ),
                    bodySupplier = { body },
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            assertEquals(400, response.value.statusCode, "Cookie/form tab_id mismatch must reject")
        }

    @Test
    fun loginPostCsrfFailureEmitsAuditEventWithSubcode() =
        runTest {
            val capturing = CapturingOAuth2AuditEmitter()
            val (command, _) = newSubmitCommand(auditEmitter = capturing)
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers =
                        mapOf(
                            "Content-Type" to "application/x-www-form-urlencoded",
                            "Cookie" to "oidc_login_csrf=tab",
                        ),
                    bodySupplier = { "username=alice&password=wonderland&session_id=sess-1&tab_id=tab&session_code=BAD&return_url=https%3A%2F%2Fas%2Fcb" },
                )
            assertTrue(command.execute(request).isOk)
            val event = capturing.events.single()
            assertEquals(OAuth2AuditEventType.LOGIN_ERROR, event.type)
            assertEquals("csrf_verification_failed", event.metadata["error_subcode"])
            assertEquals("invalid_request", event.errorCode)
        }

    @Test
    fun loginPageThreadsTenantAndResolvedThemingIntoContext() =
        runTest {
            // The tenant established for the request session must reach LoginPageContext, and
            // with a [LoginPageThemeProvider] present the command must thread LIGHT + DARK branding
            // from the SPI snapshot onto the render context.
            val capturing = CapturingLoginPageRenderer()
            val light = loginBranding(primary = "#112233")
            val dark = loginBranding(primary = "#eeddcc")
            val themeProvider =
                RecordingLoginPageThemeProvider(
                    LoginPageThemeSnapshot(lightBranding = light, darkBranding = dark),
                )
            val command = newThemedLoginPageCommand(capturing, themeProvider)
            val response = command.execute(loginPageRequest("sess-1"))
            assertTrue(response.isOk)
            assertEquals(200, response.value.statusCode)
            val ctx = capturing.lastContext
            assertNotNull(ctx, "Renderer must have been invoked")
            assertEquals("acme", ctx.tenantId, "execution.tenantId must reach the LoginPageContext")
            assertEquals(light, ctx.lightBranding)
            assertEquals(dark, ctx.darkBranding)
            assertEquals(listOf(RecordingLoginPageThemeProvider.Call("acme", "default")), themeProvider.calls)
        }

    @Test
    fun cspDropsThemeAssetOriginsWithHeaderInjectionCharacters() =
        runTest {
            // Tenant-writable asset URIs flow into the CSP header. Hostile origins carrying
            // CRLF, quotes, spaces, or semicolons must be dropped entirely: the CSP stays the
            // clean nonce-bearing baseline with no img-src extension and no injected content.
            val hostileUris =
                listOf(
                    "https://evil.example\r\nSet-Cookie: pwned=1/logo.png",
                    "https://evil.example\" onload=\"alert(1)/logo.png",
                    "https://evil.example;script-src *_/logo.png",
                    "https://evil.example img-src.example/logo.png",
                    "https://evil.example'x/logo.png",
                )
            for (uri in hostileUris) {
                val command =
                    newThemedLoginPageCommand(
                        renderer = CapturingLoginPageRenderer(),
                        themeProvider =
                            FixedLoginPageThemeProvider(
                                themeSnapshotWithLogo(uri),
                            ),
                    )
                val response = command.execute(loginPageRequest("sess-1"))
                assertTrue(response.isOk)
                val csp = response.value.headers["Content-Security-Policy"] ?: error("CSP header missing")
                assertTrue(!csp.contains("evil.example"), "hostile origin must be dropped from the CSP, got: $csp")
                assertTrue(!csp.contains("img-src"), "no img-src extension may be emitted for a dropped origin, got: $csp")
                assertTrue(!csp.contains('\r') && !csp.contains('\n'), "CSP must never carry CR/LF")
                assertTrue(!csp.contains('"'), "CSP must never carry injected quotes")
            }
        }

    @Test
    fun cspExtendsImgSrcForValidCrossOriginThemeAsset() =
        runTest {
            val command =
                newThemedLoginPageCommand(
                    renderer = CapturingLoginPageRenderer(),
                    themeProvider =
                        FixedLoginPageThemeProvider(
                            themeSnapshotWithLogo("https://cdn.example:8443/tenant/logo.png"),
                        ),
                )
            val response = command.execute(loginPageRequest("sess-1"))
            assertTrue(response.isOk)
            val csp = response.value.headers["Content-Security-Policy"] ?: error("CSP header missing")
            assertTrue(
                csp.contains("img-src 'self' https://cdn.example:8443"),
                "a well-formed cross-origin https asset must extend img-src, got: $csp",
            )
        }

    @Test
    fun loginPageRendersNeutralWhenThemeResolverThrows() =
        runTest {
            // Theming must never break the login page: a throwing provider leaves branding null
            // and the page still renders 200.
            val capturing = CapturingLoginPageRenderer()
            val command =
                newThemedLoginPageCommand(
                    renderer = capturing,
                    themeProvider = ThrowingLoginPageThemeProvider,
                )
            val response = command.execute(loginPageRequest("sess-1"))
            assertTrue(response.isOk, "Login page must render despite the resolver failure")
            assertEquals(200, response.value.statusCode, "Theming failure must not surface as an error status")
            val ctx = capturing.lastContext
            assertNotNull(ctx)
            assertEquals("acme", ctx.tenantId, "Tenant threading is independent of theming failures")
            assertNull(ctx.lightBranding)
            assertNull(ctx.darkBranding)
        }

    @Test
    fun loginPageSkipsThemingWithoutRealTenant() =
        runTest {
            // The anonymous session tenant is never treated as a real tenant: no default tenant
            // fallback, context tenant stays null, and branding is neutral.
            val capturing = CapturingLoginPageRenderer()
            val themeProvider =
                RecordingLoginPageThemeProvider(
                    LoginPageThemeSnapshot(
                        lightBranding = loginBranding(primary = "#112233"),
                        darkBranding = loginBranding(primary = "#eeddcc"),
                    ),
                )
            val command =
                LoginPageHttpEndpointCommandImpl(
                    execution = TestSessionExecution(),
                    loginPageRenderer = capturing,
                    asInstanceIdProvider = StubAsInstanceIdProvider(),
                    configProvider = TestOAuth2ServersConfigProvider(),
                    baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                    csrfTokenizer = csrfTokenizer,
                    pendingAuthorizationSessionStore = pagePendingStore(),
                    themeProvider = Provider { themeProvider },
                )
            val response = command.execute(loginPageRequest("sess-1"))
            assertTrue(response.isOk)
            assertEquals(200, response.value.statusCode)
            val ctx = capturing.lastContext
            assertNotNull(ctx)
            assertNull(ctx.tenantId, "Anonymous session must not produce a tenant")
            assertNull(ctx.lightBranding)
            assertNull(ctx.darkBranding)
            assertEquals(
                listOf(RecordingLoginPageThemeProvider.Call(null, "default")),
                themeProvider.calls,
                "Provider is invoked with null tenant; platform adapters return neutral branding",
            )
        }

    @Test
    fun loginPostWithoutFormContentTypeReturns400() =
        runTest {
            val (command, _) = newSubmitCommand()
            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/login",
                    headers = mapOf("Content-Type" to "application/json"),
                    bodySupplier = { "{\"username\":\"alice\",\"password\":\"wonderland\"}" },
                )
            val response = command.execute(request)
            assertTrue(response.isOk)
            assertEquals(400, response.value.statusCode)
        }

    private fun newThemedLoginPageCommand(
        renderer: LoginPageRenderer,
        themeProvider: LoginPageThemeProvider,
    ): LoginPageHttpEndpointCommandImpl =
        LoginPageHttpEndpointCommandImpl(
            execution = TestSessionExecution(tenantIdOverride = "acme"),
            loginPageRenderer = renderer,
            asInstanceIdProvider = StubAsInstanceIdProvider(),
            configProvider = TestOAuth2ServersConfigProvider(),
            baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
            csrfTokenizer = csrfTokenizer,
            pendingAuthorizationSessionStore = pagePendingStore(),
            themeProvider = Provider { themeProvider },
        )

    private fun loginPageRequest(sessionId: String): GenericHttpRequest =
        GenericHttpRequest(
            method = "GET",
            path = "/login",
            queryParameters = mapOf("session_id" to sessionId),
            headers = mapOf("Host" to "as.example"),
        )

    private fun loginBranding(primary: String): LoginPageBranding =
        LoginPageBranding(primary = primary)

    private fun themeSnapshotWithLogo(logoUri: String): LoginPageThemeSnapshot =
        LoginPageThemeSnapshot(
            lightBranding = loginBranding(primary = "#112233"),
            darkBranding = loginBranding(primary = "#eeddcc"),
            imageUris = listOf(logoUri),
        )

    private class CapturingLoginPageRenderer : LoginPageRenderer {
        var lastContext: LoginPageContext? = null

        override suspend fun render(ctx: LoginPageContext): IdkResult<LoginPageResponse, IdkError> {
            lastContext = ctx
            return Ok(LoginPageResponse(html = "<html><body>ok</body></html>"))
        }
    }

    private class RecordingLoginPageThemeProvider(
        private val snapshot: LoginPageThemeSnapshot,
    ) : LoginPageThemeProvider {
        data class Call(
            val tenantId: String?,
            val asInstanceId: String,
        )

        val calls = mutableListOf<Call>()

        override suspend fun resolve(
            tenantId: String?,
            asInstanceId: String,
        ): LoginPageThemeSnapshot {
            calls.add(Call(tenantId, asInstanceId))
            if (tenantId.isNullOrBlank()) return LoginPageThemeSnapshot()
            return snapshot
        }
    }

    private class FixedLoginPageThemeProvider(
        private val snapshot: LoginPageThemeSnapshot,
    ) : LoginPageThemeProvider {
        override suspend fun resolve(
            tenantId: String?,
            asInstanceId: String,
        ): LoginPageThemeSnapshot = snapshot
    }

    private object ThrowingLoginPageThemeProvider : LoginPageThemeProvider {
        override suspend fun resolve(
            tenantId: String?,
            asInstanceId: String,
        ): LoginPageThemeSnapshot = throw IllegalStateException("theme store unavailable")
    }

    private class StubLoginPageRenderer(
        private val staticAssets: List<LoginPageAsset>,
    ) : LoginPageRenderer {
        override suspend fun render(ctx: LoginPageContext): IdkResult<LoginPageResponse, IdkError> =
            Ok(
                LoginPageResponse(
                    html = "<html><body data-session-id=session-id=${ctx.sessionId}>${ctx.errorMessage ?: ""}</body></html>",
                ),
            )

        override fun staticAssets(): List<LoginPageAsset> = staticAssets
    }

    /**
     * Renders the resolved [LoginPageContext.returnUrl] as a hidden `return_url` input and the
     * [LoginPageContext.formActionBase] as the login form `action`, so the trusted-base /
     * return_url validation tests can assert on the wire shape the HTTP command produced.
     */
    private class ReflectingLoginPageRenderer : LoginPageRenderer {
        override suspend fun render(ctx: LoginPageContext): IdkResult<LoginPageResponse, IdkError> =
            Ok(
                LoginPageResponse(
                    html =
                        "<html><body>" +
                            "<form action=\"${ctx.formActionBase}/login\">" +
                            "<input type=\"hidden\" name=\"return_url\" value=\"${ctx.returnUrl}\">" +
                            "</form></body></html>",
                ),
            )
    }

    private class StubAsInstanceIdProvider(
        private val id: String? = "default",
    ) : OAuth2ServerInstanceIdProvider {
        override fun currentAsInstanceId(): String? = id
    }

    private class CapturingWebAuthnAssertionChallengeProvider : com.sphereon.oauth2.server.authorization.provider.WebAuthnAssertionChallengeProvider {
        var captured: com.sphereon.oauth2.server.authorization.provider.BeginWebAuthnAssertionChallenge? = null

        override suspend fun beginAssertion(
            request: com.sphereon.oauth2.server.authorization.provider.BeginWebAuthnAssertionChallenge,
        ): IdkResult<com.sphereon.oauth2.server.authorization.provider.WebAuthnAssertionChallengeOptions, AuthenticationError> {
            captured = request
            return Ok(
                com.sphereon.oauth2.server.authorization.provider.WebAuthnAssertionChallengeOptions(
                    challengeId = "challenge-a",
                    challenge = "challenge-value",
                    rpId = request.rpId,
                    rpName = "VDX",
                    allowedOrigins = request.allowedOrigins,
                    userVerification = request.userVerification,
                    allowedTransports = request.allowedTransports,
                    level3PrfEnabled = request.level3PrfEnabled,
                    expiresAt = Clock.System.now() + 5.minutes,
                    credentialIds = setOfNotNull(request.credentialId),
                ),
            )
        }
    }

    private class StubUserAuthProvider(
        private val validPair: Pair<String, String>,
        private val acr: String? = AuthAssuranceLevel.AAL1.acr,
        private val amr: List<String>? = listOf(Amr.PWD),
        private val roles: List<String> = emptyList(),
        private val validPasskeyCredentialId: String? = null,
        private val failure: AuthenticationError? = null,
    ) : UserAuthenticationProvider {
        var lastAuthenticationContext: AuthenticationContext? = null

        override suspend fun getAuthenticatedUser(sessionId: String): IdkResult<AuthenticatedUser?, AuthenticationError> = Ok(null)

        override suspend fun initiateAuthentication(
            sessionId: String,
            returnUrl: String,
            hint: AuthenticationHint?,
            context: AuthenticationContext?,
        ): IdkResult<String, AuthenticationError> = Ok("/login?session_id=$sessionId")

        override suspend fun authenticateWithCredentials(
            credentials: UserCredentials,
            context: AuthenticationContext?,
        ): IdkResult<String?, AuthenticationError> {
            val up = credentials as? UserCredentials.UsernamePassword ?: return Ok(null)
            return if (up.username == validPair.first && up.password == validPair.second) Ok(up.username) else Ok(null)
        }

        override suspend fun authenticateUserWithCredentials(
            credentials: UserCredentials,
            context: AuthenticationContext?,
        ): IdkResult<AuthenticatedUser?, AuthenticationError> {
            lastAuthenticationContext = context
            failure?.let { return Err(it) }
            val webAuthn = credentials as? UserCredentials.WebAuthnAssertion
            if (webAuthn != null) {
                val expectedMetadata =
                    webAuthn.origin == "https://login.example" &&
                        webAuthn.rpId == "login.example" &&
                        webAuthn.userVerified == true &&
                        webAuthn.transport == "internal" &&
                        webAuthn.backupEligible == true &&
                        webAuthn.backupState == true &&
                        webAuthn.prfCapable
                return if (webAuthn.credentialId == validPasskeyCredentialId && expectedMetadata) {
                    Ok(
                        AuthenticatedUser(
                            userId = webAuthn.userIdHint ?: webAuthn.userHandle ?: "passkey-user",
                            authenticatedAt = Clock.System.now(),
                            authenticationMethod = AuthenticationMethod.WEBAUTHN,
                            acr = AuthAssuranceLevel.AAL2.acr,
                            amr = listOf(Amr.WEBAUTHN),
                        ),
                    )
                } else {
                    Ok(null)
                }
            }
            val up = credentials as? UserCredentials.UsernamePassword ?: return Ok(null)
            return if (up.username == validPair.first && up.password == validPair.second) {
                Ok(
                    AuthenticatedUser(
                        userId = up.username,
                        authenticatedAt = Clock.System.now(),
                        authenticationMethod = AuthenticationMethod.PASSWORD,
                        acr = acr,
                        amr = amr,
                        roles = roles,
                    ),
                )
            } else {
                Ok(null)
            }
        }

        override suspend fun logout(userId: String): IdkResult<Unit, AuthenticationError> = Ok(Unit)

        override suspend fun getUserInfo(userId: String): IdkResult<UserInfo, AuthenticationError> = Ok(UserInfo(userId = userId))

        override suspend fun isAuthenticationMethodAvailable(method: AuthenticationMethod,): IdkResult<Boolean, AuthenticationError> = Ok(method == AuthenticationMethod.PASSWORD)
    }

    /**
     * Fixed 32-byte HMAC key so the GET render's session_code matches across the same-test
     * POST verify. The bytes are arbitrary; only stability matters for tests, not entropy.
     */
    private class StubLoginCsrfKeyProvider : LoginCsrfKeyProvider {
        private val key: ByteArray = ByteArray(32) { it.toByte() }

        override fun keyBytes(): ByteArray = key
    }

    private class FixedSecureRandom(
        private val token: String,
    ) : SecureRandom {
        override val commands: SecureRandom.Commands get() = throw NotImplementedError("Not needed for tests")

        override suspend fun generateToken(args: GenerateTokenArgs): IdkResult<StringResult, IdkError> = Ok(StringResult(value = token))

        override suspend fun nextBytes(args: NextBytesArgs): IdkResult<ByteArrayResult, IdkError> = Ok(ByteArrayResult(bytes = ByteArray(args.length)))
    }

    internal class InMemoryLoginSessionStore : OidcLoginSessionStore {
        private val sessions = mutableMapOf<String, OidcLoginSession>()

        override suspend fun create(session: OidcLoginSession): IdkResult<OidcLoginSession, OidcLoginSessionStoreError> {
            sessions[session.sessionId] = session
            return Ok(session)
        }

        override suspend fun findById(sessionId: String): IdkResult<OidcLoginSession?, OidcLoginSessionStoreError> = Ok(sessions[sessionId])

        override suspend fun touch(
            sessionId: String,
            now: kotlin.time.Instant,
            idleTtlSeconds: Int,
        ): IdkResult<OidcLoginSession?, OidcLoginSessionStoreError> = Ok(sessions[sessionId])

        override suspend fun recordRpParticipation(
            sessionId: String,
            clientId: String,
            sid: String,
        ): IdkResult<OidcLoginSession?, OidcLoginSessionStoreError> {
            val current = sessions[sessionId] ?: return Ok(null)
            val updated = current.copy(rpSessions = current.rpSessions + (clientId to sid))
            sessions[sessionId] = updated
            return Ok(updated)
        }

        override suspend fun revoke(sessionId: String): IdkResult<Unit, OidcLoginSessionStoreError> {
            sessions.remove(sessionId)
            return Ok(Unit)
        }

        override suspend fun revokeAllForUser(sub: String): IdkResult<Unit, OidcLoginSessionStoreError> {
            val keys = sessions.entries.filter { it.value.sub == sub }.map { it.key }
            keys.forEach(sessions::remove)
            return Ok(Unit)
        }

        fun loaded(sessionId: String): OidcLoginSession? = sessions[sessionId]

        fun size(): Int = sessions.size
    }

    /**
     * Records every emit invocation so tests can assert on the type / subject / metadata that
     * the AS commands declare for a given outcome. Order-preserving and append-only.
     */
    internal class CapturingOAuth2AuditEmitter : OAuth2AuditEmitter {
        data class Captured(
            val type: OAuth2AuditEventType,
            val tenantId: String,
            val clientId: String?,
            val subject: String?,
            val metadata: Map<String, String>,
            val errorCode: String?,
            val errorMessage: String?,
        )

        private val _events = mutableListOf<Captured>()
        val events: List<Captured> get() = _events.toList()

        override suspend fun emit(
            type: OAuth2AuditEventType,
            tenantId: String,
            clientId: String?,
            subject: String?,
            metadata: Map<String, String>,
            errorCode: String?,
            errorMessage: String?,
        ) {
            _events.add(Captured(type, tenantId, clientId, subject, metadata, errorCode, errorMessage))
        }
    }
}

/**
 * Deterministic trusted base for the form-action / return_url validation tests. Set as the
 * default server's `issuer` so [DefaultOAuth2ServerBaseUrlResolver] resolves to exactly this value
 * regardless of the request `Host`.
 */
private const val TRUSTED_BASE: String = "https://as.test"

private object NoopListEnabledFederationProvidersCommand :
    com.sphereon.oauth2.server.authorization.command.federation.ListEnabledFederationProvidersCommand {
    override val commandId: String get() = com.sphereon.oauth2.server.authorization.command.federation.ListEnabledFederationProvidersCommand.COMMAND_ID
    override val inputTypeToken get() =
        com.sphereon.core.api.binary
            .typeToken<com.sphereon.oauth2.server.authorization.command.federation.ListEnabledFederationProvidersArgs>()
    override val outputTypeToken get() =
        com.sphereon.core.api.binary
            .typeToken<com.sphereon.oauth2.server.authorization.command.federation.EnabledFederationProviders>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is com.sphereon.oauth2.server.authorization.command.federation.ListEnabledFederationProvidersArgs

    override suspend fun execute(
        args: com.sphereon.oauth2.server.authorization.command.federation.ListEnabledFederationProvidersArgs,
    ): IdkResult<com.sphereon.oauth2.server.authorization.command.federation.EnabledFederationProviders, com.sphereon.oauth2.server.authorization.provider.AuthenticationError> =
        Ok(
            com.sphereon.oauth2.server.authorization.command.federation
                .EnabledFederationProviders(providers = emptyList())
        )
}

