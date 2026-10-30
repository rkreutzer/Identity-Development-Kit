/*
 * (c) 2026 Sphereon International B.V.
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

package com.sphereon.oauth2.server.authorization.impl.http

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.TypeToken
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.service.StringResult
import com.sphereon.core.defaults.context.DefaultResolvedTenantIdProvider
import com.sphereon.core.defaults.http.NoOpRoutableSlugLookup
import com.sphereon.core.defaults.random.defaultSecureRandom
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.oauth2.common.config.FeaturePolicy
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.config.isEnabled
import com.sphereon.oauth2.common.model.AuthorizationServerMetadata
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.model.PkceMethod
import com.sphereon.oauth2.common.model.TokenIntrospectionResponse
import com.sphereon.oauth2.common.model.TokenResponse
import com.sphereon.oauth2.server.authorization.audit.NoOpOAuth2AuditEmitter
import com.sphereon.oauth2.server.authorization.command.AttestationChallengeResponse
import com.sphereon.oauth2.server.authorization.command.AuthorizationErrorResponseData
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData
import com.sphereon.oauth2.server.authorization.command.AuthorizationResponseData
import com.sphereon.oauth2.server.authorization.command.BuildServerMetadataArgs
import com.sphereon.oauth2.server.authorization.command.BuildServerMetadataCommand
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreateAttestationChallengeArgs
import com.sphereon.oauth2.server.authorization.command.CreateAttestationChallengeCommand
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationCodeArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationCodeCommand
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationErrorResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationErrorResponseCommand
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationResponseCommand
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationSessionCommand
import com.sphereon.oauth2.server.authorization.command.CreateIdTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateIdTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreatePushedAuthorizationResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreatePushedAuthorizationResponseCommand
import com.sphereon.oauth2.server.authorization.command.CreateRefreshTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateRefreshTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreateRequestUriCommand
import com.sphereon.oauth2.server.authorization.command.CreateTokenResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreateTokenResponseCommand
import com.sphereon.oauth2.server.authorization.command.GetJwksArgs
import com.sphereon.oauth2.server.authorization.command.GetJwksCommand
import com.sphereon.oauth2.server.authorization.command.GetUserInfoArgs
import com.sphereon.oauth2.server.authorization.command.GetUserInfoCommand
import com.sphereon.oauth2.server.authorization.command.GrantParameters
import com.sphereon.oauth2.server.authorization.command.HandleIaeFollowUpArgs
import com.sphereon.oauth2.server.authorization.command.HandleIaeFollowUpCommand
import com.sphereon.oauth2.server.authorization.command.HandleIaeInitialRequestArgs
import com.sphereon.oauth2.server.authorization.command.HandleIaeInitialRequestCommand
import com.sphereon.oauth2.server.authorization.command.IaeResult
import com.sphereon.oauth2.server.authorization.command.IntrospectTokenArgs
import com.sphereon.oauth2.server.authorization.command.IntrospectTokenCommand
import com.sphereon.oauth2.server.authorization.command.IntrospectionRequestData
import com.sphereon.oauth2.server.authorization.command.JwksResult
import com.sphereon.oauth2.server.authorization.command.ParseAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParseAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.command.ParseIntrospectionRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParseIntrospectionRequestCommand
import com.sphereon.oauth2.server.authorization.command.ParsePushedAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParsePushedAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.command.ParseRevocationRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParseRevocationRequestCommand
import com.sphereon.oauth2.server.authorization.command.ParseTokenRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParseTokenRequestCommand
import com.sphereon.oauth2.server.authorization.command.PushedAuthorizationResponse
import com.sphereon.oauth2.server.authorization.command.RequestUriData
import com.sphereon.oauth2.server.authorization.command.RetrieveAuthorizationRequestByUriCommand
import com.sphereon.oauth2.server.authorization.command.RetrieveByRequestUriArgs
import com.sphereon.oauth2.server.authorization.command.RevocationRequestData
import com.sphereon.oauth2.server.authorization.command.RevokeTokenArgs
import com.sphereon.oauth2.server.authorization.command.RevokeTokenCommand
import com.sphereon.oauth2.server.authorization.command.TokenRequestData
import com.sphereon.oauth2.server.authorization.command.UserInfoResponse
import com.sphereon.oauth2.server.authorization.command.VerifiedAuthorizationCodeGrant
import com.sphereon.oauth2.server.authorization.command.VerifiedAuthorizationRequest
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthentication
import com.sphereon.oauth2.server.authorization.command.VerifiedClientCredentialsGrant
import com.sphereon.oauth2.server.authorization.command.VerifiedPreAuthCodeGrant
import com.sphereon.oauth2.server.authorization.command.VerifiedRefreshTokenGrant
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantArgs
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantCommand
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationArgs
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand
import com.sphereon.oauth2.server.authorization.command.VerifyClientCredentialsGrantArgs
import com.sphereon.oauth2.server.authorization.command.VerifyClientCredentialsGrantCommand
import com.sphereon.oauth2.server.authorization.command.VerifyPreAuthCodeArgs
import com.sphereon.oauth2.server.authorization.command.VerifyPreAuthorizedCodeGrantCommand
import com.sphereon.oauth2.server.authorization.command.VerifyPushedAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.command.VerifyPushedAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.command.VerifyRefreshTokenGrantArgs
import com.sphereon.oauth2.server.authorization.command.VerifyRefreshTokenGrantCommand
import com.sphereon.oauth2.server.authorization.command.discovery.HandleDiscoveryRequestArgs
import com.sphereon.oauth2.server.authorization.command.discovery.HandleDiscoveryRequestCommand
import com.sphereon.oauth2.server.authorization.command.introspection.HandleIntrospectionRequestArgs
import com.sphereon.oauth2.server.authorization.command.introspection.HandleIntrospectionRequestCommand
import com.sphereon.oauth2.server.authorization.command.jwks.HandleJwksRequestArgs
import com.sphereon.oauth2.server.authorization.command.jwks.HandleJwksRequestCommand
import com.sphereon.oauth2.server.authorization.command.par.HandlePushedAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.command.par.HandlePushedAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.command.revocation.HandleRevocationRequestArgs
import com.sphereon.oauth2.server.authorization.command.revocation.HandleRevocationRequestCommand
import com.sphereon.oauth2.server.authorization.command.token.HandleTokenRequestArgs
import com.sphereon.oauth2.server.authorization.command.token.HandleTokenRequestCommand
import com.sphereon.oauth2.server.authorization.command.userinfo.HandleUserInfoRequestArgs
import com.sphereon.oauth2.server.authorization.command.userinfo.HandleUserInfoRequestCommand
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.http.DefaultOAuth2ServerBaseUrlResolver
import com.sphereon.oauth2.server.authorization.impl.http.command.TestSessionExecution
import com.sphereon.oauth2.server.authorization.impl.http.command.discovery.JwksHttpEndpointCommandImpl
import com.sphereon.oauth2.server.authorization.impl.http.command.discovery.OAuth2ServerMetadataHttpEndpointCommandImpl
import com.sphereon.oauth2.server.authorization.impl.http.command.discovery.OpenidDiscoveryHttpEndpointCommandImpl
import com.sphereon.oauth2.server.authorization.impl.http.command.introspection.IntrospectionHttpEndpointCommandImpl
import com.sphereon.oauth2.server.authorization.impl.http.command.par.ParHttpEndpointCommandImpl
import com.sphereon.oauth2.server.authorization.impl.http.command.revocation.RevocationHttpEndpointCommandImpl
import com.sphereon.oauth2.server.authorization.impl.http.command.token.TokenHttpEndpointCommandImpl
import com.sphereon.oauth2.server.authorization.impl.oidc.OidcScopeClaimsMapperImpl
import com.sphereon.oauth2.server.authorization.model.AuthorizationCodeData
import com.sphereon.oauth2.server.authorization.model.AuthorizationSession
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientType
import com.sphereon.oauth2.server.authorization.provider.AuthenticatedUser
import com.sphereon.oauth2.server.authorization.provider.AuthenticationContext
import com.sphereon.oauth2.server.authorization.provider.AuthenticationError
import com.sphereon.oauth2.server.authorization.provider.AuthenticationHint
import com.sphereon.oauth2.server.authorization.provider.AuthenticationMethod
import com.sphereon.oauth2.server.authorization.provider.UserAuthenticationProvider
import com.sphereon.oauth2.server.authorization.provider.UserCredentials
import com.sphereon.oauth2.server.authorization.provider.UserInfo
import com.sphereon.oauth2.server.authorization.service.AuthorizationServerService
import com.sphereon.oauth2.server.authorization.storage.PreAuthorizedCodeData
import com.sphereon.oauth2.server.authorization.storage.PreAuthorizedCodeStorage
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.putJsonArray
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes

// ============================================================================
// OID4VCI E2E tests through the OAuth2 AS HTTP adapters
//
// These tests exercise the full HTTP adapter: form parsing, routing, grant
// verification, access-token issuance, and RFC-compliant response formatting.
//
// The AuthorizationServerService is a purpose-built test implementation that
// uses real in-memory storage for pre-auth codes and auth codes, producing
// realistic token responses. Command-level business logic is already covered
// by Oid4vciAsIntegrationTest in the impl module; here we focus on the HTTP
// adapter contract.
// ============================================================================

/**
 * End-to-end tests for OID4VCI flows through the OAuth2 AS HTTP adapter set.
 *
 * Each test:
 * 1. Seeds storage with test data (pre-auth codes, auth codes, client registrations)
 * 2. Constructs a GenericHttpRequest (form-encoded body, correct headers)
 * 3. Selects one handler identity and executes it through resolved dispatch
 * 4. Asserts HTTP status, headers, and JSON response body
 */
class Oid4vciE2ETest {
    private lateinit var httpRoutes: List<TestHttpAdapterRoute>
    private lateinit var service: TestOid4vciAuthorizationServerService

    private val json = Json { ignoreUnknownKeys = true }

    private val configProvider =
        TestOid4vciConfigProvider(
            OAuth2ServersConfig(
                servers =
                    mapOf(
                        "default" to
                            OAuth2ServerInstanceConfig(
                                issuer = "https://auth.example.com",
                                oidc = FeaturePolicy.SUPPORTED,
                                introspection = FeaturePolicy.SUPPORTED,
                                grantTypesEnabled =
                                    setOf(
                                        "authorization_code",
                                        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                                    ),
                            ),
                    ),
            ),
        )

    /** Public client supporting pre-authorized code and authorization code grant */
    private val oid4vciClient =
        ClientRegistration(
            clientId = "oid4vci-wallet",
            clientSecret = null,
            clientType = ClientType.PUBLIC,
            grantTypes = listOf(GrantType.PRE_AUTHORIZED_CODE, GrantType.AUTHORIZATION_CODE),
            redirectUris = listOf("https://wallet.example.com/callback"),
            tokenEndpointAuthMethod = ClientAuthenticationMethod.NONE,
            requirePkce = true,
            requirePushedAuthorizationRequests = false,
            accessTokenLifetime = 3600,
            refreshTokenLifetime = 86400,
            authorizationCodeLifetime = 600,
            allowedScopes = listOf("openid"),
            clientName = "OID4VCI E2E Wallet Client",
        )

    @BeforeTest
    fun setup() {
        service = TestOid4vciAuthorizationServerService()
        service.registerClient(oid4vciClient)

        val exec = TestSessionExecution()
        val asResolver =
            com.sphereon.oauth2.common.config
                .DefaultOAuth2ServerInstanceResolver(configProvider)
        val asIdProvider =
            com.sphereon.oauth2.common.config
                .DefaultOAuth2ServerInstanceIdProvider()

        val tokenEndpointCommand =
            TokenHttpEndpointCommandImpl(
                execution = exec,
                handleTokenRequestCommand = Oid4vciFakeHandleTokenRequestCommand(service, configProvider),
                configProvider = configProvider,
                baseUrlResolver = DefaultOAuth2ServerBaseUrlResolver(),
                dpopNonceManager = lazyOf(Oid4vciFakeNoOpDpopNonceManager),
                clientCertificateExtractor = Oid4vciFakeNoCertExtractor,
                auditEmitter = NoOpOAuth2AuditEmitter,
            )
        val introspectionEndpointCommand =
            IntrospectionHttpEndpointCommandImpl(
                exec,
                Oid4vciFakeHandleIntrospectionRequestCommand(service),
                configProvider,
                DefaultOAuth2ServerBaseUrlResolver(),
                NoOpOAuth2AuditEmitter,
            )
        val revocationEndpointCommand =
            RevocationHttpEndpointCommandImpl(
                exec,
                Oid4vciFakeHandleRevocationRequestCommand(service),
                configProvider,
                DefaultOAuth2ServerBaseUrlResolver(),
                NoOpOAuth2AuditEmitter,
            )
        val parEndpointCommand =
            ParHttpEndpointCommandImpl(
                exec,
                Oid4vciFakeHandlePushedAuthorizationRequestCommand(service),
                configProvider,
                DefaultOAuth2ServerBaseUrlResolver(),
            )
        val tokenRegistry =
            TestHttpEndpointCommandRegistry(
                tokenEndpointCommand,
                introspectionEndpointCommand,
                revocationEndpointCommand,
                parEndpointCommand,
            )
        val tokenAdapter =
            OAuth2TokenHttpAdapter(
                execution = exec,
                endpointCommandRegistry = tokenRegistry,
                asInstanceResolver = asResolver,
                asInstanceIdProvider = asIdProvider,
                slugLookup = NoOpRoutableSlugLookup(),
                tenantIdProvider = DefaultResolvedTenantIdProvider(),
            )
        val discoveryHandler = Oid4vciFakeHandleDiscoveryRequestCommand(service)
        val oauth2ServerMetadataCommand =
            OAuth2ServerMetadataHttpEndpointCommandImpl(exec, discoveryHandler, configProvider, DefaultOAuth2ServerBaseUrlResolver())
        val openidDiscoveryCommand =
            OpenidDiscoveryHttpEndpointCommandImpl(exec, discoveryHandler, configProvider, DefaultOAuth2ServerBaseUrlResolver())
        val jwksCommand = JwksHttpEndpointCommandImpl(exec, Oid4vciFakeHandleJwksRequestCommand(service))
        val discoveryRegistry =
            TestHttpEndpointCommandRegistry(oauth2ServerMetadataCommand, openidDiscoveryCommand, jwksCommand)
        val discoveryAdapter =
            OAuth2DiscoveryHttpAdapter(
                execution = exec,
                endpointCommandRegistry = discoveryRegistry,
                asInstanceResolver = asResolver,
                asInstanceIdProvider = asIdProvider,
                slugLookup = NoOpRoutableSlugLookup(),
                tenantIdProvider = DefaultResolvedTenantIdProvider(),
            )

        httpRoutes =
            listOf(
                TestHttpAdapterRoute(tokenAdapter, tokenRegistry),
                TestHttpAdapterRoute(discoveryAdapter, discoveryRegistry),
            )
    }

    // =========================================================================
    // Test 1: Pre-auth code E2E through HTTP adapter with credential_identifiers
    // =========================================================================

    @Test
    fun preAuthorizedCodeWithCredentialIdentifiers() =
        runTest {
            val now = Clock.System.now()
            service.storePreAuthorizedCode(
                "pre-auth-001",
                PreAuthorizedCodeData(
                    sessionId = "session-preauth-1",
                    credentialConfigurationIds = listOf("UniversityDegreeCredential", "EmployeeIDCredential"),
                    subject = "did:example:holder123",
                    txCodeRequired = false,
                    txCodeHash = null,
                    clientId = oid4vciClient.clientId,
                    createdAt = now,
                    expiresAt = now + 10.minutes,
                ),
            )

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/token",
                    headers = mapOf("content-type" to "application/x-www-form-urlencoded"),
                    bodySupplier = {
                        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code" +
                            "&pre-authorized_code=pre-auth-001" +
                            "&client_id=${oid4vciClient.clientId}"
                    },
                )

            val response = dispatchForTest(httpRoutes, request)

            assertEquals(200, response.statusCode, "Pre-auth code grant should succeed")
            val body = json.parseToJsonElement(response.body!!).jsonObject

            assertNotNull(body["access_token"], "Response must have access_token")
            assertEquals("Bearer", body["token_type"]?.jsonPrimitive?.content)

            // OID4VCI 1.1 Section 7.2: authorization_details with credential_identifiers
            val authDetails = body["authorization_details"]?.jsonArray
            assertNotNull(authDetails, "Response must have authorization_details for OID4VCI")
            assertEquals(2, authDetails.size, "Should have one entry per credential configuration")

            val firstDetail = authDetails[0].jsonObject
            assertEquals("openid_credential", firstDetail["type"]?.jsonPrimitive?.content)
            assertNotNull(firstDetail["credential_configuration_id"])
            assertNotNull(firstDetail["credential_identifiers"], "Each detail must have credential_identifiers")
        }

    // =========================================================================
    // Test 2: Auth-code + PKCE E2E through HTTP adapter
    // =========================================================================

    @Test
    fun authorizationCodeWithPkceAndCredentialData() =
        runTest {
            val now = Clock.System.now()
            service.storeAuthorizationCode(
                "auth-code-pkce-001",
                AuthorizationCodeData(
                    code = "auth-code-pkce-001",
                    clientId = oid4vciClient.clientId,
                    subject = "did:example:holder456",
                    redirectUri = oid4vciClient.redirectUris.first(),
                    scope = "openid",
                    codeChallenge = PKCE_CHALLENGE_S256,
                    codeChallengeMethod = PkceMethod.S256,
                    dpopJkt = null,
                    issuedAt = now,
                    expiresAt = now + 10.minutes,
                    used = false,
                    additionalData =
                        mapOf(
                            "credential_configuration_ids" to listOf("UniversityDegreeCredential"),
                        ),
                ),
            )

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/token",
                    headers = mapOf("content-type" to "application/x-www-form-urlencoded"),
                    bodySupplier = {
                        "grant_type=authorization_code" +
                            "&code=auth-code-pkce-001" +
                            "&redirect_uri=${urlEncode(oid4vciClient.redirectUris.first())}" +
                            "&client_id=${oid4vciClient.clientId}" +
                            "&code_verifier=$PKCE_VERIFIER"
                    },
                )

            val response = dispatchForTest(httpRoutes, request)

            assertEquals(200, response.statusCode, "Auth code + PKCE flow should succeed")
            val body = json.parseToJsonElement(response.body!!).jsonObject

            assertNotNull(body["access_token"], "Must have access_token")
            assertNotNull(body["refresh_token"], "Must have refresh_token")
            assertEquals("Bearer", body["token_type"]?.jsonPrimitive?.content)

            // authorization_details from additionalData
            val authDetails = body["authorization_details"]?.jsonArray
            assertNotNull(authDetails, "Response must include authorization_details from auth code")
            assertTrue(authDetails.size > 0)

            val detail = authDetails[0].jsonObject
            assertEquals("openid_credential", detail["type"]?.jsonPrimitive?.content)
            assertNotNull(detail["credential_identifiers"])
        }

    // =========================================================================
    // Test 3: Auth-code PKCE failure E2E
    // =========================================================================

    @Test
    fun authorizationCodePkceFailure() =
        runTest {
            val now = Clock.System.now()
            service.storeAuthorizationCode(
                "auth-code-pkce-fail",
                AuthorizationCodeData(
                    code = "auth-code-pkce-fail",
                    clientId = oid4vciClient.clientId,
                    subject = "did:example:holder789",
                    redirectUri = oid4vciClient.redirectUris.first(),
                    scope = "openid",
                    codeChallenge = PKCE_CHALLENGE_S256,
                    codeChallengeMethod = PkceMethod.S256,
                    dpopJkt = null,
                    issuedAt = now,
                    expiresAt = now + 10.minutes,
                    used = false,
                    additionalData = emptyMap(),
                ),
            )

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/token",
                    headers = mapOf("content-type" to "application/x-www-form-urlencoded"),
                    bodySupplier = {
                        "grant_type=authorization_code" +
                            "&code=auth-code-pkce-fail" +
                            "&redirect_uri=${urlEncode(oid4vciClient.redirectUris.first())}" +
                            "&client_id=${oid4vciClient.clientId}" +
                            "&code_verifier=wrongverifierwrongverifierwrongverifierwrong"
                    },
                )

            val response = dispatchForTest(httpRoutes, request)

            assertEquals(400, response.statusCode, "PKCE failure should return 400")
            val body = json.parseToJsonElement(response.body!!).jsonObject
            assertEquals("invalid_grant", body["error"]?.jsonPrimitive?.content)
        }

    // =========================================================================
    // Test 4: Pre-auth code single-use E2E
    // =========================================================================

    @Test
    fun preAuthorizedCodeSingleUse() =
        runTest {
            val now = Clock.System.now()
            service.storePreAuthorizedCode(
                "pre-auth-replay",
                PreAuthorizedCodeData(
                    sessionId = "session-replay",
                    credentialConfigurationIds = listOf("VerifiableCredential"),
                    subject = "did:example:replaytest",
                    txCodeRequired = false,
                    txCodeHash = null,
                    clientId = oid4vciClient.clientId,
                    createdAt = now,
                    expiresAt = now + 10.minutes,
                ),
            )

            val makeRequest = {
                GenericHttpRequest(
                    method = "POST",
                    path = "/token",
                    headers = mapOf("content-type" to "application/x-www-form-urlencoded"),
                    bodySupplier = {
                        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code" +
                            "&pre-authorized_code=pre-auth-replay" +
                            "&client_id=${oid4vciClient.clientId}"
                    },
                )
            }

            // First exchange -- success
            val first = dispatchForTest(httpRoutes, makeRequest())
            assertEquals(200, first.statusCode, "First exchange should succeed")

            // Second exchange with same code -- failure (single-use)
            val second = dispatchForTest(httpRoutes, makeRequest())
            assertEquals(400, second.statusCode, "Second exchange must fail (single-use enforcement)")
            val body = json.parseToJsonElement(second.body!!).jsonObject
            assertEquals("invalid_grant", body["error"]?.jsonPrimitive?.content)
        }

    // =========================================================================
    // Test 5: Discovery metadata E2E
    // =========================================================================

    @Test
    fun discoveryMetadata() =
        runTest {
            val request =
                GenericHttpRequest(
                    method = "GET",
                    path = "/.well-known/oauth-authorization-server",
                    headers = mapOf("host" to "auth.example.com"),
                )

            val response = dispatchForTest(httpRoutes, request)

            assertEquals(200, response.statusCode)
            val body = json.parseToJsonElement(response.body!!).jsonObject

            assertNotNull(body["issuer"], "Metadata must have issuer")
            assertNotNull(body["token_endpoint"], "Metadata must have token_endpoint")

            // OID4VCI: pre-authorized_grant_anonymous_access_supported
            val preAuthAnonymous = body["pre-authorized_grant_anonymous_access_supported"]
            assertNotNull(preAuthAnonymous, "Metadata should include pre-authorized_grant_anonymous_access_supported")
        }

    // =========================================================================
    // Test 6: Pre-auth code with tx_code E2E
    // =========================================================================

    @Test
    fun preAuthorizedCodeWithTxCodeSuccess() =
        runTest {
            val txCodeValue = "123456"
            val txCodeHashValue = hash(txCodeValue.encodeToByteArray(), DigestAlg.SHA256).encodeToBase64Url()

            val now = Clock.System.now()
            service.storePreAuthorizedCode(
                "pre-auth-txcode",
                PreAuthorizedCodeData(
                    sessionId = "session-txcode",
                    credentialConfigurationIds = listOf("IdentityCredential"),
                    subject = "did:example:txcode-user",
                    txCodeRequired = true,
                    txCodeHash = txCodeHashValue,
                    clientId = oid4vciClient.clientId,
                    createdAt = now,
                    expiresAt = now + 10.minutes,
                ),
            )

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/token",
                    headers = mapOf("content-type" to "application/x-www-form-urlencoded"),
                    bodySupplier = {
                        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code" +
                            "&pre-authorized_code=pre-auth-txcode" +
                            "&tx_code=$txCodeValue" +
                            "&client_id=${oid4vciClient.clientId}"
                    },
                )

            val response = dispatchForTest(httpRoutes, request)

            assertEquals(200, response.statusCode, "Correct tx_code should succeed")
            val body = json.parseToJsonElement(response.body!!).jsonObject
            assertNotNull(body["access_token"])
        }

    @Test
    fun preAuthorizedCodeWithWrongTxCodeFails() =
        runTest {
            val correctTxCode = "123456"
            val txCodeHashValue = hash(correctTxCode.encodeToByteArray(), DigestAlg.SHA256).encodeToBase64Url()

            val now = Clock.System.now()
            service.storePreAuthorizedCode(
                "pre-auth-txcode-wrong",
                PreAuthorizedCodeData(
                    sessionId = "session-txcode-wrong",
                    credentialConfigurationIds = listOf("IdentityCredential"),
                    subject = "did:example:txcode-wrong",
                    txCodeRequired = true,
                    txCodeHash = txCodeHashValue,
                    clientId = oid4vciClient.clientId,
                    createdAt = now,
                    expiresAt = now + 10.minutes,
                ),
            )

            val request =
                GenericHttpRequest(
                    method = "POST",
                    path = "/token",
                    headers = mapOf("content-type" to "application/x-www-form-urlencoded"),
                    bodySupplier = {
                        "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code" +
                            "&pre-authorized_code=pre-auth-txcode-wrong" +
                            "&tx_code=999999" +
                            "&client_id=${oid4vciClient.clientId}"
                    },
                )

            val response = dispatchForTest(httpRoutes, request)

            assertEquals(400, response.statusCode, "Wrong tx_code should return 400")
            val body = json.parseToJsonElement(response.body!!).jsonObject
            assertEquals("invalid_grant", body["error"]?.jsonPrimitive?.content)
        }

    // =========================================================================
    // Helpers
    // =========================================================================

    companion object {
        // RFC 7636 test vectors
        const val PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        const val PKCE_CHALLENGE_S256 = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    }

    private fun urlEncode(value: String): String {
        val sb = StringBuilder()
        for (c in value) {
            when {
                c.isLetterOrDigit() || c in "-_.~" -> {
                    sb.append(c)
                }

                c == ' ' -> {
                    sb.append('+')
                }

                else -> {
                    val bytes = c.toString().encodeToByteArray()
                    for (b in bytes) {
                        sb.append('%')
                        sb.append(((b.toInt() shr 4) and 0xF).digitToChar(16).uppercaseChar())
                        sb.append((b.toInt() and 0xF).digitToChar(16).uppercaseChar())
                    }
                }
            }
        }
        return sb.toString()
    }
}

// ============================================================================
// Test AuthorizationServerService with real in-memory storage and commands
// ============================================================================

/**
 * Test service that implements both the AuthorizationServerService interface and its
 * Commands interface. Uses real in-memory storage for pre-auth/auth codes and real
 * PKCE/tx_code verification logic, producing realistic token responses.
 *
 * The OAuth2Handlers class uses `authorizationServerService.commands.xxx.execute()`,
 * so we must provide working command implementations.
 */
private class TestOid4vciAuthorizationServerService : AuthorizationServerService {
    // Storage
    internal val clients = mutableMapOf<String, ClientRegistration>()
    private val preAuthCodes = mutableMapOf<String, PreAuthorizedCodeData>()
    private val authCodes = mutableMapOf<String, AuthorizationCodeData>()
    private var tokenCounter = 0

    /** Exposes the internal [clients] map as a [com.sphereon.oauth2.server.authorization.storage.ClientRegistry] for adapter construction. */
    val clientRegistry: com.sphereon.oauth2.server.authorization.storage.ClientRegistry =
        object : com.sphereon.oauth2.server.authorization.storage.ClientRegistry {
            override suspend fun getClient(clientId: String) =
                com.sphereon.core.api
                    .Ok(clients[clientId])

            override suspend fun registerClient(registration: ClientRegistration) =
                com.sphereon.core.api
                    .Ok(registration)

            override suspend fun updateClient(
                clientId: String,
                registration: ClientRegistration,
            ) = com.sphereon.core.api
                .Ok(registration)

            override suspend fun deleteClient(clientId: String) =
                com.sphereon.core.api
                    .Ok(Unit)

            override suspend fun listClients(
                limit: Int,
                offset: Int,
            ) = com.sphereon.core.api
                .Ok(clients.values.toList())

            override suspend fun findClientsByName(name: String) =
                com.sphereon.core.api
                    .Ok(clients.values.filter { it.clientName == name })

            override suspend fun clientExists(clientId: String) =
                com.sphereon.core.api
                    .Ok(clientId in clients)

            override suspend fun verifyClientCredentials(
                clientId: String,
                clientSecret: String,
            ) = com.sphereon.core.api
                .Ok(clients[clientId]?.clientSecret == clientSecret)
        }

    fun registerClient(client: ClientRegistration) {
        clients[client.clientId] = client
    }

    fun storePreAuthorizedCode(
        code: String,
        data: PreAuthorizedCodeData,
    ) {
        preAuthCodes[code] = data
    }

    fun storeAuthorizationCode(
        code: String,
        data: AuthorizationCodeData,
    ) {
        authCodes[code] = data
    }

    // -- Service method implementations (delegate to the same logic as commands) --

    override suspend fun parseTokenRequest(args: ParseTokenRequestArgs) = doParseTokenRequest(args)

    override suspend fun verifyClientAuthentication(args: VerifyClientAuthenticationArgs) = doVerifyClientAuth(args)

    override suspend fun verifyPreAuthorizedCodeGrant(args: VerifyPreAuthCodeArgs) = doVerifyPreAuthCode(args)

    override suspend fun verifyAuthorizationCodeGrant(args: VerifyAuthorizationCodeGrantArgs) = doVerifyAuthCode(args)

    override suspend fun createAccessToken(args: CreateAccessTokenArgs) = doCreateAccessToken(args)

    override suspend fun createRefreshToken(args: CreateRefreshTokenArgs) = doCreateRefreshToken(args)

    override suspend fun createTokenResponse(args: CreateTokenResponseArgs) = doCreateTokenResponse(args)

    override suspend fun buildServerMetadata(args: BuildServerMetadataArgs) = doBuildServerMetadata(args)

    override suspend fun getJwks(args: GetJwksArgs) = Ok(JwksResult(keys = emptyList()))

    // -- Stubs for unexercised endpoints --

    private fun err(): Nothing = throw NotImplementedError("Not exercised in OID4VCI E2E test")

    override suspend fun verifyRefreshTokenGrant(args: VerifyRefreshTokenGrantArgs) = err()

    override suspend fun verifyClientCredentialsGrant(args: VerifyClientCredentialsGrantArgs) = err()

    override suspend fun parseAuthorizationRequest(args: ParseAuthorizationRequestArgs) = err()

    override suspend fun verifyAuthorizationRequest(args: AuthorizationRequestData) = err()

    override suspend fun createAuthorizationSession(args: VerifiedAuthorizationRequest) = err()

    override suspend fun createAuthorizationCode(args: CreateAuthorizationCodeArgs) = err()

    override suspend fun createAuthorizationResponse(args: CreateAuthorizationResponseArgs) = err()

    override suspend fun createAuthorizationErrorResponse(args: CreateAuthorizationErrorResponseArgs) = err()

    override suspend fun parsePushedAuthorizationRequest(args: ParsePushedAuthorizationRequestArgs) = err()

    override suspend fun verifyPushedAuthorizationRequest(args: VerifyPushedAuthorizationRequestArgs) = err()

    override suspend fun createRequestUri(args: VerifiedAuthorizationRequest) = err()

    override suspend fun createPushedAuthorizationResponse(args: CreatePushedAuthorizationResponseArgs) = err()

    override suspend fun retrieveAuthorizationRequestByUri(requestUri: String) = err()

    override suspend fun parseIntrospectionRequest(args: ParseIntrospectionRequestArgs) = err()

    override suspend fun introspectToken(args: IntrospectTokenArgs) = err()

    override suspend fun parseRevocationRequest(args: ParseRevocationRequestArgs) = err()

    override suspend fun revokeToken(args: RevokeTokenArgs) = err()

    override suspend fun createAttestationChallenge(args: CreateAttestationChallengeArgs) = err()

    override suspend fun createIdToken(args: CreateIdTokenArgs) = err()

    override suspend fun getUserInfo(args: GetUserInfoArgs) = err()

    // -- Business logic shared between service methods and commands --

    private fun doParseTokenRequest(args: ParseTokenRequestArgs): IdkResult<TokenRequestData, IdkError> {
        val body = args.requestBody
        val grantTypeStr =
            body["grant_type"]?.firstOrNull()
                ?: return Err(IdkError.fromString(code = "invalid_request", message = "Missing grant_type"))

        val clientId =
            body["client_id"]?.firstOrNull()
                ?: return Err(IdkError.fromString(code = "invalid_request", message = "Missing client_id"))

        val grantType =
            when (grantTypeStr) {
                "authorization_code" -> GrantType.AUTHORIZATION_CODE
                "urn:ietf:params:oauth:grant-type:pre-authorized_code" -> GrantType.PRE_AUTHORIZED_CODE
                "client_credentials" -> GrantType.CLIENT_CREDENTIALS
                "refresh_token" -> GrantType.REFRESH_TOKEN
                else -> return Err(IdkError.fromString(code = "unsupported_grant_type", message = "Unsupported grant_type: $grantTypeStr"))
            }

        val grantParams =
            when (grantType) {
                GrantType.PRE_AUTHORIZED_CODE -> {
                    val preAuthCode =
                        body["pre-authorized_code"]?.firstOrNull()
                            ?: return Err(IdkError.fromString(code = "invalid_request", message = "Missing pre-authorized_code"))
                    GrantParameters.PreAuthorizedCode(
                        preAuthorizedCode = preAuthCode,
                        txCode = body["tx_code"]?.firstOrNull(),
                    )
                }

                GrantType.AUTHORIZATION_CODE -> {
                    val code =
                        body["code"]?.firstOrNull()
                            ?: return Err(IdkError.fromString(code = "invalid_request", message = "Missing code"))
                    GrantParameters.AuthorizationCode(
                        code = code,
                        redirectUri = body["redirect_uri"]?.firstOrNull() ?: "",
                        codeVerifier = body["code_verifier"]?.firstOrNull(),
                    )
                }

                else -> {
                    return Err(IdkError.fromString(code = "unsupported_grant_type", message = "Unsupported in test"))
                }
            }

        return Ok(
            TokenRequestData(
                grantType = grantType,
                clientId = clientId,
                clientAuthentication = ClientAuthenticationConfig.None(clientId = clientId),
                httpUrl = "https://auth.example.com/token",
                grantParameters = grantParams,
            ),
        )
    }

    private fun doVerifyClientAuth(args: VerifyClientAuthenticationArgs): IdkResult<VerifiedClientAuthentication, IdkError> {
        val client = clients[args.clientId]
        if (client != null && client.tokenEndpointAuthMethod == ClientAuthenticationMethod.NONE) {
            return Ok(VerifiedClientAuthentication(clientId = args.clientId, method = ClientAuthenticationMethod.NONE))
        }
        return Err(IdkError.fromString(code = "invalid_client", message = "Client not found"))
    }

    private fun doVerifyPreAuthCode(args: VerifyPreAuthCodeArgs): IdkResult<VerifiedPreAuthCodeGrant, IdkError> {
        val data =
            preAuthCodes.remove(args.preAuthorizedCode)
                ?: return Err(IdkError.fromString(code = "invalid_grant", message = "Pre-authorized code not found or already used"))

        if (Clock.System.now() > data.expiresAt) {
            return Err(IdkError.fromString(code = "invalid_grant", message = "Pre-authorized code expired"))
        }

        if (data.txCodeRequired) {
            val txCode =
                args.txCode
                    ?: return Err(IdkError.fromString(code = "invalid_grant", message = "tx_code required but not provided"))
            val providedHash = hash(txCode.encodeToByteArray(), DigestAlg.SHA256).encodeToBase64Url()
            if (providedHash != data.txCodeHash) {
                return Err(IdkError.fromString(code = "invalid_grant", message = "Invalid tx_code"))
            }
        }

        return Ok(
            VerifiedPreAuthCodeGrant(
                sessionId = data.sessionId,
                subject = data.subject,
                credentialConfigurationIds = data.credentialConfigurationIds,
            ),
        )
    }

    @Suppress("UNCHECKED_CAST")
    private fun doVerifyAuthCode(args: VerifyAuthorizationCodeGrantArgs): IdkResult<VerifiedAuthorizationCodeGrant, IdkError> {
        val data =
            authCodes.remove(args.code)
                ?: return Err(IdkError.fromString(code = "invalid_grant", message = "Authorization code not found or already used"))

        if (args.redirectUri != data.redirectUri) {
            return Err(IdkError.fromString(code = "invalid_grant", message = "redirect_uri mismatch"))
        }

        if (data.codeChallenge != null && data.codeChallengeMethod != null) {
            val verifier =
                args.codeVerifier
                    ?: return Err(IdkError.fromString(code = "invalid_grant", message = "PKCE code_verifier required"))
            val computed =
                when (data.codeChallengeMethod) {
                    PkceMethod.S256 -> hash(verifier.encodeToByteArray(), DigestAlg.SHA256).encodeToBase64Url()
                    PkceMethod.PLAIN -> verifier
                    else -> return Err(IdkError.fromString(code = "invalid_grant", message = "Unsupported PKCE method"))
                }
            if (computed != data.codeChallenge) {
                return Err(IdkError.fromString(code = "invalid_grant", message = "PKCE verification failed"))
            }
        }

        return Ok(
            VerifiedAuthorizationCodeGrant(
                codeData = data,
                subject = data.subject,
                clientId = data.clientId,
                scope = data.scope,
                dpopJkt = data.dpopJkt,
                additionalData = data.additionalData as Map<String, Any>,
            ),
        )
    }

    private fun doCreateAccessToken(args: CreateAccessTokenArgs): IdkResult<StringResult, IdkError> {
        tokenCounter++
        return Ok(StringResult("test-access-token-$tokenCounter"))
    }

    private fun doCreateRefreshToken(args: CreateRefreshTokenArgs): IdkResult<StringResult, IdkError> {
        tokenCounter++
        return Ok(StringResult("test-refresh-token-$tokenCounter"))
    }

    private fun doCreateTokenResponse(args: CreateTokenResponseArgs): IdkResult<TokenResponse, IdkError> =
        Ok(
            TokenResponse(
                accessToken = args.accessToken,
                tokenType = args.tokenType,
                expiresIn = args.expiresIn,
                refreshToken = args.refreshToken,
                scope = args.scope,
                idToken = args.idToken,
                authorizationDetails = args.authorizationDetails,
                cNonce = args.cNonce,
                cNonceExpiresIn = args.cNonceExpiresIn,
                issuedTokenType = args.issuedTokenType,
            ),
        )

    private fun doBuildServerMetadata(args: BuildServerMetadataArgs): IdkResult<AuthorizationServerMetadata, IdkError> {
        val baseUrl = args.baseUrlOverride ?: "https://auth.example.com"
        return Ok(
            AuthorizationServerMetadata(
                issuer = baseUrl,
                tokenEndpoint = "$baseUrl/token",
                authorizationEndpoint = "$baseUrl/authorize",
                jwksUri = "$baseUrl/.well-known/jwks.json",
                grantTypesSupported =
                    listOf(
                        "authorization_code",
                        "urn:ietf:params:oauth:grant-type:pre-authorized_code",
                    ),
                preAuthorizedGrantAnonymousAccessSupported = true,
            ),
        )
    }

    // -- Commands: each command delegates to the shared business-logic methods above --
    // The Commands interface requires specific typed command interfaces, so we create
    // anonymous objects implementing each specific interface.

    override val commands: AuthorizationServerService.Commands = TestCommands()

    private inner class TestCommands : AuthorizationServerService.Commands {
        override val parseTokenRequest =
            object : ParseTokenRequestCommand {
                override val inputTypeToken = typeToken<ParseTokenRequestArgs>()
                override val outputTypeToken = typeToken<TokenRequestData>()
                override val isEnabled = true

                override suspend fun execute(args: ParseTokenRequestArgs) = doParseTokenRequest(args)
            }
        override val verifyAuthorizationCodeGrant =
            object : VerifyAuthorizationCodeGrantCommand {
                override val inputTypeToken = typeToken<VerifyAuthorizationCodeGrantArgs>()
                override val outputTypeToken = typeToken<VerifiedAuthorizationCodeGrant>()
                override val isEnabled = true

                override suspend fun execute(args: VerifyAuthorizationCodeGrantArgs) = doVerifyAuthCode(args)
            }
        override val verifyRefreshTokenGrant =
            object : VerifyRefreshTokenGrantCommand {
                override val inputTypeToken = typeToken<VerifyRefreshTokenGrantArgs>()
                override val outputTypeToken = typeToken<VerifiedRefreshTokenGrant>()
                override val isEnabled = true

                override suspend fun execute(args: VerifyRefreshTokenGrantArgs): IdkResult<VerifiedRefreshTokenGrant, IdkError> =
                    Err(IdkError.fromString(code = "unsupported_grant_type", message = "Not supported in test"))
            }
        override val verifyClientCredentialsGrant =
            object : VerifyClientCredentialsGrantCommand {
                override val inputTypeToken = typeToken<VerifyClientCredentialsGrantArgs>()
                override val outputTypeToken = typeToken<VerifiedClientCredentialsGrant>()
                override val isEnabled = true

                override suspend fun execute(args: VerifyClientCredentialsGrantArgs): IdkResult<VerifiedClientCredentialsGrant, IdkError> = err()
            }
        override val verifyPreAuthorizedCodeGrant =
            object : VerifyPreAuthorizedCodeGrantCommand {
                override val inputTypeToken = typeToken<VerifyPreAuthCodeArgs>()
                override val outputTypeToken = typeToken<VerifiedPreAuthCodeGrant>()
                override val isEnabled = true

                override suspend fun execute(args: VerifyPreAuthCodeArgs) = doVerifyPreAuthCode(args)
            }
        override val createAccessToken =
            object : CreateAccessTokenCommand {
                override val inputTypeToken = typeToken<CreateAccessTokenArgs>()
                override val outputTypeToken = typeToken<StringResult>()
                override val isEnabled = true

                override suspend fun execute(args: CreateAccessTokenArgs) = doCreateAccessToken(args)
            }
        override val createRefreshToken =
            object : CreateRefreshTokenCommand {
                override val inputTypeToken = typeToken<CreateRefreshTokenArgs>()
                override val outputTypeToken = typeToken<StringResult>()
                override val isEnabled = true

                override suspend fun execute(args: CreateRefreshTokenArgs) = doCreateRefreshToken(args)
            }
        override val createTokenResponse =
            object : CreateTokenResponseCommand {
                override val inputTypeToken = typeToken<CreateTokenResponseArgs>()
                override val outputTypeToken = typeToken<TokenResponse>()
                override val isEnabled = true

                override suspend fun execute(args: CreateTokenResponseArgs) = doCreateTokenResponse(args)
            }
        override val parseAuthorizationRequest =
            object : ParseAuthorizationRequestCommand {
                override val inputTypeToken = typeToken<ParseAuthorizationRequestArgs>()
                override val outputTypeToken = typeToken<AuthorizationRequestData>()
                override val isEnabled = true

                override suspend fun execute(args: ParseAuthorizationRequestArgs): IdkResult<AuthorizationRequestData, IdkError> = err()
            }
        override val verifyAuthorizationRequest =
            object : VerifyAuthorizationRequestCommand {
                override val inputTypeToken = typeToken<AuthorizationRequestData>()
                override val outputTypeToken = typeToken<VerifiedAuthorizationRequest>()
                override val isEnabled = true

                override suspend fun execute(args: AuthorizationRequestData): IdkResult<VerifiedAuthorizationRequest, IdkError> = err()
            }
        override val createAuthorizationSession =
            object : CreateAuthorizationSessionCommand {
                override val inputTypeToken = typeToken<VerifiedAuthorizationRequest>()
                override val outputTypeToken = typeToken<AuthorizationSession>()
                override val isEnabled = true

                override suspend fun execute(args: VerifiedAuthorizationRequest): IdkResult<AuthorizationSession, IdkError> = err()
            }
        override val createAuthorizationCode =
            object : CreateAuthorizationCodeCommand {
                override val inputTypeToken = typeToken<CreateAuthorizationCodeArgs>()
                override val outputTypeToken = typeToken<StringResult>()
                override val isEnabled = true

                override suspend fun execute(args: CreateAuthorizationCodeArgs): IdkResult<StringResult, IdkError> = err()
            }
        override val createAuthorizationResponse =
            object : CreateAuthorizationResponseCommand {
                override val inputTypeToken = typeToken<CreateAuthorizationResponseArgs>()
                override val outputTypeToken = typeToken<AuthorizationResponseData>()
                override val isEnabled = true

                override suspend fun execute(args: CreateAuthorizationResponseArgs): IdkResult<AuthorizationResponseData, IdkError> = err()
            }
        override val createAuthorizationErrorResponse =
            object : CreateAuthorizationErrorResponseCommand {
                override val inputTypeToken = typeToken<CreateAuthorizationErrorResponseArgs>()
                override val outputTypeToken = typeToken<AuthorizationErrorResponseData>()
                override val isEnabled = true

                override suspend fun execute(args: CreateAuthorizationErrorResponseArgs): IdkResult<AuthorizationErrorResponseData, IdkError> = err()
            }
        override val parsePushedAuthorizationRequest =
            object : ParsePushedAuthorizationRequestCommand {
                override val inputTypeToken = typeToken<ParsePushedAuthorizationRequestArgs>()
                override val outputTypeToken = typeToken<AuthorizationRequestData>()
                override val isEnabled = true

                override suspend fun execute(args: ParsePushedAuthorizationRequestArgs): IdkResult<AuthorizationRequestData, IdkError> = err()
            }
        override val verifyPushedAuthorizationRequest =
            object : VerifyPushedAuthorizationRequestCommand {
                override val inputTypeToken = typeToken<VerifyPushedAuthorizationRequestArgs>()
                override val outputTypeToken = typeToken<VerifiedAuthorizationRequest>()
                override val isEnabled = true

                override suspend fun execute(args: VerifyPushedAuthorizationRequestArgs): IdkResult<VerifiedAuthorizationRequest, IdkError> = err()
            }
        override val createRequestUri =
            object : CreateRequestUriCommand {
                override val inputTypeToken = typeToken<VerifiedAuthorizationRequest>()
                override val outputTypeToken = typeToken<RequestUriData>()
                override val isEnabled = true

                override suspend fun execute(args: VerifiedAuthorizationRequest): IdkResult<RequestUriData, IdkError> = err()
            }
        override val createPushedAuthorizationResponse =
            object : CreatePushedAuthorizationResponseCommand {
                override val inputTypeToken = typeToken<CreatePushedAuthorizationResponseArgs>()
                override val outputTypeToken = typeToken<PushedAuthorizationResponse>()
                override val isEnabled = true

                override suspend fun execute(args: CreatePushedAuthorizationResponseArgs): IdkResult<PushedAuthorizationResponse, IdkError> = err()
            }
        override val retrieveAuthorizationRequestByUri =
            object : RetrieveAuthorizationRequestByUriCommand {
                override val inputTypeToken = typeToken<RetrieveByRequestUriArgs>()
                override val outputTypeToken = typeToken<VerifiedAuthorizationRequest>()
                override val isEnabled = true

                override suspend fun execute(args: RetrieveByRequestUriArgs): IdkResult<VerifiedAuthorizationRequest, IdkError> = err()
            }
        override val parseIntrospectionRequest =
            object : ParseIntrospectionRequestCommand {
                override val inputTypeToken = typeToken<ParseIntrospectionRequestArgs>()
                override val outputTypeToken = typeToken<IntrospectionRequestData>()
                override val isEnabled = true

                override suspend fun execute(args: ParseIntrospectionRequestArgs): IdkResult<IntrospectionRequestData, IdkError> = err()
            }
        override val introspectToken =
            object : IntrospectTokenCommand {
                override val inputTypeToken = typeToken<IntrospectTokenArgs>()
                override val outputTypeToken = typeToken<TokenIntrospectionResponse>()
                override val isEnabled = true

                override suspend fun execute(args: IntrospectTokenArgs): IdkResult<TokenIntrospectionResponse, IdkError> = err()
            }
        override val parseRevocationRequest =
            object : ParseRevocationRequestCommand {
                override val inputTypeToken = typeToken<ParseRevocationRequestArgs>()
                override val outputTypeToken = typeToken<RevocationRequestData>()
                override val isEnabled = true

                override suspend fun execute(args: ParseRevocationRequestArgs): IdkResult<RevocationRequestData, IdkError> = err()
            }
        override val revokeToken =
            object : RevokeTokenCommand {
                override val inputTypeToken = typeToken<RevokeTokenArgs>()
                override val outputTypeToken = typeToken<Unit>()
                override val isEnabled = true

                override suspend fun execute(args: RevokeTokenArgs): IdkResult<Unit, IdkError> = err()
            }
        override val buildServerMetadata =
            object : BuildServerMetadataCommand {
                override val inputTypeToken = typeToken<BuildServerMetadataArgs>()
                override val outputTypeToken = typeToken<AuthorizationServerMetadata>()
                override val isEnabled = true

                override suspend fun execute(args: BuildServerMetadataArgs) = doBuildServerMetadata(args)
            }
        override val verifyClientAuthentication =
            object : VerifyClientAuthenticationCommand {
                override val inputTypeToken = typeToken<VerifyClientAuthenticationArgs>()
                override val outputTypeToken = typeToken<VerifiedClientAuthentication>()
                override val isEnabled = true

                override suspend fun execute(args: VerifyClientAuthenticationArgs) = doVerifyClientAuth(args)
            }
        override val createAttestationChallenge =
            object : CreateAttestationChallengeCommand {
                override val inputTypeToken = typeToken<CreateAttestationChallengeArgs>()
                override val outputTypeToken = typeToken<AttestationChallengeResponse>()
                override val isEnabled = true

                override suspend fun execute(args: CreateAttestationChallengeArgs): IdkResult<AttestationChallengeResponse, IdkError> = err()
            }
        override val createIdToken =
            object : CreateIdTokenCommand {
                override val inputTypeToken = typeToken<CreateIdTokenArgs>()
                override val outputTypeToken = typeToken<StringResult>()
                override val isEnabled = true

                override suspend fun execute(args: CreateIdTokenArgs): IdkResult<StringResult, IdkError> = Ok(StringResult("test-id-token-${++tokenCounter}"))
            }
        override val getUserInfo =
            object : GetUserInfoCommand {
                override val inputTypeToken = typeToken<GetUserInfoArgs>()
                override val outputTypeToken = typeToken<UserInfoResponse>()
                override val isEnabled = true

                override suspend fun execute(args: GetUserInfoArgs): IdkResult<UserInfoResponse, IdkError> = err()
            }
        override val getJwks =
            object : GetJwksCommand {
                override val inputTypeToken = typeToken<GetJwksArgs>()
                override val outputTypeToken = typeToken<JwksResult>()
                override val isEnabled = true

                override suspend fun execute(args: GetJwksArgs) = Ok(JwksResult(keys = emptyList()))
            }
    }
}

// ============================================================================
// Test fakes
// ============================================================================

private class TestOid4vciConfigProvider(
    private val config: OAuth2ServersConfig = OAuth2ServersConfig(),
) : OAuth2ServersConfigProvider {
    override fun getConfig(): OAuth2ServersConfig = config

    override fun getServer(id: String): OAuth2ServerInstanceConfig? = config.getServer(id)

    override fun getDefaultServer(): OAuth2ServerInstanceConfig = config.getDefaultServer()

    override fun resolveIssuer(
        serverId: String,
        tenantId: String,
    ): String {
        val server =
            config.getServer(serverId)
                ?: error("OAuth2 server '$serverId' not found in configuration")
        return server.issuer
            ?: server.issuerTemplate?.replace("{tenant-id}", tenantId)
            ?: error("OAuth2 server '$serverId' has no issuer or issuerTemplate")
    }
}

private class NoOpOid4vciUserAuthProvider : UserAuthenticationProvider {
    override suspend fun getAuthenticatedUser(sessionId: String): IdkResult<AuthenticatedUser?, AuthenticationError> = Ok(null)

    override suspend fun initiateAuthentication(
        sessionId: String,
        returnUrl: String,
        hint: AuthenticationHint?,
        context: AuthenticationContext?,
    ): IdkResult<String, AuthenticationError> = Err(AuthenticationError.Generic(description = "Not implemented in test"))

    override suspend fun authenticateWithCredentials(
        credentials: UserCredentials,
        context: AuthenticationContext?,
    ): IdkResult<String?, AuthenticationError> = Err(AuthenticationError.Generic(description = "Not implemented in test"))

    override suspend fun logout(userId: String): IdkResult<Unit, AuthenticationError> = Ok(Unit)

    override suspend fun getUserInfo(userId: String): IdkResult<UserInfo, AuthenticationError> =
        Ok(UserInfo(userId = userId, username = "test-user", displayName = "Test User", email = "test@example.com", emailVerified = true))

    override suspend fun isAuthenticationMethodAvailable(method: AuthenticationMethod): IdkResult<Boolean, AuthenticationError> = Ok(method == AuthenticationMethod.PASSWORD)
}

private class NoOpOid4vciIaeInitialCommand : HandleIaeInitialRequestCommand {
    override val commandId: String get() = HandleIaeInitialRequestCommand.COMMAND_ID
    override val inputTypeToken get() = typeToken<HandleIaeInitialRequestArgs>()
    override val outputTypeToken get() = typeToken<IaeResult>()
    override val isEnabled: Boolean = true

    override suspend fun execute(args: HandleIaeInitialRequestArgs): IdkResult<IaeResult, IdkError> = Err(IdkError.fromString(code = "NOT_IMPLEMENTED", message = "IAE not available in test"))

    override suspend fun supports(args: Any): Boolean = args is HandleIaeInitialRequestArgs
}

private class NoOpOid4vciIaeFollowUpCommand : HandleIaeFollowUpCommand {
    override val commandId: String get() = HandleIaeFollowUpCommand.COMMAND_ID
    override val inputTypeToken get() = typeToken<HandleIaeFollowUpArgs>()
    override val outputTypeToken get() = typeToken<IaeResult>()
    override val isEnabled: Boolean = true

    override suspend fun execute(args: HandleIaeFollowUpArgs): IdkResult<IaeResult, IdkError> = Err(IdkError.fromString(code = "NOT_IMPLEMENTED", message = "IAE not available in test"))

    override suspend fun supports(args: Any): Boolean = args is HandleIaeFollowUpArgs
}

private class NoOpOid4vciPendingAuthorizationSessionStore : com.sphereon.oauth2.server.authorization.storage.PendingAuthorizationSessionStore {
    private val map = mutableMapOf<String, com.sphereon.oauth2.server.authorization.model.AuthorizationSession>()

    override suspend fun create(session: com.sphereon.oauth2.server.authorization.model.AuthorizationSession) = Ok(session.also { map[it.sessionId] = it })

    override suspend fun findById(sessionId: String) = Ok(map[sessionId])

    override suspend fun remove(sessionId: String) = Ok(Unit.also { map.remove(sessionId) })
}

private class NoOpOid4vciHandleAuthorizeRequestCommand : com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestCommand {
    override val commandId: String get() = "oauth2.authorization.noop-authorize-request"
    override val inputTypeToken get() =
        com.sphereon.core.api.binary
            .typeToken<com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestArgs>()
    override val outputTypeToken get() =
        com.sphereon.core.api.binary
            .typeToken<com.sphereon.oauth2.server.authorization.command.AuthorizationRequestOutcome>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestArgs

    override suspend fun execute(
        args: com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestArgs
    ): IdkResult<com.sphereon.oauth2.server.authorization.command.AuthorizationRequestOutcome, IdkError> = Err(IdkError.fromString(code = "noop", message = "Not available in E2E test"))
}

private class NoOpOid4vciHandleAuthorizeCallbackCommand : com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeCallbackCommand {
    override val commandId: String get() = com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeCallbackCommand.COMMAND_ID
    override val inputTypeToken get() =
        com.sphereon.core.api.binary
            .typeToken<com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeCallbackArgs>()
    override val outputTypeToken get() =
        com.sphereon.core.api.binary
            .typeToken<com.sphereon.oauth2.server.authorization.command.AuthorizationResponseData>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeCallbackArgs

    override suspend fun execute(
        args: com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeCallbackArgs
    ): IdkResult<com.sphereon.oauth2.server.authorization.command.AuthorizationResponseData, IdkError> = Err(IdkError.fromString(code = "noop", message = "Not available in E2E test"))
}

private class NoOpOid4vciListEnabledFederationProvidersCommand : com.sphereon.oauth2.server.authorization.command.federation.ListEnabledFederationProvidersCommand {
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
        args: com.sphereon.oauth2.server.authorization.command.federation.ListEnabledFederationProvidersArgs
    ): IdkResult<com.sphereon.oauth2.server.authorization.command.federation.EnabledFederationProviders, com.sphereon.oauth2.server.authorization.provider.AuthenticationError> =
        Ok(
            com.sphereon.oauth2.server.authorization.command.federation
                .EnabledFederationProviders(emptyList())
        )
}

private class NoOpOid4vciRegisterPreAuthorizedCodeCommand : com.sphereon.oauth2.server.authorization.command.token.RegisterPreAuthorizedCodeCommand {
    override val commandId: String get() = com.sphereon.oauth2.server.authorization.command.token.RegisterPreAuthorizedCodeCommand.COMMAND_ID
    override val inputTypeToken get() =
        com.sphereon.core.api.binary
            .typeToken<com.sphereon.oauth2.server.authorization.command.token.RegisterPreAuthorizedCodeArgs>()
    override val outputTypeToken get() =
        com.sphereon.core.api.binary
            .typeToken<com.sphereon.oauth2.server.authorization.command.token.RegisterPreAuthorizedCodeResult>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is com.sphereon.oauth2.server.authorization.command.token.RegisterPreAuthorizedCodeArgs

    override suspend fun execute(
        args: com.sphereon.oauth2.server.authorization.command.token.RegisterPreAuthorizedCodeArgs
    ): IdkResult<com.sphereon.oauth2.server.authorization.command.token.RegisterPreAuthorizedCodeResult, IdkError> = Err(IdkError.fromString(code = "noop", message = "Not available in E2E test"))
}

private object Oid4vciNoOpFederationEndpoints {
    val authorize: com.sphereon.oauth2.server.authorization.command.federation.FederationAuthorizeHttpEndpointCommand =
        object : com.sphereon.oauth2.server.authorization.command.federation.FederationAuthorizeHttpEndpointCommand {
            override val endpoint = com.sphereon.oauth2.server.authorization.command.federation.FederationAuthorizeHttpEndpointCommand.ENDPOINT
            override val id: String get() = endpoint.commandId ?: "noop"
            override val isEnabled: Boolean = true

            override suspend fun execute(args: com.sphereon.core.api.http.GenericHttpRequest) =
                Err(IdkError.fromString(code = "NOT_IMPLEMENTED", message = "Federation endpoint not exercised in OID4VCI test"))
        }
    val reconAuthorize: com.sphereon.oauth2.server.authorization.command.federation.ReconciliationAuthorizeHttpEndpointCommand =
        object : com.sphereon.oauth2.server.authorization.command.federation.ReconciliationAuthorizeHttpEndpointCommand {
            override val endpoint = com.sphereon.oauth2.server.authorization.command.federation.ReconciliationAuthorizeHttpEndpointCommand.ENDPOINT
            override val id: String get() = endpoint.commandId ?: "noop"
            override val isEnabled: Boolean = true

            override suspend fun execute(args: com.sphereon.core.api.http.GenericHttpRequest) =
                Err(IdkError.fromString(code = "NOT_IMPLEMENTED", message = "Reconciliation authorize not exercised in OID4VCI test"))
        }
    val callback: com.sphereon.oauth2.server.authorization.command.federation.FederationCallbackHttpEndpointCommand =
        object : com.sphereon.oauth2.server.authorization.command.federation.FederationCallbackHttpEndpointCommand {
            override val endpoint = com.sphereon.oauth2.server.authorization.command.federation.FederationCallbackHttpEndpointCommand.ENDPOINT
            override val id: String get() = endpoint.commandId ?: "noop"
            override val isEnabled: Boolean = true

            override suspend fun execute(args: com.sphereon.core.api.http.GenericHttpRequest) =
                Err(IdkError.fromString(code = "NOT_IMPLEMENTED", message = "Federation callback not exercised in OID4VCI test"))
        }
    val reconCallback: com.sphereon.oauth2.server.authorization.command.federation.ReconciliationCallbackHttpEndpointCommand =
        object : com.sphereon.oauth2.server.authorization.command.federation.ReconciliationCallbackHttpEndpointCommand {
            override val endpoint = com.sphereon.oauth2.server.authorization.command.federation.ReconciliationCallbackHttpEndpointCommand.ENDPOINT
            override val id: String get() = endpoint.commandId ?: "noop"
            override val isEnabled: Boolean = true

            override suspend fun execute(args: com.sphereon.core.api.http.GenericHttpRequest) =
                Err(IdkError.fromString(code = "NOT_IMPLEMENTED", message = "Reconciliation callback not exercised in OID4VCI test"))
        }
}

// ============================================================================
// Phase 3c-1 endpoint orchestration fakes for the OID4VCI E2E test.
//
// The token-endpoint fake reproduces the orchestration in
// HandleTokenRequestCommandImpl (which itself was lifted verbatim from
// OAuth2Handlers.handleTokenRequest) so the existing OID4VCI tests assert the
// same behaviour without requiring a SessionExecution. The simpler endpoints
// delegate straight through to the test service.
// ============================================================================

private class Oid4vciFakeHandleTokenRequestCommand(
    private val authServerService: AuthorizationServerService,
    private val configProvider: OAuth2ServersConfigProvider,
    private val secureRandom: com.sphereon.core.api.random.SecureRandom = defaultSecureRandom(),
    private val scopeClaimsMapper: com.sphereon.oauth2.server.authorization.impl.oidc.OidcScopeClaimsMapper? = OidcScopeClaimsMapperImpl(),
) : HandleTokenRequestCommand {
    override val commandId: String get() = HandleTokenRequestCommand.COMMAND_ID
    override val inputTypeToken get() = typeToken<HandleTokenRequestArgs>()
    override val outputTypeToken get() = typeToken<TokenResponse>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is HandleTokenRequestArgs

    override suspend fun execute(args: HandleTokenRequestArgs): IdkResult<TokenResponse, IdkError> {
        val commands = authServerService.commands
        val tokenRequest =
            commands.parseTokenRequest
                .execute(ParseTokenRequestArgs(args.requestBody, args.requestHeaders))
                .getOrElse { error -> return Err(error) }

        commands.verifyClientAuthentication
            .execute(
                VerifyClientAuthenticationArgs(
                    clientAuthentication = tokenRequest.clientAuthentication,
                    clientId = tokenRequest.clientId,
                    tokenEndpointUrl = args.httpUrl,
                ),
            ).getOrElse { error -> return Err(error) }

        return when (val params = tokenRequest.grantParameters) {
            is GrantParameters.AuthorizationCode -> {
                val verified =
                    commands.verifyAuthorizationCodeGrant
                        .execute(
                            VerifyAuthorizationCodeGrantArgs(
                                code = params.code,
                                redirectUri = params.redirectUri,
                                clientId = tokenRequest.clientId,
                                codeVerifier = params.codeVerifier,
                            ),
                        ).getOrElse { error -> return Err(error) }
                val accessToken =
                    commands.createAccessToken
                        .execute(
                            CreateAccessTokenArgs(
                                subject = verified.subject,
                                clientId = tokenRequest.clientId,
                                scope = verified.scope,
                                dpopJkt = verified.dpopJkt,
                            ),
                        ).getOrElse { error -> return Err(error) }
                val refreshToken =
                    commands.createRefreshToken
                        .execute(
                            CreateRefreshTokenArgs(
                                subject = verified.subject,
                                clientId = tokenRequest.clientId,
                                scope = verified.scope,
                                dpopJkt = verified.dpopJkt,
                            ),
                        ).getOrElse { error -> return Err(error) }

                val grantedScopes = verified.scope?.split(" ")?.toSet() ?: emptySet()
                val oidcEnabled = configProvider.serverConfig.oidc.isEnabled == true
                val idToken =
                    if (oidcEnabled && "openid" in grantedScopes) {
                        val idTokenClaims =
                            if (scopeClaimsMapper != null && verified.userClaims.isNotEmpty()) {
                                val scopeFiltered = scopeClaimsMapper.filterClaims(verified.userClaims, grantedScopes)
                                val standardClaimKeys = scopeClaimsMapper.allStandardClaimKeys()
                                val customClaims = verified.userClaims.filterKeys { it !in standardClaimKeys }
                                scopeFiltered + customClaims
                            } else {
                                verified.userClaims
                            }
                        commands.createIdToken
                            .execute(
                                CreateIdTokenArgs(
                                    subject = verified.subject,
                                    clientId = tokenRequest.clientId,
                                    nonce = verified.codeData.nonce,
                                    authTime = verified.codeData.authTime,
                                    acr = verified.codeData.acr,
                                    amr = verified.codeData.amr,
                                    accessToken = accessToken.value,
                                    authorizationCode = params.code,
                                    userClaims = idTokenClaims,
                                    sessionId = verified.codeData.sessionId,
                                ),
                            ).getOrElse { error -> return Err(error) }
                            .value
                    } else {
                        null
                    }

                val authCodeAuthorizationDetails =
                    run {
                        val configIds =
                            (verified.additionalData["credential_configuration_ids"] as? List<*>)
                                ?.filterIsInstance<String>()
                                ?.ifEmpty { null }
                        configIds?.let { ids ->
                            val idsWithSuffixes =
                                ids.map { it to secureRandom.newToken(lengthBytes = 12, encoding = com.sphereon.core.api.Encoding.HEX) }
                            JsonArray(
                                idsWithSuffixes.map { (configId, suffix) ->
                                    buildJsonObject {
                                        put("type", JsonPrimitive("openid_credential"))
                                        put("credential_configuration_id", JsonPrimitive(configId))
                                        putJsonArray("credential_identifiers") {
                                            add(JsonPrimitive("$configId-$suffix"))
                                        }
                                    }
                                },
                            )
                        }
                    }

                commands.createTokenResponse.execute(
                    CreateTokenResponseArgs(
                        accessToken = accessToken.value,
                        tokenType = if (verified.dpopJkt != null) "DPoP" else "Bearer",
                        refreshToken = refreshToken.value,
                        scope = verified.scope,
                        idToken = idToken,
                        authorizationDetails = authCodeAuthorizationDetails,
                    ),
                )
            }

            is GrantParameters.RefreshToken -> {
                val verified =
                    commands.verifyRefreshTokenGrant
                        .execute(
                            VerifyRefreshTokenGrantArgs(
                                refreshToken = params.refreshToken,
                                clientId = tokenRequest.clientId,
                                requestedScope = params.scope,
                            ),
                        ).getOrElse { error -> return Err(error) }
                val accessToken =
                    commands.createAccessToken
                        .execute(
                            CreateAccessTokenArgs(
                                subject = verified.subject,
                                clientId = tokenRequest.clientId,
                                scope = verified.scope,
                                dpopJkt = verified.dpopJkt,
                            ),
                        ).getOrElse { error -> return Err(error) }
                commands.createTokenResponse.execute(
                    CreateTokenResponseArgs(
                        accessToken = accessToken.value,
                        tokenType = if (verified.dpopJkt != null) "DPoP" else "Bearer",
                        scope = verified.scope,
                    ),
                )
            }

            is GrantParameters.ClientCredentials -> {
                val verified =
                    commands.verifyClientCredentialsGrant
                        .execute(
                            VerifyClientCredentialsGrantArgs(
                                clientId = tokenRequest.clientId,
                                requestedScope = params.scope,
                            ),
                        ).getOrElse { error -> return Err(error) }
                val accessToken =
                    commands.createAccessToken
                        .execute(
                            CreateAccessTokenArgs(
                                subject = verified.subject,
                                clientId = tokenRequest.clientId,
                                scope = verified.scope,
                            ),
                        ).getOrElse { error -> return Err(error) }
                commands.createTokenResponse.execute(
                    CreateTokenResponseArgs(
                        accessToken = accessToken.value,
                        tokenType = "Bearer",
                        scope = verified.scope,
                    ),
                )
            }

            is GrantParameters.TokenExchange ->
                Err(IdkError.fromString(code = "unsupported_grant_type", message = "Token exchange runs through the token-exchange journey"))

            is GrantParameters.PreAuthorizedCode -> {
                val verified =
                    commands.verifyPreAuthorizedCodeGrant
                        .execute(
                            VerifyPreAuthCodeArgs(
                                preAuthorizedCode = params.preAuthorizedCode,
                                txCode = params.txCode,
                                clientId = tokenRequest.clientId,
                            ),
                        ).getOrElse { error -> return Err(error) }
                val accessToken =
                    commands.createAccessToken
                        .execute(
                            CreateAccessTokenArgs(
                                subject = verified.subject ?: tokenRequest.clientId,
                                clientId = tokenRequest.clientId,
                                audience = listOfNotNull(verified.issuerIdentifier),
                            ),
                        ).getOrElse { error -> return Err(error) }
                val authorizationDetails =
                    if (verified.useCredentialIdentifiers && verified.credentialConfigurationIds.isNotEmpty()) {
                        JsonArray(
                            verified.credentialConfigurationIds.map { configId ->
                                buildJsonObject {
                                    put("type", JsonPrimitive("openid_credential"))
                                    put("credential_configuration_id", JsonPrimitive(configId))
                                    putJsonArray("credential_identifiers") {
                                        add(JsonPrimitive(verified.sessionId))
                                    }
                                }
                            },
                        )
                    } else {
                        null
                    }
                commands.createTokenResponse.execute(
                    CreateTokenResponseArgs(
                        accessToken = accessToken.value,
                        tokenType = "Bearer",
                        authorizationDetails = authorizationDetails,
                    ),
                )
            }

            is GrantParameters.DeviceCode -> {
                Err(
                    IdkError(
                        code = "unsupported_grant_type",
                        message =
                            IdkError.Message(
                                i18nKey = "oauth2.as.error.unsupported_grant_type",
                                defaultMessage = "device_code grant not supported in this OID4VCI E2E fake",
                            ),
                    ),
                )
            }

            is GrantParameters.Password -> {
                Err(
                    IdkError(
                        code = "unsupported_grant_type",
                        message =
                            IdkError.Message(
                                i18nKey = "oauth2.as.error.unsupported_grant_type",
                                defaultMessage = "password grant not supported in this OID4VCI E2E fake",
                            ),
                    ),
                )
            }
        }
    }
}

private class Oid4vciFakeHandlePushedAuthorizationRequestCommand(
    private val authServerService: AuthorizationServerService,
) : HandlePushedAuthorizationRequestCommand {
    override val commandId: String get() = HandlePushedAuthorizationRequestCommand.COMMAND_ID
    override val inputTypeToken get() = typeToken<HandlePushedAuthorizationRequestArgs>()
    override val outputTypeToken get() = typeToken<PushedAuthorizationResponse>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is HandlePushedAuthorizationRequestArgs

    override suspend fun execute(args: HandlePushedAuthorizationRequestArgs): IdkResult<PushedAuthorizationResponse, IdkError> {
        // Test service does not exercise PAR; route the call through the parser/verifier so the
        // existing test that hits POST /par returns whatever the test commands implement.
        val singleValueBody = args.requestBody.mapValues { (_, values) -> values.first() }
        val clientAuth = ClientAuthenticationConfig.None(clientId = singleValueBody["client_id"] ?: "")
        val authRequest =
            authServerService.commands.parsePushedAuthorizationRequest
                .execute(ParsePushedAuthorizationRequestArgs(args.requestBody, clientAuth))
                .getOrElse { error -> return Err(error) }
        val verified =
            authServerService.commands.verifyPushedAuthorizationRequest
                .execute(VerifyPushedAuthorizationRequestArgs(authRequest, authRequest.clientId))
                .getOrElse { error -> return Err(error) }
        val requestUriData =
            authServerService.commands.createRequestUri
                .execute(verified)
                .getOrElse { error -> return Err(error) }
        return authServerService.commands.createPushedAuthorizationResponse.execute(
            CreatePushedAuthorizationResponseArgs(requestUri = requestUriData.requestUri, expiresIn = requestUriData.expiresIn),
        )
    }
}

private class Oid4vciFakeHandleIntrospectionRequestCommand(
    private val authServerService: AuthorizationServerService,
) : HandleIntrospectionRequestCommand {
    override val commandId: String get() = HandleIntrospectionRequestCommand.COMMAND_ID
    override val inputTypeToken get() = typeToken<HandleIntrospectionRequestArgs>()
    override val outputTypeToken get() = typeToken<TokenIntrospectionResponse>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is HandleIntrospectionRequestArgs

    override suspend fun execute(args: HandleIntrospectionRequestArgs): IdkResult<TokenIntrospectionResponse, IdkError> {
        // Mirror the production impl's auth flow using the impl-module's public extractor.
        val extracted =
            com.sphereon.oauth2.server.authorization.impl.command
                .extractClientAuthentication(args.requestBody, args.requestHeaders)
                .getOrElse { error -> return Err(IdkError.fromDTO(error)) }
        val resolvedClientId =
            extracted.clientId
                ?: return Err(IdkError.UNAUTHORIZED_ERROR(message = "client authentication is required at /introspect"))
        authServerService.commands.verifyClientAuthentication
            .execute(
                VerifyClientAuthenticationArgs(
                    clientAuthentication = extracted.clientAuthentication,
                    clientId = resolvedClientId,
                    tokenEndpointUrl = args.httpUrl,
                ),
            ).getOrElse { error -> return Err(error) }
        val introspectionRequest =
            authServerService.commands.parseIntrospectionRequest
                .execute(ParseIntrospectionRequestArgs(args.requestBody))
                .getOrElse { error -> return Err(error) }
        return authServerService.commands.introspectToken.execute(
            IntrospectTokenArgs(
                token = introspectionRequest.token,
                tokenTypeHint = introspectionRequest.tokenTypeHint,
                clientId = resolvedClientId,
            ),
        )
    }
}

private class Oid4vciFakeHandleRevocationRequestCommand(
    private val authServerService: AuthorizationServerService,
) : HandleRevocationRequestCommand {
    override val commandId: String get() = HandleRevocationRequestCommand.COMMAND_ID
    override val inputTypeToken get() = typeToken<HandleRevocationRequestArgs>()
    override val outputTypeToken get() = typeToken<Unit>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is HandleRevocationRequestArgs

    override suspend fun execute(args: HandleRevocationRequestArgs): IdkResult<Unit, IdkError> {
        val extracted =
            com.sphereon.oauth2.server.authorization.impl.command
                .extractClientAuthentication(args.requestBody, args.requestHeaders)
                .getOrElse { error -> return Err(IdkError.fromDTO(error)) }
        val resolvedClientId =
            extracted.clientId
                ?: return Err(IdkError.UNAUTHORIZED_ERROR(message = "client authentication is required at /revoke"))
        authServerService.commands.verifyClientAuthentication
            .execute(
                VerifyClientAuthenticationArgs(
                    clientAuthentication = extracted.clientAuthentication,
                    clientId = resolvedClientId,
                    tokenEndpointUrl = args.httpUrl,
                ),
            ).getOrElse { error -> return Err(error) }
        val revocationRequest =
            authServerService.commands.parseRevocationRequest
                .execute(ParseRevocationRequestArgs(args.requestBody))
                .getOrElse { error -> return Err(error) }
        return authServerService.commands.revokeToken.execute(
            RevokeTokenArgs(
                token = revocationRequest.token,
                tokenTypeHint = revocationRequest.tokenTypeHint,
                clientId = resolvedClientId,
            ),
        )
    }
}

private class Oid4vciFakeHandleDiscoveryRequestCommand(
    private val authServerService: AuthorizationServerService,
) : HandleDiscoveryRequestCommand {
    override val commandId: String get() = HandleDiscoveryRequestCommand.COMMAND_ID
    override val inputTypeToken get() = typeToken<HandleDiscoveryRequestArgs>()
    override val outputTypeToken get() = typeToken<AuthorizationServerMetadata>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is HandleDiscoveryRequestArgs

    override suspend fun execute(args: HandleDiscoveryRequestArgs): IdkResult<AuthorizationServerMetadata, IdkError> =
        authServerService.commands.buildServerMetadata.execute(BuildServerMetadataArgs(serverId = args.serverId, baseUrlOverride = args.baseUrlOverride))
}

private class Oid4vciFakeHandleUserInfoRequestCommand(
    private val authServerService: AuthorizationServerService,
) : HandleUserInfoRequestCommand {
    override val commandId: String get() = HandleUserInfoRequestCommand.COMMAND_ID
    override val inputTypeToken get() = typeToken<HandleUserInfoRequestArgs>()
    override val outputTypeToken get() = typeToken<UserInfoResponse>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is HandleUserInfoRequestArgs

    override suspend fun execute(args: HandleUserInfoRequestArgs): IdkResult<UserInfoResponse, IdkError> =
        authServerService.commands.getUserInfo.execute(GetUserInfoArgs(accessToken = args.accessToken))
}

private class Oid4vciFakeHandleJwksRequestCommand(
    private val authServerService: AuthorizationServerService,
) : HandleJwksRequestCommand {
    override val commandId: String get() = HandleJwksRequestCommand.COMMAND_ID
    override val inputTypeToken get() = typeToken<HandleJwksRequestArgs>()
    override val outputTypeToken get() = typeToken<JwksResult>()
    override val isEnabled: Boolean = true

    override suspend fun supports(args: Any): Boolean = args is HandleJwksRequestArgs

    override suspend fun execute(args: HandleJwksRequestArgs): IdkResult<JwksResult, IdkError> = authServerService.commands.getJwks.execute(GetJwksArgs())
}

/** Test stub: no-op nonce manager that returns fixed values for OID4VCI E2E. */
private object Oid4vciFakeNoOpDpopNonceManager : com.sphereon.oauth2.server.authorization.dpop.DpopNonceManager {
    override suspend fun currentNonce(): String = "test-nonce-current"

    override suspend fun rotate(): String = "test-nonce-rotated"

    override suspend fun isValid(nonce: String): Boolean = true
}

/** Test stub: no-cert extractor for OID4VCI E2E flows that don't exercise mTLS. */
private object Oid4vciFakeNoCertExtractor :
    com.sphereon.oauth2.server.authorization.command.clientauth.ClientCertificateExtractor {
    override suspend fun extractCertificate(
        request: com.sphereon.core.api.http.GenericHttpRequest,
    ): com.sphereon.core.api.IdkResult<ByteArray?, com.sphereon.oauth2.server.authorization.error.AuthorizationServerError> =
        com.sphereon.core.api
            .Ok(null)
}
