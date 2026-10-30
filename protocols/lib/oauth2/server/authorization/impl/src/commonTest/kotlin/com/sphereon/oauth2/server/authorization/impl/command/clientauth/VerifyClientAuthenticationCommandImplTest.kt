/*
 * Copyright 2023-2026 Sphereon International B.V.
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

package com.sphereon.oauth2.server.authorization.impl.command.clientauth

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.defaults.random.defaultSecureRandom
import com.sphereon.crypto.core.jose.JwaCurve
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.jose.jws.JwsJsonFlattened
import com.sphereon.crypto.jose.jws.JwsJsonGeneral
import com.sphereon.crypto.jose.jws.JwsJsonGeneralWithIdentifiers
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.crypto.jose.jws.JwtCompactResult
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.PreparedJwsObject
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonArgs
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.oauth2.common.config.FeaturePolicy
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.ClientCredentials
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.server.authorization.command.ClientAuthenticationEndpoint
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthentication
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationArgs
import com.sphereon.oauth2.server.authorization.command.clientauth.VerifyAttestationClientAuthCommand
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.resolver.ClientJwksResolver
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryAttestationChallengeStorage
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryAttestationPopJtiStorage
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryClientAssertionJtiStore
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientType
import com.sphereon.oauth2.server.authorization.storage.ClientAssertionJtiStore
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

class VerifyClientAuthenticationCommandImplTest {
    private val ctx = OAuth2ServerTestContext("client-auth-test", this)
    private val challengeStorage = InMemoryAttestationChallengeStorage(defaultSecureRandom())

    private fun createCommand(
        clientRegistry: ClientRegistry = StubClientRegistry(),
        jwtService: JwtService = StubJwtService(),
        config: OAuth2ServerInstanceConfig =
            OAuth2ServerInstanceConfig(
                issuer = "https://auth.example.com",
                attestation = FeaturePolicy.SUPPORTED,
            ),
        clientJwksResolver: ClientJwksResolver = StubClientJwksResolver(emptyList()),
        jtiStore: ClientAssertionJtiStore = InMemoryClientAssertionJtiStore(),
    ): VerifyClientAuthenticationCommandImpl {
        val configProvider =
            TestOAuth2ServersConfigProvider(
                OAuth2ServersConfig(servers = mapOf("default" to config)),
            )
        val attestationCommand =
            VerifyAttestationClientAuthCommandImpl(
                ctx.execution,
                clientRegistry,
                jwtService,
                configProvider,
                challengeStorage,
                InMemoryAttestationPopJtiStorage(),
                EmptyX509TrustAnchorLoader,
                UnreachableIdentifierService,
            )
        return VerifyClientAuthenticationCommandImpl(
            ctx.execution,
            clientRegistry,
            lazyOf(jwtService),
            configProvider,
            lazyOf(clientJwksResolver),
            lazyOf(jtiStore),
            lazyOf(attestationCommand),
        )
    }

    // ========================================================================
    // Basic Auth
    // ========================================================================

    @Test
    fun testBasicAuthSuccess() =
        runTest {
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                        ),
                    verifyResult = true,
                )
            val command = createCommand(clientRegistry = registry)

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.Basic(
                                ClientCredentials("client1", "secret1"),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isOk)
            assertEquals("client1", result.value.clientId)
            assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, result.value.method)
            assertNull(result.value.clientInstanceKey)
        }

    @Test
    fun basicAuthDoesNotConstructJwtJwksReplayOrAttestationClosures() =
        runTest {
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                        ),
                    verifyResult = true,
                )
            val configProvider =
                TestOAuth2ServersConfigProvider(
                    OAuth2ServersConfig(
                        servers =
                            mapOf(
                                "default" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://auth.example.com",
                                        attestation = FeaturePolicy.SUPPORTED,
                                    ),
                            ),
                    ),
                )
            var jwtConstructions = 0
            var jwksConstructions = 0
            var replayStoreConstructions = 0
            var attestationConstructions = 0
            val command =
                VerifyClientAuthenticationCommandImpl(
                    ctx.execution,
                    registry,
                    lazy {
                        jwtConstructions++
                        StubJwtService()
                    },
                    configProvider,
                    lazy {
                        jwksConstructions++
                        StubClientJwksResolver(emptyList())
                    },
                    lazy {
                        replayStoreConstructions++
                        InMemoryClientAssertionJtiStore()
                    },
                    lazy<VerifyAttestationClientAuthCommand> {
                        attestationConstructions++
                        error("Basic authentication must not construct attestation verification")
                    },
                )

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.Basic(
                                ClientCredentials("client1", "secret1"),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isOk)
            assertEquals(0, jwtConstructions)
            assertEquals(0, jwksConstructions)
            assertEquals(0, replayStoreConstructions)
            assertEquals(0, attestationConstructions)
        }

    @Test
    fun testBasicAuthInvalidCredentials() =
        runTest {
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                        ),
                    verifyResult = false,
                )
            val command = createCommand(clientRegistry = registry)

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.Basic(
                                ClientCredentials("client1", "wrong-secret"),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr)
        }

    @Test
    fun basicCredentialsForAnotherClientAreRejectedBeforeRegistryAccess() =
        runTest {
            val registry = StubClientRegistry()

            val result =
                createCommand(clientRegistry = registry).execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication = ClientAuthenticationConfig.Basic(ClientCredentials("client-a", "secret")),
                        clientId = "client-b",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
            assertEquals(0, registry.getClientCount)
            assertEquals(0, registry.verifyCredentialsCount)
        }

    // ========================================================================
    // Post Auth
    // ========================================================================

    @Test
    fun testPostAuthSuccess() =
        runTest {
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_POST,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                        ),
                    verifyResult = true,
                )
            val command = createCommand(clientRegistry = registry)

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.Post(
                                ClientCredentials("client1", "secret1"),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isOk)
            assertEquals("client1", result.value.clientId)
            assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_POST, result.value.method)
        }

    @Test
    fun testPostAuthInvalidCredentials() =
        runTest {
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_POST,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                        ),
                    verifyResult = false,
                )
            val command = createCommand(clientRegistry = registry)

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.Post(
                                ClientCredentials("client1", "wrong"),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr)
        }

    @Test
    fun postCredentialsForAnotherClientAreRejectedBeforeRegistryAccess() =
        runTest {
            val registry = StubClientRegistry()

            val result =
                createCommand(clientRegistry = registry).execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication = ClientAuthenticationConfig.Post(ClientCredentials("client-a", "secret")),
                        clientId = "client-b",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
            assertEquals(0, registry.getClientCount)
            assertEquals(0, registry.verifyCredentialsCount)
        }

    // ========================================================================
    // None / Anonymous
    // ========================================================================

    @Test
    fun testNoneAuthPassesThrough() =
        runTest {
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "public-client",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.NONE,
                            clientType = ClientType.PUBLIC,
                            grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
                        ),
                )
            val command = createCommand(clientRegistry = registry)

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication = ClientAuthenticationConfig.None("public-client"),
                        clientId = "public-client",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isOk)
            assertEquals("public-client", result.value.clientId)
            assertEquals(ClientAuthenticationMethod.NONE, result.value.method)
        }

    @Test
    fun unknownPublicClientIdIsInvalidAtTheTokenEndpoint() =
        runTest {
            val result =
                createCommand(clientRegistry = StubClientRegistry()).execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication = ClientAuthenticationConfig.None("unknown-wallet"),
                        clientId = "unknown-wallet",
                        tokenEndpointUrl = "https://auth.example.com/token",
                        endpoint = ClientAuthenticationEndpoint.TOKEN,
                    ),
                )

            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun testAnonymousAuthPassesThrough() =
        runTest {
            val registry = StubClientRegistry()
            val command = createCommand(clientRegistry = registry)

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication = ClientAuthenticationConfig.Anonymous,
                        clientId = "",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isOk)
            assertEquals(ClientAuthenticationMethod.NONE, result.value.method)
            assertNull(result.value.clientAuthorization)
            assertEquals(0, registry.getClientCount)
            assertEquals(0, registry.verifyCredentialsCount)
        }

    // ========================================================================
    // Attestation — disabled
    // ========================================================================

    @Test
    fun testAttestationRejectedWhenDisabled() =
        runTest {
            val command =
                createCommand(
                    config =
                        OAuth2ServerInstanceConfig(
                            issuer = "https://auth.example.com",
                            attestation = FeaturePolicy.DISABLED,
                        ),
                )

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.AttestationJwt(
                                com.sphereon.oauth2.common.model
                                    .ClientAttestation("att.jwt", "pop.jwt"),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr)
        }

    // ========================================================================
    // Registered token_endpoint_auth_method enforcement
    // ========================================================================

    private fun clientRegistration(
        clientId: String = "client1",
        method: ClientAuthenticationMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        type: ClientType = ClientType.CONFIDENTIAL,
    ) = ClientRegistration(
        clientId = clientId,
        tokenEndpointAuthMethod = method,
        clientType = type,
        grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
    )

    @Test
    fun clientAuth_basicWhenRegisteredPost_rejects() =
        runTest {
            val registry =
                StubClientRegistry(
                    client = clientRegistration(method = ClientAuthenticationMethod.CLIENT_SECRET_POST),
                    verifyResult = true,
                )
            val command = createCommand(clientRegistry = registry)

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication = ClientAuthenticationConfig.Basic(ClientCredentials("client1", "secret1")),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr, "Basic auth must be rejected when client registered for client_secret_post")
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun clientAuth_noneWhenRegisteredBasic_rejects() =
        runTest {
            val registry =
                StubClientRegistry(
                    client = clientRegistration(method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC),
                )
            val command = createCommand(clientRegistry = registry)

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication = ClientAuthenticationConfig.None("client1"),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr, "None must be rejected when client registered for client_secret_basic")
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun clientAuth_noneAllowedOnlyForPublicClients() =
        runTest {
            // Confidential client with auth method NONE should be rejected: method=none is only valid for PUBLIC clients.
            val confidentialNoneRegistry =
                StubClientRegistry(
                    client =
                        clientRegistration(
                            method = ClientAuthenticationMethod.NONE,
                            type = ClientType.CONFIDENTIAL,
                        ),
                )
            val confidentialResult =
                createCommand(clientRegistry = confidentialNoneRegistry).execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication = ClientAuthenticationConfig.None("client1"),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )
            assertTrue(confidentialResult.isErr, "method=none must be rejected for confidential clients")

            // Public client with auth method NONE should be accepted.
            val publicRegistry =
                StubClientRegistry(
                    client =
                        clientRegistration(
                            method = ClientAuthenticationMethod.NONE,
                            type = ClientType.PUBLIC,
                        ),
                )
            val publicResult =
                createCommand(clientRegistry = publicRegistry).execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication = ClientAuthenticationConfig.None("client1"),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )
            assertTrue(publicResult.isOk, "method=none must be accepted for public clients")
            assertEquals(ClientAuthenticationMethod.NONE, publicResult.value.method)
        }

    @Test
    fun clientAuth_basicMatchesRegistration_accepts() =
        runTest {
            val registry =
                StubClientRegistry(
                    client = clientRegistration(method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC),
                    verifyResult = true,
                )
            val command = createCommand(clientRegistry = registry)

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication = ClientAuthenticationConfig.Basic(ClientCredentials("client1", "secret1")),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isOk)
            val clientAuthorization = assertNotNull(result.value.clientAuthorization)
            assertEquals("client1", clientAuthorization.clientId)
            assertEquals(listOf(GrantType.CLIENT_CREDENTIALS), clientAuthorization.grantTypes)
        }

    // ========================================================================
    // private_key_jwt bound to registered JWKS
    // ========================================================================

    private fun assertionJwt(
        alg: String,
        kid: String?,
    ): String {
        val header =
            buildJsonObject {
                put("alg", alg)
                put("typ", "JWT")
                if (kid != null) put("kid", kid)
            }
        val payload = buildJsonObject { put("sub", "client1") }
        return header.toString().encodeToByteArray().encodeToBase64Url() + "." +
            payload.toString().encodeToByteArray().encodeToBase64Url() + "." +
            "sig"
    }

    private fun assertionJwtWithHeader(header: JsonObject): String =
        header.toString().encodeToByteArray().encodeToBase64Url() + "." +
            buildJsonObject { put("sub", "client1") }.toString().encodeToByteArray().encodeToBase64Url() + ".sig"

    private fun ecJwk(kid: String) =
        Jwk(
            kty = JwaKeyType.EC,
            crv = JwaCurve.P_256,
            x = "x-coord-placeholder",
            y = "y-coord-placeholder",
            kid = kid,
        )

    @Test
    fun privateKeyJwt_kidNotInRegisteredJwks_rejects() =
        runTest {
            val registeredKey = ecJwk("registered-key")
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                            jwks = listOf(registeredKey),
                            tokenEndpointAuthSigningAlg = listOf("ES256"),
                        ),
                )
            val command =
                createCommand(
                    clientRegistry = registry,
                    clientJwksResolver = StubClientJwksResolver(listOf(registeredKey)),
                )

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.PrivateKeyJwt(
                                com.sphereon.oauth2.common.model.ClientAssertion(
                                    "client1",
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                    assertionJwt(alg = "ES256", kid = "unknown-key"),
                                ),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun privateKeyJwt_algNotInRegisteredAlgs_rejects() =
        runTest {
            val registeredKey = ecJwk("registered-key")
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                            jwks = listOf(registeredKey),
                            tokenEndpointAuthSigningAlg = listOf("ES256"),
                        ),
                )
            val command =
                createCommand(
                    clientRegistry = registry,
                    clientJwksResolver = StubClientJwksResolver(listOf(registeredKey)),
                )

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.PrivateKeyJwt(
                                com.sphereon.oauth2.common.model.ClientAssertion(
                                    "client1",
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                    assertionJwt(alg = "RS256", kid = "registered-key"),
                                ),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun privateKeyJwt_happyPath_accepts() =
        runTest {
            val registeredKey = ecJwk("registered-key")
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                            jwks = listOf(registeredKey),
                            tokenEndpointAuthSigningAlg = listOf("ES256"),
                        ),
                )
            val jwtService = StubJwtService(claimsOverride = assertionClaims())
            val command =
                createCommand(
                    clientRegistry = registry,
                    clientJwksResolver = StubClientJwksResolver(listOf(registeredKey)),
                    // Stub jwt service returns valid; claim checks inside verifyJwtAssertion still run
                    // against the parsed payload. Provide a jwt service that feeds back a full set
                    // of conformant claims ((spec-aligned) requires iss/sub/aud/exp/jti).
                    jwtService = jwtService,
                )

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.PrivateKeyJwt(
                                com.sphereon.oauth2.common.model.ClientAssertion(
                                    "client1",
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                    assertionJwt(alg = "ES256", kid = "registered-key"),
                                ),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isOk, "expected accept; got: ${if (result.isErr) result.error.message.defaultMessage else ""}")
            assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, result.value.method)
            val trustedJwks = assertNotNull(jwtService.lastVerifyArgs?.trustedJwks)
            val trustedKeys = assertNotNull(trustedJwks["keys"]).jsonArray
            assertEquals(1, trustedKeys.size)
            assertEquals("registered-key", trustedKeys.single().jsonObject["kid"]?.jsonPrimitive?.content)
        }

    @Test
    fun privateKeyJwt_missingKid_rejects() =
        runTest {
            val registeredKey = ecJwk("registered-key")
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                            jwks = listOf(registeredKey),
                            tokenEndpointAuthSigningAlg = listOf("ES256"),
                        ),
                )
            val command =
                createCommand(
                    clientRegistry = registry,
                    clientJwksResolver = StubClientJwksResolver(listOf(registeredKey)),
                )

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.PrivateKeyJwt(
                                com.sphereon.oauth2.common.model.ClientAssertion(
                                    "client1",
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                    assertionJwt(alg = "ES256", kid = null),
                                ),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr)
        }

    @Test
    fun privateKeyJwt_malformedAlgAndKidTypes_returnInvalidClient() =
        runTest {
            val malformed =
                listOf(
                    kotlinx.serialization.json.JsonArray(listOf(kotlinx.serialization.json.JsonPrimitive("ES256"))),
                    buildJsonObject { put("value", "ES256") },
                    kotlinx.serialization.json.JsonNull,
                    kotlinx.serialization.json.JsonPrimitive(256),
                )
            malformed.forEach { value ->
                for (name in listOf("alg", "kid")) {
                    val header = buildJsonObject {
                        put("alg", if (name == "alg") value else kotlinx.serialization.json.JsonPrimitive("ES256"))
                        put("kid", if (name == "kid") value else kotlinx.serialization.json.JsonPrimitive("registered-key"))
                    }
                    val args = task25Args().copy(
                        clientAuthentication = ClientAuthenticationConfig.PrivateKeyJwt(
                            com.sphereon.oauth2.common.model.ClientAssertion(
                                "client1",
                                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                assertionJwtWithHeader(header),
                            ),
                        ),
                    )
                    val command =
                        createCommand(
                            clientRegistry = StubClientRegistry(task25Client()),
                            clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                            jwtService = StubJwtService(claimsOverride = assertionClaims()),
                        )
                    val result = command.execute(args)
                    assertTrue(result.isErr, "$name=$value must return invalid_client")
                    assertEquals("invalid_client", result.error.code)
                }
            }
        }

    // ========================================================================
    // assertion iss/sub/aud/exp/iat/jti validation + jti replay
    // ========================================================================

    private fun assertionClaims(
        iss: String = "client1",
        sub: String = "client1",
        aud: Any = "https://auth.example.com",
        expSecondsFromNow: Long = 120,
        iatSecondsFromNow: Long? = 0,
        jti: String? = "jti-unique-1",
    ): JsonObject =
        buildJsonObject {
            put("iss", iss)
            put("sub", sub)
            when (aud) {
                is JsonElement -> put("aud", aud)

                is String -> {
                    put("aud", aud)
                }

                is List<*> -> {
                    val arr =
                        buildJsonArray {
                            aud.forEach { add(kotlinx.serialization.json.JsonPrimitive(it.toString())) }
                        }
                    put("aud", arr)
                }

                is Number -> put("aud", kotlinx.serialization.json.JsonPrimitive(aud))
            }
            put("exp", kotlinx.serialization.json.JsonPrimitive(Clock.System.now().epochSeconds + expSecondsFromNow))
            if (iatSecondsFromNow != null) {
                put("iat", kotlinx.serialization.json.JsonPrimitive(Clock.System.now().epochSeconds + iatSecondsFromNow))
            }
            if (jti != null) put("jti", jti)
        }

    private fun task25Client(method: ClientAuthenticationMethod = ClientAuthenticationMethod.PRIVATE_KEY_JWT): ClientRegistration =
        ClientRegistration(
            clientId = "client1",
            clientSecret = "registered-secret",
            tokenEndpointAuthMethod = method,
            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
            jwks = listOf(ecJwk("registered-key")),
            tokenEndpointAuthSigningAlg = if (method == ClientAuthenticationMethod.PRIVATE_KEY_JWT) listOf("ES256") else listOf("HS256"),
        )

    private fun task25Args(): VerifyClientAuthenticationArgs =
        VerifyClientAuthenticationArgs(
            clientAuthentication =
                ClientAuthenticationConfig.PrivateKeyJwt(
                    com.sphereon.oauth2.common.model.ClientAssertion(
                        "client1",
                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        assertionJwt(alg = "ES256", kid = "registered-key"),
                    ),
                ),
            clientId = "client1",
            tokenEndpointUrl = "https://auth.example.com/token",
        )

    @Test
    fun walletInstanceAttestationRequired_rejectsBasicAuthAtTokenEndpoint() =
        runTest {
            val command =
                createCommand(
                    clientRegistry =
                        StubClientRegistry(
                            client =
                                ClientRegistration(
                                    clientId = "client1",
                                    tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                    grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                                ),
                        ),
                    config =
                        OAuth2ServerInstanceConfig(
                            issuer = "https://auth.example.com",
                            attestation = FeaturePolicy.SUPPORTED,
                            walletInstanceAttestation = FeaturePolicy.REQUIRED,
                        ),
                )

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.Basic(
                                ClientCredentials("client1", "secret1"),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                        endpoint = ClientAuthenticationEndpoint.TOKEN,
                    ),
                )

            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun walletInstanceAttestationRequired_rejectsPrivateKeyJwtAtParEndpoint() =
        runTest {
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims()),
                    config =
                        OAuth2ServerInstanceConfig(
                            issuer = "https://auth.example.com",
                            attestation = FeaturePolicy.SUPPORTED,
                            walletInstanceAttestation = FeaturePolicy.REQUIRED,
                        ),
                )

            val result = command.execute(task25Args().copy(endpoint = ClientAuthenticationEndpoint.PAR))

            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun walletInstanceAttestationRequired_doesNotBlockOtherClientAuthEndpoint() =
        runTest {
            val command =
                createCommand(
                    clientRegistry =
                        StubClientRegistry(
                            client =
                                ClientRegistration(
                                    clientId = "client1",
                                    tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                    grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                                ),
                        ),
                    config =
                        OAuth2ServerInstanceConfig(
                            issuer = "https://auth.example.com",
                            attestation = FeaturePolicy.SUPPORTED,
                            walletInstanceAttestation = FeaturePolicy.REQUIRED,
                        ),
                )

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.Basic(
                                ClientCredentials("client1", "secret1"),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                        endpoint = ClientAuthenticationEndpoint.OTHER,
                    ),
                )

            assertTrue(
                result.isOk,
                "expected non-PAR/token client-auth endpoint to proceed; got: ${if (result.isErr) result.error.message.defaultMessage else ""}",
            )
            assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_BASIC, result.value.method)
        }

    @Test
    fun assertion_issNotEqualSub_rejects() =
        runTest {
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(iss = "client1", sub = "other")),
                )
            val result = command.execute(task25Args())
            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun assertion_issNotEqualClientId_rejects() =
        runTest {
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(iss = "impostor", sub = "impostor")),
                )
            val result = command.execute(task25Args())
            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun assertion_aud_singleConfiguredIssuer_accepts() =
        runTest {
            val config =
                OAuth2ServerInstanceConfig(
                    issuer = "https://auth.example.com/issuer",
                    attestation = FeaturePolicy.SUPPORTED,
                )
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(aud = "https://auth.example.com/issuer")),
                    config = config,
                )
            val result = command.execute(task25Args())
            assertTrue(result.isOk, "expected accept; got: ${if (result.isErr) result.error.message.defaultMessage else ""}")
        }

    @Test
    fun assertion_audienceArrayWithSingleConfiguredIssuer_accepts() =
        runTest {
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(aud = listOf("https://auth.example.com"))),
                )

            assertTrue(command.execute(task25Args()).isOk)
        }

    @Test
    fun assertion_audienceArrayWithMultipleValues_rejects() =
        runTest {
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(aud = listOf("https://auth.example.com", "https://other.example.com"))),
                )

            val result = command.execute(task25Args())
            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun privateKeyJwt_duplicateIssuerAudienceArray_rejects() =
        runTest {
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(aud = listOf("https://auth.example.com", "https://auth.example.com"))),
                )
            val result = command.execute(task25Args())
            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun assertion_audienceTrustedConfiguredTokenEndpoint_accepts() =
        runTest {
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(aud = "https://auth.example.com/token")),
                )

            val result = command.execute(task25Args())
            assertTrue(result.isOk)
        }

    @Test
    fun privateKeyJwt_blankConfiguredIssuer_rejectsIssuerAudience() =
        runTest {
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(aud = "https://auth.example.com")),
                    config = OAuth2ServerInstanceConfig(issuer = " ", attestation = FeaturePolicy.SUPPORTED),
                )

            val result = command.execute(task25Args())

            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun assertion_audienceMalformedObject_rejectsWithoutThrowing() =
        runTest {
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(aud = buildJsonObject { put("value", true) })),
                )

            val result = command.execute(task25Args())
            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun assertion_audienceMalformedArrayEntry_rejectsWithoutThrowing() =
        runTest {
            val malformedAudience =
                buildJsonArray {
                    add(kotlinx.serialization.json.JsonPrimitive("https://auth.example.com"))
                    add(kotlinx.serialization.json.JsonPrimitive(42))
                }
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(aud = malformedAudience)),
                )

            val result = command.execute(task25Args())
            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun assertion_malformedIdentityAndTimeClaimTypes_returnInvalidClient() =
        runTest {
            val malformedValues =
                listOf(
                    kotlinx.serialization.json.JsonArray(listOf(kotlinx.serialization.json.JsonPrimitive("client1"))),
                    buildJsonObject { put("value", "client1") },
                    kotlinx.serialization.json.JsonNull,
                    kotlinx.serialization.json.JsonPrimitive(42),
                )
            val cases =
                buildList {
                    listOf("iss", "sub", "jti").forEach { key -> malformedValues.forEach { add(key to it) } }
                    listOf("exp", "iat").forEach { key ->
                        add(key to kotlinx.serialization.json.JsonPrimitive("not-a-number"))
                        add(key to kotlinx.serialization.json.JsonPrimitive("123"))
                        add(key to kotlinx.serialization.json.JsonArray(listOf(kotlinx.serialization.json.JsonPrimitive(123))))
                        add(key to buildJsonObject { put("value", 123) })
                        add(key to kotlinx.serialization.json.JsonNull)
                    }
                }
            cases.forEach { (claim, value) ->
                val claims = JsonObject(assertionClaims().toMutableMap().apply { put(claim, value) })
                val command =
                    createCommand(
                        clientRegistry = StubClientRegistry(task25Client()),
                        clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                        jwtService = StubJwtService(claimsOverride = claims),
                    )
                val result = command.execute(task25Args())
                assertTrue(result.isErr, "$claim=$value should be rejected")
                assertEquals("invalid_client", result.error.code)
            }
        }

    @Test
    fun assertion_aud_missing_rejects() =
        runTest {
            val claimsWithoutAud =
                buildJsonObject {
                    put("iss", "client1")
                    put("sub", "client1")
                    put("exp", kotlinx.serialization.json.JsonPrimitive(Clock.System.now().epochSeconds + 120))
                    put("jti", "jti-x")
                }
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = claimsWithoutAud),
                )
            val result = command.execute(task25Args())
            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun assertion_expInPast_rejects() =
        runTest {
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(expSecondsFromNow = -30)),
                )
            val result = command.execute(task25Args())
            assertTrue(result.isErr)
        }

    @Test
    fun assertion_iatFarInPast_rejects() =
        runTest {
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(iatSecondsFromNow = -3600)),
                )
            val result = command.execute(task25Args())
            assertTrue(result.isErr)
        }

    @Test
    fun assertion_jtiReplay_rejects() =
        runTest {
            val sharedStore = InMemoryClientAssertionJtiStore()
            val command1 =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(jti = "jti-replay")),
                    jtiStore = sharedStore,
                )
            val firstResult = command1.execute(task25Args())
            assertTrue(firstResult.isOk, "first use should succeed")

            val command2 =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(jti = "jti-replay")),
                    jtiStore = sharedStore,
                )
            val replayResult = command2.execute(task25Args())
            assertTrue(replayResult.isErr)
            assertEquals("invalid_client", replayResult.error.code)
        }

    @Test
    fun assertion_missingJti_rejects() =
        runTest {
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService = StubJwtService(claimsOverride = assertionClaims(jti = null)),
                )
            val result = command.execute(task25Args())
            assertTrue(result.isErr)
        }

    // ========================================================================
    // introspect/revoke share the /token client-auth path
    // ========================================================================

    @Test
    fun introspect_withExpiredAssertion_rejects() =
        runTest {
            // /introspect and /token route client auth through the same command; this exercises the
            // shared code path with a tokenEndpointUrl pointing at /introspect. Expired assertion →
            // invalid_client regardless of endpoint.
            val command =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService =
                        StubJwtService(
                            claimsOverride = assertionClaims(aud = "https://auth.example.com", expSecondsFromNow = -60),
                        ),
                )

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.PrivateKeyJwt(
                                com.sphereon.oauth2.common.model.ClientAssertion(
                                    "client1",
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                    assertionJwt(alg = "ES256", kid = "registered-key"),
                                ),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/introspect",
                    ),
                )

            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun revoke_withJtiReplay_rejects() =
        runTest {
            // /revoke shares the same jti store used at /token. The first submission at /token is
            // accepted; the replay at /revoke is rejected even though the endpoint differs.
            val sharedStore = InMemoryClientAssertionJtiStore()
            val tokenCommand =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService =
                        StubJwtService(
                            claimsOverride = assertionClaims(aud = "https://auth.example.com", jti = "jti-cross-endpoint"),
                        ),
                    jtiStore = sharedStore,
                )
            val first = tokenCommand.execute(task25Args())
            assertTrue(first.isOk, "first use should succeed; got: ${if (first.isErr) first.error.message.defaultMessage else ""}")

            val revokeCommand =
                createCommand(
                    clientRegistry = StubClientRegistry(task25Client()),
                    clientJwksResolver = StubClientJwksResolver(listOf(ecJwk("registered-key"))),
                    jwtService =
                        StubJwtService(
                            claimsOverride = assertionClaims(aud = "https://auth.example.com", jti = "jti-cross-endpoint"),
                        ),
                    jtiStore = sharedStore,
                    config =
                        OAuth2ServerInstanceConfig(
                            issuer = "https://auth.example.com",
                            attestation = FeaturePolicy.SUPPORTED,
                        ),
                )
            val replay =
                revokeCommand.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.PrivateKeyJwt(
                                com.sphereon.oauth2.common.model.ClientAssertion(
                                    "client1",
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                    assertionJwt(alg = "ES256", kid = "registered-key"),
                                ),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/revoke",
                    ),
                )

            assertTrue(replay.isErr)
            assertEquals("invalid_client", replay.error.code)
        }

    // ========================================================================
    // client_secret_jwt bound to registered secret
    // ========================================================================

    @Test
    fun clientSecretJwt_wrongSecret_rejects() =
        runTest {
            // The JWT service fails signature verification when the registered secret doesn't match
            // the signing key. We simulate that here with `verifyValid = false`, which stands in for
            // an HMAC-check against the registered secret that produces a different MAC than the
            // one in the assertion.
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            clientSecret = "registered-secret",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                            tokenEndpointAuthSigningAlg = listOf("HS256"),
                        ),
                )
            val command =
                createCommand(
                    clientRegistry = registry,
                    jwtService = StubJwtService(verifyValid = false),
                )

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.SecretJwt(
                                com.sphereon.oauth2.common.model.ClientAssertion(
                                    "client1",
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                    assertionJwt(alg = "HS256", kid = null),
                                ),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun clientSecretJwt_retainsRfc7523TokenEndpointAudience() =
        runTest {
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            clientSecret = "registered-secret",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                            tokenEndpointAuthSigningAlg = listOf("HS256"),
                        ),
                )
            val command =
                createCommand(
                    clientRegistry = registry,
                    jwtService = StubJwtService(claimsOverride = assertionClaims(aud = "https://auth.example.com/token")),
                )

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.SecretJwt(
                                com.sphereon.oauth2.common.model.ClientAssertion(
                                    "client1",
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                    assertionJwt(alg = "HS256", kid = null),
                                ),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isOk)
            assertEquals(ClientAuthenticationMethod.CLIENT_SECRET_JWT, result.value.method)
        }

    @Test
    fun clientSecretJwt_rejectsMalformedAudienceArrayEntries() =
        runTest {
            val malformedAudiences =
                listOf(
                    buildJsonArray {
                        add(kotlinx.serialization.json.JsonPrimitive("https://auth.example.com"))
                        add(kotlinx.serialization.json.JsonPrimitive(7))
                    },
                    buildJsonArray {
                        add(kotlinx.serialization.json.JsonPrimitive("https://auth.example.com/token"))
                        add(buildJsonObject { put("value", true) })
                    },
                )
            malformedAudiences.forEach { aud ->
                val command =
                    createCommand(
                        clientRegistry =
                            StubClientRegistry(
                                ClientRegistration(
                                    clientId = "client1",
                                    clientSecret = "registered-secret",
                                    tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT,
                                    grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                                    tokenEndpointAuthSigningAlg = listOf("HS256"),
                                ),
                            ),
                        jwtService = StubJwtService(claimsOverride = assertionClaims(aud = aud)),
                    )
                val result =
                    command.execute(
                        VerifyClientAuthenticationArgs(
                            clientAuthentication =
                                ClientAuthenticationConfig.SecretJwt(
                                    com.sphereon.oauth2.common.model.ClientAssertion(
                                        "client1",
                                        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                        assertionJwt(alg = "HS256", kid = null),
                                    ),
                                ),
                            clientId = "client1",
                            tokenEndpointUrl = "https://auth.example.com/token",
                        ),
                    )
                assertTrue(result.isErr, "malformed client_secret_jwt aud=$aud must be rejected")
                assertEquals("invalid_client", result.error.code)
            }
        }

    @Test
    fun clientSecretJwt_acceptsMultipleValidAudienceStrings() =
        runTest {
            val command =
                createCommand(
                    clientRegistry =
                        StubClientRegistry(
                            ClientRegistration(
                                clientId = "client1",
                                clientSecret = "registered-secret",
                                tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT,
                                grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                                tokenEndpointAuthSigningAlg = listOf("HS256"),
                            ),
                        ),
                    jwtService =
                        StubJwtService(
                            claimsOverride =
                                assertionClaims(
                                    aud = listOf("https://other.example.com", "https://auth.example.com/token"),
                                ),
                        ),
                )
            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.SecretJwt(
                                com.sphereon.oauth2.common.model.ClientAssertion(
                                    "client1",
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                    assertionJwt(alg = "HS256", kid = null),
                                ),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )
            assertTrue(result.isOk)
        }

    @Test
    fun clientSecretJwt_weakHsAlg_rejectsIfClientRegisteredHs256() =
        runTest {
            // Registered allow-list narrows to HS256; request arrives with HS384, so the
            // per-client signing-alg gate rejects it.
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            clientSecret = "registered-secret",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                            tokenEndpointAuthSigningAlg = listOf("HS256"),
                        ),
                )
            val command = createCommand(clientRegistry = registry)

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.SecretJwt(
                                com.sphereon.oauth2.common.model.ClientAssertion(
                                    "client1",
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                    assertionJwt(alg = "HS384", kid = null),
                                ),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    @Test
    fun clientSecretJwt_asymmetricAlg_rejectsUnconditionally() =
        runTest {
            // Even if a client misconfigures `tokenEndpointAuthSigningAlg = ["RS256"]` for
            // client_secret_jwt, the cross-binding to HMAC is enforced: RS256 is invalid for
            // this method (RFC 7518 §3.2).
            val registry =
                StubClientRegistry(
                    client =
                        ClientRegistration(
                            clientId = "client1",
                            clientSecret = "registered-secret",
                            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_JWT,
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                            tokenEndpointAuthSigningAlg = listOf("RS256"),
                        ),
                )
            val command = createCommand(clientRegistry = registry)

            val result =
                command.execute(
                    VerifyClientAuthenticationArgs(
                        clientAuthentication =
                            ClientAuthenticationConfig.SecretJwt(
                                com.sphereon.oauth2.common.model.ClientAssertion(
                                    "client1",
                                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                                    assertionJwt(alg = "RS256", kid = null),
                                ),
                            ),
                        clientId = "client1",
                        tokenEndpointUrl = "https://auth.example.com/token",
                    ),
                )

            assertTrue(result.isErr)
            assertEquals("invalid_client", result.error.code)
        }

    // ========================================================================
    // Stubs
    // ========================================================================

    private class StubClientRegistry(
        private val client: ClientRegistration? = null,
        private val verifyResult: Boolean = true,
    ) : ClientRegistry {
        var getClientCount: Int = 0
            private set
        var verifyCredentialsCount: Int = 0
            private set

        override suspend fun getClient(clientId: String): IdkResult<ClientRegistration?, AuthorizationServerError.StorageError> {
            getClientCount++
            return Ok(client)
        }

        override suspend fun registerClient(registration: ClientRegistration): IdkResult<ClientRegistration, AuthorizationServerError.StorageError> = Ok(registration)

        override suspend fun updateClient(
            clientId: String,
            registration: ClientRegistration,
        ): IdkResult<ClientRegistration, AuthorizationServerError> = Ok(registration)

        override suspend fun deleteClient(clientId: String): IdkResult<Unit, AuthorizationServerError> = Ok(Unit)

        override suspend fun listClients(
            limit: Int,
            offset: Int,
        ): IdkResult<List<ClientRegistration>, AuthorizationServerError.StorageError> = Ok(emptyList())

        override suspend fun findClientsByName(name: String): IdkResult<List<ClientRegistration>, AuthorizationServerError.StorageError> = Ok(emptyList())

        override suspend fun clientExists(clientId: String): IdkResult<Boolean, AuthorizationServerError.StorageError> = Ok(client != null)

        override suspend fun verifyClientCredentials(
            clientId: String,
            clientSecret: String,
        ): IdkResult<Boolean, AuthorizationServerError.StorageError> {
            verifyCredentialsCount++
            return Ok(verifyResult)
        }
    }

    private class StubClientJwksResolver(
        private val jwks: List<Jwk>,
    ) : ClientJwksResolver {
        override suspend fun resolveFor(client: ClientRegistration): IdkResult<List<Jwk>, AuthorizationServerError> = Ok(jwks)
    }

    private object UnreachableIdentifierService : com.sphereon.crypto.resolution.IdentifierService {
        override val supportedIdentifierMethods: List<com.sphereon.crypto.resolution.IIdentifierMethod> = emptyList()

        override suspend fun isSupportedIdentifier(identifier: Any): Boolean = false

        override suspend fun isSupportedIdentifierMethod(identifierMethod: com.sphereon.crypto.resolution.IIdentifierMethod,): Boolean = false

        override suspend fun isSupportedOpts(opts: com.sphereon.crypto.resolution.IdentifierOptsOrResult): Boolean = false

        override suspend fun asSupportedOpts(
            opts: com.sphereon.crypto.resolution.IdentifierOptsOrResult,
        ): IdkResult<com.sphereon.crypto.resolution.IdentifierOptsOrResult, com.sphereon.core.api.error.IdkErrorType> = error("IdentifierService.asSupportedOpts is not exercised by these tests")

        override suspend fun resolve(
            opts: com.sphereon.crypto.resolution.IdentifierOptsOrResult,
        ): IdkResult<out com.sphereon.crypto.resolution.IdentifierOptsOrResult, com.sphereon.core.api.error.IdkErrorType> = error("IdentifierService.resolve is not exercised by these tests")
    }

    private object EmptyX509TrustAnchorLoader : com.sphereon.trust.x509.X509TrustAnchorLoader {
        override suspend fun loadTrustedCerts(): List<String> = emptyList()
    }

    private class StubJwtService(
        private val verifyValid: Boolean = true,
        private val claimsOverride: JsonObject? = null,
    ) : JwtService {
        var lastVerifyArgs: VerifyJwsArgs? = null
            private set

        private val notImpl = IdkError(code = "not_implemented", message = IdkError.Message(i18nKey = "", defaultMessage = "Not implemented"))

        override suspend fun prepareJws(args: CreateJwsJsonArgs): IdkResult<PreparedJwsObject, IdkError> = Err(notImpl)

        override suspend fun createJwsCompact(args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError> = Err(notImpl)

        override suspend fun createJwsJsonFlattened(args: CreateJwsJsonArgs): IdkResult<JwsJsonFlattened, IdkError> = Err(notImpl)

        override suspend fun createJwsJsonGeneral(args: CreateJwsJsonArgs): IdkResult<JwsJsonGeneral, IdkError> = Err(notImpl)

        override suspend fun verifyJws(args: VerifyJwsArgs): IdkResult<JwsValidationResult, IdkError> {
            lastVerifyArgs = args
            if (!verifyValid) {
                return Err(
                    IdkError(
                        code = "verification_failed",
                        message = IdkError.Message(i18nKey = "", defaultMessage = "Verification failed"),
                    ),
                )
            }
            return Ok(
                JwsValidationResult(
                    jws = JwsJsonGeneralWithIdentifiers(payload = "", signatures = emptyList()),
                    isValid = true,
                    parsedPayload = claimsOverride ?: JsonObject(emptyMap()),
                ),
            )
        }

        override fun assembleJwsGeneral(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray,
        ): JwsJsonGeneral = throw NotImplementedError()

        override fun assembleJwsFlattened(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray,
        ): JwsJsonFlattened = throw NotImplementedError()

        override fun assembleJwsCompact(
            prepared: PreparedJwsObject,
            signatureBytes: ByteArray,
        ): JwtCompactResult = throw NotImplementedError()

        override val commands: JwtService.Commands
            get() = throw NotImplementedError()
    }
}
