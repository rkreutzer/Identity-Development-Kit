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

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.oauth2.common.config.FeaturePolicy
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.model.OAuth2ResponseMode
import com.sphereon.oauth2.common.model.PkceMethod
import com.sphereon.oauth2.common.model.ResponseType
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientType
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Tests for PKCE default + server-policy enforcement, unregistered-client admission,
 * and response_mode resolution.
 */
class VerifyAuthorizationRequestPkceResponseModeTest {
    private val ctx = OAuth2ServerTestContext("verify-pkce-rmode-test", this)

    private fun createCommand(
        registry: ClientRegistry,
        pkcePolicy: FeaturePolicy = FeaturePolicy.REQUIRED,
        pkceMethodsSupported: Set<String> = setOf("S256"),
    ): VerifyAuthorizationRequestCommandImpl {
        val serverConfig =
            OAuth2ServerInstanceConfig(
                issuer = "http://localhost:8080",
                responseTypesSupported = setOf("code"),
                pkce = pkcePolicy,
                pkceMethodsSupported = pkceMethodsSupported,
            )
        val servers = OAuth2ServersConfig(servers = mapOf("default" to serverConfig), defaultServer = "default")
        return VerifyAuthorizationRequestCommandImpl(
            ctx.execution,
            registry,
            TestOAuth2ServersConfigProvider(servers),
            emptySet(),
            com.sphereon.oauth2.server.authorization.impl.provider.NoCredentialIssuerAudienceResolver(),
            Oid4vciUnregisteredWalletAdmissionRule(),
            com.sphereon.oauth2.server.authorization.impl.testutil.fixedAsInstanceIdProvider(),
        )
    }

    private fun confidentialClient(
        clientId: String = CLIENT_ID,
        requirePkce: Boolean = false,
    ): ClientRegistration =
        ClientRegistration(
            clientId = clientId,
            clientType = ClientType.CONFIDENTIAL,
            grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
            responseTypes = listOf(ResponseType.CODE),
            redirectUris = listOf("https://rp.example.com/cb"),
            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
            requirePkce = requirePkce,
        )

    private fun request(
        clientId: String = CLIENT_ID,
        codeChallenge: String? = "a".repeat(43),
        codeChallengeMethod: PkceMethod? = PkceMethod.S256,
        redirectUri: String? = "https://rp.example.com/cb",
        responseMode: String? = null,
        responseType: List<ResponseType> = listOf(ResponseType.CODE),
    ): AuthorizationRequestData =
        AuthorizationRequestData(
            clientId = clientId,
            redirectUri = redirectUri,
            responseType = responseType,
            scope = "openid",
            state = "s1",
            codeChallenge = codeChallenge,
            codeChallengeMethod = codeChallengeMethod,
            responseMode = responseMode,
        )

    // ─── PKCE default + policy enforcement ────────────────────────

    @Test
    fun verifyAbsentPkceRequiredRejects() =
        runTest {
            val cmd = createCommand(SingleClientRegistry(confidentialClient()), pkcePolicy = FeaturePolicy.REQUIRED)
            val result = cmd.execute(request(codeChallenge = null, codeChallengeMethod = null))
            assertTrue(result.isErr, "absent code_challenge with server pkce=REQUIRED must reject")
            assertEquals("invalid_request", extractCode(result))
        }

    @Test
    fun verifyAbsentPkceAcceptedWhenServerPolicyNotRequired() =
        runTest {
            // Server doesn't mandate PKCE and the client doesn't either → absent code_challenge is OK.
            val cmd =
                createCommand(
                    SingleClientRegistry(confidentialClient(requirePkce = false)),
                    pkcePolicy = FeaturePolicy.SUPPORTED,
                )
            val result = cmd.execute(request(codeChallenge = null, codeChallengeMethod = null))
            assertTrue(result.isOk, "absent code_challenge is permissible when policy is not REQUIRED: ${if (!result.isOk) result.error else ""}")
        }

    @Test
    fun verifyAbsentMethodDefaultsPlainButServerS256OnlyRejects() =
        runTest {
            // Request supplies code_challenge but omits code_challenge_method. RFC 7636 §4.3
            // defaults to "plain"; our server advertises only S256 → reject.
            val cmd =
                createCommand(
                    SingleClientRegistry(confidentialClient()),
                    pkceMethodsSupported = setOf("S256"),
                )
            val result = cmd.execute(request(codeChallengeMethod = null))
            assertTrue(result.isErr, "absent method resolves to 'plain' which is not in pkceMethodsSupported={S256}")
            assertEquals("invalid_request", extractCode(result))
        }

    @Test
    fun verifyAbsentMethodWithPlainAllowedIsAccepted() =
        runTest {
            val cmd =
                createCommand(
                    SingleClientRegistry(confidentialClient()),
                    pkceMethodsSupported = setOf("plain", "S256"),
                )
            val result = cmd.execute(request(codeChallengeMethod = null))
            assertTrue(result.isOk, "absent method resolves to 'plain' which server permits: ${if (!result.isOk) result.error else ""}")
            assertEquals(PkceMethod.PLAIN, result.value.resolvedPkceMethod)
        }

    @Test
    fun verifyS256MethodAcceptedWhenServerAllowsS256() =
        runTest {
            val cmd = createCommand(SingleClientRegistry(confidentialClient()))
            val result = cmd.execute(request(codeChallengeMethod = PkceMethod.S256))
            assertTrue(result.isOk, "S256 with default pkceMethodsSupported={S256} must pass: ${if (!result.isOk) result.error else ""}")
            assertEquals(PkceMethod.S256, result.value.resolvedPkceMethod)
        }

    @Test
    fun verifyPlainMethodRejectedWhenServerAllowsS256Only() =
        runTest {
            val cmd = createCommand(SingleClientRegistry(confidentialClient()))
            val result = cmd.execute(request(codeChallengeMethod = PkceMethod.PLAIN))
            assertTrue(result.isErr)
            assertEquals("invalid_request", extractCode(result))
        }

    @Test
    fun verifyResolvedPkceMethodNullWhenNoChallenge() =
        runTest {
            val cmd =
                createCommand(
                    SingleClientRegistry(confidentialClient(requirePkce = false)),
                    pkcePolicy = FeaturePolicy.SUPPORTED,
                )
            val result = cmd.execute(request(codeChallenge = null, codeChallengeMethod = null))
            assertTrue(result.isOk)
            assertEquals(null, result.value.resolvedPkceMethod)
        }

    // ─── unregistered-client admission ──────────────────────────

    @Test
    fun unregisteredClientIsRejectedWithoutAnAdmissionRule() = runTest {
        val result = createCommand(EmptyRegistry()).execute(request(clientId = "unregistered", redirectUri = "https://wallet.example/cb"))
        assertTrue(result.isErr)
        assertEquals("unauthorized_client", extractCode(result))
    }

    @Test
    fun verifyResponseModeAbsentDefaultsToQueryForCodeFlow() =
        runTest {
            val cmd = createCommand(SingleClientRegistry(confidentialClient()))
            val result = cmd.execute(request(responseMode = null))
            assertTrue(result.isOk, "code flow with no response_mode must default to QUERY: ${if (!result.isOk) result.error else ""}")
            assertEquals(OAuth2ResponseMode.QUERY, result.value.responseMode)
        }

    @Test
    fun verifyResponseModeQueryExplicitPreserved() =
        runTest {
            val cmd = createCommand(SingleClientRegistry(confidentialClient()))
            val result = cmd.execute(request(responseMode = "query"))
            assertTrue(result.isOk)
            assertEquals(OAuth2ResponseMode.QUERY, result.value.responseMode)
        }

    @Test
    fun verifyResponseModeFormPostExplicitPreserved() =
        runTest {
            val cmd = createCommand(SingleClientRegistry(confidentialClient()))
            val result = cmd.execute(request(responseMode = "form_post"))
            assertTrue(result.isOk)
            assertEquals(OAuth2ResponseMode.FORM_POST, result.value.responseMode)
        }

    @Test
    fun verifyResponseModeFragmentRejectedForCodeFlow() =
        runTest {
            // Fragment is semantically incompatible with response_type=code (no tokens in URL).
            val cmd = createCommand(SingleClientRegistry(confidentialClient()))
            val result = cmd.execute(request(responseMode = "fragment"))
            assertTrue(result.isErr, "response_mode=fragment with response_type=code must reject")
            assertEquals("invalid_request", extractCode(result))
        }

    @Test
    fun verifyUnknownResponseModeRejected() =
        runTest {
            val cmd = createCommand(SingleClientRegistry(confidentialClient()))
            val result = cmd.execute(request(responseMode = "jwt"))
            assertTrue(result.isErr, "unknown response_mode must reject (we don't silently degrade to query)")
            assertEquals("invalid_request", extractCode(result))
        }

    @Test
    fun verifyResponseModeCaseInsensitiveLookup() =
        runTest {
            val cmd = createCommand(SingleClientRegistry(confidentialClient()))
            val result = cmd.execute(request(responseMode = "FORM_POST"))
            assertTrue(result.isOk, "response_mode lookup must tolerate uppercase for robustness")
            assertEquals(OAuth2ResponseMode.FORM_POST, result.value.responseMode)
        }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private fun extractCode(result: IdkResult<*, *>): String? = (result.error as? com.sphereon.core.api.error.IdkError)?.code

    private companion object {
        const val CLIENT_ID = "verify-pkce-rmode-client"
    }

    private class SingleClientRegistry(
        private val client: ClientRegistration,
    ) : ClientRegistry {
        override suspend fun getClient(clientId: String): IdkResult<ClientRegistration?, AuthorizationServerError.StorageError> = Ok(if (clientId == client.clientId) client else null)

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

        override suspend fun clientExists(clientId: String): IdkResult<Boolean, AuthorizationServerError.StorageError> = Ok(true)

        override suspend fun verifyClientCredentials(
            clientId: String,
            clientSecret: String,
        ): IdkResult<Boolean, AuthorizationServerError.StorageError> = Ok(true)
    }

    private class EmptyRegistry : ClientRegistry {
        override suspend fun getClient(clientId: String): IdkResult<ClientRegistration?, AuthorizationServerError.StorageError> = Ok(null)

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

        override suspend fun clientExists(clientId: String): IdkResult<Boolean, AuthorizationServerError.StorageError> = Ok(false)

        override suspend fun verifyClientCredentials(
            clientId: String,
            clientSecret: String,
        ): IdkResult<Boolean, AuthorizationServerError.StorageError> = Ok(false)
    }
}
