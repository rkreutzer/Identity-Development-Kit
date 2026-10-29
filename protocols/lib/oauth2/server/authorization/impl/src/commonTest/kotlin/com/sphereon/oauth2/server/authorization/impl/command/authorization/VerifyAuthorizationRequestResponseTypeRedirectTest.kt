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
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
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
import kotlin.test.assertTrue

/**
 * Tests for response_type enforcement against server metadata + client registration, and
 * for optional redirect_uri resolution from client registration.
 */
class VerifyAuthorizationRequestResponseTypeRedirectTest {
    private val ctx = OAuth2ServerTestContext("verify-response-type-redirect-test", this)

    private fun createCommand(
        client: ClientRegistration,
        serverResponseTypesSupported: Set<String> = setOf("code"),
    ): VerifyAuthorizationRequestCommandImpl {
        val serverConfig =
            OAuth2ServerInstanceConfig(
                issuer = "http://localhost:8080",
                responseTypesSupported = serverResponseTypesSupported,
            )
        val servers = OAuth2ServersConfig(servers = mapOf("default" to serverConfig), defaultServer = "default")
        return VerifyAuthorizationRequestCommandImpl(
            ctx.execution,
            SingleClientRegistry(client),
            TestOAuth2ServersConfigProvider(servers),
            emptySet(),
            com.sphereon.oauth2.server.authorization.impl.provider.NoCredentialIssuerAudienceResolver(),
            Oid4vciUnregisteredWalletAdmissionRule(),
            com.sphereon.oauth2.server.authorization.impl.testutil.fixedAsInstanceIdProvider(),
        )
    }

    private fun client(
        redirectUris: List<String> = listOf("https://rp.example.com/cb"),
        responseTypes: List<ResponseType> = listOf(ResponseType.CODE),
    ): ClientRegistration =
        ClientRegistration(
            clientId = CLIENT_ID,
            clientName = "Test Client",
            clientType = ClientType.CONFIDENTIAL,
            grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
            responseTypes = responseTypes,
            redirectUris = redirectUris,
            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        )

    private fun request(
        redirectUri: String? = "https://rp.example.com/cb",
        responseType: List<ResponseType> = listOf(ResponseType.CODE),
    ): AuthorizationRequestData =
        AuthorizationRequestData(
            clientId = CLIENT_ID,
            redirectUri = redirectUri,
            responseType = responseType,
            scope = "openid",
            state = "s1",
            codeChallenge = "a".repeat(43),
            codeChallengeMethod = PkceMethod.S256,
        )

    // ─── response_type enforcement ─────────────────────────────────

    @Test
    fun verifyResponseTypeCodeAccepted() =
        runTest {
            val cmd = createCommand(client(), serverResponseTypesSupported = setOf("code"))
            val result = cmd.execute(request(responseType = listOf(ResponseType.CODE)))
            assertTrue(result.isOk, "code flow must be accepted when advertised and registered: ${if (!result.isOk) result.error else "n/a"}")
        }

    @Test
    fun verifyResponseTypeTokenRejectedWhenServerAdvertisesOnlyCode() =
        runTest {
            val cmd = createCommand(client(), serverResponseTypesSupported = setOf("code"))
            val result = cmd.execute(request(responseType = listOf(ResponseType.TOKEN)))
            assertTrue(result.isErr, "token must be rejected when server advertises only code")
            assertEquals("unsupported_response_type", extractCode(result))
        }

    @Test
    fun verifyResponseTypeIdTokenRejectedWhenServerAdvertisesOnlyCode() =
        runTest {
            val cmd = createCommand(client(), serverResponseTypesSupported = setOf("code"))
            val result = cmd.execute(request(responseType = listOf(ResponseType.ID_TOKEN)))
            assertTrue(result.isErr, "id_token must be rejected when server advertises only code")
            assertEquals("unsupported_response_type", extractCode(result))
        }

    @Test
    fun verifyResponseTypeInServerButNotInClientRegistrationRejected() =
        runTest {
            // Server advertises code AND id_token, but the client is only registered for code.
            val cmd =
                createCommand(
                    client(responseTypes = listOf(ResponseType.CODE)),
                    serverResponseTypesSupported = setOf("code", "id_token"),
                )
            val result = cmd.execute(request(responseType = listOf(ResponseType.ID_TOKEN)))
            assertTrue(result.isErr, "id_token must be rejected when client is only registered for code")
            assertEquals("unauthorized_client", extractCode(result))
        }

    @Test
    fun verifyEmptyClientResponseTypesDefaultsToCodeOnly() =
        runTest {
            // A client with `responseTypes = []` is treated as `[CODE]` for backward
            // compatibility, so a code request succeeds but a token request still fails.
            val cmd =
                createCommand(
                    client(responseTypes = emptyList()),
                    serverResponseTypesSupported = setOf("code", "token"),
                )
            val codeResult = cmd.execute(request(responseType = listOf(ResponseType.CODE)))
            assertTrue(codeResult.isOk, "empty client responseTypes should default to [CODE]: ${if (!codeResult.isOk) codeResult.error else ""}")

            val tokenResult = cmd.execute(request(responseType = listOf(ResponseType.TOKEN)))
            assertTrue(tokenResult.isErr, "empty client responseTypes should not permit token flow")
            assertEquals("unauthorized_client", extractCode(tokenResult))
        }

    // ─── optional redirect_uri resolution ─────────────────────────

    @Test
    fun verifyOmittedRedirectUriSingleRegisteredResolves() =
        runTest {
            val cmd = createCommand(client(redirectUris = listOf("https://rp.example.com/cb")))
            val result = cmd.execute(request(redirectUri = null))
            assertTrue(result.isOk, "omitted redirect_uri with single registered URI must resolve: ${if (!result.isOk) result.error else ""}")
            assertEquals("https://rp.example.com/cb", result.value.redirectUri)
        }

    @Test
    fun verifyOmittedRedirectUriMultipleRegisteredRejects() =
        runTest {
            val cmd =
                createCommand(
                    client(
                        redirectUris =
                            listOf(
                                "https://rp.example.com/cb",
                                "https://alt.example.com/cb",
                            ),
                    ),
                )
            val result = cmd.execute(request(redirectUri = null))
            assertTrue(result.isErr, "omitted redirect_uri with multiple registered URIs must be rejected")
            assertEquals("invalid_request", extractCode(result))
        }

    @Test
    fun verifyExplicitRedirectUriMustMatchRegistered() =
        runTest {
            val cmd = createCommand(client(redirectUris = listOf("https://rp.example.com/cb")))
            val result = cmd.execute(request(redirectUri = "https://attacker.example.com/cb"))
            assertTrue(result.isErr, "unregistered redirect_uri must be rejected")
            assertEquals("invalid_request", extractCode(result))
        }

    @Test
    fun verifyExplicitRedirectUriMatchesOneOfMany() =
        runTest {
            val cmd =
                createCommand(
                    client(
                        redirectUris =
                            listOf(
                                "https://rp.example.com/cb",
                                "https://alt.example.com/cb",
                            ),
                    ),
                )
            val result = cmd.execute(request(redirectUri = "https://alt.example.com/cb"))
            assertTrue(result.isOk, "registered URI must be accepted: ${if (!result.isOk) result.error else ""}")
            assertEquals("https://alt.example.com/cb", result.value.redirectUri)
        }

    private fun extractCode(result: IdkResult<*, *>): String? = (result.error as? com.sphereon.core.api.error.IdkError)?.code

    private companion object {
        const val CLIENT_ID = "verify-rt-rd-client"
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
}
