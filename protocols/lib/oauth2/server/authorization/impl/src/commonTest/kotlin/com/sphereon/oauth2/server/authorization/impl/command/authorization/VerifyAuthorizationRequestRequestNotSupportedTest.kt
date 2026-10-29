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
 * Tests post-redirect rejection of OIDC `request` and `request_uri` parameters
 * (OIDC Core §6 / RFC 9101). The OIDF Basic RP test plan accepts either real Request Object
 * processing or a `request_not_supported` / `request_uri_not_supported` post-redirect error;
 * we take the latter path. The rejection must happen after client + redirect URI validation
 * so the error is delivered through the trusted redirect URI per OIDC §3.1.2.6.
 */
class VerifyAuthorizationRequestRequestNotSupportedTest {
    private val ctx = OAuth2ServerTestContext("verify-request-not-supported-test", this)

    private fun createCommand(registration: ClientRegistration = client(),
        mode: com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode = com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.PAR_ONLY,
    ): VerifyAuthorizationRequestCommandImpl {
        val serverConfig =
            OAuth2ServerInstanceConfig(
                issuer = "http://localhost:8080",
                responseTypesSupported = setOf("code"),
                federationAutomaticRegistrationMode = mode,
            )
        val servers = OAuth2ServersConfig(servers = mapOf("default" to serverConfig), defaultServer = "default")
        return VerifyAuthorizationRequestCommandImpl(
            ctx.execution,
            SingleClientRegistry(registration),
            TestOAuth2ServersConfigProvider(servers),
            emptySet(),
            com.sphereon.oauth2.server.authorization.impl.provider.NoCredentialIssuerAudienceResolver(),
            Oid4vciUnregisteredWalletAdmissionRule(),
            com.sphereon.oauth2.server.authorization.impl.testutil.fixedAsInstanceIdProvider(),
        )
    }

    private fun client(): ClientRegistration =
        ClientRegistration(
            clientId = CLIENT_ID,
            clientName = "Request-Not-Supported Test Client",
            clientType = ClientType.CONFIDENTIAL,
            grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
            responseTypes = listOf(ResponseType.CODE),
            redirectUris = listOf("https://rp.example.com/cb"),
            tokenEndpointAuthMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
        )

    private fun request(
        request: String? = null,
        requestUri: String? = null,
    ): AuthorizationRequestData =
        AuthorizationRequestData(
            clientId = CLIENT_ID,
            redirectUri = "https://rp.example.com/cb",
            responseType = listOf(ResponseType.CODE),
            scope = "openid",
            state = "xyz",
            codeChallenge = "a".repeat(43),
            codeChallengeMethod = PkceMethod.S256,
            request = request,
            requestUri = requestUri,
        )

    @Test
    fun requestObjectReturnsRequestNotSupportedAfterClientValidates() =
        runTest {
            val cmd = createCommand()
            val result = cmd.execute(request(request = "eyJhbGciOiJSUzI1NiJ9.eyJjbGFpbSI6InZhbCJ9.sig"))
            assertTrue(result.isErr, "request parameter must trigger post-redirect rejection")
            assertEquals("request_not_supported", extractCode(result))
        }

    @Test
    fun nonParRequestUriReturnsRequestUriNotSupported() =
        runTest {
            val cmd = createCommand()
            val result = cmd.execute(request(requestUri = "https://attacker.example.com/foo"))
            assertTrue(result.isErr, "non-PAR request_uri must trigger post-redirect rejection")
            assertEquals("request_uri_not_supported", extractCode(result))
        }

    @Test
    fun parIssuedRequestUriIsNotRejectedHere() =
        runTest {
            // PAR-issued URNs flow through PAR retrieval downstream; the verifier must NOT emit
            // `request_uri_not_supported` for them. We assert by error-code: whatever else the
            // verify pipeline does with this request (success or a different failure), it must
            // not be `request_uri_not_supported`.
            val cmd = createCommand()
            val result = cmd.execute(request(requestUri = "urn:ietf:params:oauth:request_uri:abc123"))
            val code = extractCode(result)
            assertTrue(
                code != "request_uri_not_supported",
                "PAR URN must NOT trigger request_uri_not_supported (got $code); downstream code handles PAR retrieval",
            )
        }

    @Test
    fun unsignedFederationRequestCannotUseFabricatedProcessEvidence() = runTest {
        val registration = client().copy(
            tokenEndpointAuthMethod = ClientAuthenticationMethod.PRIVATE_KEY_JWT,
            authorizationRequestProofPolicy = com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC,
        )
        val command = createCommand(registration,
            com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.SIGNED_JAR_OR_AUTHENTICATED_PAR)
        val counterfeit = object : com.sphereon.oauth2.server.authorization.command.jar.AuthorizationRequestEvidence {}
        for (evidence in listOf(null, counterfeit)) {
            val result = command.execute(request().copy(authorizationEvidence = evidence))
            assertTrue(result.isErr, "Neither missing nor caller-constructed evidence may authenticate a federation request")
            assertEquals("invalid_request", extractCode(result))
            assertEquals("Invalid request: A client-bound signed federation Request Object is required", (result.error as com.sphereon.core.api.error.IdkError).message.defaultMessage)
        }
    }

    private fun extractCode(result: IdkResult<*, *>): String? = if (result.isErr) (result.error as? com.sphereon.core.api.error.IdkError)?.code else null

    private companion object {
        const val CLIENT_ID = "verify-req-not-supported-client"
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
