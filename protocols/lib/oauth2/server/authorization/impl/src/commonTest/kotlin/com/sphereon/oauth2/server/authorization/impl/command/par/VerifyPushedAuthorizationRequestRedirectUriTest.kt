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

package com.sphereon.oauth2.server.authorization.impl.command.par

import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.model.ResponseType
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData
import com.sphereon.oauth2.server.authorization.command.VerifyPushedAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.StubClientRegistry
import com.sphereon.oauth2.server.authorization.impl.testutil.StubOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class VerifyPushedAuthorizationRequestRedirectUriTest {
    private val ctx = OAuth2ServerTestContext("verify-par-redirect-uri-test", this)

    @Test
    fun omittedRedirectUriResolvesToSoleRegisteredUri() =
        verifySoleRegisteredUriFallback(null)

    @Test
    fun blankRedirectUriResolvesToSoleRegisteredUri() =
        verifySoleRegisteredUriFallback("")

    @Test
    fun policyRejectsOmittedRedirectUri() =
        verifyRequiredRedirectUriRejected(null)

    @Test
    fun policyRejectsBlankRedirectUri() =
        verifyRequiredRedirectUriRejected("")

    /**
     * A pushed request carries the client's default access-token audience to code issuance, as the front-channel
     * verification does. Without it a client that names no resource (an OpenID Federation client registered
     * automatically, for example) gets no RFC 9068 audience and the token request fails with invalid_target.
     */
    @Test
    fun pushedRequestKeepsTheClientDefaultAccessTokenAudience() =
        runTest {
            val client =
                ClientRegistration(
                    clientId = CLIENT_ID,
                    grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
                    responseTypes = listOf(ResponseType.CODE),
                    redirectUris = listOf(REGISTERED_REDIRECT_URI),
                    requirePkce = false,
                    defaultAccessTokenAudience = DEFAULT_AUDIENCE,
                )
            val command =
                VerifyPushedAuthorizationRequestCommandImpl(
                    execution = ctx.execution,
                    clientRegistry = StubClientRegistry(mapOf(CLIENT_ID to client)),
                    configProvider = StubOAuth2ServersConfigProvider(),
                    credentialIssuerAudienceResolver = com.sphereon.oauth2.server.authorization.impl.provider.NoCredentialIssuerAudienceResolver(),
                    unregisteredClientAdmissionRule = com.sphereon.oauth2.server.authorization.impl.command.authorization.Oid4vciUnregisteredWalletAdmissionRule(),
                )

            val result =
                command.execute(
                    VerifyPushedAuthorizationRequestArgs(
                        request =
                            AuthorizationRequestData(
                                clientId = CLIENT_ID,
                                redirectUri = REGISTERED_REDIRECT_URI,
                                responseType = listOf(ResponseType.CODE),
                            ),
                        clientId = CLIENT_ID,
                    ),
                )

            assertTrue(result.isOk, "expected success but got ${if (result.isErr) result.error else "ok"}")
            assertEquals(DEFAULT_AUDIENCE, result.value.defaultAccessTokenAudience)
        }

    private fun verifySoleRegisteredUriFallback(redirectUri: String?) =
        runTest {
            val client =
                ClientRegistration(
                    clientId = CLIENT_ID,
                    grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
                    responseTypes = listOf(ResponseType.CODE),
                    redirectUris = listOf(REGISTERED_REDIRECT_URI),
                    requirePkce = false,
                )
            val command =
                VerifyPushedAuthorizationRequestCommandImpl(
                    execution = ctx.execution,
                    clientRegistry = StubClientRegistry(mapOf(CLIENT_ID to client)),
                    configProvider = StubOAuth2ServersConfigProvider(),
                    credentialIssuerAudienceResolver = com.sphereon.oauth2.server.authorization.impl.provider.NoCredentialIssuerAudienceResolver(),
                    unregisteredClientAdmissionRule = com.sphereon.oauth2.server.authorization.impl.command.authorization.Oid4vciUnregisteredWalletAdmissionRule(),
                )

            val result =
                command.execute(
                    VerifyPushedAuthorizationRequestArgs(
                        request =
                            AuthorizationRequestData(
                                clientId = CLIENT_ID,
                                redirectUri = redirectUri,
                                responseType = listOf(ResponseType.CODE),
                            ),
                        clientId = CLIENT_ID,
                    ),
                )

            assertTrue(result.isOk, "expected success but got ${if (result.isErr) result.error else "ok"}")
            assertEquals(REGISTERED_REDIRECT_URI, result.value.redirectUri)
        }

    private fun verifyRequiredRedirectUriRejected(redirectUri: String?) =
        runTest {
            val client =
                ClientRegistration(
                    clientId = CLIENT_ID,
                    grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
                    responseTypes = listOf(ResponseType.CODE),
                    redirectUris = listOf(REGISTERED_REDIRECT_URI),
                    requirePkce = false,
                )
            val command =
                VerifyPushedAuthorizationRequestCommandImpl(
                    execution = ctx.execution,
                    clientRegistry = StubClientRegistry(mapOf(CLIENT_ID to client)),
                    configProvider =
                        StubOAuth2ServersConfigProvider(
                            OAuth2ServerInstanceConfig(
                                requireRedirectUriInPushedAuthorizationRequests = true,
                            ),
                        ),
                    credentialIssuerAudienceResolver = com.sphereon.oauth2.server.authorization.impl.provider.NoCredentialIssuerAudienceResolver(),
                    unregisteredClientAdmissionRule = com.sphereon.oauth2.server.authorization.impl.command.authorization.Oid4vciUnregisteredWalletAdmissionRule(),
                )

            val result =
                command.execute(
                    VerifyPushedAuthorizationRequestArgs(
                        request =
                            AuthorizationRequestData(
                                clientId = CLIENT_ID,
                                redirectUri = redirectUri,
                                responseType = listOf(ResponseType.CODE),
                            ),
                        clientId = CLIENT_ID,
                    ),
                )

            assertTrue(result.isErr, "expected redirect_uri policy rejection")
            assertEquals("invalid_request", result.error.code)
        }

    private companion object {
        const val CLIENT_ID = "oidf-client"
        const val REGISTERED_REDIRECT_URI = "https://suite.example.test/callback"
        const val DEFAULT_AUDIENCE = "https://as.example.test/issuer"
    }
}
