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

package com.sphereon.oauth2.server.authorization.impl.command.oidc

import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.generic.KeyOperations
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.jose.jws.JwsCompact
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.JwtServiceImpl

import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.server.authorization.command.CreateIdTokenArgs
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.StubClientRegistry
import com.sphereon.oauth2.server.authorization.impl.testutil.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.signing.AsServerSigningIdentifierResolver
import com.sphereon.oauth2.server.authorization.signing.AsSigningRequirement
import com.sphereon.oauth2.server.authorization.signing.AsSigningSelection
import com.sphereon.oauth2.server.authorization.signing.CapturedAsServerConfig
import com.sphereon.oauth2.server.authorization.impl.testutil.fixedAsInstanceIdProvider
import com.sphereon.oauth2.server.authorization.storage.OidcLoginSessionIdProvider
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CreateIdTokenSigningAlgorithmTest {
    private val ctx = OAuth2ServerTestContext("create-id-token-signing-alg-test", this)

    @Test
    fun clientRequestedAlgorithmSelectsMatchingKeyAndJwtAlgorithm() =
        runTest {
            val keyPair =
                ctx.keyManagerService.generateKeyAsync(
                    alias = "sts-es384-client-key",
                    use = JwkUse.sig,
                    keyOperations = arrayOf(KeyOperations.SIGN, KeyOperations.VERIFY),
                    alg = SignatureAlgorithm.ECDSA_SHA384,
                    keyVisibility = KeyVisibility.PRIVATE,
                )
            val expectedKid = requireNotNull(keyPair.kid)
            val signingIdentifier =
                ManagedOptsKeyInfo(
                    identifier =
                        KeyInfo<KeyType>(
                            alias = keyPair.alias,
                            kid = expectedKid,
                            providerId = keyPair.providerId,
                            signatureAlgorithm = SignatureAlgorithm.ECDSA_SHA384,
                        ),
                )
            val resolver = RecordingSigningIdentifierResolver(signingIdentifier)
            val client =
                ClientRegistration(
                    clientId = CLIENT_ID,
                    grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
                    idTokenSignedResponseAlg = "ES384",
                )
            val configProvider =
                TestOAuth2ServersConfigProvider(
                    OAuth2ServersConfig(
                        servers =
                            mapOf(
                                "default" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = ISSUER,
                                        idTokenSigningAlgValuesSupported = setOf("RS256", "ES384"),
                                    ),
                            ),
                    ),
                )
            val command =
                CreateIdTokenCommandImpl(
                    execution = ctx.execution,
                    jwtService = (ctx.session.graph as JwtServiceImpl.Graph).jwtService,
                    configProvider = configProvider,
                    asInstanceIdProvider = fixedAsInstanceIdProvider(),
                    signingIdentifierResolver = resolver,
                    clientRegistry = StubClientRegistry(mapOf(CLIENT_ID to client)),

                    sessionParticipationRecorders = emptySet(),
                    loginSessionIdProvider = NoOpLoginSessionIdProvider,
                )

            val result =
                command.execute(
                    CreateIdTokenArgs(
                        subject = "user-1",
                        clientId = CLIENT_ID,
                        accessToken = "access-token",
                    ),
                )

            assertTrue(result.isOk, "ID token mint must succeed: ${if (result.isErr) result.error else ""}")
            assertEquals("ES384", resolver.requestedAlgorithm)
            val segments = result.value.value.split(".")
            assertEquals(3, segments.size)
            val header = Json.parseToJsonElement(segments[0].decodeFromBase64Url().decodeToString()) as JsonObject
            assertEquals("ES384", header["alg"]?.jsonPrimitive?.contentOrNull)
            assertEquals(expectedKid, header["kid"]?.jsonPrimitive?.contentOrNull)
        }

     @Test
    fun signingSelectionCancellationEscapesIdTokenMint() = runTest {
        val cancellation = CancellationException("ID token selection cancelled")
        val resolver = object : AsServerSigningIdentifierResolver {
            override suspend fun selectSigning(
                captured: CapturedAsServerConfig,
                requirement: AsSigningRequirement,
                requestedAlgorithm: String?,
            ): AsSigningSelection = throw cancellation
        }
        val command = CreateIdTokenCommandImpl(
            execution = ctx.execution,
            jwtService = (ctx.session.graph as JwtServiceImpl.Graph).jwtService,
            configProvider = TestOAuth2ServersConfigProvider(OAuth2ServersConfig(
                servers = mapOf("default" to OAuth2ServerInstanceConfig(issuer = ISSUER)),
            )),
            asInstanceIdProvider = fixedAsInstanceIdProvider(),
            signingIdentifierResolver = resolver,
            clientRegistry = StubClientRegistry(mapOf(CLIENT_ID to ClientRegistration(
                clientId = CLIENT_ID,
                grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
                idTokenSignedResponseAlg = "ES384",
            ))),
            sessionParticipationRecorders = emptySet(),
            loginSessionIdProvider = NoOpLoginSessionIdProvider,
        )
        val escaped = assertFailsWith<CancellationException> {
            command.execute(CreateIdTokenArgs(subject = "user-1", clientId = CLIENT_ID, accessToken = "access-token"))
        }
        assertTrue(escaped === cancellation || escaped.cause === cancellation)
    }

    @Test
    fun mixedAlgorithmCollectionCannotAuthorizeAMismatchedSelectedHandle() = runTest {
        val key = ctx.keyManagerService.generateKeyAsync(
            alias = "id-token-mismatched-es256-key", use = JwkUse.sig,
            keyOperations = arrayOf(KeyOperations.SIGN, KeyOperations.VERIFY),
            alg = SignatureAlgorithm.ECDSA_SHA256, keyVisibility = KeyVisibility.PRIVATE,
        )
        val selected = ManagedOptsKeyInfo(KeyInfo<KeyType>(alias = key.alias, kid = key.kid,
            providerId = key.providerId, signatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256))
        val resolver = object : AsServerSigningIdentifierResolver {
            override suspend fun selectSigning(captured: CapturedAsServerConfig,
                requirement: AsSigningRequirement, requestedAlgorithm: String?): AsSigningSelection {
                assertEquals("default", captured.serverKey)
                assertEquals(AsSigningRequirement.REQUIRED, requirement)
                assertEquals("ES384", requestedAlgorithm)
                return AsSigningSelection(selected, setOf("ES256", "ES384"))
            }
        }
        val jwtService = (ctx.session.graph as JwtServiceImpl.Graph).jwtService
        val command = CreateIdTokenCommandImpl(
            execution = ctx.execution, jwtService = jwtService,
            configProvider = TestOAuth2ServersConfigProvider(OAuth2ServersConfig(
                servers = mapOf("default" to OAuth2ServerInstanceConfig(issuer = ISSUER,
                    idTokenSigningAlgValuesSupported = setOf("ES256", "ES384"))),
            )),
            asInstanceIdProvider = fixedAsInstanceIdProvider(), signingIdentifierResolver = resolver,
            clientRegistry = StubClientRegistry(mapOf(CLIENT_ID to ClientRegistration(
                clientId = CLIENT_ID, grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
                idTokenSignedResponseAlg = "ES384",
            ))), sessionParticipationRecorders = emptySet(), loginSessionIdProvider = NoOpLoginSessionIdProvider,
        )
        val result = command.execute(CreateIdTokenArgs(subject = "user-1", clientId = CLIENT_ID, accessToken = "access-token"))
        // Before the repair, prove this is an actual correctly signed wrong-algorithm token,
        // rather than mistaking an unrelated fixture/configuration error for the regression.
        if (result.isOk) {
            val token = result.value.value
            val verification = jwtService.verifyJws(VerifyJwsArgs(jws = JwsCompact(token), identifier = selected))
            assertTrue(verification.isOk && verification.value.isValid, "Unexpected signature fixture failure")
            val header = Json.parseToJsonElement(token.split('.')[0].decodeFromBase64Url().decodeToString()) as JsonObject
            assertEquals("ES256", header["alg"]?.jsonPrimitive?.contentOrNull)
        }
        assertTrue(result.isErr, "A requested ES384 algorithm cannot be satisfied by the selected ES256 handle")
    }

   private class RecordingSigningIdentifierResolver(
        private val signingIdentifier: ManagedOptsKeyInfo,
    ) : AsServerSigningIdentifierResolver {
        var requestedAlgorithm: String? = null
            private set

        override suspend fun selectSigning(
            captured: CapturedAsServerConfig,
            requirement: AsSigningRequirement,
            requestedAlgorithm: String?,
        ): AsSigningSelection {
            assertEquals("default", captured.serverKey)
            assertEquals(AsSigningRequirement.REQUIRED, requirement)
            this.requestedAlgorithm = requestedAlgorithm
            return AsSigningSelection(signingIdentifier, setOf("ES384"))
        }
    }

    private object NoOpLoginSessionIdProvider : OidcLoginSessionIdProvider {
        override fun currentLoginSessionId(): String? = null
    }

    private companion object {
        const val ISSUER = "https://as.example.com"
        const val CLIENT_ID = "es384-client"
    }
}
