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

package com.sphereon.oauth2.server.authorization.impl.construction

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenCommand
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.command.jwks.HandleJwksRequestCommandImpl
import com.sphereon.oauth2.server.authorization.impl.command.token.HandleTokenRequestCommandImpl
import com.sphereon.oauth2.server.authorization.impl.storage.memory.OpaqueInternalClientSecretVerifier
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.provider.ExternalClientSource
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Exposes the session-scoped roots of the token and JWKS routes from the real test graph. */
@ContributesTo(SessionScope::class)
interface TokenAndJwksConstructionTestGraph {
    val constructionTokenRequestCommand: HandleTokenRequestCommandImpl
    val constructionJwksRequestCommand: HandleJwksRequestCommandImpl
    val constructionCreateAccessTokenCommand: CreateAccessTokenCommand
    val constructionClientRegistry: ClientRegistry
    val constructionJwtService: JwtService
}

/**
 * Stands in for a deployment's external client source, such as a federation-backed one, whose own
 * graph is large. It never claims a client, so registering it changes no lookup result.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesIntoSet(SessionScope::class, binding = binding<ExternalClientSource>())
class ConstructionProbeExternalClientSource : ExternalClientSource {
    override suspend fun resolve(clientId: String): IdkResult<ClientRegistration?, AuthorizationServerError.StorageError> = Ok(null)
}

/**
 * Resolving a route's handler from the request SessionScope must only construct what every
 * request on that route uses. Dependencies used conditionally (an unknown client's external
 * lookup, an internal client's secret verifier, JWS verification during signing, local key
 * resolution behind a deployment JWK resolver) stay deferred until a request needs them.
 */
class TokenAndJwksConstructionTest {
    private val ctx = OAuth2ServerTestContext("token-jwks-construction-test", this)
    private val graph = ctx.session.graph as TokenAndJwksConstructionTestGraph

    @Test
    fun clientRegistryDefersExternalSourcesAndTheInternalSecretVerifier() {
        val census = SessionObjectCensus.of(graph.constructionClientRegistry)
        println(census.describe("ClientRegistry"))

        assertFalse(census.reachesInstanceOf(ExternalClientSource::class.java), "External client sources are only asked for unknown clients")
        assertFalse(
            census.reachesInstanceOf(OpaqueInternalClientSecretVerifier::class.java),
            "The opaque internal secret verifier is only used for internal clients",
        )
    }

    @Test
    fun tokenRequestHandlerDefersClientAuthentication() {
        val census = SessionObjectCensus.of(graph.constructionTokenRequestCommand)
        println(census.describe("HandleTokenRequestCommandImpl"))

        assertFalse(
            census.reachesInstanceOf(VerifyClientAuthenticationCommand::class.java),
            "Token exchange authenticates in its own journey, so the endpoint's client authentication is resolved on use",
        )
        assertFalse(census.reachesInstanceOf(ExternalClientSource::class.java))
    }

    @Test
    fun accessTokenMintingDoesNotConstructJwsVerification() {
        val census = SessionObjectCensus.of(graph.constructionCreateAccessTokenCommand)
        println(census.describe("CreateAccessTokenCommand"))

        assertFalse(census.reachesInstanceOf(VerifyJwsCommand::class.java), "Minting signs, it never verifies a JWS")
        assertFalse(
            census.reachesInstanceOf(MultiManagedIdentifierService::class.java),
            "Key resolution for signing happens when a token is signed, not when the command is resolved",
        )
    }

    @Test
    fun jwtServiceResolvesItsCommandsOnUse() {
        val census = SessionObjectCensus.of(graph.constructionJwtService)
        println(census.describe("JwtService"))

        assertFalse(census.reachesInstanceOf(VerifyJwsCommand::class.java))
        assertFalse(census.reachesInstanceOf(MultiManagedIdentifierService::class.java))
    }

    @Test
    fun jwksHandlerDoesNotConstructTokenIssuanceOrLocalKeyResolution() {
        val census = SessionObjectCensus.of(graph.constructionJwksRequestCommand)
        println(census.describe("HandleJwksRequestCommandImpl"))

        assertFalse(census.reachesInstanceOf(CreateAccessTokenCommand::class.java))
        assertFalse(census.reachesInstanceOf(HandleTokenRequestCommandImpl::class.java))
        assertFalse(census.reachesInstanceOf(JwtService::class.java))
        assertFalse(
            census.reachesInstanceOf(MultiManagedIdentifierService::class.java),
            "Local key resolution is only used without a deployment JWK resolver, and only once a key is published",
        )
    }

    @Test
    fun anUnknownClientStillReachesTheExternalSources() =
        runTest {
            val registry = graph.constructionClientRegistry

            val lookup = registry.getClient("construction-unknown-client")

            assertTrue(lookup.isOk, "An unknown client is absent, not an error")
            assertTrue(lookup.value == null)
            assertTrue(
                SessionObjectCensus.of(registry).reachesInstanceOf(ExternalClientSource::class.java),
                "The deferred external sources are resolved once a lookup needs them",
            )
        }
}
