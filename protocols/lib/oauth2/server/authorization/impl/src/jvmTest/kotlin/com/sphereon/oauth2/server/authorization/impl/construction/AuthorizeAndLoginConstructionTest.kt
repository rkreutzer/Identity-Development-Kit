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

import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.server.authorization.command.BuildServerMetadataCommand
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenCommand
import com.sphereon.oauth2.server.authorization.command.GetJwksCommand
import com.sphereon.oauth2.server.authorization.command.IntrospectTokenCommand
import com.sphereon.oauth2.server.authorization.command.RevokeTokenCommand
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand
import com.sphereon.oauth2.server.authorization.command.VerifyPushedAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeCallbackCommand
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestCommand
import com.sphereon.oauth2.server.authorization.command.jar.VerifyRequestObjectCommand
import com.sphereon.oauth2.server.authorization.impl.command.authorization.StandardAuthorizeRequestCommandImpl
import com.sphereon.oauth2.server.authorization.impl.command.authorization.WalletAuthorizeRequestCommandImpl
import com.sphereon.oauth2.server.authorization.impl.provider.ConfigBackedUserAuthenticationProvider
import com.sphereon.oauth2.server.authorization.impl.provider.FederatedUserAuthenticationProvider
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.provider.AuthenticationMethod
import com.sphereon.oauth2.server.authorization.provider.UserAuthenticationProvider
import com.sphereon.oauth2.server.authorization.routing.AuthenticationRoutePlanner
import com.sphereon.oauth2.server.authorization.service.AuthorizationServerService
import dev.zacsweers.metro.ContributesTo
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Exposes the session-scoped roots of the interactive authorize, callback and login routes. */
@ContributesTo(SessionScope::class)
interface AuthorizeAndLoginConstructionTestGraph {
    val constructionAuthorizeRequestCommands: Set<HandleAuthorizeRequestCommand>
    val constructionAuthorizeCallbackCommand: HandleAuthorizeCallbackCommand
    val constructionAuthorizationServerService: AuthorizationServerService
    val constructionUserAuthenticationProvider: UserAuthenticationProvider
}

/**
 * Resolving the authorize, authorize-callback and login-submit handlers from the request
 * SessionScope must only construct what every request on those routes uses. A request takes one
 * branch (a known or admitted client, inline JAR or not, an active login session or a login hop)
 * and one login method, so the dependencies of the other branches and methods, and the commands
 * of the other endpoints behind the shared [AuthorizationServerService], stay deferred until a
 * request needs them.
 */
class AuthorizeAndLoginConstructionTest {
    private val ctx = OAuth2ServerTestContext("authorize-login-construction-test", this)
    private val graph = ctx.session.graph as AuthorizeAndLoginConstructionTestGraph

    private val otherEndpointCommands =
        listOf(
            CreateAccessTokenCommand::class.java,
            IntrospectTokenCommand::class.java,
            RevokeTokenCommand::class.java,
            GetJwksCommand::class.java,
            BuildServerMetadataCommand::class.java,
            VerifyClientAuthenticationCommand::class.java,
            VerifyPushedAuthorizationRequestCommand::class.java,
        )

    private val userAuthenticationProviders =
        listOf(
            FederatedUserAuthenticationProvider::class.java,
            ConfigBackedUserAuthenticationProvider::class.java,
        )

    private fun SessionObjectCensus.assertReachesNoneOf(
        types: List<Class<*>>,
        reason: String,
    ) {
        types.forEach { type -> assertFalse(reachesInstanceOf(type), "${type.simpleName}: $reason") }
    }

    @Test
    fun authorizationServerServiceResolvesItsCommandsOnUse() {
        val census = SessionObjectCensus.of(graph.constructionAuthorizationServerService)
        println(census.describe("AuthorizationServerService"))

        census.assertReachesNoneOf(otherEndpointCommands, "the facade only builds the commands a request calls")
    }

    @Test
    fun standardAuthorizeRequestDefersBranchDependencies() {
        val standard = graph.constructionAuthorizeRequestCommands.filterIsInstance<StandardAuthorizeRequestCommandImpl>().single()
        val census = SessionObjectCensus.of(standard)
        println(census.describe("StandardAuthorizeRequestCommandImpl"))

        assertFalse(census.reachesInstanceOf(VerifyRequestObjectCommand::class.java), "Request objects are only verified for an inline JAR")
        assertFalse(
            census.reachesInstanceOf(UserAuthenticationProvider::class.java),
            "The user provider is only asked on the branch that needs it (federation probe, SSO claims, upstream hop)",
        )
        assertFalse(
            census.reachesInstanceOf(AuthenticationRoutePlanner::class.java),
            "The route planner is only asked without an active login session that can issue the code",
        )
        census.assertReachesNoneOf(otherEndpointCommands, "the authorize route never calls them")
    }

    @Test
    fun walletAuthorizeRequestDefersTheUserProviderAndOtherEndpoints() {
        val wallet = graph.constructionAuthorizeRequestCommands.filterIsInstance<WalletAuthorizeRequestCommandImpl>().single()
        val census = SessionObjectCensus.of(wallet)
        println(census.describe("WalletAuthorizeRequestCommandImpl"))

        assertFalse(
            census.reachesInstanceOf(UserAuthenticationProvider::class.java),
            "The user provider is only asked once the request passed parsing and redirect resolution",
        )
        census.assertReachesNoneOf(otherEndpointCommands, "the authorize route never calls them")
    }

    @Test
    fun authorizeCallbackBuildsOnlyTheSelectedUserProviderOnUse() {
        val census = SessionObjectCensus.of(graph.constructionAuthorizeCallbackCommand)
        println(census.describe("HandleAuthorizeCallbackCommandImpl"))

        census.assertReachesNoneOf(userAuthenticationProviders, "the user provider is selected and built on its first call")
        census.assertReachesNoneOf(otherEndpointCommands, "the callback never calls them")
    }

    @Test
    fun userProviderDelegateBuildsNoProviderUntilOneIsSelected() {
        val census = SessionObjectCensus.of(graph.constructionUserAuthenticationProvider)
        println(census.describe("UserAuthenticationProvider"))

        census.assertReachesNoneOf(userAuthenticationProviders, "only the configured mode's provider is ever used")
    }

    @Test
    fun userProviderDelegateBuildsOnlyTheConfiguredProviderOnUse() =
        runTest {
            val delegate = graph.constructionUserAuthenticationProvider

            delegate.isAuthenticationMethodAvailable(AuthenticationMethod.OAUTH)

            val census = SessionObjectCensus.of(delegate)
            assertTrue(
                census.reachesInstanceOf(FederatedUserAuthenticationProvider::class.java),
                "The default mode's provider is built once the delegate is used",
            )
            assertFalse(
                census.reachesInstanceOf(ConfigBackedUserAuthenticationProvider::class.java),
                "Providers of other modes stay unbuilt",
            )
        }
}
