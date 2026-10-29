/*
 * Copyright 2026 Sphereon International B.V.
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

package com.sphereon.oauth2.server.authorization.impl.signing

import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.server.authorization.command.GetJwksArgs
import com.sphereon.oauth2.server.authorization.impl.command.oidc.GetJwksCommandImpl
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.signing.AsPublishableSigningKeySource
import dev.zacsweers.metro.ContributesTo
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Exposes the session-scoped publishable-key source and JWKS command of the real test graph. */
@ContributesTo(SessionScope::class)
interface PublishableSigningKeySourceTestGraph {
    val asPublishableSigningKeySource: AsPublishableSigningKeySource
    val getJwksCommandImpl: GetJwksCommandImpl
}

/** The standalone IDK graph binds the tenant-wide default source, so JWKS behavior is unchanged. */
class DefaultAsPublishableSigningKeySourceGraphTest {
    private val ctx = OAuth2ServerTestContext("publishable-source-graph-test", this)

    @Test
    fun standaloneGraphBindsTheDefaultSourceAndTheJwksCommandResolves() =
        runTest {
            val graph = ctx.session.graph as PublishableSigningKeySourceTestGraph

            assertIs<DefaultAsPublishableSigningKeySource>(graph.asPublishableSigningKeySource)
            // The anonymous test session carries no real tenant, so the command refuses before
            // reading the source. Resolution proves the graph wires the seam.
            val result = graph.getJwksCommandImpl.execute(GetJwksArgs())
            assertTrue(result.isErr, "A session without a resolved tenant must still be refused")
        }
}
