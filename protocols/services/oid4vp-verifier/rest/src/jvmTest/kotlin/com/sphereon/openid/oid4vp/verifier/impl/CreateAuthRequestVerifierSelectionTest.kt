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
 *
 */

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.core.api.conf.DefaultPrincipalMapPropertySource
import com.sphereon.core.api.service.SessionScopedCommandRegistry
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.generic.KeyOperations
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.di.context.PrincipalType
import com.sphereon.di.session.SessionScope
import com.sphereon.did.methods.jwk.JwkDidProviderImpl
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.universal.AuthorizationRequestMethod
import com.sphereon.openid.oid4vp.universal.CreateAuthRequestServiceCommand
import com.sphereon.openid.oid4vp.universal.CreateAuthorizationRequestInput
import com.sphereon.openid.oid4vp.universal.impl.createUniversalOid4vpTestAppGraph
import com.sphereon.openid.oid4vp.verifier.config.DEFAULT_OID4VP_VERIFIER_INSTANCE_ID
import com.sphereon.openid.oid4vp.verifier.config.MutableOid4vpVerifierInstanceIdProvider
import dev.zacsweers.metro.ContributesTo
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

@ContributesTo(SessionScope::class)
interface VerifierSelectionGraph {
    val verifierInstanceIdProvider: MutableOid4vpVerifierInstanceIdProvider
}

/**
 * A create request that names a `verifier_id` but arrives with no route that names a verifier, as when it is
 * dispatched over the internal transport, must run under that verifier from its first configuration read.
 *
 * The create command runs through the session command registry with no HTTP route in front of it. Three verifiers
 * have distinct signing keys in the KMS: the default one, `verifier-a` and `verifier-b`. The signer a request ends up
 * under, and the verifier instance the session is stored under, show which verifier the command really ran as.
 */
class CreateAuthRequestVerifierSelectionTest {
    @BeforeEach
    fun reset() {
        DefaultPrincipalMapPropertySource.getSource().clear()
        TestRequestObjectSigningConfig.disable()
        TestRequestObjectSigningConfig.observedInstances.clear()
    }

    @Test
    fun shouldRunUnderTheVerifierNamedInTheBodyWhenNoRouteSelectedOne() =
        runTest {
            TestRequestObjectSigningConfig.enableDidJwkSigning()
            val app = createUniversalOid4vpTestAppGraph(TestScope(), appId = "test-verifier-selection", profile = "test", version = "1.0.0")
            DefaultPrincipalMapPropertySource.addProperties(
                mapOf(
                    "kms.providers.test-software.type" to "software",
                    "kms.providers.test-software.id" to "test-software",
                    "kms.providers.test-software.keystore.type" to "memory",
                    "kms.providers.test-software.keystore.id" to "test-memory-keystore",
                    "kms.providers.test-software.keystore.keyVisibility" to "private",
                    "kms.providers.test-software.keystore.overwriteAlias" to "true",
                ),
            )
            app.userContextManager.destroyAll()
            val session = app.userContextManager.getAnonymous().sessionContextManager.createOrGetFromId("verifier-selection", principalType = PrincipalType.USER)
            val graph = session.graph
            val kms = graph.asKeyManagerServiceGraph().keyManagerService
            val rpService = (graph as RpServiceGraph).oid4vpVerifierService
            val provider = (graph as VerifierSelectionGraph).verifierInstanceIdProvider
            val create = (graph as SessionScopedCommandRegistry.Graph).sessionScopedCommandRegistry.get(CreateAuthRequestServiceCommand.COMMAND_ID) as CreateAuthRequestServiceCommand

            val instances = listOf<String?>(null, "verifier-a", "verifier-b")
            val dids =
                instances.associateWith { instance ->
                    val pair =
                        kms.generateKeyAsync(
                            providerId = "test-software",
                            alias = TestRequestObjectSigningConfig.signingKeyAlias(instance),
                            use = JwkUse.sig,
                            keyOperations = arrayOf(KeyOperations.SIGN, KeyOperations.VERIFY),
                            alg = SignatureAlgorithm.ECDSA_SHA256,
                            keyVisibility = KeyVisibility.PRIVATE,
                        )
                    JwkDidProviderImpl.didFromJwk(pair.jose.publicJwk)
                }
            assertEquals(3, dids.values.toSet().size, "the three verifiers must sign with distinct keys")

            fun createInput(verifierId: String?) =
                CreateAuthorizationRequestInput(
                    dcqlQuery = DcqlQuery(credentials = listOf(DcqlCredentialQuery(id = "pid", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:pid")))),
                    verifierId = verifierId,
                    authorizationRequestMethod = AuthorizationRequestMethod.REQUEST_URI,
                )

            suspend fun createAs(verifierId: String?): Pair<String, String> {
                val output = create.execute(createInput(verifierId)).getOrThrow()
                val stored = rpService.authorizationSessionStore.getByCorrelationId(output.correlationId).getOrThrow()!!
                return stored.instanceId to stored.authorizationRequest.clientId
            }

            // No route selected a verifier: the body's verifier_id decides, from the first read.
            val (instanceA, clientIdA) = createAs("verifier-a")
            assertEquals("verifier-a", instanceA)
            assertTrue(clientIdA.contains(dids.getValue("verifier-a")), "client_id must come from verifier-a's key: $clientIdA")
            assertNull(provider.currentInstanceId(), "the fallback is gone once the command returns")

            val (instanceB, clientIdB) = createAs("verifier-b")
            assertEquals("verifier-b", instanceB)
            assertTrue(clientIdB.contains(dids.getValue("verifier-b")), "client_id must come from verifier-b's key: $clientIdB")

            // No verifier named at all: the default verifier, not a leftover from the earlier calls.
            val (instanceDefault, clientIdDefault) = createAs(null)
            assertEquals(DEFAULT_OID4VP_VERIFIER_INSTANCE_ID, instanceDefault)
            assertTrue(clientIdDefault.contains(dids.getValue(null)), "client_id must come from the default key: $clientIdDefault")
            assertEquals(setOf<String?>("verifier-a", "verifier-b", null), TestRequestObjectSigningConfig.observedInstances.toSet())

            // A route that already named a verifier keeps priority: the same verifier is accepted, a different one is refused.
            provider.setCurrentInstanceId("verifier-b")
            try {
                val (routedInstance, routedClientId) = createAs("verifier-b")
                assertEquals("verifier-b", routedInstance)
                assertTrue(routedClientId.contains(dids.getValue("verifier-b")), "the route's verifier signs: $routedClientId")
                assertEquals("verifier-b", provider.currentInstanceId(), "a route-selected verifier is not cleared by the command")

                val refused = create.execute(createInput("verifier-a"))
                assertTrue(refused.isErr, "a body verifier_id that differs from the routed verifier must be refused")
                assertTrue(refused.errorOrNull()!!.message.defaultMessage.contains("does not match the routed verifier"), "${refused.errorOrNull()}")
                assertEquals("verifier-b", provider.currentInstanceId(), "a refused request leaves the route's verifier selected")
            } finally {
                provider.clearCurrentInstanceId()
            }
        }
}
