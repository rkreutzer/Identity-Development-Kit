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

package com.sphereon.oauth2.server.authorization.impl.command.oidc

import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.oauth2.server.authorization.command.GetJwksArgs
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemorySigningKeyStore
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.TenantOverrideSessionExecution
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKey
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKeyState
import com.sphereon.oauth2.server.authorization.storage.SigningKeyStore
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * Verifies that [GetJwksCommandImpl] uses the session tenant when looking up publishable
 * signing keys, rather than the hard-coded "default" sentinel that existed before the
 * multi-tenant fix.
 *
 * The critical contract: a session belonging to tenant "acme" must publish ONLY the key
 * registered under "acme", not the key registered under "beta"; a session with a blank
 * tenant must fail closed rather than publishing another tenant's keys.
 */
class TenantAwareSigningKeyLookupTest {
    private val ctx = OAuth2ServerTestContext("tenant-aware-jwks-test", this)

    @Test
    fun acmeSessionPublishesAcmeKeyNotBetaKey() =
        runTest {
            // Seed a store with one key per tenant so that cross-contamination is detectable.
            val store: SigningKeyStore = InMemorySigningKeyStore()
            val acmeKey = seedActiveKey(store, tenantId = "acme", kid = "k-acme")
            seedActiveKey(store, tenantId = "beta", kid = "k-beta")

            val acmeExecution = TenantOverrideSessionExecution(ctx.execution, "acme")
            val command = ctx.defaultSourceJwksCommand(acmeExecution, store)

            val result = command.execute(GetJwksArgs())

            assertTrue(result.isOk, "GetJwks for acme session must succeed: ${if (result.isErr) result.error else ""}")
            val publishedKids = result.value.keys.map { it.kid }
            assertEquals(
                listOf(acmeKey.kid),
                publishedKids,
                "acme session must publish only the acme key, not the beta key",
            )
        }

    @Test
    fun betaSessionPublishesBetaKeyNotAcmeKey() =
        runTest {
            val store: SigningKeyStore = InMemorySigningKeyStore()
            seedActiveKey(store, tenantId = "acme", kid = "k-acme")
            val betaKey = seedActiveKey(store, tenantId = "beta", kid = "k-beta")

            val betaExecution = TenantOverrideSessionExecution(ctx.execution, "beta")
            val command = ctx.defaultSourceJwksCommand(betaExecution, store)

            val result = command.execute(GetJwksArgs())

            assertTrue(result.isOk, "GetJwks for beta session must succeed: ${if (result.isErr) result.error else ""}")
            val publishedKids = result.value.keys.map { it.kid }
            assertEquals(
                listOf(betaKey.kid),
                publishedKids,
                "beta session must publish only the beta key, not the acme key",
            )
        }

    @Test
    fun blankTenantFailsClosed() =
        runTest {
            // Tenant resolution must happen before JWKS publication. A blank tenant means
            // the request bypassed tenant resolution, so the command must not publish
            // "default" keys as a fallback.
            val store: SigningKeyStore = InMemorySigningKeyStore()
            seedActiveKey(store, tenantId = "default", kid = "k-default")

            val blankExecution = TenantOverrideSessionExecution(ctx.execution, "")
            val command = ctx.defaultSourceJwksCommand(blankExecution, store)

            val result = command.execute(GetJwksArgs())

            assertTrue(result.isErr, "GetJwks with blank tenant must fail closed")
        }

    @Test
    fun acmeSessionFindsActiveKey() =
        runTest {
            // Mirrors the active-key lookup that DefaultAsServerSigningIdentifierResolver performs on the
            // jvmMain side. We exercise it here through the store directly as the store-level
            // contract is identical: getActive(tenantId) must return the acme key, not null.
            val store: SigningKeyStore = InMemorySigningKeyStore()
            seedActiveKey(store, tenantId = "acme", kid = "k-acme")

            val activeResult = store.getActive("acme")
            assertTrue(activeResult.isOk)
            assertNotNull(activeResult.value, "acme tenant must have an active key after seeding")
            assertEquals("k-acme", activeResult.value!!.kid)

            // The "beta" tenant was not seeded — its active lookup must return Ok(null).
            val betaResult = store.getActive("beta")
            assertTrue(betaResult.isOk)
            assertNull(betaResult.value, "unseeded beta tenant must have no active key")
        }

    /**
     * Register a real KMS-backed ACTIVE key in the store under the given tenant so the
     * [GetJwksCommandImpl] resolution path can turn it into a JWK. Uses the shared test KMS
     * from [ctx] so the key material is real and the JWK encoding round-trips correctly.
     */
    private suspend fun seedActiveKey(
        store: SigningKeyStore,
        tenantId: String,
        kid: String,
    ): OAuth2SigningKey {
        val alias = "oauth2.$tenantId.$kid"
        val genResult =
            ctx.keyManagerService.generateKeyResult(
                alias = alias,
                use = JwkUse.sig,
                alg = SignatureAlgorithm.RSA_SHA256,
            )
        assertTrue(
            genResult.isOk,
            "KMS must generate key for $alias: ${if (genResult.isErr) genResult.error.message.defaultMessage else ""}",
        )
        val keyPair = genResult.value.keyPair ?: error("KMS returned no keyPair for $alias")
        val now = Clock.System.now()
        val key =
            OAuth2SigningKey(
                tenantId = tenantId,
                keyInfo =
                    KeyInfo<KeyType>(
                        kid = kid,
                        alias = keyPair.alias,
                        providerId = keyPair.providerId,
                        signatureAlgorithm = SignatureAlgorithm.RSA_SHA256,
                    ),
                state = OAuth2SigningKeyState.ACTIVE,
                priority = 1,
                createdAt = now,
                notBefore = now,
            )
        val registerResult = store.register(key)
        assertTrue(
            registerResult.isOk,
            "store.register($tenantId/$kid) must succeed: ${if (registerResult.isErr) registerResult.error else ""}",
        )
        return key
    }
}
