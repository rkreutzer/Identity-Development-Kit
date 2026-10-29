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

import com.sphereon.core.api.context.SessionExecution
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.oauth2.server.authorization.command.GetJwksArgs
import com.sphereon.oauth2.server.authorization.impl.signing.DefaultAsPublishableSigningKeySource
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemorySigningKeyStore
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.TenantOverrideSessionExecution
import com.sphereon.oauth2.server.authorization.signing.AsSigningKeyPublicJwkResolver
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKey
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKeyState
import com.sphereon.oauth2.server.authorization.storage.SigningKeyStore
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * Pins the [GetJwksCommandImpl] contract that RPs depend on after every rotation: the
 * JWKS endpoint must publish the current ACTIVE key AND every still-LEGACY key, in
 * priority-descending order so RPs that pick the first match find the freshest signer.
 *
 * The store-resolution path is exercised end-to-end against a real [InMemorySigningKeyStore]
 * and the test context's KMS so the JWK encoding (kid, alg, kty, n/e or x/y) is real, not
 * stubbed. Failures here would surface as RP "kid not in JWKS" verification errors in
 * production.
 */
class GetJwksCommandImplTest {
    private val ctx = OAuth2ServerTestContext("get-jwks-test", this)
    private val tenant = "default"

    @Test
    fun emptyStoreReturnsEmptyJwks() =
        runTest {
            // Pre-bootstrap or post-emergency-revoke state: JWKS responds 200 with `keys: []`.
            // RPs interpret that as "no public verification key available" rather than treating
            // the endpoint as broken.
            val store: SigningKeyStore = InMemorySigningKeyStore()
            val command = ctx.defaultSourceJwksCommand(TenantOverrideSessionExecution(ctx.execution, tenant), store)

            val result = command.execute(GetJwksArgs())

            assertTrue(result.isOk, "GetJwks must respond OK on empty store, got: ${if (result.isErr) result.error else ""}")
            assertEquals(emptyList(), result.value.keys)
        }

    @Test
    fun publishesActiveAndLegacyKeysOrderedByPriorityDescending() =
        runTest {
            // Two real keys live in the test KMS: the previously-active LEGACY and the
            // freshly-rotated ACTIVE. JWKS must include both so RPs that fetched a token
            // signed under the LEGACY key before they refreshed their JWKS cache can still
            // verify it. Order: ACTIVE first (higher priority) so RPs picking the first
            // match by alg use the current signer.
            val store: SigningKeyStore = InMemorySigningKeyStore()

            val legacyKey = generateAndRegister(store, kid = "kid-legacy", state = OAuth2SigningKeyState.LEGACY, priority = 5)
            val activeKey = generateAndRegister(store, kid = "kid-active", state = OAuth2SigningKeyState.ACTIVE, priority = 10)

            val command = ctx.defaultSourceJwksCommand(TenantOverrideSessionExecution(ctx.execution, tenant), store)
            val result = command.execute(GetJwksArgs())

            assertTrue(result.isOk, "GetJwks must succeed when two real keys are registered")
            val publishedKids = result.value.keys.map { it.kid }
            assertEquals(
                listOf(activeKey.kid, legacyKey.kid),
                publishedKids,
                "JWKS must list ACTIVE first (highest priority) then LEGACY",
            )
            // Belt-and-suspenders: each published JWK must declare its alg so RPs can pick a
            // verifier without falling back to introspection. Compare via toString to stay
            // tolerant of whether the implementation surfaces alg as String or as the enum
            // (Jwk has subtypes for both).
            for (jwk in result.value.keys) {
                assertEquals("RS256", jwk.alg?.toString(), "RSA-SHA256 keys must publish alg=RS256")
                assertNull(jwk.d, "JWKS must not publish the RSA private exponent")
                assertNull(jwk.p, "JWKS must not publish the first RSA prime factor")
                assertNull(jwk.q, "JWKS must not publish the second RSA prime factor")
                assertNull(jwk.dP, "JWKS must not publish the first RSA CRT exponent")
                assertNull(jwk.dQ, "JWKS must not publish the second RSA CRT exponent")
                assertNull(jwk.qInv, "JWKS must not publish the RSA CRT coefficient")
                assertNull(jwk.k, "JWKS must not publish symmetric key material")
            }
        }

    @Test
    fun excludesDisabledKeys() =
        runTest {
            // DISABLED keys are tombstones — they exist for audit / operator visibility but
            // MUST NOT appear in JWKS, otherwise an attacker who captured a token signed
            // before the disable would still see a published verification key.
            val store: SigningKeyStore = InMemorySigningKeyStore()
            generateAndRegister(store, kid = "kid-active", state = OAuth2SigningKeyState.ACTIVE, priority = 10)
            generateAndRegister(store, kid = "kid-disabled", state = OAuth2SigningKeyState.DISABLED, priority = 1)

            val command = ctx.defaultSourceJwksCommand(TenantOverrideSessionExecution(ctx.execution, tenant), store)
            val result = command.execute(GetJwksArgs())

            assertTrue(result.isOk)
            val publishedKids = result.value.keys.map { it.kid }
            assertEquals(listOf("kid-active"), publishedKids, "DISABLED keys must NOT appear in JWKS")
        }

    @Test
    fun deploymentResolverDenialDoesNotFallBackToLocalProviderRegistry() =
        runTest {
            val store: SigningKeyStore = InMemorySigningKeyStore()
            generateAndRegister(store, kid = "kid-routed-denial", state = OAuth2SigningKeyState.ACTIVE, priority = 10)
            var resolverCalls = 0
            val routedResolver =
                object : AsSigningKeyPublicJwkResolver {
                    override suspend fun resolve(signingKey: OAuth2SigningKey) =
                        null.also { resolverCalls++ }
                }
            val command =
                GetJwksCommandImpl(
                    execution = TenantOverrideSessionExecution(ctx.execution, tenant),
                    publishableSigningKeySource =
                        DefaultAsPublishableSigningKeySource(TenantOverrideSessionExecution(ctx.execution, tenant), store),
                    multiManagedIdentifierService = lazyOf(ctx.identifierService),
                    signingKeyPublicJwkResolver = routedResolver,
                )

            val result = command.execute(GetJwksArgs())

            assertTrue(result.isOk)
            assertEquals(1, resolverCalls)
            assertEquals(
                emptyList(),
                result.value.keys,
                "A routed resolver denial must not retry through the locally resolvable test key",
            )
        }

    @Test
    fun preservesProviderBindingFromSigningKeyStoreWhenPublishingJwks() =
        runTest {
            // Fresh tenant AS registration provisions the signing key into a tenant-specific
            // provider. JWKS must resolve the exact KeyInfo stored for that tenant; falling
            // back to alias-only lookup checks the default provider and returns an empty JWKS.
            val providerId = "tenant-specific-jwks-provider"
            registerSoftwareProvider(providerId)

            val store: SigningKeyStore = InMemorySigningKeyStore()
            val kid = "oauth2-as-phase170583"
            val genResult =
                ctx.keyManagerService.generateKeyResult(
                    providerId = providerId,
                    alias = kid,
                    use = JwkUse.sig,
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                )
            assertTrue(
                genResult.isOk,
                "KMS must generate tenant-provider key: ${if (genResult.isErr) genResult.error.message.defaultMessage else ""}",
            )
            val keyPair = genResult.value.keyPair ?: error("KMS returned no keyPair for $kid")
            assertEquals(providerId, keyPair.providerId, "precondition: key must be stored in the tenant-specific provider")

            val now = Clock.System.now()
            val registerResult =
                store.register(
                    OAuth2SigningKey(
                        tenantId = tenant,
                        keyInfo =
                            KeyInfo<KeyType>(
                                kid = kid,
                                alias = kid,
                                providerId = providerId,
                                signatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                            ),
                        state = OAuth2SigningKeyState.ACTIVE,
                        priority = 1,
                        createdAt = now,
                        notBefore = now,
                    ),
                )
            assertTrue(registerResult.isOk, "store.register($kid) must succeed: ${if (registerResult.isErr) registerResult.error else ""}")

            val command = ctx.defaultSourceJwksCommand(TenantOverrideSessionExecution(ctx.execution, tenant), store)
            val result = command.execute(GetJwksArgs())

            assertTrue(result.isOk, "GetJwks must resolve keys by the stored provider binding")
            assertEquals(listOf(kid), result.value.keys.map { it.kid })
            assertEquals(
                "ES256",
                result.value.keys
                    .single()
                    .alg
                    ?.toString()
            )
        }

    /**
     * Generate a real RSA key in the test KMS, then register it in the store with the
     * supplied lifecycle metadata so the GetJwks path resolves an actual public key.
     * Pins the wire-visible kid via [KeyInfo.kid] so the JWKS publication preserves the
     * store-side identifier (not the KMS-derived one, which would diverge from what
     * tokens carry in their JWS header).
     */
    private suspend fun generateAndRegister(
        store: SigningKeyStore,
        kid: String,
        state: OAuth2SigningKeyState,
        priority: Int,
    ): OAuth2SigningKey {
        val alias = "oauth2.$tenant.$kid"
        val genResult =
            ctx.keyManagerService.generateKeyResult(
                alias = alias,
                use = JwkUse.sig,
                alg = SignatureAlgorithm.RSA_SHA256,
            )
        assertTrue(
            genResult.isOk,
            "KMS must generate RSA key for $alias: ${if (genResult.isErr) genResult.error.message.defaultMessage else ""}",
        )
        val keyPair = genResult.value.keyPair ?: error("KMS returned no keyPair for $alias")

        val now = Clock.System.now()
        val key =
            OAuth2SigningKey(
                tenantId = tenant,
                keyInfo =
                    KeyInfo<KeyType>(
                        kid = kid,
                        alias = keyPair.alias,
                        providerId = keyPair.providerId,
                        signatureAlgorithm = SignatureAlgorithm.RSA_SHA256,
                    ),
                state = state,
                priority = priority,
                createdAt = now,
                notBefore = now,
            )
        val registerResult = store.register(key)
        assertTrue(registerResult.isOk, "store.register($kid) must succeed: ${if (registerResult.isErr) registerResult.error else ""}")
        return key
    }

    private fun registerSoftwareProvider(providerId: String) {
        val factory = (ctx.app as SoftwareKmsProviderFactoryImpl.Graph).softwareKmsProvider
        val provider = factory.create(SoftwareKmsProviderConfig(id = providerId), ctx.execution)
        ctx.keyManagerService.registerProvider(provider, makeDefaultKms = false)
    }
}

/** Builds the command with the default publishable-key source over [store], as the IDK graph binds it. */
internal fun OAuth2ServerTestContext.defaultSourceJwksCommand(
    execution: SessionExecution,
    store: SigningKeyStore,
): GetJwksCommandImpl =
    GetJwksCommandImpl(
        execution = execution,
        publishableSigningKeySource = DefaultAsPublishableSigningKeySource(execution, store),
        multiManagedIdentifierService = lazyOf(identifierService),
    )
