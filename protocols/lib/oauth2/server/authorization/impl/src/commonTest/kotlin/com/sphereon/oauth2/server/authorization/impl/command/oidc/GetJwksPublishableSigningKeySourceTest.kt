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

package com.sphereon.oauth2.server.authorization.impl.command.oidc

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.oauth2.server.authorization.command.GetJwksArgs
import com.sphereon.oauth2.server.authorization.impl.signing.DefaultAsPublishableSigningKeySource
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemorySigningKeyStore
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.TenantOverrideSessionExecution
import com.sphereon.oauth2.server.authorization.signing.AsPublishableSigningKeySource
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKey
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKeyState
import com.sphereon.oauth2.server.authorization.storage.SigningKeyStore
import com.sphereon.oauth2.server.authorization.storage.SigningKeyStoreError
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * Pins the [AsPublishableSigningKeySource] seam of [GetJwksCommandImpl]: the JWKS publishes exactly
 * the keys the source reports, the default source reproduces the tenant-wide store set, and a
 * replacement source can restrict or extend that set for one authorization server.
 */
class GetJwksPublishableSigningKeySourceTest {
    private val ctx = OAuth2ServerTestContext("get-jwks-source-test", this)
    private val tenant = "acme"
    private val execution = TenantOverrideSessionExecution(ctx.execution, tenant)

    @Test
    fun commandReadsPublishableKeysFromTheInjectedSourceForTheSessionTenant() =
        runTest {
            val key = generateKey("kid-from-source", OAuth2SigningKeyState.ACTIVE, priority = 10)
            val requestedTenants = mutableListOf<String>()
            val source = fixedSource(listOf(key), requestedTenants)

            val result = command(source).execute(GetJwksArgs())

            assertTrue(result.isOk, "GetJwks must publish the source keys: ${if (result.isErr) result.error else ""}")
            assertEquals(listOf(tenant), requestedTenants, "The source must be asked once, for the session tenant")
            assertEquals(listOf("kid-from-source"), result.value.keys.map { it.kid })
        }

    @Test
    fun defaultSourceReproducesTheStorePublishableSetAndJwks() =
        runTest {
            val store: SigningKeyStore = InMemorySigningKeyStore()
            val legacy = generateKey("kid-legacy", OAuth2SigningKeyState.LEGACY, priority = 5).also { store.register(it) }
            val active = generateKey("kid-active", OAuth2SigningKeyState.ACTIVE, priority = 10).also { store.register(it) }
            generateKey("kid-disabled", OAuth2SigningKeyState.DISABLED, priority = 1).also { store.register(it) }

            val defaultSource = DefaultAsPublishableSigningKeySource(execution, store)
            val fromSource = defaultSource.listPublishable(tenant)
            val fromStore = store.listPublishable(tenant)

            assertTrue(fromSource.isOk && fromStore.isOk)
            assertEquals(fromStore.value, fromSource.value, "The default source must return the store publishable set unchanged")

            val viaDefault = command(defaultSource).execute(GetJwksArgs())
            val viaStoreSet = command(fixedSource(fromStore.value)).execute(GetJwksArgs())
            assertTrue(viaDefault.isOk && viaStoreSet.isOk)
            assertEquals(listOf(active.kid, legacy.kid), viaDefault.value.keys.map { it.kid })
            assertEquals(viaStoreSet.value, viaDefault.value, "The default source must publish today's JWKS")
        }

    @Test
    fun customSourceRestrictsThePublishedKeysToOneAuthorizationServer() =
        runTest {
            val store: SigningKeyStore = InMemorySigningKeyStore()
            val ownKey = generateKey("kid-own-server", OAuth2SigningKeyState.ACTIVE, priority = 1).also { store.register(it) }
            generateKey("kid-sibling-server", OAuth2SigningKeyState.ACTIVE, priority = 2).also { store.register(it) }
            val scopedSource =
                object : AsPublishableSigningKeySource {
                    override suspend fun listPublishable(tenantId: String): IdkResult<List<OAuth2SigningKey>, IdkError> {
                        val all = store.listPublishable(tenantId)
                        if (all.isErr) return Err(IdkError.INVALID_STATE(message = "store unavailable"))
                        return Ok(all.value.filter { it.kid == ownKey.kid })
                    }
                }

            val result = command(scopedSource).execute(GetJwksArgs())

            assertTrue(result.isOk)
            assertEquals(listOf(ownKey.kid), result.value.keys.map { it.kid }, "A sibling server's key must not be published")
        }

    @Test
    fun customSourceExtendsThePublishedKeysBeyondTheStore() =
        runTest {
            val store: SigningKeyStore = InMemorySigningKeyStore()
            val stored = generateKey("kid-stored", OAuth2SigningKeyState.ACTIVE, priority = 10).also { store.register(it) }
            val retained = generateKey("kid-retained-legacy", OAuth2SigningKeyState.LEGACY, priority = 1)
            val extendingSource =
                object : AsPublishableSigningKeySource {
                    override suspend fun listPublishable(tenantId: String): IdkResult<List<OAuth2SigningKey>, IdkError> =
                        Ok(store.listPublishable(tenantId).value + retained)
                }

            val result = command(extendingSource).execute(GetJwksArgs())

            assertTrue(result.isOk)
            assertEquals(listOf(stored.kid, retained.kid), result.value.keys.map { it.kid })
        }

    @Test
    fun sourceErrorIsReturnedUnchanged() =
        runTest {
            val refusal = IdkError.INVALID_STATE(message = "More than one authorization server matches the request")
            val refusingSource =
                object : AsPublishableSigningKeySource {
                    override suspend fun listPublishable(tenantId: String): IdkResult<List<OAuth2SigningKey>, IdkError> = Err(refusal)
                }

            val result = command(refusingSource).execute(GetJwksArgs())

            assertTrue(result.isErr)
            assertSame(refusal, result.error)
        }

    @Test
    fun defaultSourceKeepsTheStorageFailureRefusal() =
        runTest {
            val failingStore =
                object : SigningKeyStore by InMemorySigningKeyStore() {
                    override suspend fun listPublishable(tenantId: String): IdkResult<List<OAuth2SigningKey>, SigningKeyStoreError> =
                        Err(SigningKeyStoreError.StorageFailure(operation = "listPublishable", details = "offline"))
                }

            val result = ctx.defaultSourceJwksCommand(execution, failingStore).execute(GetJwksArgs())

            assertTrue(result.isErr)
            assertEquals("ILLEGAL_ARGUMENT_ERROR", result.error.code)
            assertEquals("Failed to list publishable signing keys", result.error.message.defaultMessage)
        }

    private fun command(source: AsPublishableSigningKeySource): GetJwksCommandImpl =
        GetJwksCommandImpl(
            execution = execution,
            publishableSigningKeySource = source,
            multiManagedIdentifierService = lazyOf(ctx.identifierService),
        )

    private fun fixedSource(
        keys: List<OAuth2SigningKey>,
        requestedTenants: MutableList<String> = mutableListOf(),
    ): AsPublishableSigningKeySource =
        object : AsPublishableSigningKeySource {
            override suspend fun listPublishable(tenantId: String): IdkResult<List<OAuth2SigningKey>, IdkError> {
                requestedTenants += tenantId
                return Ok(keys)
            }
        }

    /** Generates a real key in the test KMS and returns its durable descriptor without registering it. */
    private suspend fun generateKey(
        kid: String,
        state: OAuth2SigningKeyState,
        priority: Int,
    ): OAuth2SigningKey {
        val alias = "oauth2.$tenant.$kid"
        val generated =
            ctx.keyManagerService.generateKeyResult(
                alias = alias,
                use = JwkUse.sig,
                alg = SignatureAlgorithm.ECDSA_SHA256,
            )
        assertTrue(generated.isOk, "KMS must generate $alias: ${if (generated.isErr) generated.error.message.defaultMessage else ""}")
        val keyPair = generated.value.keyPair ?: error("KMS returned no keyPair for $alias")
        val now = Clock.System.now()
        return OAuth2SigningKey(
            tenantId = tenant,
            keyInfo =
                KeyInfo<KeyType>(
                    kid = kid,
                    alias = keyPair.alias,
                    providerId = keyPair.providerId,
                    signatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                ),
            state = state,
            priority = priority,
            createdAt = now,
            notBefore = now,
        )
    }
}
