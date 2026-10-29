package com.sphereon.openid.oid4vci.issuer.impl.signing

import com.sphereon.core.api.Err
import com.sphereon.core.api.conf.PrincipalConfigService
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.did.manager.DidProviderRegistry
import com.sphereon.did.resolver.DidResolverRegistry
import com.sphereon.openid.oid4vci.issuer.spi.IssuerPublicJwkSource
import dev.zacsweers.metro.Provider
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.lang.reflect.Proxy
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class IssuerPublicJwkSourceResolutionTest {
    @Test
    fun absentMetroProviderPointeeUsesExistingKmsLookup() = runTest {
        val fixture = Fixture(nullPointeeProvider())

        assertTrue(fixture.resolver.resolvePublicJwk("registered-test-key").isErr)
        assertEquals(1, fixture.kmsLookups)
    }

    @Test
    fun boundSourceMissingKeyRefusesWithoutKmsFallback() = runTest {
        val fixture = Fixture(provider(source { null }))

        assertTrue(fixture.resolver.resolvePublicJwk("registered-test-key").isErr)
        assertEquals(0, fixture.kmsLookups)
    }

    @Test
    fun boundSourceFailureRefusesWithoutKmsFallback() = runTest {
        val fixture = Fixture(provider(source { error("test source failure") }))

        assertTrue(fixture.resolver.resolvePublicJwk("registered-test-key").isErr)
        assertEquals(0, fixture.kmsLookups)
    }

    @Test
    fun providerInvocationFailureRefusesWithoutKmsFallback() = runTest {
        val fixture = Fixture(object : Provider<IssuerPublicJwkSource> {
            override fun invoke(): IssuerPublicJwkSource = error("test provider failure")
        })

        assertTrue(fixture.resolver.resolvePublicJwk("registered-test-key").isErr)
        assertEquals(0, fixture.kmsLookups)
    }

    @Test
    fun malformedBoundSourceRefusesWithoutKmsFallback() = runTest {
        val fixture = Fixture(provider(source { JsonObject(mapOf("unexpected" to JsonPrimitive(true))) }))

        assertTrue(fixture.resolver.resolvePublicJwk("registered-test-key").isErr)
        assertEquals(0, fixture.kmsLookups)
    }

    @Test
    fun boundSourceRemainsLazyAndExportsOnlyPublicMaterial() = runTest {
        var providerCalls = 0
        val fixture = Fixture(object : Provider<IssuerPublicJwkSource> {
            override fun invoke(): IssuerPublicJwkSource {
                providerCalls++
                return source {
                    JsonObject(mapOf(
                        "kty" to JsonPrimitive("EC"),
                        "crv" to JsonPrimitive("P-256"),
                        "x" to JsonPrimitive("test-public-x"),
                        "y" to JsonPrimitive("test-public-y"),
                        "d" to JsonPrimitive("test-private-component"),
                        "kid" to JsonPrimitive("test-internal-name"),
                    ))
                }
            }
        })
        assertEquals(0, providerCalls)

        val result = fixture.resolver.resolvePublicJwk("registered-test-key")

        assertTrue(result.isOk)
        assertEquals(1, providerCalls)
        assertEquals(setOf("kty", "crv", "x", "y"), result.value.keys)
        assertEquals(0, fixture.kmsLookups)
    }

    private class Fixture(sourceProvider: Provider<IssuerPublicJwkSource>) {
        var kmsLookups = 0
        val resolver = DefaultIssuerKeyIdResolver(
            kms = proxy<KeyManagerService> { method ->
                check(method == "getKeyResult") { "Unexpected KMS operation: $method" }
                kmsLookups++
                Err(IdkError.fromString(code = "test_key_missing", message = "Test key unavailable"))
            },
            didProviderRegistry = unused<DidProviderRegistry>(),
            didResolverRegistry = unused<DidResolverRegistry>(),
            configService = unused<PrincipalConfigService>(),
            publicJwkSource = sourceProvider,
        )
    }

    companion object {
        private fun provider(source: IssuerPublicJwkSource): Provider<IssuerPublicJwkSource> =
            object : Provider<IssuerPublicJwkSource> {
                override fun invoke(): IssuerPublicJwkSource = source
            }

        private fun source(block: () -> JsonObject?): IssuerPublicJwkSource =
            object : IssuerPublicJwkSource {
                override suspend fun resolvePublicJwk(keyName: String): JsonObject? = block()
            }

        // Models Metro's actual generated default: a non-null Provider whose pointee is null.
        private fun nullPointeeProvider(): Provider<IssuerPublicJwkSource> = proxy { method ->
            check(method == "invoke")
            null
        }

        private inline fun <reified T> unused(): T = proxy { error("Unexpected collaborator call: $it") }

        private inline fun <reified T> proxy(crossinline invoke: (String) -> Any?): T =
            Proxy.newProxyInstance(T::class.java.classLoader, arrayOf(T::class.java)) { _, method, _ ->
                invoke(method.name)
            } as T
    }
}
