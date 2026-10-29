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

package com.sphereon.oauth2.common.config

import com.sphereon.core.api.http.GenericHttpRequest
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DefaultOAuth2ServerInstanceResolverTest {
    private fun request(
        path: String = "/authorize",
        host: String = "as.example.com",
        scheme: String = "https",
    ): GenericHttpRequest =
        GenericHttpRequest(
            method = "GET",
            path = path,
            headers =
                mapOf(
                    "Host" to host,
                    "X-Forwarded-Proto" to scheme,
                ),
        )

    private fun providerOf(config: OAuth2ServersConfig): OAuth2ServersConfigProvider =
        object : OAuth2ServersConfigProvider {
            override fun getConfig(): OAuth2ServersConfig = config

            override fun getServer(id: String): OAuth2ServerInstanceConfig? = config.getServer(id)

            override fun getDefaultServer(): OAuth2ServerInstanceConfig = config.getDefaultServer()

            override fun resolveIssuer(
                serverId: String,
                tenantId: String,
            ): String =
                config.getServer(serverId)?.let { server ->
                    server.issuer
                        ?: server.issuerTemplate?.replace("{tenant-id}", tenantId)
                        ?: error("server '$serverId' has no issuer or issuerTemplate")
                } ?: error("server '$serverId' not found")
        }

    @Test
    fun singleAsReturnsThatIdRegardlessOfRequestUrl() =
        runTest {
            val provider =
                providerOf(
                    OAuth2ServersConfig(
                        defaultServer = "only",
                        servers =
                            mapOf(
                                "only" to OAuth2ServerInstanceConfig(issuer = "https://unrelated.example.com"),
                            ),
                    ),
                )
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            val result = resolver.resolve(request(host = "totally-different.example.com"))

            assertTrue(result.isOk)
            assertEquals("only", result.value)
        }

    @Test
    fun wellKnownMetadataRequestsSelectTheIssuerNamedAfterTheWellKnownSegment() =
        runTest {
            val provider =
                providerOf(
                    OAuth2ServersConfig(
                        defaultServer = "acme",
                        servers =
                            mapOf(
                                "acme" to OAuth2ServerInstanceConfig(issuer = "https://acme.example.com/as/acme"),
                                "wallet-proxy" to OAuth2ServerInstanceConfig(issuer = "https://acme.example.com/as/wallet-proxy"),
                            ),
                    ),
                )
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            for (wellKnown in listOf("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration")) {
                val result = resolver.resolve(request(path = "$wellKnown/as/wallet-proxy", host = "acme.example.com"))
                assertTrue(result.isOk)
                assertEquals("wallet-proxy", result.value, "$wellKnown must select the issuer after the well-known name")
            }
        }

    @Test
    fun multiAsMatchesByIssuerPrefix() =
        runTest {
            val provider =
                providerOf(
                    OAuth2ServersConfig(
                        defaultServer = "primary",
                        servers =
                            mapOf(
                                "primary" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://primary.example.com",
                                    ),
                                "secondary" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://secondary.example.com",
                                    ),
                            ),
                    ),
                )
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            val result = resolver.resolve(request(host = "secondary.example.com", path = "/authorize"))

            assertTrue(result.isOk)
            assertEquals("secondary", result.value)
        }

    @Test
    fun multiAsMatchesByIssuerTemplateAfterSubstitution() =
        runTest {
            val provider =
                providerOf(
                    OAuth2ServersConfig(
                        defaultServer = "tenanted",
                        servers =
                            mapOf(
                                "tenanted" to
                                    OAuth2ServerInstanceConfig(
                                        issuerTemplate = "https://{host}/auth/{tenant-id}",
                                    ),
                                "other" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://other.example.com",
                                    ),
                            ),
                    ),
                )
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            val result =
                resolver.resolve(
                    request(host = "auth.example.com", path = "/auth/tenant42/.well-known/openid-configuration"),
                )

            assertTrue(result.isOk)
            assertEquals("tenanted", result.value)
        }

    @Test
    fun multiAsFallsBackToDefaultServerWhenNothingMatches() =
        runTest {
            val provider =
                providerOf(
                    OAuth2ServersConfig(
                        defaultServer = "primary",
                        servers =
                            mapOf(
                                "primary" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://primary.example.com",
                                    ),
                                "secondary" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://secondary.example.com",
                                    ),
                            ),
                    ),
                )
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            val result = resolver.resolve(request(host = "totally-unrelated.example.com"))

            assertTrue(result.isOk)
            assertEquals("primary", result.value)
        }

    @Test
    fun multiAsErrorsWhenNoMatchAndDefaultIsNotInServersMap() =
        runTest {
            val provider =
                providerOf(
                    OAuth2ServersConfig(
                        defaultServer = "missing",
                        servers =
                            mapOf(
                                "primary" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://primary.example.com",
                                    ),
                                "secondary" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://secondary.example.com",
                                    ),
                            ),
                    ),
                )
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            val result = resolver.resolve(request(host = "totally-unrelated.example.com"))

            assertTrue(result.isErr)
            assertEquals("INVALID_STATE", result.error.code)
            assertTrue(
                result.error.message.defaultMessage
                    .contains("totally-unrelated.example.com"),
                "error should mention the request URL",
            )
            assertTrue(
                result.error.message.defaultMessage
                    .contains("primary") &&
                    result.error.message.defaultMessage
                        .contains("secondary"),
                "error should mention configured server ids",
            )
        }

    @Test
    fun serverCreatedAfterTheSnapshotIsResolvedAfterAReload() =
        runTest {
            val provider =
                SnapshotProvider(
                    snapshot = tenantServers("globex"),
                    backingStore = tenantServers("globex", "wallet-proxy"),
                )
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            val result = resolver.resolve(request(path = "/as/wallet-proxy/authorize", host = "globex.example.com"))

            assertTrue(result.isOk)
            assertEquals("wallet-proxy", result.value)
            assertEquals(1, provider.reloads)
        }

    @Test
    fun wellKnownRequestForAServerCreatedAfterTheSnapshotIsResolvedAfterAReload() =
        runTest {
            val provider =
                SnapshotProvider(
                    snapshot = tenantServers("globex", "other"),
                    backingStore = tenantServers("globex", "other", "wallet-proxy"),
                )
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            val result =
                resolver.resolve(
                    request(path = "/.well-known/oauth-authorization-server/as/wallet-proxy", host = "globex.example.com"),
                )

            assertTrue(result.isOk)
            assertEquals("wallet-proxy", result.value)
            assertEquals(1, provider.reloads)
        }

    @Test
    fun unknownSiblingIssuerIsNotFoundAfterOneReload() =
        runTest {
            val provider = SnapshotProvider(snapshot = tenantServers("globex", "other"), backingStore = tenantServers("globex", "other"))
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            val result = resolver.resolve(request(path = "/as/never-created/authorize", host = "globex.example.com"))

            assertTrue(result.isErr)
            assertEquals("NOT_FOUND_ERROR", result.error.code)
            assertEquals(1, provider.reloads)
        }

    @Test
    fun unknownSiblingIssuerIsNotFoundEvenWithASingleConfiguredServer() =
        runTest {
            val provider = SnapshotProvider(snapshot = tenantServers("globex"), backingStore = tenantServers("globex"))
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            val authorize = resolver.resolve(request(path = "/as/never-created/authorize", host = "globex.example.com"))
            val wellKnown =
                resolver.resolve(
                    request(path = "/.well-known/oauth-authorization-server/as/never-created", host = "globex.example.com"),
                )

            assertEquals("NOT_FOUND_ERROR", authorize.error.code)
            assertEquals("NOT_FOUND_ERROR", wellKnown.error.code)
        }

    @Test
    fun issuerPrefixOfAnotherSlugDoesNotMatchIt() =
        runTest {
            val provider = SnapshotProvider(snapshot = tenantServers("globex", "other"), backingStore = tenantServers("globex", "other"))
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            val collision = resolver.resolve(request(path = "/as/globex2/authorize", host = "globex.example.com"))
            val exact = resolver.resolve(request(path = "/as/globex", host = "globex.example.com"))
            val nested = resolver.resolve(request(path = "/as/globex/authorize", host = "globex.example.com"))

            assertEquals("NOT_FOUND_ERROR", collision.error.code)
            assertEquals("globex", exact.value)
            assertEquals("globex", nested.value)
        }

    @Test
    fun issuerPrefixOfAConfiguredSlugResolvesToThatSlug() =
        runTest {
            val provider =
                SnapshotProvider(snapshot = tenantServers("globex", "globex2"), backingStore = tenantServers("globex", "globex2"))
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            val result = resolver.resolve(request(path = "/as/globex2/token", host = "globex.example.com"))

            assertEquals("globex2", result.value)
            assertEquals(0, provider.reloads)
        }

    @Test
    fun requestsOutsideTheIssuerPathsNeverReload() =
        runTest {
            val provider = SnapshotProvider(snapshot = tenantServers("globex", "other"), backingStore = tenantServers("globex", "other"))
            val resolver = DefaultOAuth2ServerInstanceResolver(provider)

            val token = resolver.resolve(request(path = "/token", host = "globex.example.com"))
            val authorize = resolver.resolve(request(path = "/authorize", host = "globex.example.com"))
            val discovery = resolver.resolve(request(path = "/.well-known/openid-configuration", host = "globex.example.com"))
            val metadata = resolver.resolve(request(path = "/.well-known/oauth-authorization-server", host = "globex.example.com"))
            val known = resolver.resolve(request(path = "/as/other/token", host = "globex.example.com"))

            assertEquals("globex", token.value)
            assertEquals("globex", authorize.value)
            assertEquals("globex", discovery.value)
            assertEquals("globex", metadata.value)
            assertEquals("other", known.value)
            assertEquals(0, provider.reloads)
        }

    @Test
    fun wellKnownSuffixNamingNoIssuerIsNotFoundInsteadOfTheDefaultServer() =
        runTest {
            val resolver = DefaultOAuth2ServerInstanceResolver(providerOf(tenantServers("operator")))

            for (path in listOf(
                "/.well-known/oauth-authorization-server/zzz",
                "/.well-known/openid-configuration/zzz",
                "/.well-known/oauth-authorization-server/as",
                "/zzz/.well-known/openid-configuration",
            )) {
                val result = resolver.resolve(request(path = path, host = "globex.example.com"))
                assertTrue(result.isErr, "$path names no hosted issuer, got ${if (result.isOk) result.value else null}")
                assertEquals("NOT_FOUND_ERROR", result.error.code, path)
            }
            val own = resolver.resolve(request(path = "/.well-known/openid-configuration/as/operator", host = "globex.example.com"))
            assertEquals("operator", own.value)
        }

    /**
     * The platform tenant always hosts its authorization server at the bare origin. That server
     * answers its own bare URLs, but a URL naming another issuer path is not its URL.
     */
    @Test
    fun bareOriginServerAnswersOnlyItsOwnUrls() =
        runTest {
            val resolver =
                DefaultOAuth2ServerInstanceResolver(
                    providerOf(
                        OAuth2ServersConfig(
                            defaultServer = "platform",
                            servers = mapOf("platform" to OAuth2ServerInstanceConfig(issuer = "https://platform.example.com")),
                        ),
                    ),
                )

            for (path in listOf("/token", "/authorize", "/par", "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration")) {
                val result = resolver.resolve(request(path = path, host = "platform.example.com"))
                assertEquals("platform", result.value, path)
            }
            for (path in listOf(
                "/as/does-not-exist/token",
                "/as/does-not-exist/authorize",
                "/.well-known/oauth-authorization-server/as/does-not-exist",
                "/.well-known/openid-configuration/zzz",
                "/as/does-not-exist/.well-known/openid-configuration",
            )) {
                val result = resolver.resolve(request(path = path, host = "platform.example.com"))
                assertTrue(result.isErr, "$path must not reach the bare-origin server, got ${if (result.isOk) result.value else null}")
                assertEquals("NOT_FOUND_ERROR", result.error.code, path)
            }
        }

    @Test
    fun namedIssuerPathSelectsItsServerWhenCalledThroughAnotherHost() =
        runTest {
            // East-west calls carry the platform host while naming the tenant issuer path.
            val resolver = DefaultOAuth2ServerInstanceResolver(providerOf(tenantServers("acme", "wallet-proxy")))

            assertEquals("acme", resolver.resolve(request(path = "/as/acme/token", host = "platform.example.com")).value)
            assertEquals(
                "wallet-proxy",
                resolver.resolve(request(path = "/.well-known/oauth-authorization-server/as/wallet-proxy", host = "platform.example.com")).value,
            )
        }

    private fun tenantServers(vararg slugs: String): OAuth2ServersConfig =
        OAuth2ServersConfig(
            defaultServer = slugs.first(),
            servers = slugs.associateWith { OAuth2ServerInstanceConfig(issuer = "https://globex.example.com/as/$it") },
        )

    private class SnapshotProvider(
        snapshot: OAuth2ServersConfig,
        private val backingStore: OAuth2ServersConfig,
    ) : OAuth2ServersConfigProvider {
        private var current: OAuth2ServersConfig = snapshot
        var reloads = 0
            private set

        override fun getConfig(): OAuth2ServersConfig = current

        override suspend fun reloadConfig(): OAuth2ServersConfig {
            reloads++
            current = backingStore
            return current
        }

        override fun getServer(id: String): OAuth2ServerInstanceConfig? = current.getServer(id)

        override fun getDefaultServer(): OAuth2ServerInstanceConfig = current.getDefaultServer()

        override fun resolveIssuer(
            serverId: String,
            tenantId: String,
        ): String = current.getServer(serverId)?.issuer ?: error("server '$serverId' not found")
    }
}
