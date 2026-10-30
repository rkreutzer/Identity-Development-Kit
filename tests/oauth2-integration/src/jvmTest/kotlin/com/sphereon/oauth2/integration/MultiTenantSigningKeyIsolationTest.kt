/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.oauth2.integration

import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.di.context.MutableResolvedTenantIdProvider
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.MutableOAuth2ServerInstanceIdProvider
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenCommand
import com.sphereon.oauth2.server.authorization.command.GetJwksArgs
import com.sphereon.oauth2.server.authorization.command.GetJwksCommand
import dev.zacsweers.metro.ContributesTo
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Session-graph accessor that exposes the per-session [MutableResolvedTenantIdProvider] so
 * tests can override the tenant for a given session without going through HTTP path-peeling.
 * This is the test-only substitute for the HTTP dispatcher's peel loop; it is intentionally
 * narrow (tests only, single session at a time).
 */
@ContributesTo(SessionScope::class)
interface TenantOverrideSessionGraph {
    val mutableResolvedTenantIdProvider: MutableResolvedTenantIdProvider
    val mutableOAuth2ServerInstanceIdProvider: MutableOAuth2ServerInstanceIdProvider
}

/**
 * Proves the full Phase-1 multi-tenant AS outcome:
 *
 *  1. Two tenants ("acme" and "beta") can each have an ACTIVE signing key registered in the
 *     [com.sphereon.oauth2.server.authorization.storage.SigningKeyStore].
 *  2. The AS sign path (CreateAccessTokenCommand) produces a three-segment JWT (not an opaque
 *     string) when `tokenFormat = JWT`.
 *  3. The issued JWT carries the signing key's `kid` in its header, which matches a key in
 *     GetJwksCommand's response for that tenant.
 *  4. Tenant isolation is hard: the kid published in the acme JWKS is absent from the beta
 *     JWKS and vice versa — proving DefaultAsServerSigningIdentifierResolver.resolveSigningIdentifier
 *     and GetJwksCommandImpl both resolve per-tenant from the store rather than from a shared
 *     global.
 *
 * Uses the [InMemorySigningKeyStore] (no TestContainers / Docker required). The store is
 * [AppScope]-bound, so both tenant namespaces live in the same instance and the test is
 * entirely in-process.
 *
 * The [MutableResolvedTenantIdProvider] is set on each tenant session before executing
 * commands and cleared afterwards, mirroring the HTTP dispatcher's peel-loop idiom.
 */
class MultiTenantSigningKeyIsolationTest {
    private val ctx = OAuth2IntegrationTestContext(this)
    private val json = Json { ignoreUnknownKeys = true }

    // Two distinct tenant IDs under test.
    private val acmeTenantId = "acme"
    private val betaTenantId = "beta"

    // Separate sessions so each gets its own [DefaultAsServerSigningIdentifierResolver] DI graph binding
    // (the serverIdentifier @Provides is @SingleIn(SessionScope)) and its own
    // [MutableResolvedTenantIdProvider] override slot.
    private val acmeSession =
        ctx.app.userContextManager
            .getAnonymous()
            .sessionContextManager
            .createOrGetFromId("acme-session", principalType = com.sphereon.di.context.PrincipalType.USER)
    private val betaSession =
        ctx.app.userContextManager
            .getAnonymous()
            .sessionContextManager
            .createOrGetFromId("beta-session", principalType = com.sphereon.di.context.PrincipalType.USER)

    // Each session has its own SessionScope-bound KeyManagerService. Register the same
    // SoftwareKmsProvider instance on each so they share the AppScope-bound KeyStoreManager
    // — keys generated on one session are accessible when signing from another session.
    private val acmeKeyManager: KeyManagerService =
        acmeSession.graph
            .asKeyManagerServiceGraph()
            .keyManagerService
            .also { it.registerProvider(ctx.kmsProvider, makeDefaultKms = true) }
    private val betaKeyManager: KeyManagerService =
        betaSession.graph
            .asKeyManagerServiceGraph()
            .keyManagerService
            .also { it.registerProvider(ctx.kmsProvider, makeDefaultKms = true) }

    private val acmeGraph = acmeSession.graph as TenantOverrideSessionGraph
    private val betaGraph = betaSession.graph as TenantOverrideSessionGraph

    private val acmeCommandGraph = acmeSession.graph as OAuth2IntegrationSessionGraph
    private val betaCommandGraph = betaSession.graph as OAuth2IntegrationSessionGraph

    /**
     * Bootstrap both tenants: generate a distinct KMS signing key for each using that tenant
     * session's own [KeyManagerService], register them in the SigningKeyStore under the
     * respective tenantId, then set the MutableResolvedTenantIdProvider so the AS @Provides
     * block and GetJwksCommandImpl both see the correct tenantId when they call
     * signingKeyStore.getActive(tenantId).
     *
     * The key aliases are intentionally different ("acme-as-key" vs "beta-as-key") — the test
     * asserts that the acme JWKS publishes the acme kid and the beta JWKS publishes a DIFFERENT
     * kid, proving per-tenant isolation.
     */
    @Test
    fun each_tenant_jwt_is_signed_by_tenant_specific_key_with_isolation() =
        runTest {
            // ── Bootstrap acme ────────────────────────────────────────────────────────
            // Use acmeKeyManager so key generation goes through the acme session's KMS,
            // which shares the AppScope KeyStoreManager via ctx.kmsProvider.
            val acmeAlias = "acme-as-key"
            ctx.ensureOpSigningKey(alias = acmeAlias, tenantId = acmeTenantId, keyManagerService = acmeKeyManager)

            // ── Bootstrap beta ────────────────────────────────────────────────────────
            val betaAlias = "beta-as-key"
            ctx.ensureOpSigningKey(alias = betaAlias, tenantId = betaTenantId, keyManagerService = betaKeyManager)

            // ── Mint tokens for each tenant ────────────────────────────────────────────
            val acmeJwt = mintAccessToken(acmeTenantId, acmeGraph, acmeCommandGraph)
            val betaJwt = mintAccessToken(betaTenantId, betaGraph, betaCommandGraph)

            // ── Assert JWT structure (3 dot-separated Base64URL segments) ─────────────
            assertIsJwt(acmeJwt, "acme")
            assertIsJwt(betaJwt, "beta")

            // ── Extract kid from each token header ────────────────────────────────────
            val acmeKid = jwtHeaderKid(acmeJwt)
            val betaKid = jwtHeaderKid(betaJwt)
            assertNotNull(acmeKid, "acme JWT header must carry a kid")
            assertNotNull(betaKid, "beta JWT header must carry a kid")

            // ── Assert per-tenant key isolation: kids must differ ─────────────────────
            assertNotEquals(
                acmeKid,
                betaKid,
                "acme and beta JWTs must be signed by DIFFERENT keys; both got kid='$acmeKid'",
            )

            // ── JWKS for each tenant must publish its own kid ─────────────────────────
            val acmeJwks = fetchJwks(acmeTenantId, acmeGraph, acmeCommandGraph)
            val betaJwks = fetchJwks(betaTenantId, betaGraph, betaCommandGraph)

            val acmePublishedKids = acmeJwks.map { it["kid"]?.jsonPrimitive?.content }
            val betaPublishedKids = betaJwks.map { it["kid"]?.jsonPrimitive?.content }

            assertTrue(
                acmeKid in acmePublishedKids,
                "acme JWKS must publish the kid='$acmeKid' used to sign the acme JWT; published=$acmePublishedKids",
            )
            assertTrue(
                betaKid in betaPublishedKids,
                "beta JWKS must publish the kid='$betaKid' used to sign the beta JWT; published=$betaPublishedKids",
            )

            // ── Cross-tenant absence check: acme kid absent from beta JWKS and vice versa ──
            assertTrue(
                acmeKid !in betaPublishedKids,
                "beta JWKS must NOT publish acme's kid='$acmeKid'; published=$betaPublishedKids",
            )
            assertTrue(
                betaKid !in acmePublishedKids,
                "acme JWKS must NOT publish beta's kid='$betaKid'; published=$acmePublishedKids",
            )
        }

    /**
     * Mints an access token in a session scoped to [tenantId]. The
     * [MutableResolvedTenantIdProvider] is set before the command executes and cleared
     * afterwards to prevent tenant-id leakage between assertions.
     */
    private suspend fun mintAccessToken(
        tenantId: String,
        tenantOverrideGraph: TenantOverrideSessionGraph,
        commandGraph: OAuth2IntegrationSessionGraph,
    ): String {
        tenantOverrideGraph.mutableResolvedTenantIdProvider.setCurrentTenantId(tenantId)
        tenantOverrideGraph.mutableOAuth2ServerInstanceIdProvider.setCurrentAsInstanceId("default")
        return try {
            val result =
                commandGraph.createAccessTokenCommand.execute(
                    CreateAccessTokenArgs(
                        subject = "user-$tenantId",
                        clientId = "client-$tenantId",
                        scope = "read",
                        audience = listOf("https://api.test/resource"),
                    ),
                )
            assertTrue(
                result.isOk,
                "CreateAccessTokenCommand must succeed for tenant '$tenantId': " +
                    if (result.isErr) result.error.message.defaultMessage else "",
            )
            result.value.value
        } finally {
            tenantOverrideGraph.mutableOAuth2ServerInstanceIdProvider.clearCurrentAsInstanceId()
            tenantOverrideGraph.mutableResolvedTenantIdProvider.clearCurrentTenantId()
        }
    }

    /**
     * Fetches the JWKS entries for [tenantId] as a list of [JsonObject] (one per key). The
     * [MutableResolvedTenantIdProvider] is set/cleared around the call so
     * GetJwksCommandImpl.executeInternal() sees the correct tenantId.
     */
    private suspend fun fetchJwks(
        tenantId: String,
        tenantOverrideGraph: TenantOverrideSessionGraph,
        commandGraph: OAuth2IntegrationSessionGraph,
    ): List<JsonObject> {
        tenantOverrideGraph.mutableResolvedTenantIdProvider.setCurrentTenantId(tenantId)
        tenantOverrideGraph.mutableOAuth2ServerInstanceIdProvider.setCurrentAsInstanceId("default")
        return try {
            val result = commandGraph.getJwksCommand.execute(GetJwksArgs())
            assertTrue(result.isOk, "GetJwksCommand must succeed for tenant '$tenantId'")
            result.value.keys.map { jwk ->
                // Serialise the Jwk back to JsonObject so we can assert on fields uniformly.
                val serialised =
                    kotlinx.serialization.json.Json.encodeToString(
                        com.sphereon.crypto.core.jose.Jwk
                            .serializer(),
                        jwk,
                    )
                json.parseToJsonElement(serialised) as JsonObject
            }
        } finally {
            tenantOverrideGraph.mutableOAuth2ServerInstanceIdProvider.clearCurrentAsInstanceId()
            tenantOverrideGraph.mutableResolvedTenantIdProvider.clearCurrentTenantId()
        }
    }

    // ─── assertion helpers ────────────────────────────────────────────────────────────────

    private fun assertIsJwt(
        token: String,
        label: String
    ) {
        val parts = token.split(".")
        assertEquals(
            3,
            parts.size,
            "$label token must be a JWT (3 dot-separated Base64URL segments); got '${token.take(80)}...'",
        )
        parts.forEach { part ->
            assertTrue(
                part.isNotBlank(),
                "$label JWT segment must be non-blank; got '$part'",
            )
        }
    }

    private fun jwtHeaderKid(jwt: String): String? {
        val headerB64 = jwt.substringBefore('.')
        val padded =
            when (headerB64.length % 4) {
                0 -> headerB64
                2 -> "$headerB64=="
                3 -> "$headerB64="
                else -> headerB64
            }
        val headerBytes =
            java.util.Base64
                .getUrlDecoder()
                .decode(padded)
        val headerJson = json.parseToJsonElement(headerBytes.decodeToString()) as JsonObject
        return headerJson["kid"]?.jsonPrimitive?.content
    }
}
