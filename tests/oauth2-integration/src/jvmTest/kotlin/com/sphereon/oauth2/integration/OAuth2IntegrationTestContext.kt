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

import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.kms.KeyManagerService
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderImpl
import com.sphereon.di.app.AppGraph
import com.sphereon.di.session.SessionInstance
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.model.ResponseType
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientType
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKey
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKeyState
import com.sphereon.oauth2.server.authorization.storage.SigningKeyStore
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesTo
import kotlin.time.Clock

/**
 * Boots a single app graph carrying the OP (lib-oauth2-server-authorization-impl +
 * services-oauth2-as-rest), the RS (lib-oauth2-server-resource-impl), and the RP
 * (lib-oauth2-client-impl). Registers the software KMS provider and pre-generates the signing
 * key under the alias the `DefaultAsServerSigningIdentifierResolver` advertises (`oauth2-server-signing`), so
 * the OP's sign-token commands resolve a real key without additional config wiring.
 *
 * Lives at `@AppScope`. A single [SessionInstance] is created for the tests — sufficient since
 * the integration scenarios don't exercise per-user partitioning.
 */
class OAuth2IntegrationTestContext(
    testInstance: Any,
    sessionId: String = "oauth2-integration-test",
) {
    val app: AppGraph = createOAuth2IntegrationTestAppGraph(application = testInstance)
    val context = app.userContextManager.getAnonymous()
    val session: SessionInstance = context.sessionContextManager.createOrGetFromId(sessionId, principalType = com.sphereon.di.context.PrincipalType.USER)
    val execution = session.asCoreApiServiceGraph().serviceExecution
    val keyManagerService: KeyManagerService = session.graph.asKeyManagerServiceGraph().keyManagerService
    val signingKeyStore: SigningKeyStore = (app as OAuth2SigningKeyStoreGraph).signingKeyStore

    /**
     * The single software KMS provider shared by all sessions in this test context.
     * Exposed so additional sessions (e.g. per-tenant sessions) can register the same
     * provider instance on their own [KeyManagerService], giving them access to keys
     * already generated through this context's [keyManagerService].
     *
     * All [SoftwareKmsProviderImpl] instances created by the same factory share the
     * AppScope-bound [com.sphereon.crypto.kms.provider.software.KeyStoreManager], so
     * key material is accessible across sessions as long as the provider id matches.
     */
    val kmsProvider: SoftwareKmsProviderImpl

    init {
        (session.graph as TenantOverrideSessionGraph).mutableResolvedTenantIdProvider.setCurrentTenantId(DEFAULT_TENANT_ID)
        // This trusted in-process fixture selects its one configured hosted AS explicitly.
        (session.graph as TenantOverrideSessionGraph).mutableOAuth2ServerInstanceIdProvider.setCurrentAsInstanceId("default")

        val providerConfig = SoftwareKmsProviderConfig(id = "oauth2-integration-kms")
        val providerFactory = (app as SoftwareKmsProviderFactoryImpl.Graph).softwareKmsProvider
        kmsProvider = providerFactory.create(providerConfig, execution)
        keyManagerService.registerProvider(kmsProvider, makeDefaultKms = true)
    }

    /** Registers the RP client through the same session registry used by ID-token minting. */
    suspend fun ensureClientRegistration(clientId: String) {
        val registry = (session.graph as OAuth2ClientRegistryGraph).clientRegistry
        val existing = registry.getClient(clientId)
        check(existing.isOk) { "Failed to read integration client registration" }
        if (existing.value != null) return
        val registered =
            registry.registerClient(
                ClientRegistration(
                    clientId = clientId,
                    clientType = ClientType.PUBLIC,
                    grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
                    responseTypes = listOf(ResponseType.CODE),
                    redirectUris = listOf("https://rp.test/callback"),
                    allowedScopes = listOf("openid", "read"),
                ),
            )
        check(registered.isOk) { "Failed to register integration client" }
    }

    /**
     * Generate (or reuse) the OP signing key under the alias the default config module points
     * at, then register the resulting [KeyInfo] with the [SigningKeyStore] so the AS sign
     * paths (`CreateAccessTokenCommand` / `CreateIdTokenCommand`) and `GetJwksCommand` resolve
     * the same key. Returns the alias so callers can fold it into their `IdTokenValidationOptions`.
     *
     * [keyManagerService] defaults to this context's own (default-tenant) KMS. Pass the
     * tenant session's own [KeyManagerService] when generating keys for a specific tenant
     * session so the key resolves through that session's KMS at signing time.
     */
    suspend fun ensureOpSigningKey(
        alias: String = OP_SIGNING_KEY_ALIAS,
        alg: SignatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
        // Seed under the SESSION's resolved tenant (same resolution the AS now uses for the
        // signing-key lookup + JWKS), so seed and lookup agree. Falls back to DEFAULT_TENANT_ID
        // for a blank session tenant (single-tenant behavior).
        tenantId: String = execution.tenantId.takeIf { it.isNotBlank() } ?: DEFAULT_TENANT_ID,
        keyManagerService: KeyManagerService = this.keyManagerService,
    ): String {
        val result =
            keyManagerService.generateKeyResult(
                alias = alias,
                use = JwkUse.sig,
                alg = alg,
            )
        check(result.isOk) {
            "Failed to generate OP signing key '$alias': ${if (result.isErr) result.error.message.defaultMessage else "<unknown>"}"
        }
        val keyPair = checkNotNull(result.value.keyPair) { "generateKeyResult succeeded but keyPair is null" }
        val now = Clock.System.now()
        val signingKey =
            OAuth2SigningKey(
                tenantId = tenantId,
                keyInfo =
                    KeyInfo<KeyType>(
                        kid = keyPair.kid ?: keyPair.alias,
                        alias = alias,
                        providerId = keyPair.providerId,
                        signatureAlgorithm = alg,
                    ),
                state = OAuth2SigningKeyState.ACTIVE,
                priority = 1,
                createdAt = now,
                notBefore = now,
            )
        val register = signingKeyStore.register(signingKey)
        check(register.isOk) {
            "Failed to register OP signing key in SigningKeyStore: ${if (register.isErr) register.error else "<unknown>"}"
        }
        return alias
    }

    companion object {
        /**
         * Matches `the default AS signing alias`. When we pre-generate a
         * key under this alias before the OP touches it, the lazy `ManagedOptsAlias` resolution
         * inside the token commands finds it at signing time.
         */
        const val OP_SIGNING_KEY_ALIAS = "oauth2-server-signing"

        /**
         * The integration tests run a single-tenant deployment, so all signing keys land under a
         * fixed tenant. Matches the [com.sphereon.ktor.server.inject.resolver.FixedTenantResolver]
         * default the standalone OAuth2 AS Ktor server hands to incoming requests.
         */
        const val DEFAULT_TENANT_ID = "default"
    }
}

/**
 * Graph extension that exposes the AppScope-bound [SigningKeyStore] so the integration
 * tests can register pre-generated keys before the AS sign paths run.
 */
@ContributesTo(AppScope::class)
interface OAuth2SigningKeyStoreGraph {
    val signingKeyStore: SigningKeyStore
}

@ContributesTo(com.sphereon.di.session.SessionScope::class)
interface OAuth2ClientRegistryGraph {
    val clientRegistry: ClientRegistry
}
