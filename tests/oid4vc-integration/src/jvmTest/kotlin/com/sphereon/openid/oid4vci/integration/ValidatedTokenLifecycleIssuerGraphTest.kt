/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.openid.oid4vci.integration

import com.sphereon.core.api.conf.DefaultAppMapPropertySource
import com.sphereon.core.api.conf.DefaultPrincipalMapPropertySource
import com.sphereon.core.api.session.asCoreApiServiceGraph
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig
import com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl
import com.sphereon.di.app.AppGraph
import com.sphereon.di.context.MutableResolvedTenantIdProvider
import com.sphereon.di.session.SessionInstance
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKey
import com.sphereon.oauth2.server.authorization.storage.OAuth2SigningKeyState
import com.sphereon.oauth2.server.authorization.storage.SigningKeyStore
import com.sphereon.openid.oid4vci.issuer.config.MutableOid4vciIssuerInstanceIdProvider
import com.sphereon.openid.oid4vci.issuer.config.Oid4vciIssuerProtocolConfig
import dev.zacsweers.metro.AppScope
import dev.zacsweers.metro.ContributesTo
import kotlin.time.Clock

@dev.zacsweers.metro.DependencyGraph(
    dev.zacsweers.metro.AppScope::class,
    excludes = [
        com.sphereon.openid.oid4vci.issuer.impl.http.HttpAsBridge::class,
        com.sphereon.openid.oid4vci.issuer.impl.lifecycle.NoOpOid4vciIssuanceLifecycleHook::class,
    ],
)
internal abstract class TokenLifecycleTestAppGraph : com.sphereon.di.app.AbstractAppGraph() {
    @dev.zacsweers.metro.Provides
    @dev.zacsweers.metro.SingleIn(dev.zacsweers.metro.AppScope::class)
    fun jwtValidationConfig(): com.sphereon.oauth2.jwt.validation.JwtValidationConfig =
        com.sphereon.oauth2.jwt.validation
            .JwtValidationConfig()

    @dev.zacsweers.metro.Provides
    @dev.zacsweers.metro.SingleIn(dev.zacsweers.metro.AppScope::class)
    fun softwareWscdKeyStoreConfiguration(): com.sphereon.wallet.wscd.SoftwareWscdKeyStoreConfiguration = com.sphereon.wallet.wscd.SoftwareWscdKeyStoreConfiguration.InMemoryForTestingOnly

    @dev.zacsweers.metro.Provides
    fun optionalHook(hook: com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuanceLifecycleHook): com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuanceLifecycleHook? = hook

    @dev.zacsweers.metro.DependencyGraph.Factory
    fun interface Factory {
        fun create(
            @dev.zacsweers.metro.Provides application: Any,
            @dev.zacsweers.metro.Provides @dev.zacsweers.metro.Named("appId") appId: String,
            @dev.zacsweers.metro.Provides @dev.zacsweers.metro.Named("profile") profile: String,
            @dev.zacsweers.metro.Provides @dev.zacsweers.metro.Named("version") version: String,
            @dev.zacsweers.metro.Provides rootScopeProvider: com.sphereon.di.app.RootScopeProvider,
            @dev.zacsweers.metro.Provides hook: com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuanceLifecycleHook,
        ): TokenLifecycleTestAppGraph
    }
}

@ContributesTo(SessionScope::class)
internal interface TokenLifecycleEndpointGraph {
    val handleTokenRequest: com.sphereon.oauth2.server.authorization.command.token.HandleTokenRequestCommand
}

private fun createTokenLifecycleGraph(
    application: Any,
    hook: com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuanceLifecycleHook,
): TokenLifecycleTestAppGraph {
    DefaultPrincipalMapPropertySource.addProperty("database.app.dialect", "in-memory-test")
    val graph =
        dev.zacsweers.metro.createGraphFactory<TokenLifecycleTestAppGraph.Factory>().create(
            application,
            "com.sphereon.oid4vci.token-lifecycle.test",
            "test",
            "test",
            com.sphereon.core.defaults.app
                .DefaultRootScopeProvider(),
            hook,
        )
    graph.initRootScopeProvider()
    return graph
}

private class TokenLifecycleTestContext(
    testInstance: Any,
    lifecycleHook: com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuanceLifecycleHook,
    protocolBasePath: String = "",
    credentialConfigurationIds: List<String> = listOf("UniversityDegree"),
) {
    init {
        // The OID4VCI integration tests run a single hosted AS that issues access tokens for
        // the credential endpoint. The AS's `OAuth2ServersConfigBinder` reads these properties
        // at session-start time, so they have to be in place before the AppGraph touches its
        // session graph. Without them, `CreateAccessTokenCommand` fails with "OAuth2 server has
        // no issuer configured".
        DefaultPrincipalMapPropertySource.addProperty(
            "${com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.CONFIG_PREFIX}.default.issuer",
            OID4VCI_TEST_ISSUER_URL,
        )
        DefaultPrincipalMapPropertySource.addProperty(
            "${com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.CONFIG_PREFIX}.default.mode",
            "HOSTED",
        )
        DefaultPrincipalMapPropertySource.addProperty(
            "${com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.CONFIG_PREFIX}.default.grant-types-enabled",
            "authorization_code,client_credentials,refresh_token,urn:ietf:params:oauth:grant-type:pre-authorized_code",
        )
        configureOid4vciTestInternalClient()
        // The real registry-backed issuer requires an explicitly owned resource namespace.
        val issuerRoot = "oid4vci.issuers.$OID4VCI_TEST_ISSUER_INSTANCE_ID"
        val authorizationServerId = "00000000-0000-4000-8000-000000000002"
        val authorizationServerRoot = "$issuerRoot.authorizationServers.$authorizationServerId"
        val issuerProperties =
            mapOf(
                "oid4vci.routing.issuerResourceId" to OID4VCI_TEST_ISSUER_INSTANCE_ID,
                "$issuerRoot.identifier" to OID4VCI_TEST_ISSUER_URL,
                "$issuerRoot.credentialConfigurationIds" to credentialConfigurationIds.joinToString(","),
                "$issuerRoot.issuerCapabilityId" to "00000000-0000-4000-8000-000000000003",
                "$issuerRoot.authorizationServerIds" to authorizationServerId,
                "$issuerRoot.profile" to "OID4VCI_1_0_FINAL",
                "$issuerRoot.profileRevision" to "7",
                "$authorizationServerRoot.tenantId" to OID4VCI_TEST_TENANT_ID,
                "$authorizationServerRoot.issuerIdentifier" to OID4VCI_TEST_ISSUER_URL,
                "$authorizationServerRoot.enabled" to "true",
                "$authorizationServerRoot.default" to "true",
                "$authorizationServerRoot.lifecycle" to "ACTIVE",
                "$authorizationServerRoot.deployment" to "HOSTED",
                "$authorizationServerRoot.credentialIssuancePurpose" to "true",
                "$authorizationServerRoot.allowedGrants" to "PRE_AUTHORIZED_CODE",
                "$authorizationServerRoot.revision" to "11",
                "$authorizationServerRoot.runtimeServerKey" to "default",
                "$authorizationServerRoot.jwksUri" to "$OID4VCI_TEST_ISSUER_URL/.well-known/jwks.json",
                "$authorizationServerRoot.tokenEndpoint" to "$OID4VCI_TEST_ISSUER_URL/token",
                "$authorizationServerRoot.discoveryCurrent" to "true",
                "$authorizationServerRoot.bindingRevision" to "13",
                "$issuerRoot.credentials.[UniversityDegree].format" to "jwt_vc_json",
                "$issuerRoot.credentials.[UniversityDegree].scope" to "degree",
                "$issuerRoot.credentials.[UniversityDegree].bindingMethods" to "did:key,did:jwk,jwk",
                "$issuerRoot.credentials.[UniversityDegree].signingAlgorithms" to "ES256",
                "$issuerRoot.credentials.[UniversityDegree].proofTypes.jwt.signingAlgorithms" to "ES256",
                "$issuerRoot.credentials.[UniversityDegree].signingKeyMode" to "jwk-thumbprint",
                "$issuerRoot.credentials.[UniversityDegree].credentialDefinition.types" to "VerifiableCredential,UniversityDegreeCredential",
            )
        issuerProperties.forEach { (key, value) -> DefaultPrincipalMapPropertySource.addProperty(key, value) }
        // Credential requests execute against the app-scoped configuration. Keep the integration
        // issuer explicit about its ordinary business-authorization decision; production remains
        // fail-closed when this policy is not configured.
        DefaultAppMapPropertySource.addProperty(
            "oid4vci.business-authorization.mode",
            "ordinary",
        )
        DefaultAppMapPropertySource.addProperty(
            Oid4vciIssuerProtocolConfig.BASE_PATH_KEY,
            Oid4vciIssuerProtocolConfig.normalizeBasePath(protocolBasePath),
        )
    }

    val app: AppGraph = createTokenLifecycleGraph(testInstance, lifecycleHook)
    val context =
        app.userContextManager.createOrGet(
            tenantAware =
                object : com.sphereon.di.context.TenantAware {
                    override val tenant =
                        object : com.sphereon.di.context.TenantContextData {
                            override val tenantId = OID4VCI_TEST_TENANT_ID
                        }
                },
            principalAware =
                object : com.sphereon.di.context.PrincipalAware {
                    override val principal = "oid4vci-integration-test-user"
                },
            principalType = com.sphereon.di.context.PrincipalType.USER,
            makeActive = false,
        )
    val session: SessionInstance = context.sessionContextManager.createOrGetFromId("oid4vci-e2e-test", principalType = com.sphereon.di.context.PrincipalType.USER)
    val execution = session.asCoreApiServiceGraph().serviceExecution
    val signingKeyStore: SigningKeyStore = (app as Oid4vciSigningKeyStoreGraph).signingKeyStore

    init {
        (session.graph as Oid4vciTenantOverrideSessionGraph).mutableResolvedTenantIdProvider.setCurrentTenantId(OID4VCI_TEST_TENANT_ID)
        (session.graph as Oid4vciTenantOverrideSessionGraph).mutableOAuth2ServerInstanceIdProvider.setCurrentAsInstanceId("default")
        (session.graph as Oid4vciIssuerInstanceOverrideSessionGraph)
            .mutableOid4vciIssuerInstanceIdProvider
            .setCurrentInstanceId(OID4VCI_TEST_ISSUER_INSTANCE_ID)

        // Register software KMS provider for crypto operations in tests
        val config = SoftwareKmsProviderConfig(id = "oid4vci-test-kms")
        val factory = (app as SoftwareKmsProviderFactoryImpl.Graph).softwareKmsProvider
        val provider = factory.create(config, execution)
        val kms = session.graph.asKeyManagerServiceGraph().keyManagerService
        kms.registerProvider(provider, makeDefaultKms = true)
    }

    /**
     * Generate the AS signing key in KMS and register it with the [SigningKeyStore] so the
     * AS sign paths (`CreateAccessTokenCommand`, `CreateIdTokenCommand`) and `GetJwksCommand`
     * resolve the same active key. Returns the alias.
     */
    suspend fun ensureAsSigningKey(
        alias: String = OID4VCI_TEST_AS_SIGNING_KEY_ALIAS,
        alg: SignatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
        tenantId: String = OID4VCI_TEST_TENANT_ID,
    ): String {
        val kms = session.graph.asKeyManagerServiceGraph().keyManagerService
        val gen =
            kms.generateKeyResult(
                alias = alias,
                use = com.sphereon.crypto.core.jose.JwkUse.sig,
                alg = alg,
            )
        check(gen.isOk) { "AS signing key generation failed: ${if (gen.isErr) gen.error.message.defaultMessage else "<unknown>"}" }
        val keyPair = checkNotNull(gen.value.keyPair) { "generateKeyResult succeeded but keyPair is null" }
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
        check(register.isOk) { "Failed to register AS signing key: ${if (register.isErr) register.error else "<unknown>"}" }
        return alias
    }

    suspend fun registerIssuerSigningKey(
        keyName: String,
        issuerInstanceId: String = OID4VCI_TEST_ISSUER_INSTANCE_ID,
        tenantId: String = OID4VCI_TEST_TENANT_ID,
    ) {
        (app as Oid4vciTestIssuerKeyNameRegistryGraph)
            .oid4vciTestIssuerKeyNameRegistry
            .register(
                tenantId = tenantId,
                issuerInstanceId = issuerInstanceId,
                keyName = keyName,
            )
    }
}

private open class LegacyTokenLifecycleRecorder : com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuanceLifecycleHook {
    val phases = mutableListOf<com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciPhaseLifecycleArgs>()

    override suspend fun initializeOffer(args: com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciOfferLifecycleArgs) =
        com.sphereon.core.api
            .Ok(
                com.sphereon.openid.oid4vci.issuer.lifecycle
                    .Oid4vciOfferLifecycleResult(correlationId = "trusted-lifecycle-correlation")
            )

    override suspend fun recordPhase(
        args: com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciPhaseLifecycleArgs
    ): com.sphereon.core.api.IdkResult<com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciPhaseLifecycleResult, com.sphereon.core.api.error.IdkError> {
        phases += args
        return com.sphereon.core.api
            .Ok(
                com.sphereon.openid.oid4vci.issuer.lifecycle
                    .Oid4vciPhaseLifecycleResult()
            )
    }
}

private class TypedTokenLifecycleRecorder :
    LegacyTokenLifecycleRecorder(),
    com.sphereon.openid.oid4vci.issuer.lifecycle.ValidatedTokenOid4vciIssuanceLifecycleHook {
    val tokens = mutableListOf<com.sphereon.openid.oid4vci.issuer.bridge.ValidatedTokenContext>()

    override suspend fun recordValidatedTokenPhase(
        args: com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciPhaseLifecycleArgs,
        tokenContext: com.sphereon.openid.oid4vci.issuer.bridge.ValidatedTokenContext,
    ): com.sphereon.core.api.IdkResult<com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciPhaseLifecycleResult, com.sphereon.core.api.error.IdkError> {
        tokens += tokenContext
        return com.sphereon.core.api
            .Ok(
                com.sphereon.openid.oid4vci.issuer.lifecycle
                    .Oid4vciPhaseLifecycleResult()
            )
    }
}

class ValidatedTokenLifecycleIssuerGraphTest {
    @kotlin.test.Test
    fun typedLifecycleReceivesRealValidatedIssuerTokenAndInvalidTokenHasNoHandoff() =
        kotlinx.coroutines.test.runTest {
            exerciseIssuer(TypedTokenLifecycleRecorder())
        }

    @kotlin.test.Test
    fun legacyLifecycleKeepsExistingTokenPhaseAndInvalidTokenHasNoHandoff() =
        kotlinx.coroutines.test.runTest {
            exerciseIssuer(LegacyTokenLifecycleRecorder())
        }

    private suspend fun exerciseIssuer(hook: LegacyTokenLifecycleRecorder) {
        val ctx = TokenLifecycleTestContext(this, hook)
        try {
            val selected = ctx.session.graph as WalletIssuanceHttpTestGraph
            val issuer = selected.oid4vciIssuerService
            val offer =
                issuer.createCredentialOffer(
                    com.sphereon.openid.oid4vci.issuer.command.CreateCredentialOfferArgs(
                        instanceId = OID4VCI_TEST_ISSUER_INSTANCE_ID,
                        issuerId = OID4VCI_TEST_ISSUER_URL,
                        credentialConfigurationIds = listOf("UniversityDegree"),
                        preAuthorizedCodeGrant = true,
                        authorizationPolicySnapshot = OID4VCI_TEST_AUTHORIZATION_POLICY_SNAPSHOT,
                    ),
                )
            kotlin.test.assertTrue(offer.isOk, if (offer.isErr) offer.error.message.defaultMessage else "offer")
            val code =
                offer.value.offer.grants!!
                    .preAuthorizedCode!!
                    .preAuthorizedCode
            ctx.ensureAsSigningKey()
            val token =
                (ctx.session.graph as TokenLifecycleEndpointGraph).handleTokenRequest.execute(
                    com.sphereon.oauth2.server.authorization.command.token.HandleTokenRequestArgs(
                        requestBody =
                            mapOf(
                                "grant_type" to listOf("urn:ietf:params:oauth:grant-type:pre-authorized_code"),
                                "pre-authorized_code" to listOf(code),
                                "client_id" to listOf("wallet-e2e"),
                            ),
                        requestHeaders = emptyMap(),
                        httpUrl = "$OID4VCI_TEST_ISSUER_URL/token",
                    ),
                )
            kotlin.test.assertTrue(token.isOk, if (token.isErr) token.error.message.defaultMessage else "token")
            // The real grant handler creates the opaque authorization handle and signs its
            // authorization_details. Keep that returned mapping intact for the issuer request.
            val details = kotlin.test.assertIs<kotlinx.serialization.json.JsonArray>(token.value.authorizationDetails).single()
            val detail = kotlin.test.assertIs<kotlinx.serialization.json.JsonObject>(details)
            kotlin.test.assertEquals(kotlinx.serialization.json.JsonPrimitive("UniversityDegree"), detail["credential_configuration_id"])
            val credentialIdentifier =
                kotlin.test
                    .assertIs<kotlinx.serialization.json.JsonPrimitive>(
                        kotlin.test.assertIs<kotlinx.serialization.json.JsonArray>(detail["credential_identifiers"]).single(),
                    ).content
            val request =
                com.sphereon.openid.oid4vci.common.model.CredentialRequest(
                    credentialIdentifier = credentialIdentifier,
                    format = "jwt_vc_json",
                )
            val invalid =
                issuer.handleCredentialRequest(
                    com.sphereon.openid.oid4vci.issuer.command.HandleCredentialRequestArgs(
                        accessToken = "invalid-token",
                        credentialRequest = request,
                        issuerIdentifier = OID4VCI_TEST_ISSUER_URL,
                    ),
                )
            kotlin.test.assertTrue(invalid.isErr)
            kotlin.test.assertTrue(hook.phases.none { it.phase == com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuancePhase.TOKEN })
            if (hook is TypedTokenLifecycleRecorder) kotlin.test.assertTrue(hook.tokens.isEmpty())
            // No holder proof is supplied: this test stops at the real validated-token lifecycle,
            // before later proof/format handling. It does not claim credential issuance acceptance.
            val credentialResult =
                issuer.handleCredentialRequest(
                    com.sphereon.openid.oid4vci.issuer.command.HandleCredentialRequestArgs(
                        accessToken = token.value.accessToken,
                        credentialRequest = request,
                        issuerIdentifier = OID4VCI_TEST_ISSUER_URL,
                    ),
                )
            if (hook is TypedTokenLifecycleRecorder) {
                kotlin.test.assertEquals(1, hook.tokens.size, if (credentialResult.isErr) credentialResult.error.message.defaultMessage else "Missing typed TOKEN handoff")
                val actual = hook.tokens.single()
                kotlin.test.assertEquals("wallet-e2e", actual.subject)
                kotlin.test.assertEquals(offer.value.sessionId, actual.issuerState)
                kotlin.test.assertEquals("UniversityDegree", actual.credentialIdentifierMappings[credentialIdentifier])
                kotlin.test.assertEquals("wallet-e2e", actual.clientId)
                kotlin.test.assertTrue(actual.credentialConfigurationIds.contains("UniversityDegree"))
                kotlin.test.assertTrue(hook.phases.none { it.phase == com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuancePhase.TOKEN })
            } else {
                kotlin.test.assertEquals(
                    1,
                    hook.phases.count {
                        it.phase == com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuancePhase.TOKEN
                    },
                    if (credentialResult.isErr) credentialResult.error.message.defaultMessage else "Missing legacy TOKEN handoff"
                )
                val actual = hook.phases.single { it.phase == com.sphereon.openid.oid4vci.issuer.lifecycle.Oid4vciIssuancePhase.TOKEN }
                kotlin.test.assertEquals(kotlinx.serialization.json.JsonPrimitive("wallet-e2e"), actual.fields["oid4vci.subject"])
                kotlin.test.assertEquals("trusted-lifecycle-correlation", actual.correlationId)
            }
        } finally {
            ctx.app.destroy()
        }
    }
}
