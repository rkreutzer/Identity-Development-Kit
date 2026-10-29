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

package com.sphereon.oauth2.server.authorization.impl.config

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.AppConfigService
import com.sphereon.core.api.conf.ConfigLevel
import com.sphereon.core.api.conf.ConfigService
import com.sphereon.core.api.conf.DefaultPropertySources
import com.sphereon.core.api.conf.PrincipalConfigService
import com.sphereon.core.api.conf.MutableMapPropertySource
import com.sphereon.core.api.conf.ProtectedMutableMapPropertySource
import com.sphereon.core.api.conf.RefreshablePropertySource
import com.sphereon.core.api.conf.PropertyKeyNormalizerImpl
import com.sphereon.core.api.conf.PropertySource
import com.sphereon.core.api.conf.PropertySources
import com.sphereon.core.api.conf.TenantConfigService
import com.sphereon.core.api.context.ContextConfig
import com.sphereon.core.api.context.IdkScope
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.log.AsyncLogService
import com.sphereon.core.api.log.LogMessage
import com.sphereon.core.api.log.LogService
import com.sphereon.core.api.log.LoggerConfig
import com.sphereon.core.api.log.SessionLogManager
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.di.context.NoOpSessionContext
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionContextManager
import com.sphereon.oauth2.common.config.AuthorizationServerMode
import com.sphereon.oauth2.common.config.FeaturePolicy
import com.sphereon.oauth2.common.config.InternalClientConfig
import com.sphereon.oauth2.common.config.LoginInteraction
import com.sphereon.oauth2.common.config.LoginMethod
import com.sphereon.oauth2.common.config.LoginRenderer
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceIdProvider
import com.sphereon.oauth2.common.config.SessionConfig
import com.sphereon.oauth2.common.config.TokenFormat
import kotlinx.io.files.Path
import kotlin.reflect.KClass
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotSame
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Structural regression guard for the [OAuth2ServersConfigBinder].
 *
 * Builds a synthetic property map that assigns a sentinel value to every configurable field on
 * [OAuth2ServerInstanceConfig], drives it through the binder, and asserts the resulting config
 * carries every sentinel back. A field added to the data class without a matching read in the
 * binder leaks the default value, which fails the corresponding assertion below.
 *
 * The sentinel space is deliberately picked so a swapped-key bug (binder reads field A using key
 * B's path) shows up as a value mismatch rather than two passing reads:
 *  - every [FeaturePolicy] field is set to [FeaturePolicy.REQUIRED] (distinct from the data
 *    class defaults of `DISABLED` / `SUPPORTED`), with the read-key encoded into the value path;
 *  - every [Boolean] field is flipped from its default;
 *  - every numeric (Int/Long) field gets a per-field unique value (e.g. 9000001, 9000002, ...)
 *    so swaps surface;
 *  - every nullable [String?] / `Set<String>?` / `List<String>?` field gets a value that includes
 *    the canonical config key, so the test can assert the binder consumed the right key.
 *
 * The assertion list is explicit (not reflection-driven) because a few fields are computed from
 * sub-objects ([SessionConfig], `internalClients`) that need their own
 * key paths. When a field is added to [OAuth2ServerInstanceConfig], add the sentinel here AND
 * the assertion AND the binder read in [OAuth2ServersConfigBinder.loadServerConfig]. The "add it
 * here" step is a deliberate friction point so the binder side never gets forgotten.
 */
class OAuth2ServersConfigBinderRoundTripTest {
    @Test
    fun federationAutomaticRegistrationModeUsesNormalPerServerConfiguration() {
        val root = OAuth2ServerInstanceConfig.CONFIG_PREFIX
        val config = TypeAwarePrincipalConfigService(mapOf(
            "$root.default-server" to "primary",
            "$root.primary.issuer" to "https://as.example/primary",
            "$root.direct.issuer" to "https://as.example/direct",
            "$root.direct.federation-automatic-registration-mode" to "SIGNED_JAR_OR_AUTHENTICATED_PAR",
        ))
        val selected = com.sphereon.oauth2.common.config.DefaultOAuth2ServerInstanceIdProvider()
        val binder = OAuth2ServersConfigBinder(TestSessionExecution(config), selected)
        assertEquals(com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.PAR_ONLY, binder.serverConfig.federationAutomaticRegistrationMode)
        selected.setCurrentAsInstanceId("direct")
        assertEquals(com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.SIGNED_JAR_OR_AUTHENTICATED_PAR, binder.serverConfig.federationAutomaticRegistrationMode)
    }

    @Test
    fun unknownFederationAutomaticRegistrationModeFailsClosed() {
        val root = OAuth2ServerInstanceConfig.CONFIG_PREFIX
        val binder = OAuth2ServersConfigBinder(TestSessionExecution(TypeAwarePrincipalConfigService(mapOf(
            "$root.default-server" to "primary",
            "$root.primary.issuer" to "https://as.example/primary",
            "$root.primary.federation-automatic-registration-mode" to "unknown-mode",
        ))), com.sphereon.oauth2.server.authorization.impl.testutil.fixedAsInstanceIdProvider())
        kotlin.test.assertFailsWith<IllegalStateException> { binder.getConfig() }
    }

    private val asId = "test-as"
    private val prefix = "${OAuth2ServerInstanceConfig.CONFIG_PREFIX}.$asId"

    @Test
    fun activeServerConfigTracksRequestSelectionWithoutChangingDefault() {
        val root = OAuth2ServerInstanceConfig.CONFIG_PREFIX
        val configService = TypeAwarePrincipalConfigService(mapOf(
            "$root.default-server" to "primary",
            "$root.primary.issuer" to "https://tenant.example/as/primary",
            "$root.primary.oidc" to "DISABLED",
            "$root.proxy.issuer" to "https://tenant.example/as/proxy",
            "$root.proxy.oidc" to "REQUIRED",
        ))
        val selected = com.sphereon.oauth2.common.config.DefaultOAuth2ServerInstanceIdProvider()
        val binder = OAuth2ServersConfigBinder(TestSessionExecution(configService), selected)
        assertEquals("https://tenant.example/as/primary", binder.serverConfig.issuer)
        selected.setCurrentAsInstanceId("proxy")
        assertEquals("https://tenant.example/as/proxy", binder.serverConfig.issuer)
        assertEquals(FeaturePolicy.REQUIRED, binder.serverConfig.oidc)
        assertEquals("https://tenant.example/as/primary", binder.getDefaultServer().issuer)
        selected.clearCurrentAsInstanceId()
        assertEquals("https://tenant.example/as/primary", binder.serverConfig.issuer)
    }

    @Test
    fun internalClientRoleResolverReadsOpaqueClientIdWithoutPlaintextSecret() {
        val tenantId = "tenant-123"
        val properties =
            mapOf(
                "${OAuth2ServerInstanceConfig.CONFIG_PREFIX}.default-server" to asId,
                "$prefix.mode" to "HOSTED",
                "$prefix.internal-clients.issuer.client-id" to "issuer-service:$tenantId",
                "$prefix.internal-clients.issuer.tenant-id" to tenantId,
            )
        val configService = TypeAwarePrincipalConfigService(properties)
        val execution = TestSessionExecution(configService, tenantId = tenantId)
        val serversConfigProvider = OAuth2ServersConfigBinder(execution, com.sphereon.oauth2.common.config.DefaultOAuth2ServerInstanceIdProvider())
        val resolver =
            ConfigBackedInternalClientRoleResolver(
                execution = execution,
                asInstanceIdProvider =
                    object : OAuth2ServerInstanceIdProvider {
                        override fun currentAsInstanceId(): String? = null
                    },
                serversConfigProvider = serversConfigProvider,
            )

        assertTrue(
            serversConfigProvider.getDefaultServer().internalClients.isEmpty(),
            "opaque client without client-secret must stay out of the legacy typed config",
        )
        assertEquals("issuer-service:$tenantId", resolver.resolveClientId("issuer"))
    }

    @Test
    fun serverConfigIsResolvedOncePerPrincipalContentRevision() {
        val configService =
            TypeAwarePrincipalConfigService(
                mapOf(
                    "$prefix.mode" to "HOSTED",
                    "$prefix.issuer" to "https://before.example.com",
                ),
            )
        val binder = OAuth2ServersConfigBinder(TestSessionExecution(configService), com.sphereon.oauth2.common.config.DefaultOAuth2ServerInstanceIdProvider())

        val first = binder.getConfig()
        val readsAfterFirstBind = configService.propertyReadCount
        val unchanged = binder.getConfig()

        assertSame(first, unchanged, "an unchanged principal view must reuse the request-local bind")
        assertEquals(readsAfterFirstBind, configService.propertyReadCount, "the same revision must not rescan server properties")

        configService.putProperty("$prefix.issuer", "https://after.example.com")
        val revised = binder.getConfig()

        assertNotSame(first, revised, "a content revision must invalidate the request-local bind")
        assertEquals("https://after.example.com", revised.servers[asId]?.issuer)
        assertTrue(configService.propertyReadCount > readsAfterFirstBind)
    }

    @Test
    fun everyServerInstanceConfigFieldIsReadByBinder() {
        val properties = buildSentinelProperties()
        val binder = newBinder(properties)

        val server =
            binder.getServer(asId)
                ?: fail("binder returned null for asId='$asId'; check `mode`/`issuer` discovery probe")

        // Identity
        assertEquals(AuthorizationServerMode.EXTERNAL, server.mode, "mode")
        assertEquals("issuer-template-sentinel", server.issuerTemplate, "issuerTemplate")
        assertEquals("issuer-sentinel", server.issuer, "issuer")
        // Token lifetimes
        assertEquals(9_000_001, server.accessTokenLifetimeSeconds, "accessTokenLifetimeSeconds")
        assertEquals(9_000_002, server.refreshTokenLifetimeSeconds, "refreshTokenLifetimeSeconds")
        assertEquals(9_000_003, server.authorizationCodeLifetimeSeconds, "authorizationCodeLifetimeSeconds")
        assertEquals(TokenFormat.OPAQUE, server.tokenFormat, "tokenFormat")
        assertEquals(false, server.refreshTokenRotation, "refreshTokenRotation")
        // Grants & response types
        assertEquals(setOf("sentinel-grant-types-enabled"), server.grantTypesEnabled, "grantTypesEnabled")
        assertEquals(setOf("sentinel-response-types-supported"), server.responseTypesSupported, "responseTypesSupported")
        assertEquals(listOf("sentinel-scopes-supported"), server.scopesSupported, "scopesSupported")
        // OIDC + logout
        assertEquals(FeaturePolicy.REQUIRED, server.oidc, "oidc")
        assertEquals(FeaturePolicy.REQUIRED, server.logout, "logout")
        assertEquals(9_000_004, server.idTokenLifetimeSeconds, "idTokenLifetimeSeconds")
        assertEquals(listOf("sentinel-subject-types-supported"), server.subjectTypesSupported, "subjectTypesSupported")
        assertEquals(listOf("sentinel-claims-supported"), server.claimsSupported, "claimsSupported")
        assertEquals(setOf("sentinel-userinfo-signing-alg-values-supported"), server.userinfoSigningAlgValuesSupported, "userinfoSigningAlgValuesSupported")
        // Feature policies
        assertEquals(FeaturePolicy.REQUIRED, server.introspection, "introspection")
        assertEquals(FeaturePolicy.REQUIRED, server.revocation, "revocation")
        assertEquals(FeaturePolicy.REQUIRED, server.par, "par")
        assertEquals(FeaturePolicy.REQUIRED, server.tokenExchange, "tokenExchange")
        // RFC 8628 device authorization grant
        assertEquals(FeaturePolicy.REQUIRED, server.deviceFlow, "deviceFlow")
        assertEquals(9_000_007, server.deviceCodeLifetimeSeconds, "deviceCodeLifetimeSeconds")
        assertEquals(9_000_008, server.devicePollIntervalSeconds, "devicePollIntervalSeconds")
        assertEquals(FeaturePolicy.REQUIRED, server.pkce, "pkce")
        assertEquals(FeaturePolicy.REQUIRED, server.dpop, "dpop")
        assertEquals(true, server.dpopNonceRequired, "dpopNonceRequired")
        assertEquals(FeaturePolicy.REQUIRED, server.iae, "iae")
        // Auth methods
        assertEquals(setOf("sentinel-pkce-methods-supported"), server.pkceMethodsSupported, "pkceMethodsSupported")
        assertEquals(setOf("sentinel-token-endpoint-auth-methods-supported"), server.tokenEndpointAuthMethodsSupported, "tokenEndpointAuthMethodsSupported")
        assertEquals(setOf("sentinel-introspection-endpoint-auth-methods-supported"), server.introspectionEndpointAuthMethodsSupported, "introspectionEndpointAuthMethodsSupported")
        assertEquals(setOf("sentinel-revocation-endpoint-auth-methods-supported"), server.revocationEndpointAuthMethodsSupported, "revocationEndpointAuthMethodsSupported")
        assertEquals(setOf("sentinel-dpop-signing-alg-values-supported"), server.dpopSigningAlgValuesSupported, "dpopSigningAlgValuesSupported")
        // mTLS (RFC 8705)
        assertEquals(FeaturePolicy.REQUIRED, server.mtls, "mtls")
        assertEquals(true, server.tlsClientCertificateBoundAccessTokens, "tlsClientCertificateBoundAccessTokens")
        assertEquals("sentinel-mtls-endpoint-host-override", server.mtlsEndpointHostOverride, "mtlsEndpointHostOverride")
        // Attestation (draft-ietf-oauth-attestation-based-client-auth -07 / -08)
        assertEquals(FeaturePolicy.REQUIRED, server.attestation, "attestation")
        assertEquals(true, server.attestationChallengeRequired, "attestationChallengeRequired")
        assertEquals(setOf("sentinel-client-attestation-signing-alg-values-supported"), server.clientAttestationSigningAlgValuesSupported, "clientAttestationSigningAlgValuesSupported")
        assertEquals(setOf("sentinel-client-attestation-pop-signing-alg-values-supported"), server.clientAttestationPopSigningAlgValuesSupported, "clientAttestationPopSigningAlgValuesSupported")
        assertEquals(9_000_005, server.attestationMaxLifetimeSeconds, "attestationMaxLifetimeSeconds")
        assertEquals(9_000_006, server.attestationPopMaxAgeSeconds, "attestationPopMaxAgeSeconds")
        assertEquals(9_000_007, server.attestationPopJtiReplayWindowSeconds, "attestationPopJtiReplayWindowSeconds")
        assertEquals(FeaturePolicy.REQUIRED, server.walletInstanceAttestation, "walletInstanceAttestation")
        assertEquals(9_000_009, server.preferredClientStatusPeriodSeconds, "preferredClientStatusPeriodSeconds")
        // JARM
        assertEquals(FeaturePolicy.REQUIRED, server.jarm, "jarm")
        assertEquals(setOf("sentinel-authorization-signing-alg-values-supported"), server.authorizationSigningAlgValuesSupported, "authorizationSigningAlgValuesSupported")
        assertEquals(setOf("sentinel-authorization-encryption-alg-values-supported"), server.authorizationEncryptionAlgValuesSupported, "authorizationEncryptionAlgValuesSupported")
        assertEquals(setOf("sentinel-authorization-encryption-enc-values-supported"), server.authorizationEncryptionEncValuesSupported, "authorizationEncryptionEncValuesSupported")
        assertEquals(7_777_777L, server.jarmExpirationSeconds, "jarmExpirationSeconds")
        // JAR (RFC 9101)
        assertEquals(FeaturePolicy.REQUIRED, server.jar, "jar")
        assertEquals(true, server.requireRequestUriRegistration, "requireRequestUriRegistration")
        // Signing — `signingKeyAlias` removed in P0-K4. Per-tenant signing keys now live
        // in the SigningKeyStore SPI (oauth2-server-authorization-public/.../storage/
        // SigningKeyStore.kt) with a state machine for rotation; the per-server config field
        // it replaced is no longer expressible from YAML / properties.
        assertEquals(setOf("sentinel-signing-algorithms-supported"), server.signingAlgorithmsSupported, "signingAlgorithmsSupported")
        assertEquals(setOf("sentinel-id-token-signing-alg-values-supported"), server.idTokenSigningAlgValuesSupported, "idTokenSigningAlgValuesSupported")
        assertEquals(setOf("sentinel-request-object-signing-alg-values-supported"), server.requestObjectSigningAlgValuesSupported, "requestObjectSigningAlgValuesSupported")
        // EXTERNAL mode
        assertEquals("sentinel-token-endpoint-auth-method", server.tokenEndpointAuthMethod, "tokenEndpointAuthMethod")
        assertEquals("sentinel-client-id", server.clientId, "clientId")
        assertEquals("sentinel-client-secret", server.clientSecret, "clientSecret")
        assertEquals("sentinel-token-endpoint", server.tokenEndpoint, "tokenEndpoint")
        assertEquals("sentinel-introspection-endpoint", server.introspectionEndpoint, "introspectionEndpoint")
        assertEquals("sentinel-revocation-endpoint", server.revocationEndpoint, "revocationEndpoint")
        assertEquals("sentinel-jwks-uri", server.jwksUri, "jwksUri")
        // Internal service-to-service clients
        assertEquals(
            InternalClientConfig(
                clientId = "sentinel-issuer-client-id",
                clientSecret = "sentinel-issuer-client-secret",
                defaultAccessTokenAudience = "sentinel-platform-audience",
                allowedAccessTokenAudiences = setOf("sentinel-kms-audience", "sentinel-wallet-audience"),
            ),
            server.internalClients["issuer"],
            "internalClients[issuer]",
        )
        assertEquals(
            InternalClientConfig(
                clientId = "sentinel-kms-client-id",
                clientSecret = "sentinel-kms-client-secret",
            ),
            server.internalClients["kms"],
            "internalClients[kms]",
        )
        assertEquals(
            InternalClientConfig(
                clientId = "sentinel-verifier-client-id",
                clientSecret = "sentinel-verifier-client-secret",
            ),
            server.internalClients["verifier"],
            "internalClients[verifier]",
        )
        // Public clients
        // Browser-login session lifetimes
        assertEquals(7_001, server.session.idleTtlSeconds, "session.idleTtlSeconds")
        assertEquals(7_002, server.session.absoluteTtlSeconds, "session.absoluteTtlSeconds")
        // Local WebAuthn login
        assertEquals(true, server.webAuthn.enabled, "webAuthn.enabled")
        assertEquals("login.example", server.webAuthn.rpId, "webAuthn.rpId")
        assertEquals(setOf("https://login.example"), server.webAuthn.allowedOrigins, "webAuthn.allowedOrigins")
        assertEquals("direct", server.webAuthn.attestationPolicy, "webAuthn.attestationPolicy")
        assertEquals("preferred", server.webAuthn.userVerification, "webAuthn.userVerification")
        assertEquals(setOf("internal", "hybrid"), server.webAuthn.allowedTransports, "webAuthn.allowedTransports")
        assertEquals("require-backed-up", server.webAuthn.backupStatePolicy, "webAuthn.backupStatePolicy")
        assertEquals(7_003L, server.webAuthn.challengeTtlSeconds, "webAuthn.challengeTtlSeconds")
        assertEquals(true, server.webAuthn.level3PrfEnabled, "webAuthn.level3PrfEnabled")
        assertEquals(LoginInteraction.CHOOSER, server.login.interaction, "login.interaction")
        assertEquals(LoginRenderer.NEUTRAL, server.login.renderer, "login.renderer")
        assertEquals(false, server.login.themeResolutionEnabled, "login.themeResolutionEnabled")
        assertEquals(false, server.login.showPasswordForm, "login.showPasswordForm")
        assertEquals(true, server.login.showFederation, "login.showFederation")
        assertEquals(true, server.login.showWallet, "login.showWallet")
        assertEquals("https://wallet.example/start", server.login.walletAuthorizationUrl, "login.walletAuthorizationUrl")
        assertEquals(LoginMethod.WALLET, server.login.defaultMethod, "login.defaultMethod")
    }

    private fun buildSentinelProperties(): Map<String, Any> =
        mapOf(
            // Discovery hint so OAuth2ServersConfigBinder.discoverServerIds() picks up our id.
            "${OAuth2ServerInstanceConfig.CONFIG_PREFIX}.default-server" to asId,
            // Identity
            "$prefix.mode" to "EXTERNAL",
            "$prefix.issuer-template" to "issuer-template-sentinel",
            "$prefix.issuer" to "issuer-sentinel",
            // Token lifetimes
            "$prefix.access-token-lifetime-seconds" to 9_000_001,
            "$prefix.refresh-token-lifetime-seconds" to 9_000_002,
            "$prefix.authorization-code-lifetime-seconds" to 9_000_003,
            "$prefix.token-format" to "OPAQUE",
            "$prefix.refresh-token-rotation" to false,
            // Grants & response types
            "$prefix.grant-types-enabled" to "sentinel-grant-types-enabled",
            "$prefix.response-types-supported" to "sentinel-response-types-supported",
            "$prefix.scopes-supported" to "sentinel-scopes-supported",
            // OIDC + logout
            "$prefix.oidc" to "REQUIRED",
            "$prefix.logout" to "REQUIRED",
            "$prefix.id-token-lifetime-seconds" to 9_000_004,
            "$prefix.subject-types-supported" to "sentinel-subject-types-supported",
            "$prefix.claims-supported" to "sentinel-claims-supported",
            "$prefix.userinfo-signing-alg-values-supported" to "sentinel-userinfo-signing-alg-values-supported",
            // Feature policies
            "$prefix.introspection" to "REQUIRED",
            "$prefix.revocation" to "REQUIRED",
            "$prefix.par" to "REQUIRED",
            "$prefix.token-exchange" to "REQUIRED",
            "$prefix.device-flow" to "REQUIRED",
            "$prefix.device-code-lifetime-seconds" to 9_000_007,
            "$prefix.device-poll-interval-seconds" to 9_000_008,
            "$prefix.pkce" to "REQUIRED",
            "$prefix.dpop" to "REQUIRED",
            "$prefix.dpop-nonce-required" to true,
            "$prefix.iae" to "REQUIRED",
            // Auth methods
            "$prefix.pkce-methods-supported" to "sentinel-pkce-methods-supported",
            "$prefix.token-endpoint-auth-methods-supported" to "sentinel-token-endpoint-auth-methods-supported",
            "$prefix.introspection-endpoint-auth-methods-supported" to "sentinel-introspection-endpoint-auth-methods-supported",
            "$prefix.revocation-endpoint-auth-methods-supported" to "sentinel-revocation-endpoint-auth-methods-supported",
            "$prefix.dpop-signing-alg-values-supported" to "sentinel-dpop-signing-alg-values-supported",
            // mTLS
            "$prefix.mtls" to "REQUIRED",
            "$prefix.tls-client-certificate-bound-access-tokens" to true,
            "$prefix.mtls-endpoint-host-override" to "sentinel-mtls-endpoint-host-override",
            // Attestation
            "$prefix.attestation" to "REQUIRED",
            "$prefix.attestation-challenge-required" to true,
            "$prefix.client-attestation-signing-alg-values-supported" to "sentinel-client-attestation-signing-alg-values-supported",
            "$prefix.client-attestation-pop-signing-alg-values-supported" to "sentinel-client-attestation-pop-signing-alg-values-supported",
            "$prefix.attestation-max-lifetime-seconds" to 9_000_005,
            "$prefix.attestation-pop-max-age-seconds" to 9_000_006,
            "$prefix.attestation-pop-jti-replay-window-seconds" to 9_000_007,
            "$prefix.wallet-instance-attestation" to "REQUIRED",
            "$prefix.preferred-client-status-period-seconds" to 9_000_009,
            // JARM
            "$prefix.jarm" to "REQUIRED",
            "$prefix.authorization-signing-alg-values-supported" to "sentinel-authorization-signing-alg-values-supported",
            "$prefix.authorization-encryption-alg-values-supported" to "sentinel-authorization-encryption-alg-values-supported",
            "$prefix.authorization-encryption-enc-values-supported" to "sentinel-authorization-encryption-enc-values-supported",
            "$prefix.jarm-expiration-seconds" to 7_777_777L,
            // JAR
            "$prefix.jar" to "REQUIRED",
            "$prefix.require-request-uri-registration" to true,
            // Signing — `signing-key-alias` property removed in P0-K4 (replaced by the
            // SigningKeyStore SPI; signing keys are now state-machine-tracked, not config-
            // expressed).
            "$prefix.signing-algorithms-supported" to "sentinel-signing-algorithms-supported",
            "$prefix.id-token-signing-alg-values-supported" to "sentinel-id-token-signing-alg-values-supported",
            "$prefix.request-object-signing-alg-values-supported" to "sentinel-request-object-signing-alg-values-supported",
            // EXTERNAL mode
            "$prefix.token-endpoint-auth-method" to "sentinel-token-endpoint-auth-method",
            "$prefix.client-id" to "sentinel-client-id",
            "$prefix.client-secret" to "sentinel-client-secret",
            "$prefix.token-endpoint" to "sentinel-token-endpoint",
            "$prefix.introspection-endpoint" to "sentinel-introspection-endpoint",
            "$prefix.revocation-endpoint" to "sentinel-revocation-endpoint",
            "$prefix.jwks-uri" to "sentinel-jwks-uri",
            // Internal clients
            "$prefix.internal-clients.issuer.client-id" to "sentinel-issuer-client-id",
            "$prefix.internal-clients.issuer.client-secret" to "sentinel-issuer-client-secret",
            "$prefix.internal-clients.issuer.default-access-token-audience" to "sentinel-platform-audience",
            "$prefix.internal-clients.issuer.allowed-access-token-audiences" to "sentinel-kms-audience,sentinel-wallet-audience",
            "$prefix.internal-clients.kms.client-id" to "sentinel-kms-client-id",
            "$prefix.internal-clients.kms.client-secret" to "sentinel-kms-client-secret",
            "$prefix.internal-clients.verifier.client-id" to "sentinel-verifier-client-id",
            "$prefix.internal-clients.verifier.client-secret" to "sentinel-verifier-client-secret",
            // Public clients
            "$prefix.public-clients.allowed-client-ids" to "sentinel-public-client-1, sentinel-public-client-2",
            // Session lifetimes
            "$prefix.session.idle-ttl-seconds" to 7_001,
            "$prefix.session.absolute-ttl-seconds" to 7_002,
            // Local WebAuthn login
            "$prefix.webauthn.enabled" to true,
            "$prefix.webauthn.rp-id" to "login.example",
            "$prefix.webauthn.allowed-origins" to "https://login.example",
            "$prefix.webauthn.attestation-policy" to "direct",
            "$prefix.webauthn.user-verification" to "preferred",
            "$prefix.webauthn.allowed-transports" to "internal,hybrid",
            "$prefix.webauthn.backup-state-policy" to "require-backed-up",
            "$prefix.webauthn.challenge-ttl-seconds" to 7_003L,
            "$prefix.webauthn.level3-prf-enabled" to true,
            "$prefix.login.interaction" to "chooser",
            "$prefix.login.renderer" to "neutral",
            "$prefix.login.theme-resolution-enabled" to false,
            "$prefix.login.methods.password" to false,
            "$prefix.login.methods.federation" to true,
            "$prefix.login.methods.wallet" to true,
            "$prefix.login.wallet.authorization-url" to "https://wallet.example/start",
            "$prefix.login.default-method" to "wallet",
        )

    @Test
    fun internalClientsWithDashedRoleNamesSurviveNormalizedPropertySources() {
        val serverId = "platform"
        val serverPrefix = "${OAuth2ServerInstanceConfig.CONFIG_PREFIX}.$serverId"
        val secret = "edk-internal-local-only"
        val binder =
            newBinder(
                mapOf(
                    "${OAuth2ServerInstanceConfig.CONFIG_PREFIX}.default-server" to serverId,
                    "$serverPrefix.mode" to "HOSTED",
                    "$serverPrefix.issuer" to "https://platform.saas.localtest.me",
                    "$serverPrefix.internal-clients.authorization-server.client-id" to "tenant-as-service",
                    "$serverPrefix.internal-clients.authorization-server.client-secret" to secret,
                    "$serverPrefix.internal-clients.authorization-server.default-access-token-audience" to "enterprise-platform",
                    "$serverPrefix.internal-clients.authorization-server.allowed-access-token-audiences" to "enterprise-tenant-kms",
                    "$serverPrefix.internal-clients.issuer.client-id" to "issuer-service",
                    "$serverPrefix.internal-clients.issuer.client-secret" to secret,
                ),
                normalizeKeys = true,
            )

        val server =
            binder.getServer(serverId)
                ?: fail("binder returned null for normalized serverId='$serverId'")

        assertEquals(
            InternalClientConfig(
                clientId = "tenant-as-service",
                clientSecret = secret,
                defaultAccessTokenAudience = "enterprise-platform",
                allowedAccessTokenAudiences = setOf("enterprise-tenant-kms"),
            ),
            server.internalClients["authorization.server"],
            "internalClients[authorization.server]",
        )
        assertEquals(
            InternalClientConfig(clientId = "issuer-service", clientSecret = secret),
            server.internalClients["issuer"],
            "internalClients[issuer]",
        )
        assertTrue(
            server.internalClients.values.any { it.clientId == "tenant-as-service" && it.clientSecret == secret },
            "configured internal clients must expose tenant-as-service to the client registry",
        )
    }

    private fun newBinder(
        properties: Map<String, Any>,
        normalizeKeys: Boolean = false,
    ): OAuth2ServersConfigBinder {
        val configService = TypeAwarePrincipalConfigService(properties, normalizeKeys = normalizeKeys)
        val execution = TestSessionExecution(configService)
        return OAuth2ServersConfigBinder(execution, com.sphereon.oauth2.common.config.DefaultOAuth2ServerInstanceIdProvider())
    }

    @Test
    fun defaultsAreReturnedWhenPropertiesAreAbsent() {
        // Sanity check: with no properties set, the binder still produces a non-null default
        // server config (via the empty-discovery branch). Guards against accidental tightening
        // of the discovery probe that would yield an empty servers map for new deployments.
        val binder = newBinder(emptyMap())
        val server = binder.getDefaultServer()
        // Default mode is HOSTED per OAuth2ServerInstanceConfig.
        assertEquals(AuthorizationServerMode.HOSTED, server.mode)
        assertEquals(SessionConfig.DEFAULT_IDLE_TTL_SECONDS, server.session.idleTtlSeconds)
        assertEquals(SessionConfig.DEFAULT_ABSOLUTE_TTL_SECONDS, server.session.absoluteTtlSeconds)
    }
}

/**
 * Test fake [PrincipalConfigService] that converts string values to [Int]/[Long]/[Boolean] on
 * demand, mirroring what real property sources do via property-value conversion. Mirrors the
 * shape of [com.sphereon.oauth2.server.authorization.impl.provider.FakePrincipalConfigService]
 * but with explicit type coercion so the binder's `getProperty(key, Int::class, ...)` calls
 * resolve correctly when the underlying value is a string (the common shape for `.properties`
 * sources).
 */
/**
 * Property source that carries only the revision signal. Real sources bump `contentRevision` on
 * every write; the fake's reads are served from its own map, so this source exists to make the
 * revision the fake publishes agree with the content it serves.
 */
internal class RevisionTrackingPropertySource(
    name: String,
) : MutableMapPropertySource(name),
    RefreshablePropertySource {
    private var revision = 0L

    override val contentRevision: Long
        get() = revision

    override fun refreshIfNeeded() = Unit

    fun recordWrite() {
        revision += 1
    }
}

internal class TypeAwarePrincipalConfigService(
    properties: Map<String, Any>,
    private val subPropertiesOverride: ((Set<String>, Boolean, Map<String, Any>) -> Map<String, Any>)? = null,
    private val normalizeKeys: Boolean = false,
    tenantConfigOverride: TenantConfigService? = null,
    principalScopedProperties: Map<String, Any> = emptyMap(),
) : PrincipalConfigService {
    internal var propertyReadCount: Int = 0
        private set
    private val keyNormalizer = PropertyKeyNormalizerImpl.Default
    private val properties: MutableMap<String, Any> =
        if (normalizeKeys) {
            properties.mapKeys { (key, _) -> keyNormalizer.normalize(key) }.toMutableMap()
        } else {
            properties.toMutableMap()
        }

    /**
     * Carries the same revision signal a real property source carries. Reads are served from
     * [properties]; this source exists so consumers that memoize against
     * `configContentRevision()` observe the same mutations the read path observes.
     */
    private val revisionSource = RevisionTrackingPropertySource("type-aware-principal-test")

    private val propertySources =
        DefaultPropertySources(
            mutableListOf<PropertySource<*>>(revisionSource).apply {
                if (principalScopedProperties.isNotEmpty()) {
                    add(
                        ProtectedMutableMapPropertySource(
                            sourceName = "type-aware-principal-owned-test",
                            sourceLevel = ConfigLevel.PRINCIPAL,
                        ).apply { addProperties(principalScopedProperties) },
                    )
                }
            },
        )
    private val tenantConfig: TenantConfigService =
        tenantConfigOverride ?: TypeAwareTenantConfigService(this)

    internal fun putProperty(
        key: String,
        value: Any,
    ) {
        properties[normalizeKey(key)] = value
        revisionSource.recordWrite()
    }

    /**
     * Models a remote tenant-config publication that reaches a fresh request before the local
     * source's revision notification. Production client visibility must still be correct in that
     * window; request-scoped registry metadata therefore cannot be reused across requests.
     */
    internal fun putPropertyWithoutRevision(
        key: String,
        value: Any,
    ) {
        properties[normalizeKey(key)] = value
    }

    override val parent: TenantConfigService
        get() = tenantConfig

    override val configLevel: ConfigLevel = ConfigLevel.PRINCIPAL

    override fun addPropertySource(source: PropertySource<*>): Nothing = error("not used")

    override fun removePropertySource(source: PropertySource<*>): Nothing = error("not used")

    override fun getActiveProfile(): String = "test"

    override fun getAppName(): String = "test-app"

    override fun getConfigLocation(): Path = error("not used")

    override fun getPropertySources(includeParents: Boolean): PropertySources = propertySources

    @Suppress("DEPRECATION")
    override fun getNamespace(): String = ""

    override fun containsProperty(key: String): Boolean {
        propertyReadCount += 1
        return properties.containsKey(normalizeKey(key))
    }

    @Suppress("UNCHECKED_CAST")
    override fun <T : Any> getProperty(
        key: String,
        targetType: KClass<T>,
        defaultValue: T?,
    ): T? {
        propertyReadCount += 1
        val raw = properties[normalizeKey(key)] ?: return defaultValue
        if (targetType.isInstance(raw)) {
            return raw as T
        }
        // String -> primitive coercion. Real property resolvers do this through a
        // PropertyValueConversion chain. The binder asks for Int/Long/Boolean only, so we
        // hand-roll the three coercions instead of pulling the full conversion pipeline.
        val coerced: Any? =
            when (targetType) {
                Int::class -> {
                    (raw as? String)?.trim()?.toIntOrNull()
                }

                Long::class -> {
                    (raw as? String)?.trim()?.toLongOrNull()
                }

                Boolean::class -> {
                    (raw as? String)?.trim()?.lowercase()?.let { s ->
                        when (s) {
                            "true", "1", "yes", "on" -> true
                            "false", "0", "no", "off" -> false
                            else -> null
                        }
                    }
                }

                String::class -> {
                    raw.toString()
                }

                else -> {
                    null
                }
            }
        return coerced as T?
    }

    override fun getPropertyAsString(
        key: String,
        defaultValue: String?,
    ): String? {
        propertyReadCount += 1
        return properties[normalizeKey(key)]?.toString() ?: defaultValue
    }

    override fun <T : Any> getRequiredProperty(
        key: String,
        targetType: KClass<T>,
        defaultValue: T?,
    ): T =
        getProperty(key, targetType, defaultValue)
            ?: error("Missing required property $key")

    override fun getRequiredPropertyAsString(
        key: String,
        defaultValue: String?,
    ): String =
        getPropertyAsString(key, defaultValue)
            ?: error("Missing required property $key")

    override fun getAllProperties(): Map<String, Any> = properties.toMap()

    override fun getAllPropertiesAsString(redact: Boolean): Map<String, String> = properties.mapValues { it.value.toString() }

    override fun getSubProperties(
        prefixes: Set<String>,
        stripPrefix: Boolean,
    ): Map<String, Any> {
        propertyReadCount += 1
        subPropertiesOverride?.let { return it(prefixes, stripPrefix, properties) }
        val matched = mutableMapOf<String, Any>()
        for (prefix in prefixes) {
            val normalizedPrefix = normalizeKey(prefix)
            for ((key, value) in properties) {
                val matches = key.startsWith("$normalizedPrefix.") || key == normalizedPrefix
                if (!matches) continue
                val outKey = if (stripPrefix) key.removePrefix("$normalizedPrefix.") else key
                matched[outKey] = value
            }
        }
        return matched
    }

    private fun normalizeKey(key: String): String =
        if (normalizeKeys) {
            keyNormalizer.normalize(key)
        } else {
            key
        }

    override fun getSubPropertiesAsString(
        prefixes: Set<String>,
        stripPrefix: Boolean,
        redact: Boolean,
    ): Map<String, String> = getSubProperties(prefixes, stripPrefix).mapValues { it.value.toString() }
}

/**
 * Tenant facade used by binder tests whose synthetic map historically represented the complete
 * effective config view. Opaque internal-client tests now read the tenant parent explicitly,
 * while principal-owned client tests continue to use the principal service itself.
 */
internal class TypeAwareTenantConfigService(
    private val delegate: TypeAwarePrincipalConfigService,
) : TenantConfigService {
    override val parent: AppConfigService
        get() = error("app parent not used in this test")

    override val configLevel: ConfigLevel = ConfigLevel.TENANT

    override fun addPropertySource(source: PropertySource<*>): ConfigService = delegate.addPropertySource(source)

    override fun removePropertySource(source: PropertySource<*>): ConfigService = delegate.removePropertySource(source)

    override fun getActiveProfile(): String = delegate.getActiveProfile()

    override fun getAppName(): String = delegate.getAppName()

    override fun getConfigLocation(): Path = delegate.getConfigLocation()

    override fun getPropertySources(includeParents: Boolean): PropertySources = delegate.getPropertySources(includeParents)

    override fun containsProperty(key: String): Boolean = delegate.containsProperty(key)

    override fun <T : Any> getProperty(
        key: String,
        targetType: KClass<T>,
        defaultValue: T?,
    ): T? = delegate.getProperty(key, targetType, defaultValue)

    override fun getPropertyAsString(
        key: String,
        defaultValue: String?,
    ): String? = delegate.getPropertyAsString(key, defaultValue)

    override fun <T : Any> getRequiredProperty(
        key: String,
        targetType: KClass<T>,
        defaultValue: T?,
    ): T = delegate.getRequiredProperty(key, targetType, defaultValue)

    override fun getRequiredPropertyAsString(
        key: String,
        defaultValue: String?,
    ): String = delegate.getRequiredPropertyAsString(key, defaultValue)

    override fun getAllProperties(): Map<String, Any> = delegate.getAllProperties()

    override fun getAllPropertiesAsString(redact: Boolean): Map<String, String> =
        delegate.getAllPropertiesAsString(redact)

    override fun getSubProperties(
        prefixes: Set<String>,
        stripPrefix: Boolean,
    ): Map<String, Any> = delegate.getSubProperties(prefixes, stripPrefix)

    override fun getSubPropertiesAsString(
        prefixes: Set<String>,
        stripPrefix: Boolean,
        redact: Boolean,
    ): Map<String, String> = delegate.getSubPropertiesAsString(prefixes, stripPrefix, redact)

    @Suppress("DEPRECATION")
    override fun getNamespace(): String = delegate.getNamespace()
}

/**
 * Minimal [SessionExecution] surface: only [conf] is exercised by the binder under test, so the
 * remaining members throw to flag accidental scope creep in [OAuth2ServersConfigBinder].
 */
internal class TestSessionExecution(
    principal: PrincipalConfigService,
    override val tenantId: String = NoOpSessionContext.context.tenant.tenantId,
    override val principalId: String = NoOpSessionContext.context.principal.toString(),
    override val log: SessionLogService = NoOpSessionLogService,
) : SessionExecution {
    override val sessionContext: SessionContext = NoOpSessionContext
    override val sessionContextManager: SessionContextManager
        get() = error("sessionContextManager not used in this test")
    override val conf: ContextConfig = TestContextConfig(principal)
}

internal class TestContextConfig(
    override val principal: PrincipalConfigService,
) : ContextConfig {
    override val app: AppConfigService get() = error("app config not used in this test")
    override val tenant: TenantConfigService get() = principal.parent

    override fun conf(level: ConfigLevel): ConfigService =
        when (level) {
            ConfigLevel.PRINCIPAL -> principal
            ConfigLevel.TENANT -> tenant
            else -> error("APP config is not exercised by these OAuth2 config tests")
        }
}

/** Session log that keeps every emitted message so a test can assert on what was reported. */
internal class RecordingSessionLogService : SessionLogService {
    val messages = mutableListOf<LogMessage>()

    override val sessionContext: SessionContext = NoOpSessionContext
    override val id: String = "test-recording-log"
    override val isEnabled: Boolean = true
    override val scope: IdkScope = IdkScope.SESSION
    override val logManager: SessionLogManager
        get() = throw NotImplementedError("logManager not used in this test")

    override suspend fun setConfig(config: LoggerConfig): LogService = this

    override fun executeAsync(message: LogMessage): IdkResult<Unit, IdkErrorType> {
        messages += message
        return Ok(Unit)
    }

    override fun toAsync(): AsyncLogService = throw NotImplementedError("toAsync not used in this test")
}

internal object NoOpSessionLogService : SessionLogService {
    override val sessionContext: SessionContext = NoOpSessionContext
    override val id: String = "test-binder-log"
    override val isEnabled: Boolean = false
    override val scope: IdkScope = IdkScope.SESSION
    override val logManager: SessionLogManager
        get() = throw NotImplementedError("logManager not used in this test")

    override suspend fun setConfig(config: LoggerConfig): LogService = this

    override fun executeAsync(message: LogMessage): IdkResult<Unit, IdkErrorType> = Ok(Unit)

    override fun toAsync(): AsyncLogService = throw NotImplementedError("toAsync not used in this test")
}
