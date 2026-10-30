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

import com.sphereon.core.api.conf.ConfigLevel
import com.sphereon.core.api.conf.PrincipalConfigService
import com.sphereon.core.api.conf.PropertyKeyNormalizerImpl
import com.sphereon.core.api.conf.configContentRevision
import com.sphereon.core.api.conf.reloadFromBackingSources
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.AuthorizationServerMode
import com.sphereon.oauth2.common.config.ClientRegistrySourcePrecedence
import com.sphereon.oauth2.common.config.FeaturePolicy
import com.sphereon.oauth2.common.config.InternalClientConfig
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceIdProvider
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.config.SessionConfig
import com.sphereon.oauth2.common.config.TokenFormat
import com.sphereon.oauth2.common.config.WebAuthnLoginConfig
import com.sphereon.oauth2.common.model.GrantType
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized

/**
 * Binds OAuth2 server configuration from IDK's ConfigService.
 *
 * Configuration uses the prefix "oauth2.servers":
 *
 * ```properties
 * sphereon.app.oauth2.servers.default-server=primary
 * sphereon.app.oauth2.servers.primary.mode=HOSTED
 * sphereon.app.oauth2.servers.primary.issuer=https://auth.example.com
 * sphereon.app.oauth2.servers.primary.access-token-lifetime-seconds=1800
 * sphereon.app.oauth2.servers.primary.revocation=SUPPORTED
 * ```
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<OAuth2ServersConfigProvider>())
@ContributesBinding(SessionScope::class, binding = binding<OAuth2ServersConfigProvider?>())
class OAuth2ServersConfigBinder(
    private val execution: SessionExecution,
    private val asInstanceIdProvider: OAuth2ServerInstanceIdProvider,
) : OAuth2ServersConfigProvider {
    private val keyNormalizer = PropertyKeyNormalizerImpl.Default
    private val configCacheLock = SynchronizedObject()
    private var cachedConfig: RevisionedServersConfig? = null

    private val configService: PrincipalConfigService
        get() = execution.conf.conf(ConfigLevel.PRINCIPAL) as PrincipalConfigService

    private val prefix: String
        get() = OAuth2ServerInstanceConfig.CONFIG_PREFIX

    /**
     * Resolves the principal view once per content revision for this request.
     *
     * Token handling consults the server configuration from DPoP, client-registry, grant, and
     * signing stages. Re-scanning the same principal property view in every stage is both
     * redundant and expensive for a large internal-client registry. The binder is SessionScope,
     * so this cache cannot cross a principal boundary or extend secret lifetime beyond the
     * request. A content-revision change within the request invalidates it immediately.
     */
    override fun getConfig(): OAuth2ServersConfig {
        while (true) {
            val principalConfig = configService
            val refreshedRevision = principalConfig.configContentRevision()
            val resolved =
                synchronized(configCacheLock) {
                    // Invalidation can race the refresh above. Never bind or publish a config for
                    // a revision that is no longer current.
                    if (principalConfig.configContentRevision(refresh = false) != refreshedRevision) {
                        return@synchronized null
                    }
                    cachedConfig
                        ?.takeIf { it.revision == refreshedRevision }
                        ?.config
                        ?: loadConfig().let { loaded ->
                            if (principalConfig.configContentRevision(refresh = false) != refreshedRevision) {
                                null
                            } else {
                                cachedConfig = RevisionedServersConfig(refreshedRevision, loaded)
                                loaded
                            }
                        }
                }
            if (resolved != null) return resolved
        }
    }

    override suspend fun reloadConfig(): OAuth2ServersConfig {
        configService.reloadFromBackingSources()
        return getConfig()
    }

    override fun getServer(id: String): OAuth2ServerInstanceConfig? = getConfig().getServer(id)

    override val serverConfig: OAuth2ServerInstanceConfig
        get() {
            val activeId = asInstanceIdProvider.currentAsInstanceId() ?: return getDefaultServer()
            return requireNotNull(getServer(activeId)) {
                "Active OAuth2 server '$activeId' not found in configuration"
            }
        }

    override fun getDefaultServer(): OAuth2ServerInstanceConfig = getConfig().getDefaultServer()

    override fun resolveIssuer(
        serverId: String,
        tenantId: String,
    ): String {
        val server =
            getConfig().getServer(serverId)
                ?: error("OAuth2 server '$serverId' not found in configuration")
        return server.resolveIssuer(serverId, tenantId)
    }

    private fun loadConfig(): OAuth2ServersConfig {
        val defaultServer =
            configService.getPropertyAsString(
                "$prefix.default-server",
                null,
            )
                ?: configService.getPropertyAsString(
                    "$prefix.default.server",
                    null,
                )
                ?: "default"

        // Scan the oauth2.servers.* keyspace to find every configured server id.
        val serverIds = discoverServerIds(defaultServer)

        val servers =
            if (serverIds.isEmpty()) {
                mapOf("default" to OAuth2ServerInstanceConfig())
            } else {
                serverIds.associateWith { id -> loadServerConfig(id) }
            }

        return OAuth2ServersConfig(
            defaultServer = defaultServer,
            servers = servers,
            explicitlyConfigured = serverIds.isNotEmpty(),
        )
    }

    /**
     * Discovers configured server ids by scanning every property under the `oauth2.servers.`
     * keyspace. Property sources normalize hyphenated ids into dotted segments, so issuer
     * values are used to recover the canonical slug spelling (for example `wallet-proxy`).
     *
     * For a property map of the form
     * ```
     * oauth2.servers.default-server = production
     * oauth2.servers.production.issuer = https://auth.example.com
     * oauth2.servers.production.mode  = HOSTED
     * oauth2.servers.auth-eu.issuer   = https://auth.eu.example.com
     * ```
     * the scan strips the `oauth2.servers.` prefix, identifies configured instance prefixes,
     * deduplicates, and
     * filters out the reserved [DEFAULT_SERVER_KEY] segment (which selects the default server,
     * not a server named `default-server`). The remaining set is the discovered server ids.
     *
     * The reserved [DEFAULT_SERVER_KEY] is the only sibling-of-server-id key under
     * `oauth2.servers.`; every other key path is `oauth2.servers.<id>.<...>` per the
     * [OAuth2ServerInstanceConfig] property layout.
     */
    private fun discoverServerIds(defaultServer: String): Set<String> {
        val stripped = configService.getSubProperties(prefixes = setOf(prefix), stripPrefix = true)
        if (stripped.isEmpty()) {
            val selectedDefault = defaultServer.trim().takeIf { it.isNotEmpty() && it != "default" }
            if (selectedDefault != null) {
                return setOf(selectedDefault)
            }
            return if (DEFAULT_SERVER_PROBE_KEYS.any { configService.containsProperty("$prefix.default.$it") }) {
                setOf("default")
            } else {
                emptySet()
            }
        }
        val normalizedDefaultServer = keyNormalizer.normalize(defaultServer)
        // Property sources normalize hyphens in instance IDs into dots. An issuer leaf
        // identifies the whole instance prefix; taking its first segment loses non-default
        // hosted servers such as `wallet-proxy`. Where the issuer path supplies that same
        // identifier, retain its original spelling for downstream instance selection.
        val issuerIds = stripped.entries.mapNotNull { (key, value) ->
            val suffix = listOf(".issuer-template", ".issuer.template", ".issuer").firstOrNull(key::endsWith)
                ?: return@mapNotNull null
            val keyId = key.removeSuffix(suffix)
            val pathId = value.toString().substringBefore('?').substringBefore('#').trimEnd('/').substringAfterLast('/')
            val id = if (keyNormalizer.normalize(pathId) == keyNormalizer.normalize(keyId)) pathId else keyId
            keyNormalizer.normalize(keyId) to id
        }.toMap()
        return stripped.keys
            .asSequence()
            .filterNot { it == DEFAULT_SERVER_KEY || it == NORMALIZED_DEFAULT_SERVER_KEY }
            .map { key ->
                if (normalizedDefaultServer.isNotBlank() && (key == normalizedDefaultServer || key.startsWith("$normalizedDefaultServer."))) {
                    defaultServer
                } else {
                    val normalizedKey = keyNormalizer.normalize(key)
                    issuerIds.keys.sortedByDescending(String::length)
                        .firstOrNull { normalizedKey.startsWith("$it.") }
                        ?.let(issuerIds::get)
                        ?: key.substringBefore('.')
                }
            }.filter { it.isNotEmpty() }
            .toSet()
    }

    private companion object {
        /**
         * Reserved sibling key under `oauth2.servers.` that selects which discovered server id is
         * the default. Excluded from the discovered-id set so an operator's
         * `oauth2.servers.default-server=production` does not synthesise a phantom server named
         * `default-server`.
         */
        const val DEFAULT_SERVER_KEY = "default-server"
        const val NORMALIZED_DEFAULT_SERVER_KEY = "default.server"
        const val CLIENT_ID_SUFFIX = ".client.id"
        const val CLIENT_SECRET_SUFFIX = ".client.secret"
        const val GRANT_TYPES_SUFFIX = ".grant.types"
        const val TENANT_ID_SUFFIX = ".tenant.id"
        const val DEFAULT_ACCESS_TOKEN_AUDIENCE_SUFFIX = ".default.access.token.audience"
        const val ALLOWED_ACCESS_TOKEN_AUDIENCES_SUFFIX = ".allowed.access.token.audiences"
        val DEFAULT_SERVER_PROBE_KEYS =
            setOf(
                "mode",
                "issuer",
                "issuer-template",
                "access-token-lifetime-seconds",
                "grant-types-enabled",
                "response-types-supported",
                "scopes-supported",
                "oidc",
                "par",
                "wallet-instance-attestation",
                "introspection",
                "revocation",
                "trust-forwarded-headers",
            )
    }

    private data class RevisionedServersConfig(
        val revision: Long,
        val config: OAuth2ServersConfig,
    )

    private fun loadServerConfig(id: String): OAuth2ServerInstanceConfig {
        val serverPrefix = "$prefix.$id"
        val defaults = OAuth2ServerInstanceConfig()

        return OAuth2ServerInstanceConfig(
            mode =
                configService
                    .getPropertyAsString("$serverPrefix.mode", null)
                    ?.let { runCatching { AuthorizationServerMode.valueOf(it.uppercase()) }.getOrNull() }
                    ?: defaults.mode,
            issuerTemplate = configService.getPropertyAsString("$serverPrefix.issuer-template", null),
            clientRegistrySourcePrecedence =
                ClientRegistrySourcePrecedence
                    .fromConfigValue(configService.getPropertyAsString("$serverPrefix.client-registry-source-precedence", null))
                    ?: defaults.clientRegistrySourcePrecedence,
            issuer = configService.getPropertyAsString("$serverPrefix.issuer", null),
            // When the AS has no configured issuer, outbound URLs fall back to the request's
            // `X-Forwarded-Proto`/`Host`. Honoring those headers is only safe behind a trusted
            // proxy, so deployments that terminate at an untrusted edge set this false and rely
            // on a configured issuer or a per-tenant OAUTH2_AUTHORIZATION_SERVER binding instead.
            // Default stays true (correct for a single trusted gateway); this binder makes the
            // knob live so a hardened deployment can turn it off.
            trustForwardedHeaders =
                configService.getProperty(
                    "$serverPrefix.trust-forwarded-headers",
                    Boolean::class,
                    defaults.trustForwardedHeaders,
                ) ?: defaults.trustForwardedHeaders,
            accessTokenLifetimeSeconds =
                configService.getProperty(
                    "$serverPrefix.access-token-lifetime-seconds",
                    Int::class,
                    defaults.accessTokenLifetimeSeconds,
                ) ?: defaults.accessTokenLifetimeSeconds,
            refreshTokenLifetimeSeconds =
                configService.getProperty(
                    "$serverPrefix.refresh-token-lifetime-seconds",
                    Int::class,
                    defaults.refreshTokenLifetimeSeconds,
                ) ?: defaults.refreshTokenLifetimeSeconds,
            authorizationCodeLifetimeSeconds =
                configService.getProperty(
                    "$serverPrefix.authorization-code-lifetime-seconds",
                    Int::class,
                    defaults.authorizationCodeLifetimeSeconds,
                ) ?: defaults.authorizationCodeLifetimeSeconds,
            tokenFormat =
                configService
                    .getPropertyAsString("$serverPrefix.token-format", null)
                    ?.let { runCatching { TokenFormat.valueOf(it.uppercase()) }.getOrNull() }
                    ?: defaults.tokenFormat,
            refreshTokenRotation =
                configService.getProperty(
                    "$serverPrefix.refresh-token-rotation",
                    Boolean::class,
                    defaults.refreshTokenRotation,
                ) ?: defaults.refreshTokenRotation,
            refreshTokenRetryGracePeriodSeconds =
                configService.getProperty(
                    "$serverPrefix.refresh-token-retry-grace-period-seconds",
                    Int::class,
                    defaults.refreshTokenRetryGracePeriodSeconds,
                ) ?: defaults.refreshTokenRetryGracePeriodSeconds,
            grantTypesEnabled =
                configService
                    .getPropertyAsString("$serverPrefix.grant-types-enabled", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet()
                    ?: defaults.grantTypesEnabled,
            responseTypesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.response-types-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet()
                    ?: defaults.responseTypesSupported,
            scopesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.scopes-supported", null)
                    ?.split(",")
                    ?.mapNotNull { it.trim().takeIf { value -> value.isNotEmpty() } },
            authorizationDetailsTypesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.authorization-details-types-supported", null)
                    ?.split(",")
                    ?.mapNotNull { it.trim().takeIf { value -> value.isNotEmpty() } }
                    ?.takeIf { it.isNotEmpty() },
            // OpenID Connect
            oidc = readFeaturePolicy("$serverPrefix.oidc", defaults.oidc),
            requireRedirectUriInPushedAuthorizationRequests =
                configService.getProperty(
                    "$serverPrefix.require-redirect-uri-in-pushed-authorization-requests",
                    Boolean::class,
                    defaults.requireRedirectUriInPushedAuthorizationRequests,
                ) ?: defaults.requireRedirectUriInPushedAuthorizationRequests,
            // OIDC RP-Initiated Logout 1.0 + Front-Channel Logout 1.0 + Back-Channel Logout 1.0
            logout = readFeaturePolicy("$serverPrefix.logout", defaults.logout),
            idTokenLifetimeSeconds =
                configService.getProperty(
                    "$serverPrefix.id-token-lifetime-seconds",
                    Int::class,
                    defaults.idTokenLifetimeSeconds,
                ) ?: defaults.idTokenLifetimeSeconds,
            // Optional knob (deviates from OIDC §5.4 — see model docs):
            // `embed-userinfo-claims-in-id-token: true` forces all projected user
            // claims into the id_token in addition to the standard /userinfo response.
            embedUserinfoClaimsInIdToken =
                configService.getProperty(
                    "$serverPrefix.embed-userinfo-claims-in-id-token",
                    Boolean::class,
                    defaults.embedUserinfoClaimsInIdToken,
                ) ?: defaults.embedUserinfoClaimsInIdToken,
            subjectTypesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.subject-types-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?: defaults.subjectTypesSupported,
            claimsSupported =
                configService
                    .getPropertyAsString("$serverPrefix.claims-supported", null)
                    ?.split(",")
                    ?.map { it.trim() },
            userinfoSigningAlgValuesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.userinfo-signing-alg-values-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet(),
            introspection = readFeaturePolicy("$serverPrefix.introspection", defaults.introspection),
            revocation = readFeaturePolicy("$serverPrefix.revocation", defaults.revocation),
            par = readFeaturePolicy("$serverPrefix.par", defaults.par),
            federationAutomaticRegistrationMode = readFederationRegistrationMode("$serverPrefix.federation-automatic-registration-mode", defaults.federationAutomaticRegistrationMode),
            tokenExchange = readFeaturePolicy("$serverPrefix.token-exchange", defaults.tokenExchange),
            // RFC 8628 (Device Authorization Grant): feature gate plus the two timing knobs that
            // shape the issued device-authorization record (`expires_in`, `interval`).
            deviceFlow = readFeaturePolicy("$serverPrefix.device-flow", defaults.deviceFlow),
            deviceCodeLifetimeSeconds =
                configService.getProperty(
                    "$serverPrefix.device-code-lifetime-seconds",
                    Int::class,
                    defaults.deviceCodeLifetimeSeconds,
                ) ?: defaults.deviceCodeLifetimeSeconds,
            devicePollIntervalSeconds =
                configService.getProperty(
                    "$serverPrefix.device-poll-interval-seconds",
                    Int::class,
                    defaults.devicePollIntervalSeconds,
                ) ?: defaults.devicePollIntervalSeconds,
            pkce = readFeaturePolicy("$serverPrefix.pkce", defaults.pkce),
            dpop = readFeaturePolicy("$serverPrefix.dpop", defaults.dpop),
            dpopNonceRequired =
                configService.getProperty(
                    "$serverPrefix.dpop-nonce-required",
                    Boolean::class,
                    defaults.dpopNonceRequired,
                ) ?: defaults.dpopNonceRequired,
            iae = readFeaturePolicy("$serverPrefix.iae", defaults.iae),
            pkceMethodsSupported =
                configService
                    .getPropertyAsString("$serverPrefix.pkce-methods-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet()
                    ?: defaults.pkceMethodsSupported,
            tokenEndpointAuthMethodsSupported =
                configService
                    .getPropertyAsString("$serverPrefix.token-endpoint-auth-methods-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet()
                    ?: defaults.tokenEndpointAuthMethodsSupported,
            introspectionEndpointAuthMethodsSupported =
                configService
                    .getPropertyAsString("$serverPrefix.introspection-endpoint-auth-methods-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet()
                    ?: defaults.introspectionEndpointAuthMethodsSupported,
            revocationEndpointAuthMethodsSupported =
                configService
                    .getPropertyAsString("$serverPrefix.revocation-endpoint-auth-methods-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet()
                    ?: defaults.revocationEndpointAuthMethodsSupported,
            dpopSigningAlgValuesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.dpop-signing-alg-values-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet(),
            // signing-key-alias removed (P0-K4): the AS now owns a SigningKeyStore SPI; per-
            // server signing-key configuration moved to that store and is no longer
            // expressed via this config field.
            signingAlgorithmsSupported =
                configService
                    .getPropertyAsString("$serverPrefix.signing-algorithms-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet(),
            idTokenSigningAlgValuesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.id-token-signing-alg-values-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet(),
            requestObjectSigningAlgValuesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.request-object-signing-alg-values-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet(),
            // EXTERNAL mode fields
            tokenEndpointAuthMethod = configService.getPropertyAsString("$serverPrefix.token-endpoint-auth-method", null),
            clientId = configService.getPropertyAsString("$serverPrefix.client-id", null),
            clientSecret = configService.getPropertyAsString("$serverPrefix.client-secret", null),
            tokenEndpoint = configService.getPropertyAsString("$serverPrefix.token-endpoint", null),
            introspectionEndpoint = configService.getPropertyAsString("$serverPrefix.introspection-endpoint", null),
            revocationEndpoint = configService.getPropertyAsString("$serverPrefix.revocation-endpoint", null),
            jwksUri = configService.getPropertyAsString("$serverPrefix.jwks-uri", null),
            internalClients = loadInternalClients(serverPrefix),
            // OAuth2 Attestation-Based Client Authentication
            // (draft-ietf-oauth-attestation-based-client-auth). Discovery hides the surface
            // entirely until [attestation] is opted in; [attestationChallengeRequired] toggles
            // the /attestation-challenge endpoint and forces the verifier to demand a fresh
            // server-issued nonce in the PoP. The two `*-signing-alg-values-supported` lists
            // cap which JOSE algs the AS will accept on the attestation and PoP JWTs.
            attestation = readFeaturePolicy("$serverPrefix.attestation", defaults.attestation),
            attestationChallengeRequired =
                configService.getProperty(
                    "$serverPrefix.attestation-challenge-required",
                    Boolean::class,
                    defaults.attestationChallengeRequired,
                ) ?: defaults.attestationChallengeRequired,
            clientAttestationSigningAlgValuesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.client-attestation-signing-alg-values-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet(),
            clientAttestationPopSigningAlgValuesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.client-attestation-pop-signing-alg-values-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet(),
            attestationMaxLifetimeSeconds =
                configService.getProperty(
                    "$serverPrefix.attestation-max-lifetime-seconds",
                    Int::class,
                    defaults.attestationMaxLifetimeSeconds,
                ) ?: defaults.attestationMaxLifetimeSeconds,
            attestationPopMaxAgeSeconds =
                configService.getProperty(
                    "$serverPrefix.attestation-pop-max-age-seconds",
                    Int::class,
                    defaults.attestationPopMaxAgeSeconds,
                ) ?: defaults.attestationPopMaxAgeSeconds,
            attestationPopJtiReplayWindowSeconds =
                configService.getProperty(
                    "$serverPrefix.attestation-pop-jti-replay-window-seconds",
                    Int::class,
                    defaults.attestationPopJtiReplayWindowSeconds,
                ) ?: defaults.attestationPopJtiReplayWindowSeconds,
            walletInstanceAttestation = readFeaturePolicy("$serverPrefix.wallet-instance-attestation", defaults.walletInstanceAttestation),
            preferredClientStatusPeriodSeconds =
                configService.getProperty(
                    "$serverPrefix.preferred-client-status-period-seconds",
                    Int::class,
                    defaults.preferredClientStatusPeriodSeconds,
                ) ?: defaults.preferredClientStatusPeriodSeconds,
            // RFC 8705 (OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access
            // Tokens). [mtls] gates discovery's `mtls_endpoint_aliases` and the AS's acceptance
            // of `tls_client_auth` / `self_signed_tls_client_auth`. The bound flag is the
            // server-wide default for cnf.x5t#S256 binding on issued access tokens; per-client
            // opt-in on [ClientRegistration.tlsClientCertificateBoundAccessTokens] overrides.
            // [mtlsEndpointHostOverride] is the hostname inserted into `mtls_endpoint_aliases`
            // when the operator deploys a separate TLS-terminating front door.
            mtls = readFeaturePolicy("$serverPrefix.mtls", defaults.mtls),
            tlsClientCertificateBoundAccessTokens =
                configService.getProperty(
                    "$serverPrefix.tls-client-certificate-bound-access-tokens",
                    Boolean::class,
                    defaults.tlsClientCertificateBoundAccessTokens,
                ) ?: defaults.tlsClientCertificateBoundAccessTokens,
            mtlsEndpointHostOverride =
                configService.getPropertyAsString("$serverPrefix.mtls-endpoint-host-override", null),
            // OIDF JARM (https://openid.net/specs/oauth-v2-jarm.html)
            jarm = readFeaturePolicy("$serverPrefix.jarm", defaults.jarm),
            authorizationSigningAlgValuesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.authorization-signing-alg-values-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet(),
            authorizationEncryptionAlgValuesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.authorization-encryption-alg-values-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet(),
            authorizationEncryptionEncValuesSupported =
                configService
                    .getPropertyAsString("$serverPrefix.authorization-encryption-enc-values-supported", null)
                    ?.split(",")
                    ?.map { it.trim() }
                    ?.toSet(),
            jarmExpirationSeconds =
                configService.getProperty(
                    "$serverPrefix.jarm-expiration-seconds",
                    Long::class,
                    defaults.jarmExpirationSeconds,
                ) ?: defaults.jarmExpirationSeconds,
            // RFC 9101 JAR feature gate + request_uri pre-registration policy.
            jar = readFeaturePolicy("$serverPrefix.jar", defaults.jar),
            requireRequestUriRegistration =
                configService.getProperty(
                    "$serverPrefix.require-request-uri-registration",
                    Boolean::class,
                    defaults.requireRequestUriRegistration,
                ) ?: defaults.requireRequestUriRegistration,
            session = loadSessionConfig(serverPrefix),
            webAuthn = loadWebAuthnConfig(serverPrefix),
            login = loadLoginConfig(serverPrefix),
            // Optional plain-text login-page notice (demo test-account hint, maintenance banner).
            // Unset in production → null → the renderer emits no notice markup.
            loginNotice = configService.getPropertyAsString("$serverPrefix.login-notice", null),
        )
    }

    private fun loadLoginConfig(serverPrefix: String): com.sphereon.oauth2.common.config.LoginPageConfig {
        val defaults = com.sphereon.oauth2.common.config.LoginPageConfig()
        val interaction =
            configService
                .getPropertyAsString("$serverPrefix.login.interaction", defaults.interaction.name)
                ?.trim()
                ?.uppercase()
                ?.let { value ->
                    runCatching { com.sphereon.oauth2.common.config.LoginInteraction.valueOf(value) }.getOrNull()
                } ?: defaults.interaction
        val renderer =
            configService
                .getPropertyAsString("$serverPrefix.login.renderer", defaults.renderer.name)
                ?.trim()
                ?.uppercase()
                ?.let { value ->
                    runCatching { com.sphereon.oauth2.common.config.LoginRenderer.valueOf(value) }.getOrNull()
                } ?: defaults.renderer
        val defaultMethod =
            configService
                .getPropertyAsString("$serverPrefix.login.default-method", defaults.defaultMethod.name)
                ?.trim()
                ?.uppercase()
                ?.let { value ->
                    runCatching { com.sphereon.oauth2.common.config.LoginMethod.valueOf(value) }.getOrNull()
                } ?: defaults.defaultMethod
        return com.sphereon.oauth2.common.config.LoginPageConfig(
            interaction = interaction,
            renderer = renderer,
            themeResolutionEnabled =
                configService.getProperty(
                    "$serverPrefix.login.theme-resolution-enabled",
                    Boolean::class,
                    defaults.themeResolutionEnabled,
                ) ?: defaults.themeResolutionEnabled,
            showPasswordForm =
                configService.getProperty(
                    "$serverPrefix.login.methods.password",
                    Boolean::class,
                    defaults.showPasswordForm,
                ) ?: defaults.showPasswordForm,
            showFederation =
                configService.getProperty(
                    "$serverPrefix.login.methods.federation",
                    Boolean::class,
                    defaults.showFederation,
                ) ?: defaults.showFederation,
            showWallet =
                configService.getProperty(
                    "$serverPrefix.login.methods.wallet",
                    Boolean::class,
                    defaults.showWallet,
                ) ?: defaults.showWallet,
            walletAuthorizationUrl =
                configService
                    .getPropertyAsString("$serverPrefix.login.wallet.authorization-url", defaults.walletAuthorizationUrl)
                    ?.trim()
                    ?.takeIf(String::isNotEmpty),
            defaultMethod = defaultMethod,
        )
    }

    private fun loadSessionConfig(serverPrefix: String): SessionConfig {
        val defaults = SessionConfig()
        return SessionConfig(
            idleTtlSeconds =
                configService.getProperty(
                    "$serverPrefix.session.idle-ttl-seconds",
                    Int::class,
                    defaults.idleTtlSeconds,
                ) ?: defaults.idleTtlSeconds,
            absoluteTtlSeconds =
                configService.getProperty(
                    "$serverPrefix.session.absolute-ttl-seconds",
                    Int::class,
                    defaults.absoluteTtlSeconds,
                ) ?: defaults.absoluteTtlSeconds,
        )
    }

    private fun loadWebAuthnConfig(serverPrefix: String): WebAuthnLoginConfig {
        val defaults = WebAuthnLoginConfig()
        val webAuthnPrefix = "$serverPrefix.webauthn"
        return WebAuthnLoginConfig(
            enabled =
                configService.getProperty(
                    "$webAuthnPrefix.enabled",
                    Boolean::class,
                    defaults.enabled,
                ) ?: defaults.enabled,
            rpId = configService.getPropertyAsString("$webAuthnPrefix.rp-id", null),
            allowedOrigins =
                configService
                    .getPropertyAsString("$webAuthnPrefix.allowed-origins", null)
                    ?.split(",")
                    ?.map(String::trim)
                    ?.filter(String::isNotEmpty)
                    ?.toSet()
                    ?: defaults.allowedOrigins,
            attestationPolicy =
                configService.getPropertyAsString("$webAuthnPrefix.attestation-policy", null)
                    ?: defaults.attestationPolicy,
            userVerification =
                configService.getPropertyAsString("$webAuthnPrefix.user-verification", null)
                    ?: defaults.userVerification,
            allowedTransports =
                configService
                    .getPropertyAsString("$webAuthnPrefix.allowed-transports", null)
                    ?.split(",")
                    ?.map(String::trim)
                    ?.filter(String::isNotEmpty)
                    ?.toSet()
                    ?: defaults.allowedTransports,
            backupStatePolicy =
                configService.getPropertyAsString("$webAuthnPrefix.backup-state-policy", null)
                    ?: defaults.backupStatePolicy,
            challengeTtlSeconds =
                configService.getProperty(
                    "$webAuthnPrefix.challenge-ttl-seconds",
                    Long::class,
                    defaults.challengeTtlSeconds,
                ) ?: defaults.challengeTtlSeconds,
            level3PrfEnabled =
                configService.getProperty(
                    "$webAuthnPrefix.level3-prf-enabled",
                    Boolean::class,
                    defaults.level3PrfEnabled,
                ) ?: defaults.level3PrfEnabled,
        )
    }

    private fun loadInternalClients(serverPrefix: String): Map<String, InternalClientConfig> {
        val clients = mutableMapOf<String, InternalClientConfig>()
        val internalClientsPrefix = "$serverPrefix.internal-clients"
        val roleKeys =
            configService
                .getSubProperties(setOf(internalClientsPrefix), stripPrefix = true)
                .keys
                .asSequence()
                .map { keyNormalizer.normalize(it) }
                .mapNotNull { key ->
                    when {
                        key.endsWith(CLIENT_ID_SUFFIX) -> key.removeSuffix(CLIENT_ID_SUFFIX)
                        key.endsWith(CLIENT_SECRET_SUFFIX) -> key.removeSuffix(CLIENT_SECRET_SUFFIX)
                        key.endsWith(GRANT_TYPES_SUFFIX) -> key.removeSuffix(GRANT_TYPES_SUFFIX)
                        key.endsWith(TENANT_ID_SUFFIX) -> key.removeSuffix(TENANT_ID_SUFFIX)
                        key.endsWith(DEFAULT_ACCESS_TOKEN_AUDIENCE_SUFFIX) -> key.removeSuffix(DEFAULT_ACCESS_TOKEN_AUDIENCE_SUFFIX)
                        key.endsWith(ALLOWED_ACCESS_TOKEN_AUDIENCES_SUFFIX) -> key.removeSuffix(ALLOWED_ACCESS_TOKEN_AUDIENCES_SUFFIX)
                        else -> null
                    }?.takeIf { it.isNotBlank() }
                }.distinct()
                .sorted()
        for (roleKey in roleKeys) {
            val clientId = configService.getPropertyAsString("$internalClientsPrefix.$roleKey.client-id", null)
            val clientSecret = configService.getPropertyAsString("$internalClientsPrefix.$roleKey.client-secret", null)
            if (clientId != null && clientSecret != null) {
                clients[roleKey] =
                    InternalClientConfig(
                        clientId = clientId,
                        clientSecret = clientSecret,
                        grantTypes =
                            configService
                                .getPropertyAsString("$internalClientsPrefix.$roleKey.grant-types", null)
                                ?.split(",")
                                ?.map(String::trim)
                                ?.filter(String::isNotEmpty)
                                ?.mapNotNull { configured -> GrantType.entries.firstOrNull { it.value == configured } }
                                ?.toSet()
                                ?.takeIf { it.isNotEmpty() }
                                ?: setOf(GrantType.CLIENT_CREDENTIALS),
                        tenantId =
                            configService
                                .getPropertyAsString("$internalClientsPrefix.$roleKey.tenant-id", null)
                                ?.trim()
                                ?.takeIf { it.isNotEmpty() },
                        defaultAccessTokenAudience =
                            configService
                                .getPropertyAsString("$internalClientsPrefix.$roleKey.default-access-token-audience", null)
                                ?.trim()
                                ?.takeIf { it.isNotEmpty() },
                        allowedAccessTokenAudiences =
                            configService
                                .getPropertyAsString("$internalClientsPrefix.$roleKey.allowed-access-token-audiences", null)
                                ?.split(",")
                                ?.map(String::trim)
                                ?.filter(String::isNotEmpty)
                                ?.toSet()
                                .orEmpty(),
                        tokenExchangeAuthority =
                            configService
                                .getSubProperties(setOf("$internalClientsPrefix.$roleKey.token-exchange"), stripPrefix = true)
                                .entries
                                .associate { (key, value) -> keyNormalizer.normalize(key) to value.toString().trim() },
                    )
            }
        }
        return clients
    }

    private fun readFederationRegistrationMode(
        key: String, default: com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode,
    ): com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode {
        val raw = configService.getPropertyAsString(key, null) ?: return default
        return com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.entries.singleOrNull { it.name == raw.trim().uppercase() }
            ?: error("Unsupported federation automatic-registration mode for $key")
    }

    private fun readFeaturePolicy(
        key: String,
        default: FeaturePolicy,
    ): FeaturePolicy =
        configService
            .getPropertyAsString(key, null)
            ?.let { runCatching { FeaturePolicy.valueOf(it.uppercase()) }.getOrNull() }
            ?: default
}
