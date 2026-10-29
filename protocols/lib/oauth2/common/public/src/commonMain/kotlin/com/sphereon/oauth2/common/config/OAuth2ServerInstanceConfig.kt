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

import com.sphereon.core.compat.JsExportCompat
import com.sphereon.oauth2.common.model.GrantType
import kotlinx.serialization.Serializable

@JsExportCompat
@Serializable
data class InternalClientConfig(
    val clientId: String,
    val clientSecret: String,
    /** OAuth grants this confidential workload client may use. */
    val grantTypes: Set<GrantType> = setOf(GrantType.CLIENT_CREDENTIALS),
    /** Server-controlled tenant claim for this workload client, if tenant-bound. */
    val tenantId: String? = null,
    val defaultAccessTokenAudience: String? = null,
    val allowedAccessTokenAudiences: Set<String> = emptySet(),
    /**
     * Registration-controlled token-exchange authority. Attribute names and values are interpreted
     * only by the deployment's token-exchange profile. They are bound from server-side
     * configuration, are never accepted from dynamic registration and are never minted as claims.
     */
    val tokenExchangeAuthority: Map<String, String> = emptyMap(),
)

/**
 * Configuration for a single authorization server instance.
 *
 * Each instance can operate in HOSTED mode (IDK serves as the AS)
 * or EXTERNAL mode (IDK connects to this AS as an OAuth2 client).
 */
@JsExportCompat
@Serializable
enum class FederatedAuthorizationRequestMode { PAR_ONLY, SIGNED_JAR_OR_AUTHENTICATED_PAR }

@JsExportCompat
@Suppress("NON_EXPORTABLE_TYPE")
@Serializable
data class OAuth2ServerInstanceConfig(
    // Identity
    val mode: AuthorizationServerMode = AuthorizationServerMode.HOSTED,
    val issuerTemplate: String? = null,
    val issuer: String? = null,
    // Token lifetimes (HOSTED mode)
    val accessTokenLifetimeSeconds: Int = 3600,
    val refreshTokenLifetimeSeconds: Int = 86400,
    val authorizationCodeLifetimeSeconds: Int = 600,
    val tokenFormat: TokenFormat = TokenFormat.JWT,
    val refreshTokenRotation: Boolean = true,
    /**
     * Grace period for retrying a refresh token that has just been rotated.
     *
     * FAPI 2.0 clients can lose the successful rotation response and retry the previous token.
     * During this window the AS returns the already-created successor token instead of creating
     * a second branch in the refresh-token chain. Reuse after the window remains `invalid_grant`.
     */
    val refreshTokenRetryGracePeriodSeconds: Int = 60,
    // Grant types & response types
    val grantTypesEnabled: Set<String> = setOf("authorization_code", "client_credentials", "refresh_token"),
    // OIDC Core §3 — `code` is OAuth2 Authorization Code (Basic Profile). The hybrid trio
    // (`code id_token`, `code token`, `code id_token token`) covers OIDC Core §3.3 Hybrid
    // Flow. Pure-implicit (`id_token`, `id_token token`) is INTENTIONALLY OMITTED — RFC 9700
    // / OAuth 2.1 deprecate it (token leakage in URL fragment, no CSRF protection at
    // issuance). Operators who need it can opt in by overriding this set.
    val responseTypesSupported: Set<String> =
        setOf(
            "code",
            "code id_token",
            "code token",
            "code id_token token",
        ),
    val scopesSupported: List<String>? = null,
    /**
     * RFC 9396 authorization-detail type identifiers accepted by this authorization server.
     * OID4VCI 1.0 uses `openid_credential` when a credential configuration has no scope.
     */
    val authorizationDetailsTypesSupported: List<String>? = null,
    // OpenID Connect
    val oidc: FeaturePolicy = FeaturePolicy.DISABLED,
    /**
     * OIDC logout feature policy (RP-Initiated Logout 1.0, Back-Channel Logout 1.0,
     * Front-Channel Logout 1.0). Default [FeaturePolicy.DISABLED] so discovery metadata does
     * NOT advertise `end_session_endpoint` / `*_logout_supported` until a deployment explicitly
     * opts in — OIDF Basic OP runs leave this off. When enabled, the end-session endpoint is
     * expected on the EDK auth HTTP adapter (see [endSessionEndpoint] construction in
     * `BuildServerMetadataCommandImpl`).
     */
    val logout: FeaturePolicy = FeaturePolicy.DISABLED,
    val idTokenLifetimeSeconds: Int = 3600,
    val subjectTypesSupported: List<String> = listOf("public"),
    val claimsSupported: List<String>? = null,
    val userinfoSigningAlgValuesSupported: Set<String>? = null,
    /**
     * When `true`, the AS embeds every projected user claim (the same set served from
     * `/userinfo`) directly into the id_token, regardless of whether the response_type
     * also issues an access_token. Defaults to `false`, which is OIDC Core §5.4
     * conformant — profile/email/address/phone scope claims live on `/userinfo` for
     * code/hybrid flows and only land in the id_token for pure `response_type=id_token`.
     *
     * Use this knob when you have RPs that consume the id_token without ever calling
     * `/userinfo` (Auth.js v5 with default settings, simple SPA bearer-token clients,
     * legacy SAML-bridge consumers expecting all claims in the assertion). It deviates
     * from §5.4, so the OIDC Basic OP conformance suite's
     * `EnsureIdTokenDoesNotContainNonRequestedClaims` will warn — turn it off for
     * conformance runs.
     *
     * Per-client overrides (when the IDK adds them) win over this server-level default.
     */
    val embedUserinfoClaimsInIdToken: Boolean = false,
    // Feature policies
    val introspection: FeaturePolicy = FeaturePolicy.SUPPORTED,
    val revocation: FeaturePolicy = FeaturePolicy.SUPPORTED,
    val par: FeaturePolicy = FeaturePolicy.SUPPORTED,
    /**
     * Require every pushed authorization request to carry an explicit `redirect_uri`.
     *
     * Baseline OAuth 2.0 permits omission when the client has exactly one registered redirect
     * URI. FAPI 2.0 Security Profile section 5.3.2.1 deliberately tightens that rule, so HAIP
     * deployments enable this policy through their authorization-server REST configuration.
     */
    val requireRedirectUriInPushedAuthorizationRequests: Boolean = false,
    val tokenExchange: FeaturePolicy = FeaturePolicy.DISABLED,
    /**
     * RFC 8628 (OAuth 2.0 Device Authorization Grant) feature policy. Gates whether the AS
     * exposes the `/device_authorization` endpoint, accepts the
     * `urn:ietf:params:oauth:grant-type:device_code` grant at `/token`, and advertises
     * `device_authorization_endpoint` in discovery. Default [FeaturePolicy.DISABLED] so OIDF
     * Basic OP runs and any deployment that does not target input-constrained devices keeps the
     * surface entirely off until opted in.
     */
    val deviceFlow: FeaturePolicy = FeaturePolicy.DISABLED,
    /**
     * RFC 8628 §3.2 `expires_in`: lifetime (seconds) of an issued device-authorization record
     * before it transitions to `expired_token`. Default 1800s (30 minutes) matches typical IdP
     * guidance and gives the user-agent enough headroom for the verification step on a phone.
     */
    val deviceCodeLifetimeSeconds: Int = 1800,
    /**
     * RFC 8628 §3.2 `interval`: minimum number of seconds the client SHOULD wait between polling
     * requests at `/token`. Default 5s. A `slow_down` response bumps the per-record interval by
     * 5s on top of this baseline (RFC 8628 §3.5).
     */
    val devicePollIntervalSeconds: Int = 5,
    val pkce: FeaturePolicy = FeaturePolicy.REQUIRED,
    /**
     * RFC 8414 §2 `signed_metadata`: when [FeaturePolicy.SUPPORTED] (or stricter), the AS
     * additionally embeds a JWS-signed copy of its discovery metadata under the
     * `signed_metadata` JSON member. RPs that pin a key for the AS verify the JWS
     * (header carries `kid` matching JWKS) and trust the signed copy over the unsigned
     * one — defends against metadata tampering between the AS and the RP. The AS
     * always returns the unsigned fields too; signed_metadata is additive.
     *
     * Default [FeaturePolicy.DISABLED] so OIDF Basic conformance (which does NOT
     * require signed metadata) is unaffected; deployments that need to publish a
     * signed copy opt in by setting this to SUPPORTED or REQUIRED.
     */
    val signedMetadata: FeaturePolicy = FeaturePolicy.DISABLED,
    val dpop: FeaturePolicy = FeaturePolicy.SUPPORTED,
    /**
     * RFC 9449 §8: when `true`, the AS REQUIRES the DPoP proof JWT to carry a `nonce` claim
     * equal to a server-issued nonce. Proofs without a nonce, or carrying a stale nonce, are
     * rejected with `use_dpop_nonce` and the response includes a fresh `DPoP-Nonce` header.
     * When `false` (default), nonce challenges are not initiated, but the AS still emits the
     * `DPoP-Nonce` header on DPoP-bearing responses so clients can opt in proactively.
     */
    val dpopNonceRequired: Boolean = false,
    val iae: FeaturePolicy = FeaturePolicy.DISABLED,
    // Auth methods
    val pkceMethodsSupported: Set<String> = setOf("S256"),
    val tokenEndpointAuthMethodsSupported: Set<String> = setOf("client_secret_basic", "client_secret_post"),
    val introspectionEndpointAuthMethodsSupported: Set<String> = setOf("client_secret_basic"),
    val revocationEndpointAuthMethodsSupported: Set<String> = setOf("client_secret_basic", "client_secret_post"),
    val dpopSigningAlgValuesSupported: Set<String>? = null,
    // RFC 8705: OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens.
    // [mtls] gates whether the AS accepts `tls_client_auth` and `self_signed_tls_client_auth`
    // at the token endpoint and whether discovery advertises `mtls_endpoint_aliases`.
    // [tlsClientCertificateBoundAccessTokens] is the server-wide default for whether issued
    // access tokens are bound to the presented TLS certificate via `cnf.x5t#S256` (RFC 8705 §3);
    // per-client opt-in on [com.sphereon.oauth2.server.authorization.model.ClientRegistration]
    // overrides this default.
    // [mtlsEndpointHostOverride] supplies the hostname used in `mtls_endpoint_aliases` when the
    // operator deploys a separate mTLS-only host (RFC 8705 §5). When `null`, aliases reuse the
    // regular issuer host so the operator's TLS-terminating proxy can route based on path alone.
    val mtls: FeaturePolicy = FeaturePolicy.DISABLED,
    val tlsClientCertificateBoundAccessTokens: Boolean = false,
    val mtlsEndpointHostOverride: String? = null,
    // Attestation-based client auth (draft-ietf-oauth-attestation-based-client-auth)
    val attestation: FeaturePolicy = FeaturePolicy.DISABLED,
    val attestationChallengeRequired: Boolean = false,
    val clientAttestationSigningAlgValuesSupported: Set<String>? = null,
    val clientAttestationPopSigningAlgValuesSupported: Set<String>? = null,
    val attestationMaxLifetimeSeconds: Int = 3600,
    val attestationPopMaxAgeSeconds: Int = 120,
    // Per draft-ietf-oauth-attestation-based-client-auth-08 §10.5 / §12.1 the AS keeps a sliding
    // window of seen PoP `jti` values to detect replays. The window is anchored on the PoP `iat`;
    // any PoP whose iat lies outside it is rejected by the freshness check above, so this only
    // bounds how long a jti needs to stay in the dedup table. Default 600s gives ample headroom
    // around the 120s freshness window without growing the table unnecessarily.
    val attestationPopJtiReplayWindowSeconds: Int = 600,
    /**
     * Wallet Instance Attestation (WIA) production enforcement for PAR and token
     * attestation-based client authentication. This is intentionally separate from the generic
     * OAuth client-attestation feature above: [attestation] accepts the OAuth2 client-auth method,
     * while [walletInstanceAttestation] decides whether the AS must bind that authentication to
     * persisted Wallet Unit evidence, status evidence, and trust evidence.
     *
     * REQUIRED is production mode and fails closed when no persisted-evidence enforcer is bound.
     * SUPPORTED only advertises the capability; backendless/local IDK flows cannot satisfy
     * REQUIRED by construction.
     */
    val walletInstanceAttestation: FeaturePolicy = FeaturePolicy.DISABLED,
    /**
     * Optional client-status refresh period advertised in AS metadata when WIA is enabled.
     * The value is seconds and maps to the discovery field `preferred_client_status_period`.
     */
    val preferredClientStatusPeriodSeconds: Int? = null,
    // JARM (OpenID Foundation JWT Secured Authorization Response Mode for OAuth 2.0,
    // https://openid.net/specs/oauth-v2-jarm.html). Gated DISABLED by default so discovery
    // does not advertise JARM signing/encryption metadata or `*.jwt` response modes until a
    // deployment opts in. When enabled, [authorizationSigningAlgValuesSupported] /
    // [authorizationEncryptionAlgValuesSupported] / [authorizationEncryptionEncValuesSupported]
    // describe what the AS can mint, and the per-client metadata fields
    // (`authorizationSignedResponseAlg`, `authorizationEncryptedResponseAlg`,
    // `authorizationEncryptedResponseEnc` on [com.sphereon.oauth2.server.authorization.model.ClientRegistration])
    // pin the actual algorithms used for that client.
    val jarm: FeaturePolicy = FeaturePolicy.DISABLED,
    val authorizationSigningAlgValuesSupported: Set<String>? = null,
    val authorizationEncryptionAlgValuesSupported: Set<String>? = null,
    val authorizationEncryptionEncValuesSupported: Set<String>? = null,
    /**
     * JARM JWT lifetime (seconds). Per the OIDF JARM spec the response JWT is short-lived; 600s
     * (10 minutes) is the spec's recommended ceiling. Default 300s (5 minutes) leaves headroom
     * for clock skew while staying well within the spec recommendation.
     */
    val jarmExpirationSeconds: Long = 300,
    /**
     * RFC 9101 (JAR) feature policy. Controls whether the AS accepts `request` (inline signed JWT)
     * and `request_uri` parameters at `/authorize` and `/par`. When enabled, discovery advertises
     * `request_parameter_supported=true`, `request_uri_parameter_supported=true`, and the
     * `request_object_signing_alg_values_supported` list. Default [FeaturePolicy.SUPPORTED] so
     * FAPI 2.0 deployments work without extra wiring; deployments that want to refuse JAR (and
     * have the AS fall back to the legacy `request_not_supported` path) flip to
     * [FeaturePolicy.DISABLED].
     */
    val jar: FeaturePolicy = FeaturePolicy.SUPPORTED,
    /**
     * RFC 9101 §5.2.2: when `true`, only `request_uri` values that are pre-registered for the
     * client via [com.sphereon.oauth2.server.authorization.model.ClientRegistration.requestUris]
     * are accepted. Discovery advertises `require_request_uri_registration=true`. Default `false`
     * so well-known JAR clients can host the request object at any HTTPS URL they control.
     */
    val requireRequestUriRegistration: Boolean = false,
    // Signing key references are no longer carried on this config — the AS now owns a
    // SigningKeyStore SPI (vdx/edk/idk/lib/oauth2/server/authorization/public/.../storage/
    // SigningKeyStore.kt) that tracks one or more keys per tenant in a state machine
    // (ACTIVE / LEGACY / DISABLED). The active signer is resolved by reading the store at
    // session-start time; multi-key JWKS publication uses listPublishable. See P0-K4 in the
    // security plan for the rotation rationale.
    // Algorithms (null = auto-discover from KMS for HOSTED, or from metadata for EXTERNAL)
    val signingAlgorithmsSupported: Set<String>? = null,
    val idTokenSigningAlgValuesSupported: Set<String>? = null,
    /**
     * RFC 9101 §5.2.2: list of JWS `alg` values the AS accepts on signed JARs. When `null`, the
     * AS derives the list from its server signing key (mirrors the
     * [idTokenSigningAlgValuesSupported] auto-derivation). `none` is never accepted regardless of
     * what is configured here, per RFC 9101 §6 / OIDC Core §6.1.
     */
    val requestObjectSigningAlgValuesSupported: Set<String>? = null,
    // EXTERNAL mode: client credentials for connecting to this AS
    val tokenEndpointAuthMethod: String? = null,
    val clientId: String? = null,
    val clientSecret: String? = null,
    // EXTERNAL mode: endpoint overrides (if not using metadata discovery)
    val tokenEndpoint: String? = null,
    val introspectionEndpoint: String? = null,
    val revocationEndpoint: String? = null,
    val jwksUri: String? = null,
    // Internal service-to-service clients (role → client configuration)
    val internalClients: Map<String, InternalClientConfig> = emptyMap(),
    // Public client policy for authorization code flow (OID4VCI wallets)
    // Browser-login session lifetimes (OIDC Core 1.0 §2 auth_time, prompt/max_age semantics)
    val session: SessionConfig = SessionConfig(),
    val webAuthn: WebAuthnLoginConfig = WebAuthnLoginConfig(),
    val login: LoginPageConfig = LoginPageConfig(),
    /**
     * Optional plain-text notice rendered above the credential form on the AS login page (for
     * example, a demo deployment advertising its seeded test account). Null or blank renders
     * nothing, so production deployments that never set it carry no extra markup. The renderer
     * treats this as plain text and HTML-escapes it. Config key:
     * `${CONFIG_PREFIX}.<asId>.login-notice`.
     */
    val loginNotice: String? = null,
    /**
     * Whether the AS may derive its outbound URL scheme/host from `X-Forwarded-Proto` /
     * `X-Forwarded-Host` / `Host` request headers when [issuer] is not configured. Defaults to
     * `true` so existing dev deployments behind a single trusted reverse proxy keep working
     * without explicit issuer configuration.
     *
     * Operators MUST set [issuer] to a fixed external URL in production. When [issuer] is set
     * the AS already prefers it over header reconstruction, so this flag has no effect — its
     * sole purpose is to lock down the no-issuer fallback in deployments that cannot or will
     * not configure the issuer URL but still want to refuse header-driven scheme/host
     * derivation. With `false` and no issuer, scheme defaults to `https` and the host to the
     * literal `host` header value (which the operator must validate at the transport layer).
     *
     * Recommended production posture: configure [issuer] AND set this to `false`.
     */
    val trustForwardedHeaders: Boolean = true,
    /**
     * Which client-registry source is authoritative for this authorization server when a client
     * id exists both in persistent storage and in configuration.
     *
     * A tenant authorization server keeps the default: its administered, durable registrations
     * are primary and configuration is the secondary source. A platform authorization server is
     * provisioned from configuration, so it sets [ClientRegistrySourcePrecedence.CONFIGURATION_PRIMARY].
     */
    val clientRegistrySourcePrecedence: ClientRegistrySourcePrecedence = ClientRegistrySourcePrecedence.PERSISTENCE_PRIMARY,
    /** Normal federation admission capability; existing PAR-only behavior is the default. */
    val federationAutomaticRegistrationMode: FederatedAuthorizationRequestMode = FederatedAuthorizationRequestMode.PAR_ONLY,
) {
    /** Resolve this already-selected server's issuer without reading configuration again. */
    fun resolveIssuer(serverId: String, tenantId: String): String =
        when {
            issuer != null -> issuer
            issuerTemplate != null -> issuerTemplate.replace("{tenant-id}", tenantId)
            else -> error(
                "OAuth2 server '$serverId' has no issuer configured; " +
                    "set oauth2.servers.$serverId.issuer or oauth2.servers.$serverId.issuer-template",
            )
        }

    companion object {
        const val CONFIG_PREFIX = "oauth2.servers"
    }
}

@JsExportCompat
@Serializable
enum class LoginMethod {
    PASSWORD,
    FEDERATION,
    WALLET,
}

@JsExportCompat
@Serializable
enum class LoginInteraction {
    AUTO,
    CHOOSER,
}

@JsExportCompat
@Serializable
enum class LoginRenderer {
    SPHEREON,
    NEUTRAL,
}

@JsExportCompat
@Serializable
data class LoginPageConfig(
    val interaction: LoginInteraction = LoginInteraction.AUTO,
    val renderer: LoginRenderer = LoginRenderer.SPHEREON,
    val themeResolutionEnabled: Boolean = true,
    val showPasswordForm: Boolean = true,
    val showFederation: Boolean = true,
    val showWallet: Boolean = false,
    val walletAuthorizationUrl: String? = null,
    val defaultMethod: LoginMethod = LoginMethod.PASSWORD,
) {
    fun enabledMethodCount(): Int =
        listOf(showPasswordForm, showFederation, showWallet).count { it }

    fun requiresChooser(): Boolean = interaction == LoginInteraction.CHOOSER
}

@JsExportCompat
@Suppress("NON_EXPORTABLE_TYPE")
@Serializable
data class WebAuthnLoginConfig(
    val enabled: Boolean = false,
    val rpId: String? = null,
    val allowedOrigins: Set<String> = emptySet(),
    val attestationPolicy: String = "none",
    val userVerification: String = "required",
    val allowedTransports: Set<String> = emptySet(),
    val backupStatePolicy: String = "allow-any",
    val challengeTtlSeconds: Long = 300,
    val level3PrfEnabled: Boolean = false,
)

/**
 * TTLs for the OIDC browser-login session backing the `oidc_login_sid` cookie.
 *
 * Two ceilings apply jointly: [idleTtlSeconds] caps inactivity between authorization requests,
 * [absoluteTtlSeconds] caps total wall-clock lifetime. The shorter of the two wins on every
 * lookup. Defaults follow common IdP guidance (30 minutes idle, 8 hours absolute).
 *
 * Config keys (under `${OAuth2ServerInstanceConfig.CONFIG_PREFIX}.<asId>`):
 * - `session.idle-ttl-seconds`
 * - `session.absolute-ttl-seconds`
 */
@JsExportCompat
@Serializable
data class SessionConfig(
    val idleTtlSeconds: Int = DEFAULT_IDLE_TTL_SECONDS,
    val absoluteTtlSeconds: Int = DEFAULT_ABSOLUTE_TTL_SECONDS,
) {
    companion object {
        const val DEFAULT_IDLE_TTL_SECONDS: Int = 1800
        const val DEFAULT_ABSOLUTE_TTL_SECONDS: Int = 28800
    }
}
