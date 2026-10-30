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

package com.sphereon.oauth2.server.authorization.model

import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.model.ResponseType
import kotlinx.serialization.Contextual
import kotlinx.serialization.Serializable

/**
 * Client registration data
 *
 * RFC 7591: OAuth 2.0 Dynamic Client Registration Protocol
 * RFC 7592: OAuth 2.0 Dynamic Client Registration Management Protocol
 */
@Serializable
enum class AuthorizationRequestProofPolicy { NONE, FEDERATED_RP_ASYMMETRIC }

@Serializable
data class ClientRegistration(
    /**
     * Unique client identifier
     */
    val clientId: String,
    /**
     * Client secret (if applicable)
     * Only present for confidential clients
     */
    val clientSecret: String? = null,
    /**
     * Client name
     */
    val clientName: String? = null,
    /**
     * Client type
     */
    val clientType: ClientType = ClientType.CONFIDENTIAL,
    /**
     * Allowed grant types
     * RFC 6749 Section 1.3
     */
    val grantTypes: List<GrantType>,
    /**
     * Allowed response types
     * RFC 6749 Section 3.1.1
     */
    val responseTypes: List<ResponseType> = emptyList(),
    /**
     * Registered redirect URIs
     * RFC 6749 Section 3.1.2: The authorization server MUST require public clients
     * and SHOULD require confidential clients to register their redirection URIs
     */
    val redirectUris: List<String> = emptyList(),
    /**
     * Allowed scopes for this client (null = all scopes allowed)
     */
    val allowedScopes: List<String>? = null,
    /**
     * Exact audience used for access tokens when an authorization request does not carry an RFC
     * 8707 resource indicator. This is configured by the AS client registration; it is never
     * derived from the client id or a request-local non-standard parameter.
     */
    val defaultAccessTokenAudience: String? = null,
    /**
     * Explicit additional audiences this client may request for a client_credentials access
     * token. A request may name several of them at once; every requested audience must be
     * [defaultAccessTokenAudience] or a member of this set. An empty set authorizes no target
     * beyond [defaultAccessTokenAudience].
     */
    val allowedAccessTokenAudiences: Set<String> = emptySet(),
    /**
     * Roles stamped as the `roles` claim on access tokens this client obtains through the
     * client_credentials grant. Empty issues service-scoped tokens without a `roles` claim.
     * Grants that carry a user subject ignore this list.
     */
    val principalRoles: List<String> = emptyList(),
    /**
     * Client authentication method
     * RFC 7591 Section 2: token_endpoint_auth_method
     */
    val tokenEndpointAuthMethod: ClientAuthenticationMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
    /**
     * Signing algorithms accepted on JWT-based client authentication methods
     * (`private_key_jwt`, `client_secret_jwt`). RFC 7591 § 2: `token_endpoint_auth_signing_alg`.
     *
     * `null` = defaults per OIDC Core §9 (RS256 for `private_key_jwt`, HS256 for `client_secret_jwt`).
     * Non-null explicit allow-list that restricts the acceptable assertion `alg` header. `"none"` is
     * never permitted.
     */
    val tokenEndpointAuthSigningAlg: List<String>? = null,
    /**
     * JWKs for client authentication or encryption
     * Used with private_key_jwt or client_secret_jwt
     */
    val jwks: List<Jwk>? = null,
    /**
     * JWK Set URI
     * Alternative to embedding JWKs directly
     */
    val jwksUri: String? = null,
    /**
     * Whether PKCE is required for this client
     * RFC 7636: REQUIRED for public clients
     */
    val requirePkce: Boolean = clientType == ClientType.PUBLIC,
    /**
     * Whether PAR (Pushed Authorization Requests) is required
     * RFC 9126
     */
    val requirePushedAuthorizationRequests: Boolean = false,
    /**
     * Whether DPoP is supported/required
     * RFC 9449
     */
    val dpopBoundAccessTokens: Boolean = false,
    /**
     * Access token lifetime in seconds
     * Default is typically 3600 (1 hour)
     */
    val accessTokenLifetime: Int = 3600,
    /**
     * Refresh token lifetime in seconds
     * null = no expiration
     */
    val refreshTokenLifetime: Int? = null,
    /**
     * Authorization code lifetime in seconds
     * Default is 600 (10 minutes), MUST be short-lived
     */
    val authorizationCodeLifetime: Int = 600,
    /**
     * Allow-list of OID4VCI `credential_configuration_id` values this client is permitted to
     * request via RFC 9396 `authorization_details`. `null` = unrestricted (pre-S2-3 behaviour).
     * `emptySet()` = explicitly forbid any credential request. Populated set = strict allow-list.
     */
    val credentialConfigurationIds: Set<String>? = null,
    /**
     * Trusted attester issuers for attestation-based client auth
     * (draft-ietf-oauth-attestation-based-client-auth §4). When non-null, the attestation JWT's
     * `iss` claim MUST be a member; `null` skips the issuer allow-list check.
     */
    val trustedAttesterIssuers: List<String>? = null,
    /**
     * Inline JWKs the AS will accept on attestation JWT signatures for this client. Mirrors the
     * shape of [jwks]: a flat list of public keys keyed by `kid` at verification time. The
     * verifier pins these as the trusted JWKS for the attestation JWT, refusing embedded
     * `jwk` / `x5c` headers and external identifier resolvers per
     * draft-ietf-oauth-attestation-based-client-auth §4 trust model.
     */
    val trustedAttesterJwks: List<Jwk>? = null,
    /**
     * URIs that publish the attester's public JWKS document. Alternative to [trustedAttesterJwks]
     * when the attester rotates keys out-of-band. The verifier dereferences and pins each URI
     * at verification time. May be combined with [trustedAttesterJwks]; the union forms the
     * acceptable signer set.
     */
    val trustedAttesterJwksUris: List<String>? = null,
    /**
     * Registered redirect URIs the RP may pass as `post_logout_redirect_uri` on the
     * OIDC RP-Initiated Logout end-session endpoint. Validation is exact-match per
     * RP-Initiated Logout 1.0 §2: an unregistered value causes the AS to skip the
     * post-logout redirect and render its own logged-out confirmation page instead.
     */
    val postLogoutRedirectUris: List<String> = emptyList(),
    /**
     * RP front-channel logout URI per OIDC Front-Channel Logout 1.0 §3.1. When the
     * AS receives an end-session request, it embeds an `<iframe>` pointing at this
     * URI so the RP can clear its browser-side session in-band. Empty / `null`
     * means the client does not support front-channel logout.
     */
    val frontchannelLogoutUri: String? = null,
    /**
     * When `true`, the AS appends `iss` and `sid` query parameters to the front-
     * channel logout iframe URL so the RP can correlate the logout to a specific
     * AS session, per OIDC Front-Channel Logout 1.0 §3 `frontchannel_logout_session_required`.
     * Ignored when [frontchannelLogoutUri] is `null`.
     */
    val frontchannelLogoutSessionRequired: Boolean = false,
    /**
     * OIDC Dynamic Client Registration `id_token_signed_response_alg`.
     * When set, ID tokens issued to this client use the named JWS algorithm. The server rejects
     * token creation when that algorithm is not advertised or no matching active private key is
     * available. A null value uses the authorization server's default active signing key.
     */
    val idTokenSignedResponseAlg: String? = null,
    /**
     * JARM `authorization_signed_response_alg` per OIDF JARM spec
     * (https://openid.net/specs/oauth-v2-jarm.html). When non-null, authorization responses for
     * this client (in any `*.jwt` response mode) are signed with the named JWS algorithm.
     * `null` means the client does not opt into JARM signing. The AS rejects a JARM response
     * mode request when this is unset and JARM is enabled at the server level.
     */
    val authorizationSignedResponseAlg: String? = null,
    /**
     * JARM `authorization_encrypted_response_alg` per OIDF JARM spec. JWE key-encryption
     * algorithm. When set together with [authorizationSignedResponseAlg], JARM uses
     * sign-then-encrypt; with [authorizationEncryptedResponseEnc], encryption-only.
     */
    val authorizationEncryptedResponseAlg: String? = null,
    /**
     * JARM `authorization_encrypted_response_enc` per OIDF JARM spec. JWE content-encryption
     * algorithm; defaults to `A256GCM` at the JARM library when omitted.
     */
    val authorizationEncryptedResponseEnc: String? = null,
    /**
     * RP back-channel logout URI per OIDC Back-Channel Logout 1.0 §2.5. The AS
     * POSTs a signed `logout_token` JWT to this URI when terminating a session
     * the RP participated in. Empty / `null` means the client does not support
     * back-channel logout.
     */
    val backchannelLogoutUri: String? = null,
    /**
     * When `true`, the `logout_token` minted for this client carries the `sid`
     * claim per OIDC Back-Channel Logout 1.0 §2.4 `backchannel_logout_session_required`.
     * Ignored when [backchannelLogoutUri] is `null`.
     */
    val backchannelLogoutSessionRequired: Boolean = false,
    /**
     * RFC 9101 §5.2.2 / OIDC Core §2 `request_object_signing_alg`: pinned JWS algorithm the AS
     * accepts on signed authorization requests (JAR) for this client. When non-null, JARs whose
     * header `alg` differs are rejected with `invalid_request_object`. When `null`, any algorithm
     * advertised in the server's `request_object_signing_alg_values_supported` list is accepted
     * (still subject to the `none`-is-forbidden rule).
     */
    val requestObjectSigningAlg: String? = null,
    /**
     * Request Objects from this client are single-use proofs of key possession: each must carry a `jti` that is
     * accepted once, must not carry `sub`, and must name this server as its only audience. Set for clients that
     * register implicitly through their first signed request.
     */
    val singleUseRequestObjects: Boolean = false,
    /**
     * Epoch seconds after which this registration is no longer served, for registrations that last only as long as
     * the trust they were made under. Null for a registration without expiry.
     */
    val expiresAt: Long? = null,
    /**
     * RFC 9101 §5.2.2 / OIDC Core §2 `request_uris`: pre-registered list of URIs the client may
     * use as `request_uri` at the authorization endpoint. Empty list means no pre-registration.
     * Consulted only when the server is configured with
     * [com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.requireRequestUriRegistration]
     * = `true`; otherwise the AS accepts any HTTPS URI the client supplies.
     */
    val requestUris: List<String> = emptyList(),
    /**
     * RFC 8705 §2.1.2.1: subject DN the AS expects on the TLS client certificate when this
     * client uses `tls_client_auth`. Compared against the cert's RFC 4514 canonical DN.
     * Mutually exclusive with the `tlsClientAuthSan*` family: registration MUST set exactly
     * one of (subject DN, dnsName SAN, email SAN, IP SAN, URI SAN). Ignored when the
     * registered method is `self_signed_tls_client_auth` or anything other than mTLS.
     */
    val tlsClientAuthSubjectDn: String? = null,
    /**
     * RFC 8705 §2.1.2.2: dNSName SAN the AS expects on the TLS client certificate.
     */
    val tlsClientAuthSanDns: String? = null,
    /**
     * RFC 8705 §2.1.2.3: rfc822Name SAN (email) the AS expects on the TLS client certificate.
     */
    val tlsClientAuthSanEmail: String? = null,
    /**
     * RFC 8705 §2.1.2.4: iPAddress SAN the AS expects on the TLS client certificate.
     */
    val tlsClientAuthSanIp: String? = null,
    /**
     * RFC 8705 §2.1.2.5: uniformResourceIdentifier SAN the AS expects on the TLS client
     * certificate.
     */
    val tlsClientAuthSanUri: String? = null,
    /**
     * RFC 8705 §3.1: when `true`, access tokens minted for this client carry a `cnf.x5t#S256`
     * confirmation claim bound to the TLS client certificate presented at the token endpoint.
     * Subsequent resource-server requests MUST then be made over mTLS with a certificate
     * whose SHA-256 thumbprint matches. Per-client opt-in overrides the server-wide default
     * [com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig.tlsClientCertificateBoundAccessTokens].
     */
    val tlsClientCertificateBoundAccessTokens: Boolean = false,
    /**
     * Identifiers of [com.sphereon.oauth2.server.authorization.policy.ClientPolicy] bundles
     * the AS applies to requests on behalf of this client. The AS's
     * [com.sphereon.oauth2.server.authorization.policy.ClientPolicyResolver] looks each id
     * up in the [com.sphereon.oauth2.server.authorization.policy.ClientPolicyRegistry] at
     * request time and runs the matched executors.
     *
     * Empty list (the default) means policy-driven enforcement is OFF for this client —
     * the AS still honours the per-flag legacy fields ([requirePkce], [requirePushedAuthorizationRequests]
     * etc.). Attaching policy ids is additive: a flag that's `false` on the client but
     * required by an attached policy is still enforced (policies cannot weaken individual
     * client flags, only strengthen them). See [com.sphereon.oauth2.server.authorization.policy.ClientPolicy].
     */
    val policyIds: List<String> = emptyList(),
    /**
     * Additional client metadata
     */
    val additionalMetadata: Map<String, @Contextual Any> = emptyMap(),
    /**
     * Registration-controlled token-exchange authority. Attribute names and values are interpreted
     * only by the deployment's token-exchange profile. They are bound from server-side
     * configuration, are never accepted from dynamic registration and are never minted as claims.
     */
    val tokenExchangeAuthority: Map<String, String> = emptyMap(),
    /** Process-owned external-source policy; never client metadata or durable registration authority. */
    @kotlinx.serialization.Transient
    val authorizationRequestProofPolicy: AuthorizationRequestProofPolicy = AuthorizationRequestProofPolicy.NONE,
)

/**
 * Client type
 *
 * RFC 6749 Section 2.1: Clients are categorized into confidential and public clients
 */
enum class ClientType {
    /**
     * Confidential clients are capable of maintaining the confidentiality of their credentials
     * (e.g., server-side applications)
     */
    CONFIDENTIAL,

    /**
     * Public clients are incapable of maintaining the confidentiality of their credentials
     * (e.g., mobile apps, SPAs, native apps)
     */
    PUBLIC,
}
