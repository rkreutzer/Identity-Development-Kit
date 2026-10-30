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

package com.sphereon.oauth2.client.command

import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.ServiceCommand
import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.oauth2.common.model.AuthorizationServerMetadata
import com.sphereon.oauth2.common.model.IdTokenPayload
import com.sphereon.oauth2.common.model.TokenResponse
import kotlinx.serialization.Serializable

/*
 * Relying Party side of OpenID Federation for OpenID Connect 1.1, Section 12.1 (Automatic Registration).
 *
 * The RP uses its Entity Identifier as `client_id` and has no registration step: the OP resolves the RP's Trust
 * Chain from the Request Object or the client authentication it receives. The RP proves control of the keys it
 * publishes in its `openid_relying_party` metadata (its protocol keys, separate from its Federation Entity Keys)
 * with a signed Request Object and with `private_key_jwt`.
 *
 * Trust Chain resolution of the OP is the caller's job: the RP MUST resolve the OP's Trust Chain and metadata to a
 * Trust Anchor it accepts before it sends anything (§12.1). These commands take that result as a
 * [FederatedOpenIdProvider] and never read the OP's unsigned discovery documents.
 */

/**
 * An OpenID Provider whose Trust Chain the caller resolved and verified to [trustAnchor].
 *
 * @property entityIdentifier The OP's Entity Identifier. It is the OP's issuer, the only Request Object and client
 *   assertion audience, and the expected ID Token `iss`.
 * @property metadata The OP's Resolved Metadata for `openid_provider`, after the metadata policies of the chain.
 * @property signingKeys The keys the OP publishes for `openid_provider` (`jwks`, `signed_jwks_uri` or `jwks_uri`),
 *   used to verify ID Tokens.
 * @property validUntilEpochSeconds The earliest expiry in the Trust Chain. Nothing is sent after it.
 */
data class FederatedOpenIdProvider(
    val entityIdentifier: String,
    val trustAnchor: String,
    val metadata: AuthorizationServerMetadata,
    val signingKeys: List<Jwk>,
    val validUntilEpochSeconds: Long,
)

/**
 * The Relying Party as registered by its Entity Configuration.
 *
 * @property entityIdentifier The RP's Entity Identifier, used as `client_id` and as `iss` of everything it signs.
 * @property redirectUri One of the `redirect_uris` in the RP's `openid_relying_party` metadata.
 * @property signingKey The private protocol key. Its public key is in the RP's `openid_relying_party` JWK Set.
 * @property signingKeyId The `kid` of that key in the RP's JWK Set.
 * @property signingAlgorithm The JWS algorithm for the Request Object and the client assertion. It is the RP's
 *   registered `request_object_signing_alg` and `token_endpoint_auth_signing_alg`.
 * @property idTokenSignedResponseAlg The RP's registered `id_token_signed_response_alg` (RS256 when it registers
 *   none, OpenID Connect Dynamic Client Registration 1.0 §2).
 */
data class FederatedRelyingParty(
    val entityIdentifier: String,
    val redirectUri: String,
    val signingKey: KeyInfoType<*>,
    val signingKeyId: String,
    val signingAlgorithm: String,
    val idTokenSignedResponseAlg: String = "RS256",
)

/** How the Authentication Request reaches the OP (§12.1.1). */
enum class FederatedAuthenticationRequestTransport {
    /** PAR when the OP has a `pushed_authorization_request_endpoint`, otherwise the Request Object by value. */
    AUTO,

    /** RFC 9126 PAR carrying the Request Object, with `private_key_jwt` at the PAR endpoint (§12.1.1.2). */
    PUSHED_AUTHORIZATION_REQUEST,

    /** The Request Object by value in the `request` parameter at the Authorization Endpoint (§12.1.1.1). */
    REQUEST_OBJECT,
}

data class StartFederatedAuthenticationArgs(
    val provider: FederatedOpenIdProvider,
    val relyingParty: FederatedRelyingParty,
    val scope: String = "openid",
    val transport: FederatedAuthenticationRequestTransport = FederatedAuthenticationRequestTransport.AUTO,
    /**
     * The RP's own Trust Chain to the Trust Anchor it selected, sent in the `trust_chain` JWS header parameter of the
     * Request Object (OpenID Federation 1.1 §4.3). The OP may use it as a hint; it still verifies every statement.
     */
    val trustChain: List<String>? = null,
    val loginHint: String? = null,
    val prompt: String? = null,
    val acrValues: String? = null,
    /** Lifetime of the Request Object and the client assertion, at most 300 seconds. */
    val lifetimeSeconds: Long = 120,
)

/**
 * The state the RP keeps between the Authentication Request and the redirect back. It holds the PKCE verifier, so
 * store it server-side, bound to the user agent, and use it once.
 */
@Serializable
data class FederatedAuthenticationTransaction(
    val providerEntityIdentifier: String,
    val clientId: String,
    val redirectUri: String,
    val state: String,
    val nonce: String,
    val codeVerifier: String,
    val pushed: Boolean,
    val createdAtEpochSeconds: Long,
)

data class FederatedAuthenticationRequest(
    /** Where to send the user agent. For PAR it carries only `client_id` and `request_uri`. */
    val authorizationUrl: String,
    val transaction: FederatedAuthenticationTransaction,
    /** The `request_uri` the PAR endpoint returned, when PAR was used. */
    val requestUri: String? = null,
)

/**
 * Builds and sends the Authentication Request of an RP that registers automatically (§12.1.1): a signed Request
 * Object (`typ` `oauth-authz-req+jwt`, `aud` the OP's Entity Identifier, `iss` and `client_id` the RP's Entity
 * Identifier, a unique `jti`, `exp`, no `sub`) with PKCE, pushed to the PAR endpoint with `private_key_jwt` or passed
 * by value.
 */
interface StartFederatedAuthenticationCommand :
    ServiceCommand<StartFederatedAuthenticationArgs, FederatedAuthenticationRequest, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.federation-rp.start"
    }
}

data class CompleteFederatedAuthenticationArgs(
    /** The OP as resolved for this login; its Entity Identifier must match the transaction. */
    val provider: FederatedOpenIdProvider,
    val relyingParty: FederatedRelyingParty,
    val transaction: FederatedAuthenticationTransaction,
    /** The full redirect URL the OP sent the user agent to, with its query parameters. */
    val callbackUrl: String,
)

data class FederatedAuthenticationResult(
    val accessToken: String,
    val tokenType: String?,
    val refreshToken: String?,
    val idToken: String,
    val idTokenClaims: IdTokenPayload,
    val tokenResponse: TokenResponse,
    val providerEntityIdentifier: String,
    val trustAnchor: String,
)

/**
 * Completes the login: checks the authorization response (`state`, RFC 9207 `iss`), redeems the code at the token
 * endpoint with `private_key_jwt` (`aud` the OP's Entity Identifier) and the PKCE verifier, and verifies the ID Token
 * with the keys from the OP's resolved federation metadata: signature and registered algorithm, `iss`, `aud`, `azp`,
 * `exp`, `iat` and `nonce`.
 */
interface CompleteFederatedAuthenticationCommand :
    ServiceCommand<CompleteFederatedAuthenticationArgs, FederatedAuthenticationResult, IdkError> {
    override val commandId: String get() = COMMAND_ID

    companion object {
        const val COMMAND_ID = "oauth2.federation-rp.complete"
    }
}
