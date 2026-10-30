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

package com.sphereon.oauth2.server.authorization.impl.command.authorization

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.FeaturePolicy
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.config.isEnabled
import com.sphereon.oauth2.common.config.isRequired
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.model.OAuth2ResponseMode
import com.sphereon.oauth2.common.model.PkceMethod
import com.sphereon.oauth2.common.model.ResponseType
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData
import com.sphereon.oauth2.server.authorization.command.VerifiedAuthorizationRequest
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.extension.AuthorizeExtensionResult
import com.sphereon.oauth2.server.authorization.extension.AuthorizeRequestExtension
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientType
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import com.sphereon.oauth2.server.authorization.provider.CredentialIssuerAudienceResolver
import com.sphereon.oauth2.server.authorization.provider.UnregisteredClientAdmissionRule
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of VerifyAuthorizationRequestCommand
 *
 * Verifies OAuth2 authorization endpoint requests according to RFC 6749 Section 4.1.2.
 *
 * Verification steps:
 * 1. Retrieve client registration
 * 2. Verify client is authorized to use authorization_code grant
 * 3. Verify redirect_uri matches registered URIs
 * 4. Verify PKCE is used if required for client
 * 5. Validate requested scope
 * 6. Return verified request data
 *
 * Security considerations:
 * - Public clients MUST use PKCE (RFC 8252)
 * - redirect_uri MUST be validated against registered URIs (RFC 6749 Section 3.1.2.3)
 * - Exact string matching for redirect_uri validation
 * - Scope validation depends on server policy
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("VerifyAuthorizationRequestCommandImpl", exact = true)
@ExposeImplBinding
class VerifyAuthorizationRequestCommandImpl(
    execution: SessionExecution,
    private val clientRegistry: ClientRegistry,
    private val serversConfigProvider: OAuth2ServersConfigProvider,
    private val authorizeExtensions: Set<AuthorizeRequestExtension>,
    private val credentialIssuerAudienceResolver: CredentialIssuerAudienceResolver,
    private val unregisteredClientAdmissionRule: UnregisteredClientAdmissionRule,
    private val actualAsSelection: com.sphereon.oauth2.common.config.OAuth2ServerInstanceIdProvider,
) : TypedServiceCommandAdapter<AuthorizationRequestData, VerifiedAuthorizationRequest, IdkError>(
        commandId = VerifyAuthorizationRequestCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<AuthorizationRequestData>(),
        outputTypeToken = typeToken<VerifiedAuthorizationRequest>(),
    ),
    VerifyAuthorizationRequestCommand {
    override val commandId: String get() = VerifyAuthorizationRequestCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is AuthorizationRequestData

    override suspend fun doExecute(
        args: AuthorizationRequestData,
        applyDuring: (AuthorizationRequestData) -> AuthorizationRequestData,
    ): IdkResult<VerifiedAuthorizationRequest, IdkError> {
        val applied = applyDuring(args)
        return executeInternal(applied).mapError { IdkError.fromDTO(it) }
    }

    private suspend fun executeInternal(request: AuthorizationRequestData): IdkResult<VerifiedAuthorizationRequest, AuthorizationServerError> {
        // ── Client + grant-type + redirect URI + response_mode resolution ──
        // Shared with the authorization endpoint's error-routing path (OAuth2Handlers) — see
        // [resolveTrustedRedirect]. All failures here are pre-redirect (redirect URI cannot be
        // trusted), so the HTTP adapter will serve them as JSON.
        val resolution = resolveTrustedRedirect(request, clientRegistry, serversConfigProvider, unregisteredClientAdmissionRule, credentialIssuerAudienceResolver)
        val trusted =
            when (resolution) {
                is RedirectResolution.RejectPreRedirect -> return Err(resolution.error)
                is RedirectResolution.Trusted -> resolution
            }
        val client = trusted.client
        val finalRedirectUri = trusted.redirectUri
        val resolvedResponseMode = trusted.responseMode

        // ── JAR / Request Object rejection (post-redirect) ─────────────────
        // OIDC Core §6 / RFC 9101: the AS MAY decline to support the `request` and `request_uri`
        // parameters by responding with `request_not_supported` / `request_uri_not_supported`.
        // Delivered post-redirect since the redirect URI has been validated above; OIDF Basic RP
        // tests (e.g. OIDCCEnsureRequestObjectStandardClaimSupports) accept this rejection path
        // in lieu of full Request Object processing. PAR-issued URNs are exempt (filtered at
        // parse time) and travel through PAR retrieval downstream.
        if (request.request != null) {
            return Err(AuthorizationServerError.RequestNotSupported())
        }
        val requestUri = request.requestUri
        if (requestUri != null && !requestUri.startsWith("urn:ietf:params:oauth:request_uri:")) {
            return Err(AuthorizationServerError.RequestUriNotSupported())
        }

        // ── response_type against server metadata + client registration ────
        // OIDC Core §3.1.2.1 / RFC 6749 §3.1.1: every requested response-type value MUST be
        // advertised by the server (`response_types_supported`) AND registered for the client.
        // An empty client registration list defaults to `[CODE]` for legacy clients.
        //
        // Empty list = the parser saw no `response_type` parameter at all (or saw only
        // unrecognised values). Surface as `unsupported_response_type` per RFC 6749 §4.1.2.1
        // so the standard authorize flow redirects the error back to the client's
        // registered redirect_uri rather than rendering an AS-side HTML error page.
        if (request.responseType.isEmpty()) {
            return Err(AuthorizationServerError.UnsupportedResponseType(responseType = ""))
        }
        // OIDC Core §3.1.2.1 + OIDC Discovery §3: `response_types_supported` lists
        // SPACE-SEPARATED COMBINATIONS, not individual values — `code id_token` is one entry,
        // not two. Membership check normalizes both sides: parse each entry into a set of
        // ResponseType values and compare set-equality so request-side ordering doesn't
        // matter (`id_token code` ≡ `code id_token`).
        val serverSupportedSets: List<Set<ResponseType>> =
            serversConfigProvider.serverConfig.responseTypesSupported.mapNotNull { entry ->
                entry
                    .split(" ")
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
                    .mapNotNull { ResponseType.fromValue(it) }
                    .toSet()
                    .takeIf { it.isNotEmpty() }
            }
        val requestedSet = request.responseType.toSet()
        if (requestedSet !in serverSupportedSets) {
            return Err(
                AuthorizationServerError.UnsupportedResponseType(
                    responseType = request.responseType.joinToString(" ") { it.value },
                ),
            )
        }
        // Client-registration check uses the same set semantics. An empty list defaults to
        // [CODE] for legacy clients — they're code-flow-only.
        val clientAllowed: Set<ResponseType> =
            client.responseTypes.ifEmpty { listOf(ResponseType.CODE) }.toSet()
        if (!clientAllowed.containsAll(requestedSet)) {
            return Err(AuthorizationServerError.UnauthorizedClient(clientId = request.clientId))
        }

        // ── Hybrid-flow constraints (OIDC Core §3.3) ────────────────────────
        // §3.3.2.11 — when an id_token is returned from /authorize (front-channel), the
        // request MUST carry `nonce` so the front-channel id_token can bind it.
        if (ResponseType.ID_TOKEN in requestedSet && request.nonce.isNullOrBlank()) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "nonce is required when response_type contains id_token (OIDC Core §3.3.2.11)",
                ),
            )
        }
        // §3.3.2.4 — when a token (id_token / access_token) is returned via the front
        // channel, response_mode MUST NOT be `query` (the token would land in the URL bar /
        // referer / history). `fragment` and `form_post` are the only valid choices.
        val frontChannelToken = ResponseType.ID_TOKEN in requestedSet || ResponseType.TOKEN in requestedSet
        if (frontChannelToken && request.responseMode?.equals("query", ignoreCase = true) == true) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "response_mode=query is not permitted for response_type values that return tokens (OIDC Core §3.3.2.4)",
                ),
            )
        }

        // ── PKCE required? ──────────────────────────────────────────────────
        // A code_challenge is REQUIRED when ANY of the following signal it:
        //   • server policy: `oauth2.servers.<id>.pkce = REQUIRED` (default)
        //   • client registration: `requirePkce = true`
        //   • RFC 8252: public clients MUST use PKCE
        val serverConfig = serversConfigProvider.serverConfig
        val pkceRequired =
            serverConfig.pkce == FeaturePolicy.REQUIRED ||
                client.requirePkce ||
                client.clientType == ClientType.PUBLIC
        if (pkceRequired && request.codeChallenge == null) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "PKCE (code_challenge) is required for this client",
                ),
            )
        }

        // ── Resolve PKCE code_challenge_method + enforce server policy ──────
        // RFC 7636 §4.3: when code_challenge is present but code_challenge_method is absent,
        // the default is "plain". Server policy may reject "plain"; OIDF/OIDC deployments
        // normally advertise S256 only. The parser left the method `null` when absent so the
        // server default is applied here rather than upstream.
        val resolvedPkceMethod: PkceMethod? =
            if (request.codeChallenge == null) {
                null
            } else {
                val resolved = request.codeChallengeMethod ?: PkceMethod.PLAIN
                val supportedNormalized = serverConfig.pkceMethodsSupported.map { it.uppercase() }.toSet()
                if (resolved.value.uppercase() !in supportedNormalized) {
                    return Err(
                        AuthorizationServerError.InvalidRequest(
                            details =
                                "code_challenge_method '${resolved.value}' is not permitted by server policy " +
                                    "(allowed: ${serverConfig.pkceMethodsSupported.joinToString(", ")})",
                        ),
                    )
                }
                resolved
            }

        // RFC 9126 + FAPI2-SP §5.3.1.1: enforce PAR when either the AS-level policy is REQUIRED
        // (covers HAIP / FAPI2 deployments where every client must use PAR) or the per-client
        // setting demands it. The metadata advertisement (`require_pushed_authorization_requests`)
        // is built from `serverConfig.par.isRequired`, so the enforcement check has to mirror that
        // same source — otherwise the AS lies in discovery and accepts the very requests it claims
        // to forbid (OIDF condition `EnsureUnsignedAuthorizationRequestWithoutUsingParFails`).
        val federationProofRequired = client.authorizationRequestProofPolicy == com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC
        val parRequired = serverConfig.par.isRequired || client.requirePushedAuthorizationRequests ||
            (federationProofRequired && serverConfig.federationAutomaticRegistrationMode == com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.PAR_ONLY)
        if (parRequired && request.requestUri == null) {
            return Err(
                AuthorizationServerError.InvalidRequest(
                    details = "Pushed Authorization Requests (PAR) is required",
                ),
            )
        }

        if (federationProofRequired) {
            val scope = try { captureFederationAuthorizationScope(execution, serversConfigProvider, actualAsSelection) }
            catch (expected: IllegalArgumentException) { return Err(AuthorizationServerError.InvalidRequest(details = "Federation AS scope is unavailable")) }
            catch (expected: IllegalStateException) { return Err(AuthorizationServerError.InvalidRequest(details = "Federation AS scope is unavailable")) }
            if (!validFederationAuthorizationEvidence(request.authorizationEvidence, scope, request, client)) {
                return Err(AuthorizationServerError.InvalidRequest(details = "A client-bound signed federation Request Object is required"))
            }
        }

        // Validate requested scope
        // If client has allowedScopes configured, validate that all requested scopes are permitted
        val requestedScope = request.scope
        val grantedScopes =
            if (requestedScope != null && requestedScope.isNotBlank()) {
                val requestedScopes = requestedScope.split(" ").map { it.trim() }.filter { it.isNotEmpty() }
                val allowedScopes = client.allowedScopes
                if (allowedScopes != null) {
                    val disallowed = requestedScopes.filter { it !in allowedScopes }
                    if (disallowed.isNotEmpty()) {
                        return Err(
                            AuthorizationServerError.InvalidScope(
                                scope = disallowed.joinToString(" "),
                                allowedScopes = allowedScopes,
                            ),
                        )
                    }
                }
                requestedScopes
            } else {
                emptyList()
            }

        // RFC 9396 §6 + §10: validate each authorization_details entry's credential_configuration_id
        // against the client's registered allow-list. null = grandfathered (pre-S2-3 clients).
        val allowList = client.credentialConfigurationIds
        if (allowList != null) {
            val raw = request.additionalParameters["authorization_details"]
            if (!raw.isNullOrBlank()) {
                val parsedCcids =
                    try {
                        Json
                            .parseToJsonElement(raw)
                            .jsonArray
                            .mapNotNull { it.jsonObject["credential_configuration_id"]?.jsonPrimitive?.content }
                    } catch (expected: Exception) {
                        return Err(
                            AuthorizationServerError.InvalidAuthorizationDetails(
                                details = "Malformed authorization_details JSON: ${expected.message}",
                                clientId = request.clientId,
                            ),
                        )
                    }
                val disallowed = parsedCcids.firstOrNull { it !in allowList }
                if (disallowed != null) {
                    return Err(
                        AuthorizationServerError.InvalidAuthorizationDetails(
                            details =
                                "client '${request.clientId}' is not authorized for " +
                                    "credential_configuration_id '$disallowed'",
                            credentialConfigurationId = disallowed,
                            clientId = request.clientId,
                        ),
                    )
                }
            }
        }

        // ── response_mode semantic checks ──────────────────────────────────
        // resolvedResponseMode was already computed by resolveTrustedRedirect (so unknown values
        // are caught there as pre-redirect). Here we only apply the code-flow-specific rule:
        // Fragment response mode is only meaningful when the URL carries tokens directly
        // (id_token or token). Per OAuth 2.0 Multiple Response Type Encoding Practices §2.1,
        // pure `code` flows default to `query`; emitting `fragment` for a code-only response
        // is a protocol error regardless of server capability. Reject loudly instead of silently
        // degrading. This also future-proofs against hybrid flows (e.g. `code id_token`) when
        // WP5 lights them up — fragment will become valid automatically.
        if (resolvedResponseMode == OAuth2ResponseMode.FRAGMENT) {
            val responseProducesTokens =
                ResponseType.ID_TOKEN in request.responseType ||
                    ResponseType.TOKEN in request.responseType
            if (!responseProducesTokens) {
                return Err(
                    AuthorizationServerError.InvalidRequest(
                        details = "response_mode=fragment requires a response_type that returns tokens (id_token or token)",
                    ),
                )
            }
        }

        // OIDF JARM (https://openid.net/specs/oauth-v2-jarm.html): a `*.jwt` response_mode is only
        // permitted when JARM is enabled server-side AND the client has opted in via at least one
        // of `authorization_signed_response_alg` or `authorization_encrypted_response_alg`. Both
        // checks are post-redirect: the redirect URI is already validated, so the AS surfaces
        // `invalid_request` through the resolved response mode (or its underlying carrier when
        // the JARM mode itself is the violation).
        if (resolvedResponseMode.isJarm) {
            if (!serverConfig.jarm.isEnabled) {
                return Err(
                    AuthorizationServerError.InvalidRequest(
                        details = "response_mode='${resolvedResponseMode.value}' requires JARM, which is not enabled on this server",
                    ),
                )
            }
            if (client.authorizationSignedResponseAlg.isNullOrBlank() &&
                client.authorizationEncryptedResponseAlg.isNullOrBlank()
            ) {
                return Err(
                    AuthorizationServerError.InvalidRequest(
                        details =
                            "Client '${client.clientId}' requested response_mode='${resolvedResponseMode.value}' but has no " +
                                "authorization_signed_response_alg or authorization_encrypted_response_alg configured",
                    ),
                )
            }
        }

        // ── AuthorizeRequestExtension hook (P2-K8 wiring point) ────────────
        // Run every registered extension. The IDK ships zero default extensions; EDK's
        // policy module installs `PolicyDrivenAuthorizeRequestExtension` (a bridge over
        // the EDK [ClientPolicy] framework) via @ContributesIntoSet so it appears in this
        // multibinding when the policy module is on the classpath. Empty set (pure-IDK
        // deployment) makes this a no-op — the per-flag legacy checks above are the only
        // enforcement.
        for (extension in authorizeExtensions) {
            when (val outcome = extension.evaluate(client, request)) {
                is AuthorizeExtensionResult.Allow -> {
                    Unit
                }

                is AuthorizeExtensionResult.Deny -> {
                    return Err(toAuthorizationServerError(outcome, extension::class.simpleName))
                }
            }
        }

        // Return verified request
        return Ok(
            VerifiedAuthorizationRequest(
                request = request.copy(authorizationEvidence = null),
                clientId = request.clientId,
                redirectUri = finalRedirectUri,
                grantedScopes = grantedScopes,
                defaultAccessTokenAudience = client.defaultAccessTokenAudience,
                pkceRequired = pkceRequired,
                parRequired = client.requirePushedAuthorizationRequests,
                resolvedPkceMethod = resolvedPkceMethod,
                responseMode = resolvedResponseMode,
                admittedAudiences = trusted.admission?.audiences?.toList(),
                admittedClient = trusted.admission?.client,
            ),
        )
    }

    /**
     * Translate an extension [AuthorizeExtensionResult.Deny] into the matching
     * [AuthorizationServerError] variant. Most denials are invalid_request (parameter
     * shape / completeness) — that's the default. The two named alternatives
     * ([AuthorizationServerError.UnauthorizedClient], [AuthorizationServerError.AccessDenied])
     * cover extensions that semantically reject the client or the user's grant.
     */
    private fun toAuthorizationServerError(
        deny: AuthorizeExtensionResult.Deny,
        extensionName: String?,
    ): AuthorizationServerError {
        val annotated = "${deny.description} (extension=${extensionName ?: "?"})"
        return when (deny.errorCode) {
            "unauthorized_client" -> AuthorizationServerError.UnauthorizedClient(clientId = "")
            "access_denied" -> AuthorizationServerError.AccessDenied(reason = annotated)
            else -> AuthorizationServerError.InvalidRequest(details = annotated)
        }
    }
}
