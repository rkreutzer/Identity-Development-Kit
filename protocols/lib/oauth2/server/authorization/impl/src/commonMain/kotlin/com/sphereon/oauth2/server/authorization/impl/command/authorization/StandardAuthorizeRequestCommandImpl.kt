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

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.http.query.percentEncodeQueryComponent
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.config.isEnabled
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestOutcome
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationCodeArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationResponseArgs
import com.sphereon.oauth2.server.authorization.command.ParseAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.command.RetrieveByRequestUriArgs
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestArgs
import com.sphereon.oauth2.server.authorization.command.authorization.HandleAuthorizeRequestCommand
import com.sphereon.oauth2.server.authorization.command.jar.VerifyRequestObjectArgs
import com.sphereon.oauth2.server.authorization.command.jar.VerifyRequestObjectCommand
import com.sphereon.oauth2.server.authorization.model.AuthorizationSession
import com.sphereon.oauth2.server.authorization.model.ConsentDecision
import com.sphereon.oauth2.server.authorization.model.Prompt
import com.sphereon.oauth2.server.authorization.provider.AuthenticationContext
import com.sphereon.oauth2.server.authorization.provider.AuthenticationHint
import com.sphereon.oauth2.server.authorization.provider.AuthenticationMethod
import com.sphereon.oauth2.server.authorization.provider.UserAuthenticationProvider
import com.sphereon.oauth2.server.authorization.routing.AuthenticationRoute
import com.sphereon.oauth2.server.authorization.routing.AuthenticationRoutePlanner
import com.sphereon.oauth2.server.authorization.routing.AuthenticationRouteRequest
import com.sphereon.oauth2.server.authorization.service.AuthorizationServerService
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import com.sphereon.oauth2.server.authorization.storage.OidcLoginSession
import com.sphereon.oauth2.server.authorization.storage.OidcLoginSessionIdProvider
import com.sphereon.oauth2.server.authorization.storage.OidcLoginSessionStore
import com.sphereon.oauth2.server.authorization.storage.PendingAuthorizationSessionStore
import com.sphereon.oauth2.server.authorization.provider.CredentialIssuerAudienceResolver
import com.sphereon.oauth2.server.authorization.provider.UnregisteredClientAdmissionRule
import dev.zacsweers.metro.ContributesIntoSet
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

/**
 * Standard `/authorize` flow: parse, trusted-redirect resolution, verify, create session, and
 * then dispatch on the OIDC `prompt` / `max_age` / `id_token_hint` table against any active
 * [com.sphereon.oauth2.server.authorization.storage.OidcLoginSession]:
 *
 *  - active session that satisfies the request -> issue the authorization code inline (so the
 *    `auth_time` from the session lands on downstream id_token claims) and return
 *    [AuthorizationRequestOutcome.WalletCompleted];
 *  - active session but `prompt=login` / `prompt=select_account` / stale `max_age` -> return
 *    [AuthorizationRequestOutcome.NeedsLogin] with `forceReauth = true`;
 *  - `prompt=none` with no session, or `id_token_hint.sub` that does not match the session ->
 *    return [AuthorizationRequestOutcome.PostRedirectError] carrying `error=login_required`;
 *  - no session and no OIDC signals -> fall through to the federation IdP path and return
 *    [AuthorizationRequestOutcome.AuthInitiated] with the upstream redirect.
 *
 * Selected by `supports()` when `login_hint` is absent or does not start with `oid4vp:`.
 */
@SingleIn(SessionScope::class)
@ContributesIntoSet(SessionScope::class, binding = binding<HandleAuthorizeRequestCommand>())
class StandardAuthorizeRequestCommandImpl @Inject constructor(
    execution: SessionExecution,
    private val authorizationServerService: AuthorizationServerService,
    private val clientRegistry: ClientRegistry,
    private val serversConfigProvider: OAuth2ServersConfigProvider,
    userAuthProviderFactory: () -> UserAuthenticationProvider,
    private val pendingAuthorizationSessionStore: PendingAuthorizationSessionStore,
    private val loginSessionStore: OidcLoginSessionStore,
    private val loginSessionIdProvider: OidcLoginSessionIdProvider,
    authenticationRoutePlannerFactory: () -> AuthenticationRoutePlanner,
    verifyRequestObjectCommandFactory: () -> VerifyRequestObjectCommand,
    private val clock: Clock,
    private val credentialIssuerAudienceResolver: CredentialIssuerAudienceResolver,
    private val unregisteredClientAdmissionRule: UnregisteredClientAdmissionRule,
) : TypedServiceCommandAdapter<HandleAuthorizeRequestArgs, AuthorizationRequestOutcome, IdkError>(
        commandId = COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<HandleAuthorizeRequestArgs>(),
        outputTypeToken = typeToken<AuthorizationRequestOutcome>(),
    ),
    HandleAuthorizeRequestCommand {
    private val userAuthProvider: UserAuthenticationProvider by lazy(userAuthProviderFactory)
    private val authenticationRoutePlanner: AuthenticationRoutePlanner by lazy(authenticationRoutePlannerFactory)
    private val verifyRequestObjectCommand: VerifyRequestObjectCommand by lazy(verifyRequestObjectCommandFactory)

    /** Source-compatible constructor for callers that already own these dependencies. */
    constructor(
        execution: SessionExecution,
        authorizationServerService: AuthorizationServerService,
        clientRegistry: ClientRegistry,
        serversConfigProvider: OAuth2ServersConfigProvider,
        userAuthProvider: UserAuthenticationProvider,
        pendingAuthorizationSessionStore: PendingAuthorizationSessionStore,
        loginSessionStore: OidcLoginSessionStore,
        loginSessionIdProvider: OidcLoginSessionIdProvider,
        authenticationRoutePlanner: AuthenticationRoutePlanner,
        verifyRequestObjectCommand: VerifyRequestObjectCommand,
        clock: Clock,
        credentialIssuerAudienceResolver: CredentialIssuerAudienceResolver,
        unregisteredClientAdmissionRule: UnregisteredClientAdmissionRule,
    ) : this(
        execution = execution,
        authorizationServerService = authorizationServerService,
        clientRegistry = clientRegistry,
        serversConfigProvider = serversConfigProvider,
        userAuthProviderFactory = { userAuthProvider },
        pendingAuthorizationSessionStore = pendingAuthorizationSessionStore,
        loginSessionStore = loginSessionStore,
        loginSessionIdProvider = loginSessionIdProvider,
        authenticationRoutePlannerFactory = { authenticationRoutePlanner },
        verifyRequestObjectCommandFactory = { verifyRequestObjectCommand },
        clock = clock,
        credentialIssuerAudienceResolver = credentialIssuerAudienceResolver,
        unregisteredClientAdmissionRule = unregisteredClientAdmissionRule,
    )

    override val commandId: String get() = COMMAND_ID

    private val commands get() = authorizationServerService.commands

    override suspend fun supports(args: Any): Boolean = args is HandleAuthorizeRequestArgs && args.loginHint?.startsWith("oid4vp:") != true

    override suspend fun doExecute(
        args: HandleAuthorizeRequestArgs,
        applyDuring: (HandleAuthorizeRequestArgs) -> HandleAuthorizeRequestArgs,
    ): IdkResult<AuthorizationRequestOutcome, IdkError> {
        val applied = applyDuring(args)
        val rawQueryParameters = applied.queryParameters
        if (rawQueryParameters.containsKey("request") && rawQueryParameters.containsKey("request_uri")) {
            return Ok(AuthorizationRequestOutcome.PreRedirectError(
                error = "invalid_request",
                errorDescription = "request and request_uri MUST NOT both be present",
            ))
        }
        var verifiedEvidence: com.sphereon.oauth2.server.authorization.command.jar.AuthorizationRequestEvidence? = null

        // RFC 9101 (JAR) — when the AS has JAR enabled and the front-channel carries a `request`
        // (inline JWT) or a non-PAR `request_uri`, verify the JWT, replace the parsed parameters
        // with the JAR claims, then proceed through the normal parse/verify pipeline. PAR-issued
        // URNs (`urn:ietf:params:oauth:request_uri:`) are not JARs, they flow through PAR
        // retrieval downstream.
        val queryParameters =
            run {
                val raw = rawQueryParameters["request"]?.takeIf { it.isNotBlank() }
                val rawUri = rawQueryParameters["request_uri"]?.takeIf { it.isNotBlank() }
                val isParUrn = rawUri != null && rawUri.startsWith("urn:ietf:params:oauth:request_uri:")
                val serverConfig = serversConfigProvider.serverConfig
                if (serverConfig.jar.isEnabled && (raw != null || (rawUri != null && !isParUrn))) {
                    val issuer = applied.baseUrlOverride?.takeIf { it.isNotBlank() } ?: serverConfig.issuer
                    if (issuer == null) {
                        return Ok(
                            AuthorizationRequestOutcome.PreRedirectError(
                                error = "server_error",
                                errorDescription = "Cannot verify JAR audience without an AS issuer",
                            ),
                        )
                    }
                    if (rawUri != null && !isParUrn && serverConfig.requireRequestUriRegistration) {
                        val clientId = rawQueryParameters["client_id"]
                        if (clientId != null) {
                            val client = clientRegistry.getClient(clientId).getOrNull()
                            if (client != null && rawUri !in client.requestUris) {
                                return Ok(
                                    AuthorizationRequestOutcome.PreRedirectError(
                                        error = "invalid_request_uri",
                                        errorDescription =
                                            "request_uri '$rawUri' is not registered for client '$clientId'",
                                    ),
                                )
                            }
                        }
                    }
                    val jarResult =
                        verifyRequestObjectCommand.execute(
                            VerifyRequestObjectArgs(
                                requestJwt = raw,
                                requestUri = rawUri,
                                clientIdHint = rawQueryParameters["client_id"],
                                issuer = issuer,
                                queryParameters = rawQueryParameters,
                            ),
                        )
                    if (jarResult.isErr) {
                        return Ok(
                            AuthorizationRequestOutcome.PreRedirectError(
                                error = jarResult.error.code,
                                errorDescription = jarResult.error.message.defaultMessage,
                            ),
                        )
                    }
                    verifiedEvidence = jarResult.value.authorizationEvidence
                    jarResult.value.mergedParameters
                        .toMutableMap()
                        .apply {
                            remove("request")
                            remove("request_uri")
                        }
                } else {
                    rawQueryParameters
                }
            }

        // Parse
        val parseResult = commands.parseAuthorizationRequest.execute(ParseAuthorizationRequestArgs(queryParameters))
        if (parseResult.isErr) {
            return Ok(
                AuthorizationRequestOutcome.PreRedirectError(
                    error = parseResult.error.code,
                    errorDescription = parseResult.error.message.defaultMessage,
                ),
            )
        }
        // The private evidence checker compares the full parsed request to its immutable signed snapshot.
        val parsed = parseResult.value.copy(authorizationEvidence = verifiedEvidence)

        // RFC 9126 §4: when the request carries a PAR URN in `request_uri`, swap the parsed
        // request for the previously verified one stored at /par. The retrieve command consumes
        // the entry on hit (single-use). On miss we surface invalid_request pre-redirect since
        // the redirect URI inside the (missing) stored request cannot be trusted.
        val parsedRequestUri = parsed.requestUri
        val (verified, _) =
            if (parsedRequestUri != null && parsedRequestUri.startsWith("urn:ietf:params:oauth:request_uri:")) {
                val retrieveResult =
                    commands.retrieveAuthorizationRequestByUri.execute(RetrieveByRequestUriArgs(parsedRequestUri))
                if (retrieveResult.isErr) {
                    // RFC 6749 §4.1.2.1: when the original request data is unrecoverable but
                    // the wallet identified itself with a registered `client_id` at /authorize,
                    // bounce the error back to that client's registered redirect_uri instead
                    // of stranding the user on a raw error page in the browser. The redirect
                    // resolver still gates on the registry — if the client is unknown we keep
                    // the pre-redirect path.
                    return Ok(
                        toPreOrPostRedirectError(
                            error = retrieveResult.error.code,
                            errorDescription = retrieveResult.error.message.defaultMessage,
                            parsed = parsed,
                        ),
                    )
                }
                val storedVerified = retrieveResult.value
                if (storedVerified.admittedClient != null && parsed.redirectUri != storedVerified.request.redirectUri) {
                    return Ok(
                        AuthorizationRequestOutcome.PreRedirectError(
                            error = "invalid_request",
                            errorDescription = "redirect_uri does not match the pushed authorization request",
                        ),
                    )
                }
                // Reject mismatched client_id between `client_id` query param and the pushed
                // request, per RFC 9126 §4 (client_id MUST match). The PAR-stored client is the
                // authenticated party; surface the error via its registered redirect_uri so the
                // wallet sees `error=invalid_request` instead of a JSON body in the browser.
                if (storedVerified.clientId != parsed.clientId) {
                    return Ok(
                        toPreOrPostRedirectError(
                            error = "invalid_request",
                            errorDescription = "client_id does not match the pushed authorization request",
                            parsed = storedVerified.request,
                        ),
                    )
                }
                // FAPI2-SP §5.3.2.1 + RFC 9126 §4: when the front-channel /authorize request
                // carries a conflicting `response_type` URL parameter, refuse rather than silently
                // honouring the PAR-stored value. OIDC Core §6.2 lets the AS treat URL params as
                // ignored, but the FAPI2 conformance suite probes this exact scenario
                // (`…-ensure-response-type-token-fails`) and expects an error response so callers
                // cannot smuggle implicit/hybrid semantics on top of a `code`-only PAR. Empty
                // `response_type` from the URL means the wallet didn't supply one and the PAR
                // value is authoritative.
                val urlResponseTypes = parsed.responseType.toSet()
                if (urlResponseTypes.isNotEmpty() && urlResponseTypes != storedVerified.request.responseType.toSet()) {
                    return Ok(
                        toPreOrPostRedirectError(
                            error = "invalid_request",
                            errorDescription =
                                "response_type front-channel value does not match the pushed authorization request " +
                                    "(URL=${urlResponseTypes.joinToString(" ") { it.value }}, " +
                                    "PAR=${storedVerified.request.responseType.joinToString(" ") { it.value }})",
                            parsed = storedVerified.request,
                        ),
                    )
                }
                val resolved =
                    when (val resolution = resolveTrustedRedirect(storedVerified.request.copy(requestUri = parsedRequestUri), clientRegistry, serversConfigProvider, unregisteredClientAdmissionRule, credentialIssuerAudienceResolver)) {
                        is RedirectResolution.RejectPreRedirect -> {
                            return Ok(
                                AuthorizationRequestOutcome.PreRedirectError(
                                    error = resolution.error.code,
                                    errorDescription = resolution.error.message.defaultMessage,
                                ),
                            )
                        }

                        is RedirectResolution.Trusted -> {
                            resolution
                        }
                    }
                // Stamp the request_uri back onto the stored request so downstream code-
                // issuance (CreateAuthorizationCodeCommand) can finalize single-use semantics
                // by atomically consuming it (FAPI 2.0 SP §5.3.2.2 Note 3 + RFC 9126 §7.3).
                // The PAR push doesn't set this field — the URI is generated server-side
                // *after* the push — so we have to thread it through here.
                val storedWithUri = storedVerified.copy(
                    request = storedVerified.request.copy(requestUri = parsedRequestUri),
                    admittedAudiences = resolved.admission?.audiences?.toList(),
                    admittedClient = resolved.admission?.client,
                )
                storedWithUri to resolved
            } else {
                // Resolve trusted redirect (shared with verifier)
                val resolved =
                    when (val resolution = resolveTrustedRedirect(parsed, clientRegistry, serversConfigProvider, unregisteredClientAdmissionRule, credentialIssuerAudienceResolver)) {
                        is RedirectResolution.RejectPreRedirect -> {
                            return Ok(
                                AuthorizationRequestOutcome.PreRedirectError(
                                    error = resolution.error.code,
                                    errorDescription = resolution.error.message.defaultMessage,
                                ),
                            )
                        }

                        is RedirectResolution.Trusted -> {
                            resolution
                        }
                    }

                // Full verify (redirect URI is now trusted)
                val verifyResult = commands.verifyAuthorizationRequest.execute(parsed)
                if (verifyResult.isErr) {
                    return Ok(
                        AuthorizationRequestOutcome.PostRedirectError(
                            error = verifyResult.error.code,
                            errorDescription = verifyResult.error.message.defaultMessage,
                            redirectUri = resolved.redirectUri,
                            state = resolved.state,
                            responseMode = resolved.responseMode,
                        ),
                    )
                }
                verifyResult.value to resolved
            }

        // Create session
        val sessionResult = commands.createAuthorizationSession.execute(verified)
        if (sessionResult.isErr) {
            return Ok(
                AuthorizationRequestOutcome.PostRedirectError(
                    error = sessionResult.error.code,
                    errorDescription = sessionResult.error.message.defaultMessage,
                    redirectUri = verified.redirectUri,
                    state = verified.request.state,
                    responseMode = verified.responseMode,
                ),
            )
        }
        val session = sessionResult.value

        // Group I: evaluate the active OIDC login session (if any) against `prompt`, `max_age`,
        // and `id_token_hint`. Outcomes:
        //   - IssueCode         -> short-circuit the federation hop and assemble the authorization
        //                          response inline, propagating the session's auth_time / sub into
        //                          the issued code (downstream id_token claims).
        //   - RedirectToLogin   -> stop here, send the user to the AS's first-party login surface
        //                          (Group J). `forceReauth = true` clears the cookie at the HTTP
        //                          layer so the renderer cannot silently reuse the rejected session.
        //   - FailLoginRequired -> post-redirect `error=login_required` per OIDC Core §3.1.2.6.
        //   - ProceedToFederation -> no OIDC session signals apply, continue with the existing
        //                            federation IdP redirect (deployment's chosen login UX).
        // For PAR-redeemed requests `parsed` only carries client_id + request_uri; the OIDC
        // session-eval signals (prompt / max_age / id_token_hint) live on the resolved
        // [verified.request] instead.
        val sessionEvalRequest = verified.request
        val providerParam = queryParameters["provider"]
        var forceReauth = false
        when (val evaluation = evaluateSession(sessionEvalRequest, explicitProviderSelected = providerParam != null)) {
            is SessionEvaluation.IssueCode -> {
                return issueCodeFromActiveSession(session, evaluation.session, applied.baseUrlOverride)
            }

            is SessionEvaluation.FailLoginRequired -> {
                return Ok(
                    AuthorizationRequestOutcome.PostRedirectError(
                        error = "login_required",
                        errorDescription = evaluation.reason,
                        redirectUri = session.redirectUri,
                        state = session.state,
                        responseMode = session.responseMode,
                    ),
                )
            }

            is SessionEvaluation.RedirectToLogin -> {
                // A rejected session forces fresh authentication, but the durable hosted-AS
                // policy still decides whether that means local login or an exact upstream.
                forceReauth = evaluation.forceReauth
            }

            SessionEvaluation.ProceedToFederation -> {
                // No OIDC session signals apply; fall through to the federation IdP path.
            }
        }

        val routeResult =
            authenticationRoutePlanner.decide(
                AuthenticationRouteRequest(
                    downstreamSessionId = session.sessionId,
                    clientId = session.clientId,
                    requestedBindingId = providerParam,
                    requestedAcrValues = session.acrValues.orEmpty(),
                    loginHint = applied.loginHint,
                ),
            )
        if (routeResult.isErr) {
            return Ok(
                AuthorizationRequestOutcome.PostRedirectError(
                    error = "server_error",
                    errorDescription = routeResult.error.message.defaultMessage,
                    redirectUri = session.redirectUri,
                    state = session.state,
                    responseMode = session.responseMode,
                ),
            )
        }
        val route = routeResult.value
        val routedSession = session.copy(authenticationRoute = route)
        val storeResult = pendingAuthorizationSessionStore.create(routedSession)
        if (storeResult.isErr) {
            return Ok(
                AuthorizationRequestOutcome.PostRedirectError(
                    error = "server_error",
                    errorDescription = storeResult.error.message.defaultMessage,
                    redirectUri = session.redirectUri,
                    state = session.state,
                    responseMode = session.responseMode,
                ),
            )
        }

        if (route.route != AuthenticationRoute.UPSTREAM_REDIRECT) {
            val loginUrl = buildLoginUrl(applied.returnUrl, session.sessionId, forceReauth, applied.loginHint)
            return Ok(AuthorizationRequestOutcome.NeedsLogin(loginUrl = loginUrl, forceReauth = forceReauth))
        }

        // Build the auth-provider hint and initiate authentication. The HTTP layer hands us the
        // base callback URL; we append the session id since it's only known after createSession.
        val returnUrlBase =
            applied.returnUrl
                ?: return Ok(
                    AuthorizationRequestOutcome.PostRedirectError(
                        error = "server_error",
                        errorDescription = "Missing returnUrl for standard authorize flow",
                        redirectUri = session.redirectUri,
                        state = session.state,
                        responseMode = session.responseMode,
                    ),
                )
        val returnUrl = "$returnUrlBase?session_id=${session.sessionId}"

        val loginHint = applied.loginHint
        val hint = AuthenticationHint(loginHint = loginHint, providerId = route.selectedBindingId)

        val authResult =
            userAuthProvider.initiateAuthentication(
                sessionId = session.sessionId,
                returnUrl = returnUrl,
                hint = hint,
                context =
                    AuthenticationContext(
                        sessionId = session.sessionId,
                        applicationId = session.applicationId,
                        acrValues = session.acrValues.orEmpty(),
                    ),
            )
        if (authResult.isErr) {
            // Auth-provider unreachable / misconfigured; surface to the client via the
            // already-validated redirect URI using the session's resolved response mode,
            // not as bare JSON.
            return Ok(
                AuthorizationRequestOutcome.PostRedirectError(
                    error = "server_error",
                    errorDescription = authResult.error.message.defaultMessage,
                    redirectUri = session.redirectUri,
                    state = session.state,
                    responseMode = session.responseMode,
                ),
            )
        }

        return Ok(AuthorizationRequestOutcome.AuthInitiated(authProviderRedirectUrl = authResult.value))
    }

    /**
     * Apply the OIDC `prompt` / `max_age` / `id_token_hint` table to the inbound request and the
     * active OIDC login session (if any). The decision is local to this command — the session
     * lookup runs once here and the result feeds both the in-line code-issuance branch and the
     * NeedsLogin branch downstream.
     */
    private suspend fun evaluateSession(
        parsed: com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData,
        explicitProviderSelected: Boolean,
    ): SessionEvaluation {
        val sessionId = loginSessionIdProvider.currentLoginSessionId()
        val activeSession =
            sessionId
                ?.let { loginSessionStore.findById(it) }
                ?.let { if (it.isOk) it.value else null }
        val now = clock.now()

        if (activeSession == null) {
            val loginConfig = serversConfigProvider.serverConfig.login
            return when {
                Prompt.NONE in parsed.prompt -> {
                    SessionEvaluation.FailLoginRequired("prompt=none with no active login session")
                }

                explicitProviderSelected -> {
                    SessionEvaluation.ProceedToFederation
                }

                loginConfig.requiresChooser() -> {
                    SessionEvaluation.RedirectToLogin(forceReauth = false)
                }

                loginConfig.showFederation && supportsRedirectAuthentication() -> {
                    // Federated IdP is wired in; let the deployment's chosen redirect-based UX
                    // ([UserAuthenticationProvider.initiateAuthentication]) drive the login.
                    SessionEvaluation.ProceedToFederation
                }

                else -> {
                    // The active provider cannot redirect to an upstream IdP (e.g.
                    // `oauth2.user-provider.mode = local-config` for the AS first-party login
                    // form, or the explicit `noop` provider). Send the browser to the AS
                    // `/login` surface so the user can authenticate inline.
                    SessionEvaluation.RedirectToLogin(forceReauth = false)
                }
            }
        }

        if (Prompt.LOGIN in parsed.prompt || Prompt.SELECT_ACCOUNT in parsed.prompt) {
            return SessionEvaluation.RedirectToLogin(forceReauth = true)
        }

        val maxAge = parsed.maxAge
        if (maxAge != null && now > activeSession.authTime.plus(maxAge.seconds)) {
            return SessionEvaluation.RedirectToLogin(forceReauth = true)
        }

        val hint = parsed.idTokenHint
        if (hint != null) {
            val hintedSub = decodeIdTokenHintSub(hint, expectedIssuer = serversConfigProvider.serverConfig.issuer)
            if (hintedSub != null && hintedSub != activeSession.sub) {
                return SessionEvaluation.FailLoginRequired("id_token_hint sub does not match active session")
            }
        }

        return SessionEvaluation.IssueCode(activeSession)
    }

    /**
     * Probe the configured [UserAuthenticationProvider] for redirect-based (OAuth/OIDC federation)
     * support. The AS first-party login surface is selected when this is `false` so deployments
     * configured with `oauth2.user-provider.mode = local-config` (PBKDF2-backed users in config)
     * or `noop` redirect to `/login` instead of attempting a federation hop the provider cannot
     * service.
     */
    private suspend fun supportsRedirectAuthentication(): Boolean {
        val available = userAuthProvider.isAuthenticationMethodAvailable(AuthenticationMethod.OAUTH)
        return available.isOk && available.value
    }

    /**
     * Issue an authorization code directly from the active OIDC login session, bypassing the
     * federation hop. The session's `sub` becomes the subject; the session's `authTime` flows
     * through [AuthorizationSession.authTime] (epoch seconds) into [com.sphereon.oauth2.server.authorization.model.AuthorizationCodeData.authTime]
     * and onward to the id_token's `auth_time` claim. Consent is auto-approved on the same
     * grounds the wallet flow uses: the upstream login established the user identity and the
     * user already accepted the client at that time (the consent surface, when needed, lives at
     * the login layer).
     */
    private suspend fun issueCodeFromActiveSession(
        authorizationSession: AuthorizationSession,
        oidcSession: OidcLoginSession,
        baseUrlOverride: String? = null,
    ): IdkResult<AuthorizationRequestOutcome, IdkError> {
        val resumed =
            authorizationSession.copy(
                authTime = oidcSession.authTime.epochSeconds,
                authenticatedUserId = oidcSession.sub,
            )
        val consent =
            ConsentDecision(
                userId = oidcSession.sub,
                clientId = resumed.clientId,
                granted = true,
                grantedScopes = resumed.scope?.split(" "),
                grantedAt = clock.now(),
            )
        // Pull the cached user claims so the issued code carries them downstream
        // into id_token / userinfo. The federation outcome handler stores the
        // projected upstream claims keyed by `oidcSession.sub`; without this
        // fetch the SSO short-circuit (`issueCodeFromActiveSession`) would emit
        // a code with empty userClaims, dropping every claim except the few
        // mapped onto top-level UserInfo fields. The non-SSO path
        // (`HandleAuthorizeCallbackCommandImpl`) does this same lookup —
        // mirror it here so both paths produce identical id_tokens.
        val currentUserClaims =
            userAuthProvider.getUserInfo(oidcSession.sub).let { result ->
                if (result.isOk) result.value.toClaimsMap() else emptyMap()
            }
        // In split deployments, credential verification runs in the
        // identity-owning runtime. Authorization claims returned by that
        // trusted verification are frozen into the login session. Merge them
        // here so an unavailable local userinfo store cannot silently strip
        // roles; current provider claims win when available.
        val userClaims = oidcSession.claims + currentUserClaims
        val codeResult =
            commands.createAuthorizationCode.execute(
                CreateAuthorizationCodeArgs(
                    session = resumed,
                    userId = oidcSession.sub,
                    consent = consent,
                    userClaims = userClaims,
                    acr = oidcSession.acr,
                    amr = oidcSession.amr,
                ),
            )
        if (codeResult.isErr) {
            return Ok(
                AuthorizationRequestOutcome.PostRedirectError(
                    error = "server_error",
                    errorDescription = codeResult.error.message.defaultMessage,
                    redirectUri = resumed.redirectUri,
                    state = resumed.state,
                    responseMode = resumed.responseMode,
                ),
            )
        }
        // OIDC Core §3.3 Hybrid Flow — when response_type asks for id_token / token in
        // addition to code, mint them here so they can ride back in the same front-channel
        // response (URL fragment or form_post body).
        val frontChannel =
            mintFrontChannelTokens(
                service = authorizationServerService,
                session = resumed,
                code = codeResult.value.value,
                subject = oidcSession.sub,
                authTime = oidcSession.authTime.epochSeconds,
                acr = oidcSession.acr,
                amr = oidcSession.amr,
                baseUrlOverride = baseUrlOverride,
            ).getOrElse { error ->
                return Ok(
                    AuthorizationRequestOutcome.PostRedirectError(
                        error = "server_error",
                        errorDescription = error.message.defaultMessage,
                        redirectUri = resumed.redirectUri,
                        state = resumed.state,
                        responseMode = resumed.responseMode,
                    ),
                )
            }
        val responseResult =
            commands.createAuthorizationResponse.execute(
                CreateAuthorizationResponseArgs(
                    code = codeResult.value.value,
                    state = resumed.state,
                    redirectUri = resumed.redirectUri,
                    responseMode = resumed.responseMode,
                    clientId = resumed.clientId,
                    baseUrlOverride = baseUrlOverride,
                    idToken = frontChannel.idToken,
                    accessToken = frontChannel.accessToken,
                    tokenType = frontChannel.accessToken?.let { "Bearer" },
                    accessTokenExpiresIn = frontChannel.accessTokenExpiresIn,
                ),
            )
        if (responseResult.isErr) {
            return Ok(
                AuthorizationRequestOutcome.PostRedirectError(
                    error = "server_error",
                    errorDescription = responseResult.error.message.defaultMessage,
                    redirectUri = resumed.redirectUri,
                    state = resumed.state,
                    responseMode = resumed.responseMode,
                ),
            )
        }
        return Ok(AuthorizationRequestOutcome.WalletCompleted(authorizationResponseData = responseResult.value))
    }

    /**
     * Convert an authorization-request error into a redirect to the client's registered
     * `redirect_uri` whenever a trusted redirect can be resolved from the parsed request, falling
     * back to the pre-redirect (browser-rendered) error otherwise. Used by branches that today
     * surface raw JSON errors to the user agent for problems where RFC 6749 §4.1.2.1 actually
     * permits — and wallets expect — a redirect (e.g. the original PAR data is unrecoverable but
     * the wallet identified itself with a valid `client_id`).
     */
    private suspend fun toPreOrPostRedirectError(
        error: String,
        errorDescription: String,
        parsed: com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData,
    ): AuthorizationRequestOutcome =
        when (val resolution = resolveTrustedRedirect(parsed, clientRegistry, serversConfigProvider, unregisteredClientAdmissionRule, credentialIssuerAudienceResolver)) {
            is RedirectResolution.Trusted -> {
                AuthorizationRequestOutcome.PostRedirectError(
                    error = error,
                    errorDescription = errorDescription,
                    redirectUri = resolution.redirectUri,
                    state = resolution.state,
                    responseMode = resolution.responseMode,
                )
            }

            is RedirectResolution.RejectPreRedirect -> {
                AuthorizationRequestOutcome.PreRedirectError(
                    error = error,
                    errorDescription = errorDescription,
                )
            }
        }

    private fun buildLoginUrl(
        returnUrlBase: String?,
        pendingSessionId: String,
        forceReauth: Boolean,
        loginHint: String? = null,
    ): String {
        val callbackBase = returnUrlBase ?: ""
        val basePath = callbackBase.substringBefore("/authorize/callback")
        val resumeUrl = "$callbackBase?session_id=$pendingSessionId"
        val params =
            buildString {
                append("session_id=$pendingSessionId")
                append("&return_url=")
                append(percentEncodeQueryComponent(resumeUrl))
                if (forceReauth) append("&force_reauth=true")
                // OIDC Core §3.1.2.1: when the wallet supplied `login_hint`, the OP MAY use
                // it to pre-fill the login form's username field. The /login renderer reads
                // `login_hint` from query params (LoginPageHttpEndpointCommandImpl §84) and
                // populates the username input.
                if (!loginHint.isNullOrBlank()) {
                    append("&login_hint=")
                    append(percentEncodeQueryComponent(loginHint))
                }
            }
        return "$basePath/login?$params"
    }

    /**
     * Result of [evaluateSession]; consumed by the main command body to pick between issuing a
     * code from the active session, redirecting to the login surface, failing fast, or letting
     * the existing federation path run.
     */
    internal sealed interface SessionEvaluation {
        data class IssueCode(
            val session: OidcLoginSession
        ) : SessionEvaluation

        data class RedirectToLogin(
            val forceReauth: Boolean
        ) : SessionEvaluation

        data class FailLoginRequired(
            val reason: String
        ) : SessionEvaluation

        data object ProceedToFederation : SessionEvaluation
    }

    companion object {
        const val COMMAND_ID: String = "oauth2.authorization.standard-authorize-request"
    }
}
