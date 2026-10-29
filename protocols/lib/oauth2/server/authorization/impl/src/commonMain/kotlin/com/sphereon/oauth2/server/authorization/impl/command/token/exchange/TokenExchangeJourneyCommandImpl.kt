/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.oauth2.server.authorization.impl.command.token.exchange

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.core.api.session.Command
import com.sphereon.core.api.session.JourneyBuilder
import com.sphereon.core.api.session.JourneyContract
import com.sphereon.core.api.session.JourneyPipeline
import com.sphereon.core.api.session.JourneyProfile
import com.sphereon.core.api.session.JourneySpecReference
import com.sphereon.core.api.session.JourneyStep
import com.sphereon.core.api.session.JourneyStepContract
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.command.VerifyDpopProofCommand
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.common.model.TokenResponse
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreateTokenResponseCommand
import com.sphereon.oauth2.server.authorization.command.GrantParameters
import com.sphereon.oauth2.server.authorization.command.ParseTokenRequestCommand
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand
import com.sphereon.oauth2.server.authorization.command.token.AuthorizeTokenExchangeCommand
import com.sphereon.oauth2.server.authorization.command.token.BuildTokenExchangeActorChainCommand
import com.sphereon.oauth2.server.authorization.command.token.HandleTokenRequestArgs
import com.sphereon.oauth2.server.authorization.command.token.MapTokenExchangeClaimsCommand
import com.sphereon.oauth2.server.authorization.command.token.TokenExchangeJourneyCommand
import com.sphereon.oauth2.server.authorization.command.token.TokenExchangeJourneySteps
import com.sphereon.oauth2.server.authorization.command.token.TokenExchangeProfile
import com.sphereon.oauth2.server.authorization.dpop.DpopNonceManager
import com.sphereon.oauth2.server.authorization.dpop.DpopProofJtiCache
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.command.TokenPathStageTimings
import com.sphereon.oauth2.server.authorization.impl.command.token.TokenEndpointRequestAuthenticator
import com.sphereon.oauth2.server.authorization.signing.AsSigningKeyPublicJwkResolver
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import com.sphereon.oauth2.server.authorization.storage.SigningKeyStore
import com.sphereon.oauth2.server.authorization.trust.SubjectTokenIssuerTrust
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

private val RFC6749_TOKEN_ENDPOINT = JourneySpecReference("RFC 6749", "3.2")
private val RFC8693_REQUEST = JourneySpecReference("RFC 8693", "2.1")
private val RFC8693_RESPONSE = JourneySpecReference("RFC 8693", "2.2")
private val RFC8693_ACT = JourneySpecReference("RFC 8693", "4.1")
private val RFC8693_MAY_ACT = JourneySpecReference("RFC 8693", "4.4")
private val RFC8707_RESOURCE = JourneySpecReference("RFC 8707", "2")
private val RFC7519_VALIDATION = JourneySpecReference("RFC 7519", "7.2")
private val RFC9449_BINDING = JourneySpecReference("RFC 9449", "10.1")

internal const val TOKEN_EXCHANGE_JOURNEY_ID = "oauth2.journey.token-exchange"

/**
 * The RFC 8693 token-exchange journey. The executed pipeline is built from [TokenExchangeStepCommands];
 * its [journeyContract] is captured from those same steps.
 */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<TokenExchangeJourneyCommand>())
class TokenExchangeJourneyCommandImpl(
    execution: SessionExecution,
    parseTokenRequestCommand: ParseTokenRequestCommand,
    verifyClientAuthenticationCommand: VerifyClientAuthenticationCommand,
    serversConfigProvider: OAuth2ServersConfigProvider,
    verifyDpopProofCommand: Lazy<VerifyDpopProofCommand>,
    dpopProofJtiCache: Lazy<DpopProofJtiCache>,
    dpopNonceManager: Lazy<DpopNonceManager>,
    clientRegistry: ClientRegistry,
    jwtService: JwtService,
    signingKeyStore: SigningKeyStore,
    subjectTokenIssuerTrust: SubjectTokenIssuerTrust,
    tokenExchangeProfile: TokenExchangeProfile,
    createAccessToken: CreateAccessTokenCommand,
    createTokenResponse: CreateTokenResponseCommand,
    signingKeyPublicJwkResolver: AsSigningKeyPublicJwkResolver? = null,
) : TypedServiceCommandAdapter<HandleTokenRequestArgs, TokenResponse, IdkError>(
        commandId = TokenExchangeJourneyCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<HandleTokenRequestArgs>(),
        outputTypeToken = typeToken<TokenResponse>(),
    ),
    TokenExchangeJourneyCommand {
    override val commandId: String get() = TokenExchangeJourneyCommand.COMMAND_ID

    private val tenantId = execution.tenantId

    private val authenticator =
        TokenEndpointRequestAuthenticator(
            parseTokenRequestCommand = parseTokenRequestCommand,
            verifyClientAuthenticationCommand = lazyOf(verifyClientAuthenticationCommand),
            serversConfigProvider = serversConfigProvider,
            verifyDpopProofCommand = verifyDpopProofCommand,
            dpopProofJtiCache = dpopProofJtiCache,
            dpopNonceManager = dpopNonceManager,
            log = log,
        )

    private val steps =
        TokenExchangeStepCommands(
            tenantId = execution.tenantId,
            clientRegistry = clientRegistry,
            jwtService = jwtService,
            signingKeyStore = signingKeyStore,
            serversConfigProvider = serversConfigProvider,
            signingKeyPublicJwkResolver = signingKeyPublicJwkResolver,
            subjectTokenIssuerTrust = subjectTokenIssuerTrust,
            profile = tokenExchangeProfile,
            createAccessToken = createAccessToken,
            createTokenResponse = createTokenResponse,
        )

    private val authenticateClient: Command<HandleTokenRequestArgs, ClientAuthenticatedExchange, AuthorizationServerError> =
        object : Command<HandleTokenRequestArgs, ClientAuthenticatedExchange, AuthorizationServerError> {
            override val id: String = "oauth2.tokenexchange.authenticate-client"
            override val isEnabled: Boolean = true

            override suspend fun supports(args: Any): Boolean = args is HandleTokenRequestArgs

            override suspend fun execute(args: HandleTokenRequestArgs): IdkResult<ClientAuthenticatedExchange, AuthorizationServerError> =
                authenticate(args)
        }

    private val pipeline: JourneyPipeline<HandleTokenRequestArgs, TokenResponse, AuthorizationServerError> =
        tokenExchangeJourney(authenticateClient, steps)

    override val journeyContract: JourneyContract get() = pipeline.contract

    override val journeyProfile: JourneyProfile = tokenExchangeProfile

    override suspend fun supports(args: Any): Boolean = args is HandleTokenRequestArgs

    override suspend fun doExecute(
        args: HandleTokenRequestArgs,
        applyDuring: (HandleTokenRequestArgs) -> HandleTokenRequestArgs,
    ): IdkResult<TokenResponse, IdkError> = pipeline.execute(applyDuring(args)).mapError { IdkError.fromDTO(it) }

    private suspend fun authenticate(args: HandleTokenRequestArgs): IdkResult<ClientAuthenticatedExchange, AuthorizationServerError> {
        val timings = TokenPathStageTimings(operation = "token-exchange")
        var outcome = "failed"
        return try {
            authenticateOnce(args, timings).also { result -> outcome = if (result.isOk) "authenticated" else "rejected" }
        } finally {
            timings.report(log, outcome)
        }
    }

    private suspend fun authenticateOnce(
        args: HandleTokenRequestArgs,
        timings: TokenPathStageTimings,
    ): IdkResult<ClientAuthenticatedExchange, AuthorizationServerError> {
        val tokenRequest = authenticator.parse(args, timings).getOrElse { return Err(it.asProtocolError()) }
        val parameters = tokenRequest.grantParameters as? GrantParameters.TokenExchange
            ?: return Err(AuthorizationServerError.ServerError(details = "Token exchange journey received a different grant type"))
        val authenticated = authenticator.authenticate(args, tokenRequest, tenantId, timings).getOrElse { return Err(it.asProtocolError()) }
        val context = authenticated.context
        return Ok(
            ClientAuthenticatedExchange(
                requestedClientId = tokenRequest.clientId,
                clientAuthorization = authenticated.clientAuthorization,
                sender =
                    TokenExchangeSender(
                        proofJkt = context.proofJkt,
                        certThumbprintS256 = context.certThumbprintS256,
                        baseUrlOverride = args.baseUrlOverride,
                    ),
                parameters =
                    TokenExchangeParameters(
                        subjectToken = parameters.subjectToken,
                        subjectTokenType = parameters.subjectTokenType,
                        actorToken = parameters.actorToken,
                        actorTokenType = parameters.actorTokenType,
                        resources = parameters.resources,
                        audiences = parameters.audiences,
                        scope = parameters.scope,
                        requestedTokenType = parameters.requestedTokenType,
                    ),
            ),
        )
    }
}

/** The full raw-request journey, from client authentication to the token response. */
internal fun tokenExchangeJourney(
    authenticateClient: Command<HandleTokenRequestArgs, ClientAuthenticatedExchange, AuthorizationServerError>,
    steps: TokenExchangeStepCommands,
): JourneyPipeline<HandleTokenRequestArgs, TokenResponse, AuthorizationServerError> =
    JourneyBuilder
        .start(
            TOKEN_EXCHANGE_JOURNEY_ID,
            listOf(RFC8693_REQUEST, RFC8693_RESPONSE),
            JourneyStep(JourneyStepContract(TokenExchangeJourneySteps.AUTHENTICATE_CLIENT, authenticateClient.id, listOf(RFC6749_TOKEN_ENDPOINT)), authenticateClient),
            TokenExchangeProtocolErrorMapper,
        ).then(parseStep(steps))
        .then(resolveIssuerTrustStep(steps))
        .then(verifySubjectStep(steps))
        .then(verifyActorStep(steps))
        .then(authorizeStep(steps))
        .then(boundTargetsStep(steps))
        .then(mapClaimsStep(steps))
        .then(buildActorChainStep(steps))
        .then(JourneyStep(JourneyStepContract(TokenExchangeJourneySteps.MINT, steps.mint.id, listOf(RFC8693_RESPONSE, RFC9449_BINDING)), steps.mint))
        .then(JourneyStep(JourneyStepContract(TokenExchangeJourneySteps.RESPOND, steps.respond.id, listOf(RFC8693_RESPONSE)), steps.respond))
        .build()

private fun parseStep(steps: TokenExchangeStepCommands) =
    JourneyStep(JourneyStepContract(TokenExchangeJourneySteps.PARSE_EXCHANGE, steps.parse.id, listOf(RFC8693_REQUEST, RFC8707_RESOURCE)), steps.parse)

private fun resolveIssuerTrustStep(steps: TokenExchangeStepCommands) =
    JourneyStep(JourneyStepContract(TokenExchangeJourneySteps.RESOLVE_ISSUER_TRUST, steps.resolveIssuerTrust.id, listOf(RFC8693_REQUEST)), steps.resolveIssuerTrust)

private fun verifySubjectStep(steps: TokenExchangeStepCommands) =
    JourneyStep(JourneyStepContract(TokenExchangeJourneySteps.VERIFY_SUBJECT, steps.verifySubject.id, listOf(RFC8693_REQUEST, RFC7519_VALIDATION)), steps.verifySubject)

private fun verifyActorStep(steps: TokenExchangeStepCommands) =
    JourneyStep(JourneyStepContract(TokenExchangeJourneySteps.VERIFY_ACTOR, steps.verifyActor.id, listOf(RFC8693_REQUEST, RFC8693_MAY_ACT, RFC7519_VALIDATION)), steps.verifyActor)

private fun authorizeStep(steps: TokenExchangeStepCommands) =
    JourneyStep(
        JourneyStepContract(TokenExchangeJourneySteps.AUTHORIZE_EXCHANGE, steps.authorize.id, listOf(RFC8693_REQUEST), extensionPoint = AuthorizeTokenExchangeCommand.COMMAND_ID),
        steps.authorize,
    )

private fun boundTargetsStep(steps: TokenExchangeStepCommands) =
    JourneyStep(JourneyStepContract(TokenExchangeJourneySteps.BOUND_TARGETS, steps.boundTargets.id, listOf(RFC8693_REQUEST, RFC8707_RESOURCE)), steps.boundTargets)

private fun mapClaimsStep(steps: TokenExchangeStepCommands) =
    JourneyStep(
        JourneyStepContract(TokenExchangeJourneySteps.MAP_CLAIMS, steps.mapClaims.id, listOf(RFC8693_RESPONSE), extensionPoint = MapTokenExchangeClaimsCommand.COMMAND_ID),
        steps.mapClaims,
    )

private fun buildActorChainStep(steps: TokenExchangeStepCommands) =
    JourneyStep(
        JourneyStepContract(TokenExchangeJourneySteps.BUILD_ACTOR_CHAIN, steps.buildActorChain.id, listOf(RFC8693_ACT), extensionPoint = BuildTokenExchangeActorChainCommand.COMMAND_ID),
        steps.buildActorChain,
    )
