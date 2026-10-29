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

package com.sphereon.oauth2.server.authorization.impl.service

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.StringResult
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.common.model.AuthorizationServerMetadata
import com.sphereon.oauth2.common.model.TokenIntrospectionResponse
import com.sphereon.oauth2.common.model.TokenResponse
import com.sphereon.oauth2.server.authorization.command.AttestationChallengeResponse
import com.sphereon.oauth2.server.authorization.command.AuthorizationErrorResponseData
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData
import com.sphereon.oauth2.server.authorization.command.AuthorizationResponseData
import com.sphereon.oauth2.server.authorization.command.BuildServerMetadataArgs
import com.sphereon.oauth2.server.authorization.command.BuildServerMetadataCommand
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreateAttestationChallengeArgs
import com.sphereon.oauth2.server.authorization.command.CreateAttestationChallengeCommand
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationCodeArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationCodeCommand
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationErrorResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationErrorResponseCommand
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationResponseCommand
import com.sphereon.oauth2.server.authorization.command.CreateAuthorizationSessionCommand
import com.sphereon.oauth2.server.authorization.command.CreateIdTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateIdTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreatePushedAuthorizationResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreatePushedAuthorizationResponseCommand
import com.sphereon.oauth2.server.authorization.command.CreateRefreshTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateRefreshTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreateRequestUriCommand
import com.sphereon.oauth2.server.authorization.command.CreateTokenResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreateTokenResponseCommand
import com.sphereon.oauth2.server.authorization.command.GetJwksArgs
import com.sphereon.oauth2.server.authorization.command.GetJwksCommand
import com.sphereon.oauth2.server.authorization.command.GetUserInfoArgs
import com.sphereon.oauth2.server.authorization.command.GetUserInfoCommand
import com.sphereon.oauth2.server.authorization.command.IntrospectTokenArgs
import com.sphereon.oauth2.server.authorization.command.IntrospectTokenCommand
import com.sphereon.oauth2.server.authorization.command.IntrospectionRequestData
import com.sphereon.oauth2.server.authorization.command.JwksResult
import com.sphereon.oauth2.server.authorization.command.ParseAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParseAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.command.ParseIntrospectionRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParseIntrospectionRequestCommand
import com.sphereon.oauth2.server.authorization.command.ParsePushedAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParsePushedAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.command.ParseRevocationRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParseRevocationRequestCommand
import com.sphereon.oauth2.server.authorization.command.ParseTokenRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParseTokenRequestCommand
import com.sphereon.oauth2.server.authorization.command.PushedAuthorizationResponse
import com.sphereon.oauth2.server.authorization.command.RequestUriData
import com.sphereon.oauth2.server.authorization.command.RetrieveAuthorizationRequestByUriCommand
import com.sphereon.oauth2.server.authorization.command.RetrieveByRequestUriArgs
import com.sphereon.oauth2.server.authorization.command.RevocationRequestData
import com.sphereon.oauth2.server.authorization.command.RevokeTokenArgs
import com.sphereon.oauth2.server.authorization.command.RevokeTokenCommand
import com.sphereon.oauth2.server.authorization.command.TokenRequestData
import com.sphereon.oauth2.server.authorization.command.UserInfoResponse
import com.sphereon.oauth2.server.authorization.command.VerifiedAuthorizationCodeGrant
import com.sphereon.oauth2.server.authorization.command.VerifiedAuthorizationRequest
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthentication
import com.sphereon.oauth2.server.authorization.command.VerifiedClientCredentialsGrant
import com.sphereon.oauth2.server.authorization.command.VerifiedPreAuthCodeGrant
import com.sphereon.oauth2.server.authorization.command.VerifiedRefreshTokenGrant
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantArgs
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantCommand
import com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationArgs
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand
import com.sphereon.oauth2.server.authorization.command.VerifyClientCredentialsGrantArgs
import com.sphereon.oauth2.server.authorization.command.VerifyClientCredentialsGrantCommand
import com.sphereon.oauth2.server.authorization.command.VerifyPreAuthCodeArgs
import com.sphereon.oauth2.server.authorization.command.VerifyPreAuthorizedCodeGrantCommand
import com.sphereon.oauth2.server.authorization.command.VerifyPushedAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.command.VerifyPushedAuthorizationRequestCommand
import com.sphereon.oauth2.server.authorization.command.VerifyRefreshTokenGrantArgs
import com.sphereon.oauth2.server.authorization.command.VerifyRefreshTokenGrantCommand
import com.sphereon.oauth2.server.authorization.model.AuthorizationSession
import com.sphereon.oauth2.server.authorization.service.AuthorizationServerService
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<AuthorizationServerService>())
@OptIn(ExperimentalObjCName::class)
@ObjCName("AuthorizationServerServiceImpl", exact = true)
class AuthorizationServerServiceImpl @Inject constructor(
    parseTokenRequestCommandFactory: () -> ParseTokenRequestCommand,
    verifyAuthorizationCodeGrantCommandFactory: () -> VerifyAuthorizationCodeGrantCommand,
    verifyRefreshTokenGrantCommandFactory: () -> VerifyRefreshTokenGrantCommand,
    verifyClientCredentialsGrantCommandFactory: () -> VerifyClientCredentialsGrantCommand,
    verifyPreAuthorizedCodeGrantCommandFactory: () -> VerifyPreAuthorizedCodeGrantCommand,
    createAccessTokenCommandFactory: () -> CreateAccessTokenCommand,
    createRefreshTokenCommandFactory: () -> CreateRefreshTokenCommand,
    createTokenResponseCommandFactory: () -> CreateTokenResponseCommand,
    parseAuthorizationRequestCommandFactory: () -> ParseAuthorizationRequestCommand,
    verifyAuthorizationRequestCommandFactory: () -> VerifyAuthorizationRequestCommand,
    createAuthorizationSessionCommandFactory: () -> CreateAuthorizationSessionCommand,
    createAuthorizationCodeCommandFactory: () -> CreateAuthorizationCodeCommand,
    createAuthorizationResponseCommandFactory: () -> CreateAuthorizationResponseCommand,
    createAuthorizationErrorResponseCommandFactory: () -> CreateAuthorizationErrorResponseCommand,
    parsePushedAuthorizationRequestCommandFactory: () -> ParsePushedAuthorizationRequestCommand,
    verifyPushedAuthorizationRequestCommandFactory: () -> VerifyPushedAuthorizationRequestCommand,
    createRequestUriCommandFactory: () -> CreateRequestUriCommand,
    createPushedAuthorizationResponseCommandFactory: () -> CreatePushedAuthorizationResponseCommand,
    retrieveAuthorizationRequestByUriCommandFactory: () -> RetrieveAuthorizationRequestByUriCommand,
    parseIntrospectionRequestCommandFactory: () -> ParseIntrospectionRequestCommand,
    introspectTokenCommandFactory: () -> IntrospectTokenCommand,
    parseRevocationRequestCommandFactory: () -> ParseRevocationRequestCommand,
    revokeTokenCommandFactory: () -> RevokeTokenCommand,
    buildServerMetadataCommandFactory: () -> BuildServerMetadataCommand,
    verifyClientAuthenticationCommandFactory: () -> VerifyClientAuthenticationCommand,
    createAttestationChallengeCommandFactory: () -> CreateAttestationChallengeCommand,
    createIdTokenCommandFactory: () -> CreateIdTokenCommand,
    getUserInfoCommandFactory: () -> GetUserInfoCommand,
    getJwksCommandFactory: () -> GetJwksCommand,
) : AuthorizationServerService {
    private val parseTokenRequestCommand: ParseTokenRequestCommand by lazy(parseTokenRequestCommandFactory)
    private val verifyAuthorizationCodeGrantCommand: VerifyAuthorizationCodeGrantCommand by lazy(verifyAuthorizationCodeGrantCommandFactory)
    private val verifyRefreshTokenGrantCommand: VerifyRefreshTokenGrantCommand by lazy(verifyRefreshTokenGrantCommandFactory)
    private val verifyClientCredentialsGrantCommand: VerifyClientCredentialsGrantCommand by lazy(verifyClientCredentialsGrantCommandFactory)
    private val verifyPreAuthorizedCodeGrantCommand: VerifyPreAuthorizedCodeGrantCommand by lazy(verifyPreAuthorizedCodeGrantCommandFactory)
    private val createAccessTokenCommand: CreateAccessTokenCommand by lazy(createAccessTokenCommandFactory)
    private val createRefreshTokenCommand: CreateRefreshTokenCommand by lazy(createRefreshTokenCommandFactory)
    private val createTokenResponseCommand: CreateTokenResponseCommand by lazy(createTokenResponseCommandFactory)
    private val parseAuthorizationRequestCommand: ParseAuthorizationRequestCommand by lazy(parseAuthorizationRequestCommandFactory)
    private val verifyAuthorizationRequestCommand: VerifyAuthorizationRequestCommand by lazy(verifyAuthorizationRequestCommandFactory)
    private val createAuthorizationSessionCommand: CreateAuthorizationSessionCommand by lazy(createAuthorizationSessionCommandFactory)
    private val createAuthorizationCodeCommand: CreateAuthorizationCodeCommand by lazy(createAuthorizationCodeCommandFactory)
    private val createAuthorizationResponseCommand: CreateAuthorizationResponseCommand by lazy(createAuthorizationResponseCommandFactory)
    private val createAuthorizationErrorResponseCommand: CreateAuthorizationErrorResponseCommand by lazy(createAuthorizationErrorResponseCommandFactory)
    private val parsePushedAuthorizationRequestCommand: ParsePushedAuthorizationRequestCommand by lazy(parsePushedAuthorizationRequestCommandFactory)
    private val verifyPushedAuthorizationRequestCommand: VerifyPushedAuthorizationRequestCommand by lazy(verifyPushedAuthorizationRequestCommandFactory)
    private val createRequestUriCommand: CreateRequestUriCommand by lazy(createRequestUriCommandFactory)
    private val createPushedAuthorizationResponseCommand: CreatePushedAuthorizationResponseCommand by lazy(createPushedAuthorizationResponseCommandFactory)
    private val retrieveAuthorizationRequestByUriCommand: RetrieveAuthorizationRequestByUriCommand by lazy(retrieveAuthorizationRequestByUriCommandFactory)
    private val parseIntrospectionRequestCommand: ParseIntrospectionRequestCommand by lazy(parseIntrospectionRequestCommandFactory)
    private val introspectTokenCommand: IntrospectTokenCommand by lazy(introspectTokenCommandFactory)
    private val parseRevocationRequestCommand: ParseRevocationRequestCommand by lazy(parseRevocationRequestCommandFactory)
    private val revokeTokenCommand: RevokeTokenCommand by lazy(revokeTokenCommandFactory)
    private val buildServerMetadataCommand: BuildServerMetadataCommand by lazy(buildServerMetadataCommandFactory)
    private val verifyClientAuthenticationCommand: VerifyClientAuthenticationCommand by lazy(verifyClientAuthenticationCommandFactory)
    private val createAttestationChallengeCommand: CreateAttestationChallengeCommand by lazy(createAttestationChallengeCommandFactory)
    private val createIdTokenCommand: CreateIdTokenCommand by lazy(createIdTokenCommandFactory)
    private val getUserInfoCommand: GetUserInfoCommand by lazy(getUserInfoCommandFactory)
    private val getJwksCommand: GetJwksCommand by lazy(getJwksCommandFactory)

    /** Source-compatible constructor for callers that already own these dependencies. */
    constructor(
        parseTokenRequestCommand: ParseTokenRequestCommand,
        verifyAuthorizationCodeGrantCommand: VerifyAuthorizationCodeGrantCommand,
        verifyRefreshTokenGrantCommand: VerifyRefreshTokenGrantCommand,
        verifyClientCredentialsGrantCommand: VerifyClientCredentialsGrantCommand,
        verifyPreAuthorizedCodeGrantCommand: VerifyPreAuthorizedCodeGrantCommand,
        createAccessTokenCommand: CreateAccessTokenCommand,
        createRefreshTokenCommand: CreateRefreshTokenCommand,
        createTokenResponseCommand: CreateTokenResponseCommand,
        parseAuthorizationRequestCommand: ParseAuthorizationRequestCommand,
        verifyAuthorizationRequestCommand: VerifyAuthorizationRequestCommand,
        createAuthorizationSessionCommand: CreateAuthorizationSessionCommand,
        createAuthorizationCodeCommand: CreateAuthorizationCodeCommand,
        createAuthorizationResponseCommand: CreateAuthorizationResponseCommand,
        createAuthorizationErrorResponseCommand: CreateAuthorizationErrorResponseCommand,
        parsePushedAuthorizationRequestCommand: ParsePushedAuthorizationRequestCommand,
        verifyPushedAuthorizationRequestCommand: VerifyPushedAuthorizationRequestCommand,
        createRequestUriCommand: CreateRequestUriCommand,
        createPushedAuthorizationResponseCommand: CreatePushedAuthorizationResponseCommand,
        retrieveAuthorizationRequestByUriCommand: RetrieveAuthorizationRequestByUriCommand,
        parseIntrospectionRequestCommand: ParseIntrospectionRequestCommand,
        introspectTokenCommand: IntrospectTokenCommand,
        parseRevocationRequestCommand: ParseRevocationRequestCommand,
        revokeTokenCommand: RevokeTokenCommand,
        buildServerMetadataCommand: BuildServerMetadataCommand,
        verifyClientAuthenticationCommand: VerifyClientAuthenticationCommand,
        createAttestationChallengeCommand: CreateAttestationChallengeCommand,
        createIdTokenCommand: CreateIdTokenCommand,
        getUserInfoCommand: GetUserInfoCommand,
        getJwksCommand: GetJwksCommand,
    ) : this(
        parseTokenRequestCommandFactory = { parseTokenRequestCommand },
        verifyAuthorizationCodeGrantCommandFactory = { verifyAuthorizationCodeGrantCommand },
        verifyRefreshTokenGrantCommandFactory = { verifyRefreshTokenGrantCommand },
        verifyClientCredentialsGrantCommandFactory = { verifyClientCredentialsGrantCommand },
        verifyPreAuthorizedCodeGrantCommandFactory = { verifyPreAuthorizedCodeGrantCommand },
        createAccessTokenCommandFactory = { createAccessTokenCommand },
        createRefreshTokenCommandFactory = { createRefreshTokenCommand },
        createTokenResponseCommandFactory = { createTokenResponseCommand },
        parseAuthorizationRequestCommandFactory = { parseAuthorizationRequestCommand },
        verifyAuthorizationRequestCommandFactory = { verifyAuthorizationRequestCommand },
        createAuthorizationSessionCommandFactory = { createAuthorizationSessionCommand },
        createAuthorizationCodeCommandFactory = { createAuthorizationCodeCommand },
        createAuthorizationResponseCommandFactory = { createAuthorizationResponseCommand },
        createAuthorizationErrorResponseCommandFactory = { createAuthorizationErrorResponseCommand },
        parsePushedAuthorizationRequestCommandFactory = { parsePushedAuthorizationRequestCommand },
        verifyPushedAuthorizationRequestCommandFactory = { verifyPushedAuthorizationRequestCommand },
        createRequestUriCommandFactory = { createRequestUriCommand },
        createPushedAuthorizationResponseCommandFactory = { createPushedAuthorizationResponseCommand },
        retrieveAuthorizationRequestByUriCommandFactory = { retrieveAuthorizationRequestByUriCommand },
        parseIntrospectionRequestCommandFactory = { parseIntrospectionRequestCommand },
        introspectTokenCommandFactory = { introspectTokenCommand },
        parseRevocationRequestCommandFactory = { parseRevocationRequestCommand },
        revokeTokenCommandFactory = { revokeTokenCommand },
        buildServerMetadataCommandFactory = { buildServerMetadataCommand },
        verifyClientAuthenticationCommandFactory = { verifyClientAuthenticationCommand },
        createAttestationChallengeCommandFactory = { createAttestationChallengeCommand },
        createIdTokenCommandFactory = { createIdTokenCommand },
        getUserInfoCommandFactory = { getUserInfoCommand },
        getJwksCommandFactory = { getJwksCommand },
    )

    inner class CommandsImpl : AuthorizationServerService.Commands {
        override val parseTokenRequest get() = this@AuthorizationServerServiceImpl.parseTokenRequestCommand
        override val verifyAuthorizationCodeGrant get() = this@AuthorizationServerServiceImpl.verifyAuthorizationCodeGrantCommand
        override val verifyRefreshTokenGrant get() = this@AuthorizationServerServiceImpl.verifyRefreshTokenGrantCommand
        override val verifyClientCredentialsGrant get() = this@AuthorizationServerServiceImpl.verifyClientCredentialsGrantCommand
        override val verifyPreAuthorizedCodeGrant get() = this@AuthorizationServerServiceImpl.verifyPreAuthorizedCodeGrantCommand
        override val createAccessToken get() = this@AuthorizationServerServiceImpl.createAccessTokenCommand
        override val createRefreshToken get() = this@AuthorizationServerServiceImpl.createRefreshTokenCommand
        override val createTokenResponse get() = this@AuthorizationServerServiceImpl.createTokenResponseCommand
        override val parseAuthorizationRequest get() = this@AuthorizationServerServiceImpl.parseAuthorizationRequestCommand
        override val verifyAuthorizationRequest get() = this@AuthorizationServerServiceImpl.verifyAuthorizationRequestCommand
        override val createAuthorizationSession get() = this@AuthorizationServerServiceImpl.createAuthorizationSessionCommand
        override val createAuthorizationCode get() = this@AuthorizationServerServiceImpl.createAuthorizationCodeCommand
        override val createAuthorizationResponse get() = this@AuthorizationServerServiceImpl.createAuthorizationResponseCommand
        override val createAuthorizationErrorResponse get() = this@AuthorizationServerServiceImpl.createAuthorizationErrorResponseCommand
        override val parsePushedAuthorizationRequest get() = this@AuthorizationServerServiceImpl.parsePushedAuthorizationRequestCommand
        override val verifyPushedAuthorizationRequest get() = this@AuthorizationServerServiceImpl.verifyPushedAuthorizationRequestCommand
        override val createRequestUri get() = this@AuthorizationServerServiceImpl.createRequestUriCommand
        override val createPushedAuthorizationResponse get() = this@AuthorizationServerServiceImpl.createPushedAuthorizationResponseCommand
        override val retrieveAuthorizationRequestByUri get() = this@AuthorizationServerServiceImpl.retrieveAuthorizationRequestByUriCommand
        override val parseIntrospectionRequest get() = this@AuthorizationServerServiceImpl.parseIntrospectionRequestCommand
        override val introspectToken get() = this@AuthorizationServerServiceImpl.introspectTokenCommand
        override val parseRevocationRequest get() = this@AuthorizationServerServiceImpl.parseRevocationRequestCommand
        override val revokeToken get() = this@AuthorizationServerServiceImpl.revokeTokenCommand
        override val buildServerMetadata get() = this@AuthorizationServerServiceImpl.buildServerMetadataCommand
        override val verifyClientAuthentication get() = this@AuthorizationServerServiceImpl.verifyClientAuthenticationCommand
        override val createAttestationChallenge get() = this@AuthorizationServerServiceImpl.createAttestationChallengeCommand
        override val createIdToken get() = this@AuthorizationServerServiceImpl.createIdTokenCommand
        override val getUserInfo get() = this@AuthorizationServerServiceImpl.getUserInfoCommand
        override val getJwks get() = this@AuthorizationServerServiceImpl.getJwksCommand
    }

    override val commands: AuthorizationServerService.Commands = CommandsImpl()

    // Authorization Endpoint delegations
    override suspend fun parseAuthorizationRequest(args: ParseAuthorizationRequestArgs): IdkResult<AuthorizationRequestData, IdkError> = parseAuthorizationRequestCommand.execute(args)

    override suspend fun verifyAuthorizationRequest(args: AuthorizationRequestData): IdkResult<VerifiedAuthorizationRequest, IdkError> = verifyAuthorizationRequestCommand.execute(args)

    override suspend fun createAuthorizationSession(args: VerifiedAuthorizationRequest): IdkResult<AuthorizationSession, IdkError> = createAuthorizationSessionCommand.execute(args)

    override suspend fun createAuthorizationCode(args: CreateAuthorizationCodeArgs): IdkResult<StringResult, IdkError> = createAuthorizationCodeCommand.execute(args)

    override suspend fun createAuthorizationResponse(args: CreateAuthorizationResponseArgs): IdkResult<AuthorizationResponseData, IdkError> = createAuthorizationResponseCommand.execute(args)

    override suspend fun createAuthorizationErrorResponse(args: CreateAuthorizationErrorResponseArgs): IdkResult<AuthorizationErrorResponseData, IdkError> =
        createAuthorizationErrorResponseCommand.execute(args)

    // Token Endpoint delegations
    override suspend fun parseTokenRequest(args: ParseTokenRequestArgs): IdkResult<TokenRequestData, IdkError> = parseTokenRequestCommand.execute(args)

    override suspend fun verifyAuthorizationCodeGrant(args: VerifyAuthorizationCodeGrantArgs): IdkResult<VerifiedAuthorizationCodeGrant, IdkError> = verifyAuthorizationCodeGrantCommand.execute(args)

    override suspend fun verifyRefreshTokenGrant(args: VerifyRefreshTokenGrantArgs): IdkResult<VerifiedRefreshTokenGrant, IdkError> = verifyRefreshTokenGrantCommand.execute(args)

    override suspend fun verifyClientCredentialsGrant(args: VerifyClientCredentialsGrantArgs): IdkResult<VerifiedClientCredentialsGrant, IdkError> = verifyClientCredentialsGrantCommand.execute(args)

    override suspend fun verifyPreAuthorizedCodeGrant(args: VerifyPreAuthCodeArgs): IdkResult<VerifiedPreAuthCodeGrant, IdkError> = verifyPreAuthorizedCodeGrantCommand.execute(args)

    override suspend fun createAccessToken(args: CreateAccessTokenArgs): IdkResult<StringResult, IdkError> = createAccessTokenCommand.execute(args)

    override suspend fun createRefreshToken(args: CreateRefreshTokenArgs): IdkResult<StringResult, IdkError> = createRefreshTokenCommand.execute(args)

    override suspend fun createTokenResponse(args: CreateTokenResponseArgs): IdkResult<TokenResponse, IdkError> = createTokenResponseCommand.execute(args)

    // PAR Endpoint delegations
    override suspend fun parsePushedAuthorizationRequest(args: ParsePushedAuthorizationRequestArgs): IdkResult<AuthorizationRequestData, IdkError> =
        parsePushedAuthorizationRequestCommand.execute(args)

    override suspend fun verifyPushedAuthorizationRequest(args: VerifyPushedAuthorizationRequestArgs): IdkResult<VerifiedAuthorizationRequest, IdkError> =
        verifyPushedAuthorizationRequestCommand.execute(args)

    override suspend fun createRequestUri(args: VerifiedAuthorizationRequest): IdkResult<RequestUriData, IdkError> = createRequestUriCommand.execute(args)

    override suspend fun createPushedAuthorizationResponse(args: CreatePushedAuthorizationResponseArgs): IdkResult<PushedAuthorizationResponse, IdkError> =
        createPushedAuthorizationResponseCommand.execute(args)

    override suspend fun retrieveAuthorizationRequestByUri(requestUri: String): IdkResult<VerifiedAuthorizationRequest, IdkError> =
        retrieveAuthorizationRequestByUriCommand.execute(RetrieveByRequestUriArgs(requestUri))

    // Introspection Endpoint delegations
    override suspend fun parseIntrospectionRequest(args: ParseIntrospectionRequestArgs): IdkResult<IntrospectionRequestData, IdkError> = parseIntrospectionRequestCommand.execute(args)

    override suspend fun introspectToken(args: IntrospectTokenArgs): IdkResult<TokenIntrospectionResponse, IdkError> = introspectTokenCommand.execute(args)

    // Revocation Endpoint delegations
    override suspend fun parseRevocationRequest(args: ParseRevocationRequestArgs): IdkResult<RevocationRequestData, IdkError> = parseRevocationRequestCommand.execute(args)

    override suspend fun revokeToken(args: RevokeTokenArgs): IdkResult<Unit, IdkError> = revokeTokenCommand.execute(args)

    // Discovery Endpoint delegations
    override suspend fun buildServerMetadata(args: BuildServerMetadataArgs): IdkResult<AuthorizationServerMetadata, IdkError> = buildServerMetadataCommand.execute(args)

    // Client Authentication delegations
    override suspend fun verifyClientAuthentication(args: VerifyClientAuthenticationArgs): IdkResult<VerifiedClientAuthentication, IdkError> = verifyClientAuthenticationCommand.execute(args)

    // Attestation Challenge delegations
    override suspend fun createAttestationChallenge(args: CreateAttestationChallengeArgs): IdkResult<AttestationChallengeResponse, IdkError> = createAttestationChallengeCommand.execute(args)

    // OIDC delegations
    override suspend fun createIdToken(args: CreateIdTokenArgs): IdkResult<StringResult, IdkError> = createIdTokenCommand.execute(args)

    override suspend fun getUserInfo(args: GetUserInfoArgs): IdkResult<UserInfoResponse, IdkError> = getUserInfoCommand.execute(args)

    override suspend fun getJwks(args: GetJwksArgs): IdkResult<JwksResult, IdkError> = getJwksCommand.execute(args)

    @ContributesTo(scope = SessionScope::class)
    interface Graph {
        val authorizationServerService: AuthorizationServerService
    }
}
