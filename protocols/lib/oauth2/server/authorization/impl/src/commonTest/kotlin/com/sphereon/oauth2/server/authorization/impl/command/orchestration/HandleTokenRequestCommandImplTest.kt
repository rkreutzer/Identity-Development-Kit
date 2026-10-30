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

package com.sphereon.oauth2.server.authorization.impl.command.orchestration

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.StringResult
import com.sphereon.core.api.context.IdkScope
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.log.AsyncLogService
import com.sphereon.core.api.log.Log
import com.sphereon.core.api.log.LogLevel
import com.sphereon.core.api.log.LogManager
import com.sphereon.core.api.log.LogMessage
import com.sphereon.core.api.log.LogService
import com.sphereon.core.api.log.LoggerConfig
import com.sphereon.di.context.NoOpSessionContext
import com.sphereon.di.session.SessionContext
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.core.defaults.random.defaultSecureRandom
import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.oauth2.common.command.VerifyDpopProofCommand
import com.sphereon.oauth2.common.config.FeaturePolicy
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.DpopJwtHeader
import com.sphereon.oauth2.common.model.DpopJwtPayload
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.model.TokenResponse
import com.sphereon.oauth2.common.model.VerifyDpopProofOptions
import com.sphereon.oauth2.common.model.VerifyDpopProofResult
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreateIdTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateIdTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreateRefreshTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateRefreshTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreateTokenResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreateTokenResponseCommand
import com.sphereon.oauth2.server.authorization.command.GrantParameters
import com.sphereon.oauth2.server.authorization.command.ParseTokenRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParseTokenRequestCommand
import com.sphereon.oauth2.server.authorization.command.TokenRequestData
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthentication
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthorization
import com.sphereon.oauth2.server.authorization.command.VerifiedClientCredentialsGrant
import com.sphereon.oauth2.server.authorization.command.VerifiedRefreshTokenGrant
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationArgs
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand
import com.sphereon.oauth2.server.authorization.command.VerifyClientCredentialsGrantArgs
import com.sphereon.oauth2.server.authorization.command.VerifyClientCredentialsGrantCommand
import com.sphereon.oauth2.server.authorization.command.VerifyRefreshTokenGrantArgs
import com.sphereon.oauth2.server.authorization.command.VerifyRefreshTokenGrantCommand
import com.sphereon.oauth2.server.authorization.command.token.HandleTokenRequestArgs
import com.sphereon.oauth2.server.authorization.command.token.VerifiedDeviceCodeGrant
import com.sphereon.oauth2.server.authorization.command.token.VerifyDeviceCodeGrantArgs
import com.sphereon.oauth2.server.authorization.command.token.VerifyDeviceCodeGrantCommand
import com.sphereon.oauth2.server.authorization.dpop.DpopNonceManager
import com.sphereon.oauth2.server.authorization.dpop.DpopProofJtiCache
import com.sphereon.oauth2.server.authorization.impl.command.token.HandleTokenRequestCommandImpl
import com.sphereon.oauth2.server.authorization.impl.command.token.VerifyRefreshTokenGrantCommandImpl
import com.sphereon.oauth2.server.authorization.impl.dpop.InMemoryDpopProofJtiCacheImpl
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryClientRegistryImpl
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryDeviceAuthorizationStorageImpl
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryOAuth2BackingStorageImpl
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemorySingleUseObjectStore
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryTokenStorageImpl
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.StubClientRegistry
import com.sphereon.oauth2.server.authorization.impl.testutil.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.model.RefreshTokenData
import com.sphereon.oauth2.server.authorization.storage.ClientRegistry
import com.sphereon.oauth2.server.authorization.storage.TokenStorage
import com.sphereon.oauth2.server.authorization.command.token.TokenExchangeJourneyCommand
import com.sphereon.oauth2.server.authorization.impl.command.token.exchange.TokenExchangeJourneyCommandImpl
import com.sphereon.oauth2.server.authorization.impl.policy.StandardTokenExchangeProfile
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemorySigningKeyStore
import com.sphereon.oauth2.server.authorization.impl.testutil.RecordingJwtService
import com.sphereon.oauth2.server.authorization.impl.trust.NoForeignSubjectTokenIssuerTrust
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Clock
import kotlin.time.Duration.Companion.seconds

class HandleTokenRequestCommandImplTest {
    private val ctx = OAuth2ServerTestContext("handle-token-test", this)

    private val configProvider =
        TestOAuth2ServersConfigProvider(
            OAuth2ServersConfig(
                servers = mapOf("default" to OAuth2ServerInstanceConfig(issuer = "https://as.example.com")),
            ),
        )

    private fun stubParseTokenRequest(handler: suspend (ParseTokenRequestArgs) -> IdkResult<TokenRequestData, IdkError>): ParseTokenRequestCommand =
        object : ParseTokenRequestCommand {
            override val inputTypeToken = typeToken<ParseTokenRequestArgs>()
            override val outputTypeToken = typeToken<TokenRequestData>()
            override val isEnabled = true

            override suspend fun execute(args: ParseTokenRequestArgs) = handler(args)
        }

    private fun stubVerifyClientCredentialsGrant(handler: suspend (VerifyClientCredentialsGrantArgs) -> IdkResult<VerifiedClientCredentialsGrant, IdkError>): VerifyClientCredentialsGrantCommand =
        object : VerifyClientCredentialsGrantCommand {
            override val inputTypeToken = typeToken<VerifyClientCredentialsGrantArgs>()
            override val outputTypeToken = typeToken<VerifiedClientCredentialsGrant>()
            override val isEnabled = true

            override suspend fun execute(args: VerifyClientCredentialsGrantArgs) = handler(args)
        }

    private fun stubCreateAccessToken(handler: suspend (CreateAccessTokenArgs) -> IdkResult<StringResult, IdkError>): CreateAccessTokenCommand =
        object : CreateAccessTokenCommand {
            override val inputTypeToken = typeToken<CreateAccessTokenArgs>()
            override val outputTypeToken = typeToken<StringResult>()
            override val isEnabled = true

            override suspend fun execute(args: CreateAccessTokenArgs) = handler(args)
        }

    private fun stubCreateTokenResponse(handler: suspend (CreateTokenResponseArgs) -> IdkResult<TokenResponse, IdkError>): CreateTokenResponseCommand =
        object : CreateTokenResponseCommand {
            override val inputTypeToken = typeToken<CreateTokenResponseArgs>()
            override val outputTypeToken = typeToken<TokenResponse>()
            override val isEnabled = true

            override suspend fun execute(args: CreateTokenResponseArgs) = handler(args)
        }

    private val noOpSecureRandom = defaultSecureRandom()

    /** DPoP-verify stub that always rejects: tests in this file never present DPoP headers. */
    private val rejectingDpopVerify: Lazy<VerifyDpopProofCommand> =
        lazyOf(object : VerifyDpopProofCommand {
            override val inputTypeToken = typeToken<VerifyDpopProofOptions>()
            override val outputTypeToken = typeToken<VerifyDpopProofResult>()
            override val isEnabled = true

            override suspend fun execute(args: VerifyDpopProofOptions): IdkResult<VerifyDpopProofResult, IdkError> = Err(IdkError.fromString(code = "invalid_dpop_proof", message = "test stub"))
        })

    private fun newDpopJtiCache(): Lazy<DpopProofJtiCache> = lazyOf(InMemoryDpopProofJtiCacheImpl(InMemorySingleUseObjectStore()))

    /**
     * Lightweight [DpopNonceManager] for unit tests: never requires nonce, returns predictable
     * fixed values. Tests that exercise nonce challenges should construct their own manager.
     */
    private fun newDpopNonceManager(): Lazy<DpopNonceManager> =
        lazyOf(object : DpopNonceManager {
            private var counter = 0

            override suspend fun currentNonce(): String = "test-nonce-current"

            override suspend fun rotate(): String = "test-nonce-rotated-${++counter}"

            override suspend fun isValid(nonce: String): Boolean = true
        })

    private fun newTokenStorage(): InMemoryTokenStorageImpl = InMemoryTokenStorageImpl(InMemoryOAuth2BackingStorageImpl())

    private fun newClientRegistry(): ClientRegistry = InMemoryClientRegistryImpl(InMemoryOAuth2BackingStorageImpl())

    private fun tokenExchangeJourney(
        parse: ParseTokenRequestCommand,
        verifyClientAuthentication: VerifyClientAuthenticationCommand,
        createAccessToken: CreateAccessTokenCommand,
        createTokenResponse: CreateTokenResponseCommand,
    ): TokenExchangeJourneyCommand =
        TokenExchangeJourneyCommandImpl(
            execution = ctx.execution,
            parseTokenRequestCommand = parse,
            verifyClientAuthenticationCommand = verifyClientAuthentication,
            serversConfigProvider = configProvider,
            verifyDpopProofCommand = rejectingDpopVerify,
            dpopProofJtiCache = newDpopJtiCache(),
            dpopNonceManager = newDpopNonceManager(),
            clientRegistry = newClientRegistry(),
            jwtService = RecordingJwtService(),
            signingKeyStore = InMemorySigningKeyStore(),
            subjectTokenIssuerTrust = NoForeignSubjectTokenIssuerTrust(),
            tokenExchangeProfile = StandardTokenExchangeProfile(),
            createAccessToken = createAccessToken,
            createTokenResponse = createTokenResponse,
        )

    @Test
    fun unknownPublicClientCannotUseClientCredentialsTokenExchangeOrRefresh() = runTest {
        val tokenStorage = newTokenStorage()
        val verifyRefreshTokenGrant =
            VerifyRefreshTokenGrantCommandImpl(
                execution = ctx.execution,
                tokenStorage = tokenStorage,
                configProvider = configProvider,
                clientRegistry = StubClientRegistry(),
            )
        val grants = listOf(
            GrantType.CLIENT_CREDENTIALS to GrantParameters.ClientCredentials(),
            GrantType.TOKEN_EXCHANGE to GrantParameters.TokenExchange(
                subjectToken = "subject-token",
                subjectTokenType = "urn:ietf:params:oauth:token-type:access_token",
            ),
            GrantType.REFRESH_TOKEN to GrantParameters.RefreshToken("refresh-token"),
        )
        for ((grantType, parameters) in grants) {
            var authenticationCalls = 0
            val parse = stubParseTokenRequest {
                Ok(
                    TokenRequestData(
                        grantType = grantType,
                        clientId = "unknown-wallet",
                        clientAuthentication = ClientAuthenticationConfig.None("unknown-wallet"),
                        grantParameters = parameters,
                        httpUrl = "https://as.example.com/token",
                    ),
                )
            }
            val verify = object : VerifyClientAuthenticationCommand {
                override val inputTypeToken = typeToken<VerifyClientAuthenticationArgs>()
                override val outputTypeToken = typeToken<VerifiedClientAuthentication>()
                override val isEnabled = true

                override suspend fun execute(args: VerifyClientAuthenticationArgs): IdkResult<VerifiedClientAuthentication, IdkError> {
                    authenticationCalls++
                    return Err(IdkError.fromString(code = "invalid_client", message = "Unknown client"))
                }
            }
            val service =
                serviceForClientCredentialsFlow(
                    parseStub = parse,
                    verifyClientAuthStub = verify,
                    verifyGrantStub =
                        stubVerifyClientCredentialsGrant {
                            error("client-credentials grant verifier must not run for an unknown client")
                        },
                    createAccessTokenStub =
                        stubCreateAccessToken {
                            error("access token must not be minted for an unknown client")
                        },
                    createTokenResponseStub =
                        stubCreateTokenResponse {
                            error("token response must not be created for an unknown client")
                        },
                )
            val command = HandleTokenRequestCommandImpl(
                execution = ctx.execution,
                parseTokenRequestCommand = parse,
                verifyClientAuthenticationCommand = lazyOf(verify),
                serversConfigProvider = configProvider,
                verifyDpopProofCommand = rejectingDpopVerify,
                dpopProofJtiCache = newDpopJtiCache(),
                dpopNonceManager = newDpopNonceManager(),
                grantHandlers = grantHandlersFor(
                    commands = service.commands,
                    tokenStorage = tokenStorage,
                    verifyRefreshTokenGrant = lazyOf(verifyRefreshTokenGrant),
                    tokenExchangeJourney = {
                        tokenExchangeJourney(
                            parse = parse,
                            verifyClientAuthentication = verify,
                            createAccessToken = service.commands.createAccessToken,
                            createTokenResponse = service.commands.createTokenResponse,
                        )
                    },
                ),
            )

            val result = command.execute(
                HandleTokenRequestArgs(
                    requestBody = emptyMap(),
                    requestHeaders = emptyMap(),
                    httpUrl = "https://as.example.com/token",
                ),
            )

            assertTrue(result.isErr, "$grantType must reject an unknown client")
            assertEquals("invalid_client", result.error.code, "$grantType must return invalid_client")
            val expectedAuthenticationCalls = if (grantType == GrantType.REFRESH_TOKEN) 0 else 1
            assertEquals(expectedAuthenticationCalls, authenticationCalls, "$grantType client-authentication path")
        }
    }

    /**
     * Device-code grant verifier stub: tests in this file never exercise the device-code branch,
     * so this rejects unconditionally. The dedicated state-machine tests live in
     * [com.sphereon.oauth2.server.authorization.impl.command.token.VerifyDeviceCodeGrantCommandImplTest].
     */
    private val rejectingVerifyDeviceCodeGrant: VerifyDeviceCodeGrantCommand =
        object : VerifyDeviceCodeGrantCommand {
            override val inputTypeToken = typeToken<VerifyDeviceCodeGrantArgs>()
            override val outputTypeToken = typeToken<VerifiedDeviceCodeGrant>()
            override val isEnabled = true

            override suspend fun execute(args: VerifyDeviceCodeGrantArgs): IdkResult<VerifiedDeviceCodeGrant, IdkError> = Err(IdkError.fromString(code = "invalid_grant", message = "test stub"))
        }

    private fun newDeviceAuthorizationStorage(): InMemoryDeviceAuthorizationStorageImpl = InMemoryDeviceAuthorizationStorageImpl(InMemoryOAuth2BackingStorageImpl())

    /**
     * Fixed clock for handle-token tests that don't depend on time (DPoP iat/exp checks happen
     * inside the verify stub). Real Clock from `kotlin.time.Clock` is fine since none of the
     * non-device-code branches consult it directly.
     */
    private val testClock: Clock = Clock.System

    /** Builds lazy keyed handlers without constructing grants unrelated to the parsed request. */
    private fun grantHandlersFor(
        commands: com.sphereon.oauth2.server.authorization.service.AuthorizationServerService.Commands,
        tokenStorage: TokenStorage,
        verifyDeviceCodeGrant: VerifyDeviceCodeGrantCommand = rejectingVerifyDeviceCodeGrant,
        deviceAuthorizationStorage: com.sphereon.oauth2.server.authorization.storage.DeviceAuthorizationStorage = newDeviceAuthorizationStorage(),
        authorizationCodeStorage: com.sphereon.oauth2.server.authorization.storage.AuthorizationCodeStorage =
            com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryAuthorizationCodeStorageImpl(
                com.sphereon.oauth2.server.authorization.impl.storage.memory
                    .InMemoryOAuth2BackingStorageImpl(),
            ),
        refreshAuditEmitter: com.sphereon.oauth2.server.authorization.audit.OAuth2AuditEmitter =
            com.sphereon.oauth2.server.authorization.audit.NoOpOAuth2AuditEmitter,
        verifyRefreshTokenGrant: Lazy<VerifyRefreshTokenGrantCommand> = lazy { commands.verifyRefreshTokenGrant },
        clock: Clock = testClock,
        clientRegistry: ClientRegistry = newClientRegistry(),
        tokenExchangeJourney: () -> TokenExchangeJourneyCommand = { error("token exchange journey is not configured for this test") },
    ): Map<String, Lazy<com.sphereon.oauth2.server.authorization.command.token.GrantHandler>> =
        mapOf(
            com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys.AUTHORIZATION_CODE to
                lazy {
                    com.sphereon.oauth2.server.authorization.impl.command.token.grant.AuthorizationCodeGrantHandlerImpl(
                        authorizationCodeStorage = authorizationCodeStorage,
                        log = ctx.execution.log,
                        scopeClaimsMapper = null,
                        verifyAuthorizationCodeGrant = commands.verifyAuthorizationCodeGrant,
                        createAccessToken = commands.createAccessToken,
                        createRefreshToken = lazy { commands.createRefreshToken },
                        createIdToken = lazy { commands.createIdToken },
                        createTokenResponse = commands.createTokenResponse,
                        credentialIssuerAudienceResolver =
                            com.sphereon.oauth2.server.authorization.impl.provider.NoCredentialIssuerAudienceResolver(),
                    )
                },
            com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys.REFRESH_TOKEN to
                lazy {
                    com.sphereon.oauth2.server.authorization.impl.command.token.grant.RefreshTokenGrantHandlerImpl(
                        tokenStorage = tokenStorage,
                        auditEmitter = refreshAuditEmitter,
                        verifyRefreshTokenGrant = verifyRefreshTokenGrant.value,
                        createAccessToken = commands.createAccessToken,
                        createRefreshToken = lazy { commands.createRefreshToken },
                        createIdToken = lazy { commands.createIdToken },
                        createTokenResponse = commands.createTokenResponse,
                        credentialIssuerAudienceResolver =
                            com.sphereon.oauth2.server.authorization.impl.provider.NoCredentialIssuerAudienceResolver(),
                    )
                },
            com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys.CLIENT_CREDENTIALS to
                lazy {
                    com.sphereon.oauth2.server.authorization.impl.command.token.grant.ClientCredentialsGrantHandlerImpl(
                        verifyClientCredentialsGrant = commands.verifyClientCredentialsGrant,
                        createAccessToken = commands.createAccessToken,
                        createTokenResponse = commands.createTokenResponse,
                    )
                },
            com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys.TOKEN_EXCHANGE to
                lazy {
                    com.sphereon.oauth2.server.authorization.impl.command.token.grant.TokenExchangeGrantHandlerImpl(
                        tokenExchangeJourney = tokenExchangeJourney(),
                    )
                },
            com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys.PRE_AUTHORIZED_CODE to
                lazy {
                    com.sphereon.oauth2.server.authorization.impl.command.token.grant.PreAuthorizedCodeGrantHandlerImpl(
                        verifyPreAuthorizedCodeGrant = commands.verifyPreAuthorizedCodeGrant,
                        createAccessToken = commands.createAccessToken,
                        createTokenResponse = commands.createTokenResponse,
                        credentialIssuerAudienceResolver =
                            com.sphereon.oauth2.server.authorization.impl.provider.NoCredentialIssuerAudienceResolver(),
                    )
                },
            com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys.DEVICE_CODE to
                lazy {
                    com.sphereon.oauth2.server.authorization.impl.command.token.grant.DeviceCodeGrantHandlerImpl(
                        verifyDeviceCodeGrantCommand = verifyDeviceCodeGrant,
                        deviceAuthorizationStorage = deviceAuthorizationStorage,
                        clock = clock,
                        createAccessToken = commands.createAccessToken,
                        createRefreshToken = lazy { commands.createRefreshToken },
                        createIdToken = lazy { commands.createIdToken },
                        createTokenResponse = commands.createTokenResponse,
                        clientRegistry = clientRegistry,
                    )
                },
        )

    private fun serviceForClientCredentialsFlow(
        parseStub: ParseTokenRequestCommand,
        verifyClientAuthStub: com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand,
        verifyGrantStub: VerifyClientCredentialsGrantCommand,
        createAccessTokenStub: CreateAccessTokenCommand,
        createTokenResponseStub: CreateTokenResponseCommand,
    ): com.sphereon.oauth2.server.authorization.service.AuthorizationServerService =
        object : StubAuthorizationServerService(
            parseTokenRequestStub = parseStub,
            verifyClientAuthenticationStub = verifyClientAuthStub,
        ) {
            override val commands: com.sphereon.oauth2.server.authorization.service.AuthorizationServerService.Commands =
                TestCommands(
                    parseStub = parseStub,
                    verifyClientAuthStub = verifyClientAuthStub,
                    verifyGrantStub = verifyGrantStub,
                    createAccessTokenStub = createAccessTokenStub,
                    createTokenResponseStub = createTokenResponseStub,
                )
        }

    /** Per-test fully-stubbed [com.sphereon.oauth2.server.authorization.service.AuthorizationServerService.Commands]. */
    private class TestCommands(
        private val parseStub: ParseTokenRequestCommand,
        private val verifyClientAuthStub: com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand,
        private val verifyGrantStub: VerifyClientCredentialsGrantCommand,
        private val createAccessTokenStub: CreateAccessTokenCommand,
        private val createTokenResponseStub: CreateTokenResponseCommand,
    ) : com.sphereon.oauth2.server.authorization.service.AuthorizationServerService.Commands {
        override val parseTokenRequest get() = parseStub
        override val verifyAuthorizationCodeGrant get(): com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantCommand = throw NotImplementedError()
        override val verifyRefreshTokenGrant get(): com.sphereon.oauth2.server.authorization.command.VerifyRefreshTokenGrantCommand = throw NotImplementedError()
        override val verifyClientCredentialsGrant get() = verifyGrantStub
        override val verifyPreAuthorizedCodeGrant get(): com.sphereon.oauth2.server.authorization.command.VerifyPreAuthorizedCodeGrantCommand = throw NotImplementedError()
        override val createAccessToken get() = createAccessTokenStub
        override val createRefreshToken get(): com.sphereon.oauth2.server.authorization.command.CreateRefreshTokenCommand = throw NotImplementedError()
        override val createTokenResponse get() = createTokenResponseStub
        override val parseAuthorizationRequest get(): com.sphereon.oauth2.server.authorization.command.ParseAuthorizationRequestCommand = throw NotImplementedError()
        override val verifyAuthorizationRequest get(): com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationRequestCommand = throw NotImplementedError()
        override val createAuthorizationSession get(): com.sphereon.oauth2.server.authorization.command.CreateAuthorizationSessionCommand = throw NotImplementedError()
        override val createAuthorizationCode get(): com.sphereon.oauth2.server.authorization.command.CreateAuthorizationCodeCommand = throw NotImplementedError()
        override val createAuthorizationResponse get(): com.sphereon.oauth2.server.authorization.command.CreateAuthorizationResponseCommand = throw NotImplementedError()
        override val createAuthorizationErrorResponse get(): com.sphereon.oauth2.server.authorization.command.CreateAuthorizationErrorResponseCommand = throw NotImplementedError()
        override val parsePushedAuthorizationRequest get(): com.sphereon.oauth2.server.authorization.command.ParsePushedAuthorizationRequestCommand = throw NotImplementedError()
        override val verifyPushedAuthorizationRequest get(): com.sphereon.oauth2.server.authorization.command.VerifyPushedAuthorizationRequestCommand = throw NotImplementedError()
        override val createRequestUri get(): com.sphereon.oauth2.server.authorization.command.CreateRequestUriCommand = throw NotImplementedError()
        override val createPushedAuthorizationResponse get(): com.sphereon.oauth2.server.authorization.command.CreatePushedAuthorizationResponseCommand = throw NotImplementedError()
        override val retrieveAuthorizationRequestByUri get(): com.sphereon.oauth2.server.authorization.command.RetrieveAuthorizationRequestByUriCommand = throw NotImplementedError()
        override val parseIntrospectionRequest get(): com.sphereon.oauth2.server.authorization.command.ParseIntrospectionRequestCommand = throw NotImplementedError()
        override val introspectToken get(): com.sphereon.oauth2.server.authorization.command.IntrospectTokenCommand = throw NotImplementedError()
        override val parseRevocationRequest get(): com.sphereon.oauth2.server.authorization.command.ParseRevocationRequestCommand = throw NotImplementedError()
        override val revokeToken get(): com.sphereon.oauth2.server.authorization.command.RevokeTokenCommand = throw NotImplementedError()
        override val buildServerMetadata get(): com.sphereon.oauth2.server.authorization.command.BuildServerMetadataCommand = throw NotImplementedError()
        override val verifyClientAuthentication get() = verifyClientAuthStub
        override val createAttestationChallenge get(): com.sphereon.oauth2.server.authorization.command.CreateAttestationChallengeCommand = throw NotImplementedError()
        override val createIdToken get(): com.sphereon.oauth2.server.authorization.command.CreateIdTokenCommand = throw NotImplementedError()
        override val getUserInfo get(): com.sphereon.oauth2.server.authorization.command.GetUserInfoCommand = throw NotImplementedError()
        override val getJwks get(): com.sphereon.oauth2.server.authorization.command.GetJwksCommand = throw NotImplementedError()
    }

    @Test
    fun tokenDispatchConstructsOnlyTheSelectedGrantHandler() =
        runTest {
            var selectedConstructions = 0
            var unrelatedConstructions = 0
            var dpopVerifierConstructions = 0
            var dpopReplayCacheConstructions = 0
            var dpopNonceManagerConstructions = 0
            val parse =
                stubParseTokenRequest {
                    Ok(
                        TokenRequestData(
                            grantType = GrantType.CLIENT_CREDENTIALS,
                            clientId = "client-1",
                            clientAuthentication = ClientAuthenticationConfig.Anonymous,
                            grantParameters = GrantParameters.ClientCredentials(scope = "read"),
                            httpUrl = "https://as.example.com/token",
                        ),
                    )
                }
            val verifyClient =
                stubVerifyClientAuthentication {
                    Ok(VerifiedClientAuthentication(clientId = "client-1", method = ClientAuthenticationMethod.NONE))
                }
            val selected =
                object : com.sphereon.oauth2.server.authorization.command.token.GrantHandler {
                    override val grantType =
                        com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys.CLIENT_CREDENTIALS

                    override fun supports(params: GrantParameters): Boolean = params is GrantParameters.ClientCredentials

                    override suspend fun handle(
                        params: GrantParameters,
                        context: com.sphereon.oauth2.server.authorization.command.token.GrantContext,
                    ): IdkResult<TokenResponse, IdkError> = Ok(TokenResponse(accessToken = "selected", tokenType = "Bearer"))
                }
            val handlers: Map<String, Lazy<com.sphereon.oauth2.server.authorization.command.token.GrantHandler>> =
                mapOf(
                    selected.grantType to
                        lazy {
                            selectedConstructions++
                            selected
                        },
                    com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys.REFRESH_TOKEN to
                        lazy<com.sphereon.oauth2.server.authorization.command.token.GrantHandler> {
                            unrelatedConstructions++
                            error("unrelated grant handler must not be constructed")
                        },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = parse,
                    verifyClientAuthenticationCommand = lazyOf(verifyClient),
                    serversConfigProvider = configProvider,
                    verifyDpopProofCommand =
                        lazy {
                            dpopVerifierConstructions++
                            error("DPoP verifier must not be constructed without a proof")
                        },
                    dpopProofJtiCache =
                        lazy {
                            dpopReplayCacheConstructions++
                            error("DPoP replay cache must not be constructed without a proof")
                        },
                    dpopNonceManager =
                        lazy {
                            dpopNonceManagerConstructions++
                            error("DPoP nonce manager must not be constructed without a proof")
                        },
                    grantHandlers = handlers,
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody = mapOf("grant_type" to listOf("client_credentials")),
                        requestHeaders = emptyMap(),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isOk)
            assertEquals("selected", result.value.accessToken)
            assertEquals(1, selectedConstructions)
            assertEquals(0, unrelatedConstructions)
            assertEquals(0, dpopVerifierConstructions)
            assertEquals(0, dpopReplayCacheConstructions)
            assertEquals(0, dpopNonceManagerConstructions)
        }

    @Test
    fun publicClientCodeExchangeDoesNotConstructClientAuthentication() =
        runTest {
            var clientAuthenticationResolutions = 0
            val parse =
                stubParseTokenRequest {
                    Ok(
                        TokenRequestData(
                            grantType = GrantType.AUTHORIZATION_CODE,
                            clientId = "wallet",
                            clientAuthentication = ClientAuthenticationConfig.None("wallet"),
                            grantParameters = GrantParameters.AuthorizationCode(code = "code", redirectUri = "https://wallet.example/cb"),
                            httpUrl = "https://as.example.com/token",
                        ),
                    )
                }
            val selected =
                object : com.sphereon.oauth2.server.authorization.command.token.GrantHandler {
                    override val grantType =
                        com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys.AUTHORIZATION_CODE

                    override fun supports(params: GrantParameters): Boolean = params is GrantParameters.AuthorizationCode

                    override suspend fun handle(
                        params: GrantParameters,
                        context: com.sphereon.oauth2.server.authorization.command.token.GrantContext,
                    ): IdkResult<TokenResponse, IdkError> = Ok(TokenResponse(accessToken = "code-token", tokenType = "Bearer"))
                }
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = parse,
                    verifyClientAuthenticationCommand =
                        lazy {
                            clientAuthenticationResolutions++
                            error("A none-auth code exchange defers client authentication to the grant verifier")
                        },
                    serversConfigProvider = configProvider,
                    verifyDpopProofCommand = rejectingDpopVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = mapOf(selected.grantType to lazyOf(selected)),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody = mapOf("grant_type" to listOf("authorization_code")),
                        requestHeaders = emptyMap(),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isOk)
            assertEquals("code-token", result.value.accessToken)
            assertEquals(0, clientAuthenticationResolutions)
        }

    @Test
    fun clientCredentialsGrantHappyPath() =
        runTest {
            val clientAuthorization =
                VerifiedClientAuthorization(
                    clientId = "client-1",
                    grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                )
            val service =
                serviceForClientCredentialsFlow(
                    parseStub =
                        stubParseTokenRequest {
                            Ok(
                                TokenRequestData(
                                    grantType = GrantType.CLIENT_CREDENTIALS,
                                    clientId = "client-1",
                                    clientAuthentication =
                                        ClientAuthenticationConfig.Basic(
                                            credentials =
                                                com.sphereon.oauth2.common.model
                                                    .ClientCredentials(clientId = "client-1", clientSecret = "secret"),
                                        ),
                                    grantParameters = GrantParameters.ClientCredentials(scope = "read"),
                                    httpUrl = "https://as.example.com/token",
                                ),
                            )
                        },
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(
                                VerifiedClientAuthentication(
                                    clientId = it.clientId,
                                    method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                                    clientAuthorization = clientAuthorization,
                                ),
                            )
                        },
                    verifyGrantStub =
                        stubVerifyClientCredentialsGrant {
                            Ok(VerifiedClientCredentialsGrant(subject = "client-1", clientId = "client-1", scope = "read"))
                        },
                    createAccessTokenStub = stubCreateAccessToken { Ok(StringResult(value = "AT-123")) },
                    createTokenResponseStub =
                        stubCreateTokenResponse { args ->
                            Ok(TokenResponse(accessToken = args.accessToken, tokenType = args.tokenType, scope = args.scope))
                        },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = configProvider,
                    verifyDpopProofCommand = rejectingDpopVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = newTokenStorage()),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody = mapOf("grant_type" to listOf("client_credentials"), "scope" to listOf("read")),
                        requestHeaders = mapOf("Authorization" to "Basic Y2xpZW50LTE6c2VjcmV0"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isOk, "expected success but got ${if (!result.isOk) result.error else "ok"}")
            assertEquals("AT-123", result.value.accessToken)
            assertEquals("Bearer", result.value.tokenType)
            assertEquals("read", result.value.scope)
        }

    @Test
    fun clientCredentialsRefusalsLogOneDiagnosticWarnEach() =
        runTest {
            val unknownClient =
                refusalLines {
                    clientCredentialsCommand(
                        verifyClientAuth = {
                            Err(IdkError.fromDTO(AuthorizationServerError.InvalidClient(details = "Unknown client")))
                        },
                    ).execute(clientCredentialsArgs())
                }
            val wrongSecret =
                refusalLines {
                    clientCredentialsCommand(
                        verifyClientAuth = {
                            Err(IdkError.fromDTO(AuthorizationServerError.InvalidClient(details = "Invalid client credentials")))
                        },
                    ).execute(clientCredentialsArgs())
                }
            val unregisteredAudience =
                refusalLines {
                    clientCredentialsCommand(
                        verifyGrant = {
                            Err(
                                IdkError.fromDTO(
                                    AuthorizationServerError.InvalidTarget(
                                        audience = "unregistered-audience",
                                        reason = "Requested audience is not registered for this client",
                                    ),
                                ),
                            )
                        },
                    ).execute(clientCredentialsArgs())
                }

            val cases =
                listOf(
                    "unknown client" to unknownClient,
                    "wrong secret" to wrongSecret,
                    "unregistered audience" to unregisteredAudience,
                )
            for ((name, lines) in cases) {
                assertEquals(1, lines.size, "$name must log exactly one refusal: $lines")
                val line = lines.single()
                assertTrue("client_id=issuer-service" in line, "$name: $line")
                assertTrue("tenant=${ctx.execution.tenantId}" in line, "$name: $line")
                assertTrue("grant_type=client_credentials" in line, "$name: $line")
                assertFalse(REFUSAL_TEST_SECRET in line, "$name must not log the client secret: $line")
                assertFalse("Basic" in line, "$name must not log the authorization header: $line")
            }
            assertTrue("stage=request-authentication" in unknownClient.single(), unknownClient.single())
            assertTrue("code=invalid_client" in unknownClient.single(), unknownClient.single())
            assertTrue("reason=Invalid client: Unknown client" in unknownClient.single(), unknownClient.single())
            assertTrue("stage=request-authentication" in wrongSecret.single(), wrongSecret.single())
            assertTrue("reason=Invalid client: Invalid client credentials" in wrongSecret.single(), wrongSecret.single())
            assertTrue("stage=grant-dispatch" in unregisteredAudience.single(), unregisteredAudience.single())
            assertTrue("code=invalid_target" in unregisteredAudience.single(), unregisteredAudience.single())
            assertTrue(
                "reason=Invalid target: Requested audience is not registered for this client" in unregisteredAudience.single(),
                unregisteredAudience.single(),
            )
        }

    @Test
    fun unsupportedGrantAndHandlerMismatchRefusalsAreLogged() =
        runTest {
            val unsupported =
                refusalLines {
                    clientCredentialsCommand(grantHandlers = { emptyMap() }).execute(clientCredentialsArgs())
                }
            val mismatched =
                refusalLines {
                    clientCredentialsCommand(
                        grantHandlers = {
                            val wrongHandler =
                                object : com.sphereon.oauth2.server.authorization.command.token.GrantHandler {
                                    override val grantType =
                                        com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys.AUTHORIZATION_CODE

                                    override fun supports(params: GrantParameters): Boolean = false

                                    override suspend fun handle(
                                        params: GrantParameters,
                                        context: com.sphereon.oauth2.server.authorization.command.token.GrantContext,
                                    ): IdkResult<TokenResponse, IdkError> = error("a mismatched handler must not run")
                                }
                            mapOf(
                                com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys.CLIENT_CREDENTIALS to
                                    lazyOf(wrongHandler),
                            )
                        },
                    ).execute(clientCredentialsArgs())
                }

            val unsupportedLine = unsupported.single()
            assertTrue("stage=grant-selection" in unsupportedLine, unsupportedLine)
            assertTrue("code=unsupported_grant_type" in unsupportedLine, unsupportedLine)
            assertTrue("client_id=issuer-service" in unsupportedLine, unsupportedLine)
            val mismatchLine = mismatched.single()
            assertTrue("stage=grant-binding" in mismatchLine, mismatchLine)
            assertTrue("code=server_error" in mismatchLine, mismatchLine)
            assertTrue(
                "reason=Server error: Grant handler binding mismatch for 'client_credentials'" in mismatchLine,
                mismatchLine,
            )
        }

    @Test
    fun refusalReasonIsStrippedOfControlCharactersAndBounded() =
        runTest {
            val lines =
                refusalLines {
                    clientCredentialsCommand(
                        verifyClientAuth = {
                            Err(
                                IdkError.fromDTO(
                                    AuthorizationServerError.InvalidClient(details = "line\r\nforged=1 " + "x".repeat(400)),
                                ),
                            )
                        },
                    ).execute(clientCredentialsArgs())
                }

            val line = lines.single()
            assertFalse(line.any { it.isISOControl() }, line)
            assertTrue(line.length < 600, "refusal line must stay bounded, got ${line.length} characters")
        }

    private suspend fun refusalLines(block: suspend () -> Unit): List<String> {
        val previous = Log.app()
        val recorder = RecordingTokenRefusalLog()
        Log.register(IdkScope.APP, recorder)
        try {
            block()
        } finally {
            Log.register(IdkScope.APP, previous)
        }
        return recorder.warnings.filter { it.startsWith("Token request refused") }
    }

    private fun clientCredentialsArgs() =
        HandleTokenRequestArgs(
            requestBody =
                mapOf(
                    "grant_type" to listOf("client_credentials"),
                    "audience" to listOf("unregistered-audience"),
                ),
            requestHeaders = mapOf("Authorization" to "Basic aXNzdWVyLXNlcnZpY2U6czNjcmV0"),
            httpUrl = "https://as.example.com/token",
        )

    private fun clientCredentialsCommand(
        verifyClientAuth: suspend (VerifyClientAuthenticationArgs) -> IdkResult<VerifiedClientAuthentication, IdkError> = {
            Ok(
                VerifiedClientAuthentication(
                    clientId = "issuer-service",
                    method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                    clientAuthorization =
                        VerifiedClientAuthorization(
                            clientId = "issuer-service",
                            grantTypes = listOf(GrantType.CLIENT_CREDENTIALS),
                        ),
                ),
            )
        },
        verifyGrant: suspend (VerifyClientCredentialsGrantArgs) -> IdkResult<VerifiedClientCredentialsGrant, IdkError> = {
            Ok(VerifiedClientCredentialsGrant(subject = "issuer-service", clientId = "issuer-service", scope = null))
        },
        grantHandlers: (
            com.sphereon.oauth2.server.authorization.service.AuthorizationServerService.Commands,
        ) -> Map<String, Lazy<com.sphereon.oauth2.server.authorization.command.token.GrantHandler>>? = { null },
    ): HandleTokenRequestCommandImpl {
        val service =
            serviceForClientCredentialsFlow(
                parseStub =
                    stubParseTokenRequest {
                        Ok(
                            TokenRequestData(
                                grantType = GrantType.CLIENT_CREDENTIALS,
                                clientId = "issuer-service",
                                clientAuthentication =
                                    ClientAuthenticationConfig.Basic(
                                        credentials =
                                            com.sphereon.oauth2.common.model
                                                .ClientCredentials(clientId = "issuer-service", clientSecret = REFUSAL_TEST_SECRET),
                                    ),
                                grantParameters = GrantParameters.ClientCredentials(audiences = listOf("unregistered-audience")),
                                httpUrl = "https://as.example.com/token",
                            ),
                        )
                    },
                verifyClientAuthStub = stubVerifyClientAuthentication(verifyClientAuth),
                verifyGrantStub = stubVerifyClientCredentialsGrant(verifyGrant),
                createAccessTokenStub = stubCreateAccessToken { Ok(StringResult(value = "AT-not-for-logs")) },
                createTokenResponseStub =
                    stubCreateTokenResponse { args ->
                        Ok(TokenResponse(accessToken = args.accessToken, tokenType = args.tokenType))
                    },
            )
        return HandleTokenRequestCommandImpl(
            execution = ctx.execution,
            parseTokenRequestCommand = service.commands.parseTokenRequest,
            verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
            serversConfigProvider = configProvider,
            verifyDpopProofCommand = rejectingDpopVerify,
            dpopProofJtiCache = newDpopJtiCache(),
            dpopNonceManager = newDpopNonceManager(),
            grantHandlers =
                grantHandlers(service.commands)
                    ?: grantHandlersFor(commands = service.commands, tokenStorage = newTokenStorage()),
        )
    }

    @Test
    fun anonymousPreAuthorizedCodeDoesNotResolveClientRegistry() =
        runTest {
            val delegateRegistry = newClientRegistry()
            var registryReadCount = 0
            val preAuthorizedConfigProvider =
                TestOAuth2ServersConfigProvider(
                    OAuth2ServersConfig(
                        servers =
                            mapOf(
                                "default" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://as.example.com",
                                        grantTypesEnabled =
                                            setOf(
                                                GrantType.AUTHORIZATION_CODE.value,
                                                GrantType.CLIENT_CREDENTIALS.value,
                                                GrantType.REFRESH_TOKEN.value,
                                                GrantType.PRE_AUTHORIZED_CODE.value,
                                            ),
                                    ),
                            ),
                    ),
                )
            val registry =
                object : ClientRegistry by delegateRegistry {
                    override suspend fun getClient(clientId: String) =
                        delegateRegistry.getClient(clientId).also { registryReadCount++ }
                }
            val service =
                serviceForClientCredentialsFlow(
                    parseStub =
                        stubParseTokenRequest {
                            Ok(
                                TokenRequestData(
                                    grantType = GrantType.PRE_AUTHORIZED_CODE,
                                    clientId = "wallet-instance",
                                    clientAuthentication = ClientAuthenticationConfig.None("wallet-instance"),
                                    grantParameters =
                                        GrantParameters.PreAuthorizedCode(
                                            preAuthorizedCode = "pre-authorized-code",
                                        ),
                                    httpUrl = "https://as.example.com/token",
                                ),
                            )
                        },
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication { args ->
                            assertSame(ClientAuthenticationConfig.Anonymous, args.clientAuthentication)
                            Ok(
                                VerifiedClientAuthentication(
                                    clientId = args.clientId,
                                    method = ClientAuthenticationMethod.NONE,
                                ),
                            )
                        },
                    verifyGrantStub = stubVerifyClientCredentialsGrant { error("client credentials verifier must not run") },
                    createAccessTokenStub = stubCreateAccessToken { error("access token command must not run") },
                    createTokenResponseStub = stubCreateTokenResponse { error("token response command must not run") },
                )
            val handler =
                object : com.sphereon.oauth2.server.authorization.command.token.GrantHandler {
                    override val grantType: String = GrantType.PRE_AUTHORIZED_CODE.value

                    override fun supports(params: GrantParameters): Boolean = params is GrantParameters.PreAuthorizedCode

                    override suspend fun handle(
                        params: GrantParameters,
                        context: com.sphereon.oauth2.server.authorization.command.token.GrantContext,
                    ): IdkResult<TokenResponse, IdkError> {
                        return Ok(TokenResponse(accessToken = "AT-PRE-AUTHORIZED", tokenType = "Bearer"))
                    }
                }
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = preAuthorizedConfigProvider,
                    verifyDpopProofCommand = rejectingDpopVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = mapOf(handler.grantType to lazyOf(handler)),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody = mapOf("grant_type" to listOf(GrantType.PRE_AUTHORIZED_CODE.value)),
                        requestHeaders = emptyMap(),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isOk)
            assertEquals(0, registryReadCount)
        }

    @Test
    fun clientCredentialsGrantPropagatesOnlyVerifiedAudienceToAccessToken() =
        runTest {
            var capturedAccessTokenArgs: CreateAccessTokenArgs? = null
            val service =
                serviceForClientCredentialsFlow(
                    parseStub =
                        stubParseTokenRequest {
                            Ok(
                                TokenRequestData(
                                    grantType = GrantType.CLIENT_CREDENTIALS,
                                    clientId = "tenant-as-service",
                                    clientAuthentication =
                                        ClientAuthenticationConfig.Basic(
                                            credentials =
                                                com.sphereon.oauth2.common.model
                                                    .ClientCredentials(clientId = "tenant-as-service", clientSecret = "secret"),
                                        ),
                                    grantParameters =
                                        GrantParameters.ClientCredentials(
                                            scope = "internal",
                                            audiences = listOf("enterprise-tenant-kms"),
                                        ),
                                    httpUrl = "https://as.example.com/token",
                                ),
                            )
                        },
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                        },
                    verifyGrantStub =
                        stubVerifyClientCredentialsGrant {
                            assertEquals(listOf("enterprise-tenant-kms"), it.requestedAudience)
                            Ok(
                                VerifiedClientCredentialsGrant(
                                    subject = "tenant-as-service",
                                    clientId = "tenant-as-service",
                                    scope = "internal",
                                    audience = listOf("enterprise-tenant-kms"),
                                ),
                            )
                        },
                    createAccessTokenStub =
                        stubCreateAccessToken { args ->
                            capturedAccessTokenArgs = args
                            Ok(StringResult(value = "AT-KMS"))
                        },
                    createTokenResponseStub =
                        stubCreateTokenResponse { args ->
                            Ok(TokenResponse(accessToken = args.accessToken, tokenType = args.tokenType, scope = args.scope))
                        },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = configProvider,
                    verifyDpopProofCommand = rejectingDpopVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = newTokenStorage()),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody =
                            mapOf(
                                "grant_type" to listOf("client_credentials"),
                                "scope" to listOf("internal"),
                                "audience" to listOf("enterprise-tenant-kms"),
                            ),
                        requestHeaders = mapOf("Authorization" to "Basic dGVuYW50LWFzLXNlcnZpY2U6c2VjcmV0"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isOk, "expected success but got ${if (!result.isOk) result.error else "ok"}")
            assertEquals(listOf("enterprise-tenant-kms"), capturedAccessTokenArgs?.audience)
        }

    /**
     * Regression: A2 fix. The HTTP shell resolves a per-request base URL from `Host` +
     * `X-Forwarded-Proto` and threads it through [HandleTokenRequestArgs.baseUrlOverride] so
     * the inner [CreateAccessTokenArgs.baseUrlOverride] reaches the access-token impl with the
     * external host. Without propagation, tokens emit `iss=http://localhost:8080` while
     * discovery emits `iss=https://abc.ngrok.app` and OIDF rejects the divergence.
     */
    @Test
    fun baseUrlOverridePropagatesToCreateAccessTokenArgs() =
        runTest {
            var capturedAccessTokenArgs: CreateAccessTokenArgs? = null
            val service =
                serviceForClientCredentialsFlow(
                    parseStub =
                        stubParseTokenRequest {
                            Ok(
                                TokenRequestData(
                                    grantType = GrantType.CLIENT_CREDENTIALS,
                                    clientId = "client-1",
                                    clientAuthentication =
                                        ClientAuthenticationConfig.Basic(
                                            credentials =
                                                com.sphereon.oauth2.common.model
                                                    .ClientCredentials(clientId = "client-1", clientSecret = "secret"),
                                        ),
                                    grantParameters = GrantParameters.ClientCredentials(scope = "read"),
                                    httpUrl = "https://as.example.com/token",
                                ),
                            )
                        },
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                        },
                    verifyGrantStub =
                        stubVerifyClientCredentialsGrant {
                            Ok(VerifiedClientCredentialsGrant(subject = "client-1", clientId = "client-1", scope = "read"))
                        },
                    createAccessTokenStub =
                        stubCreateAccessToken { args ->
                            capturedAccessTokenArgs = args
                            Ok(StringResult(value = "AT-456"))
                        },
                    createTokenResponseStub =
                        stubCreateTokenResponse { args ->
                            Ok(TokenResponse(accessToken = args.accessToken, tokenType = args.tokenType, scope = args.scope))
                        },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = configProvider,
                    verifyDpopProofCommand = rejectingDpopVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = newTokenStorage()),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody = mapOf("grant_type" to listOf("client_credentials"), "scope" to listOf("read")),
                        requestHeaders = mapOf("Authorization" to "Basic Y2xpZW50LTE6c2VjcmV0"),
                        httpUrl = "https://request-host.ngrok.app/token",
                        baseUrlOverride = "https://request-host.ngrok.app",
                    ),
                )

            assertTrue(result.isOk, "expected success but got ${if (!result.isOk) result.error else "ok"}")
            assertEquals("https://request-host.ngrok.app", capturedAccessTokenArgs?.baseUrlOverride)
        }

    @Test
    fun parseFailureSurfacesAsError() =
        runTest {
            val service =
                serviceForClientCredentialsFlow(
                    parseStub = stubParseTokenRequest { Err(IdkError.fromString(code = "invalid_request", message = "bad form")) },
                    verifyClientAuthStub = stubVerifyClientAuthentication { Ok(VerifiedClientAuthentication(clientId = "x", method = ClientAuthenticationMethod.NONE)) },
                    verifyGrantStub = stubVerifyClientCredentialsGrant { Err(IdkError.fromString(code = "x", message = "x")) },
                    createAccessTokenStub = stubCreateAccessToken { Err(IdkError.fromString(code = "x", message = "x")) },
                    createTokenResponseStub = stubCreateTokenResponse { Err(IdkError.fromString(code = "x", message = "x")) },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = configProvider,
                    verifyDpopProofCommand = rejectingDpopVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = newTokenStorage()),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody = emptyMap(),
                        requestHeaders = emptyMap(),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isErr)
            assertEquals("invalid_request", result.error.code)
        }

    // ============================================================================
    // Refresh-token grant rotation
    // ============================================================================

    private fun stubVerifyRefreshTokenGrant(handler: suspend (VerifyRefreshTokenGrantArgs) -> IdkResult<VerifiedRefreshTokenGrant, IdkError>): VerifyRefreshTokenGrantCommand =
        object : VerifyRefreshTokenGrantCommand {
            override val inputTypeToken = typeToken<VerifyRefreshTokenGrantArgs>()
            override val outputTypeToken = typeToken<VerifiedRefreshTokenGrant>()
            override val isEnabled = true

            override suspend fun execute(args: VerifyRefreshTokenGrantArgs) = handler(args)
        }

    private fun stubCreateRefreshToken(handler: suspend (CreateRefreshTokenArgs) -> IdkResult<StringResult, IdkError>): CreateRefreshTokenCommand =
        object : CreateRefreshTokenCommand {
            override val inputTypeToken = typeToken<CreateRefreshTokenArgs>()
            override val outputTypeToken = typeToken<StringResult>()
            override val isEnabled = true

            override suspend fun execute(args: CreateRefreshTokenArgs) = handler(args)
        }

    private fun stubCreateIdToken(handler: suspend (CreateIdTokenArgs) -> IdkResult<StringResult, IdkError>): CreateIdTokenCommand =
        object : CreateIdTokenCommand {
            override val inputTypeToken = typeToken<CreateIdTokenArgs>()
            override val outputTypeToken = typeToken<StringResult>()
            override val isEnabled = true

            override suspend fun execute(args: CreateIdTokenArgs) = handler(args)
        }

    private fun serviceForRefreshTokenFlow(
        parseStub: ParseTokenRequestCommand,
        verifyClientAuthStub: com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand,
        verifyRefreshStub: VerifyRefreshTokenGrantCommand,
        createAccessTokenStub: CreateAccessTokenCommand,
        createRefreshTokenStub: CreateRefreshTokenCommand,
        createTokenResponseStub: CreateTokenResponseCommand,
        createIdTokenStub: CreateIdTokenCommand? = null,
    ): com.sphereon.oauth2.server.authorization.service.AuthorizationServerService =
        object : StubAuthorizationServerService(
            parseTokenRequestStub = parseStub,
            verifyClientAuthenticationStub = verifyClientAuthStub,
        ) {
            override val commands: com.sphereon.oauth2.server.authorization.service.AuthorizationServerService.Commands =
                RefreshTestCommands(
                    parseStub = parseStub,
                    verifyClientAuthStub = verifyClientAuthStub,
                    verifyRefreshStub = verifyRefreshStub,
                    createAccessTokenStub = createAccessTokenStub,
                    createRefreshTokenStub = createRefreshTokenStub,
                    createTokenResponseStub = createTokenResponseStub,
                    createIdTokenStub = createIdTokenStub,
                )
        }

    /** Per-test fully-stubbed [com.sphereon.oauth2.server.authorization.service.AuthorizationServerService.Commands] for refresh-token flow. */
    private class RefreshTestCommands(
        private val parseStub: ParseTokenRequestCommand,
        private val verifyClientAuthStub: com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand,
        private val verifyRefreshStub: VerifyRefreshTokenGrantCommand,
        private val createAccessTokenStub: CreateAccessTokenCommand,
        private val createRefreshTokenStub: CreateRefreshTokenCommand,
        private val createTokenResponseStub: CreateTokenResponseCommand,
        private val createIdTokenStub: CreateIdTokenCommand? = null,
    ) : com.sphereon.oauth2.server.authorization.service.AuthorizationServerService.Commands {
        override val parseTokenRequest get() = parseStub
        override val verifyAuthorizationCodeGrant get(): com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationCodeGrantCommand = throw NotImplementedError()
        override val verifyRefreshTokenGrant get() = verifyRefreshStub
        override val verifyClientCredentialsGrant get(): VerifyClientCredentialsGrantCommand = throw NotImplementedError()
        override val verifyPreAuthorizedCodeGrant get(): com.sphereon.oauth2.server.authorization.command.VerifyPreAuthorizedCodeGrantCommand = throw NotImplementedError()
        override val createAccessToken get() = createAccessTokenStub
        override val createRefreshToken get() = createRefreshTokenStub
        override val createTokenResponse get() = createTokenResponseStub
        override val parseAuthorizationRequest get(): com.sphereon.oauth2.server.authorization.command.ParseAuthorizationRequestCommand = throw NotImplementedError()
        override val verifyAuthorizationRequest get(): com.sphereon.oauth2.server.authorization.command.VerifyAuthorizationRequestCommand = throw NotImplementedError()
        override val createAuthorizationSession get(): com.sphereon.oauth2.server.authorization.command.CreateAuthorizationSessionCommand = throw NotImplementedError()
        override val createAuthorizationCode get(): com.sphereon.oauth2.server.authorization.command.CreateAuthorizationCodeCommand = throw NotImplementedError()
        override val createAuthorizationResponse get(): com.sphereon.oauth2.server.authorization.command.CreateAuthorizationResponseCommand = throw NotImplementedError()
        override val createAuthorizationErrorResponse get(): com.sphereon.oauth2.server.authorization.command.CreateAuthorizationErrorResponseCommand = throw NotImplementedError()
        override val parsePushedAuthorizationRequest get(): com.sphereon.oauth2.server.authorization.command.ParsePushedAuthorizationRequestCommand = throw NotImplementedError()
        override val verifyPushedAuthorizationRequest get(): com.sphereon.oauth2.server.authorization.command.VerifyPushedAuthorizationRequestCommand = throw NotImplementedError()
        override val createRequestUri get(): com.sphereon.oauth2.server.authorization.command.CreateRequestUriCommand = throw NotImplementedError()
        override val createPushedAuthorizationResponse get(): com.sphereon.oauth2.server.authorization.command.CreatePushedAuthorizationResponseCommand = throw NotImplementedError()
        override val retrieveAuthorizationRequestByUri get(): com.sphereon.oauth2.server.authorization.command.RetrieveAuthorizationRequestByUriCommand = throw NotImplementedError()
        override val parseIntrospectionRequest get(): com.sphereon.oauth2.server.authorization.command.ParseIntrospectionRequestCommand = throw NotImplementedError()
        override val introspectToken get(): com.sphereon.oauth2.server.authorization.command.IntrospectTokenCommand = throw NotImplementedError()
        override val parseRevocationRequest get(): com.sphereon.oauth2.server.authorization.command.ParseRevocationRequestCommand = throw NotImplementedError()
        override val revokeToken get(): com.sphereon.oauth2.server.authorization.command.RevokeTokenCommand = throw NotImplementedError()
        override val buildServerMetadata get(): com.sphereon.oauth2.server.authorization.command.BuildServerMetadataCommand = throw NotImplementedError()
        override val verifyClientAuthentication get() = verifyClientAuthStub
        override val createAttestationChallenge get(): com.sphereon.oauth2.server.authorization.command.CreateAttestationChallengeCommand = throw NotImplementedError()
        override val createIdToken get(): CreateIdTokenCommand = createIdTokenStub ?: throw NotImplementedError()
        override val getUserInfo get(): com.sphereon.oauth2.server.authorization.command.GetUserInfoCommand = throw NotImplementedError()
        override val getJwks get(): com.sphereon.oauth2.server.authorization.command.GetJwksCommand = throw NotImplementedError()
    }

    private suspend fun seedRefreshToken(
        storage: TokenStorage,
        token: String,
        clientId: String,
        subject: String,
        scope: String?,
        authTime: Long? = null,
        acr: String? = null,
        amr: List<String>? = null,
        nonce: String? = null,
        loginSessionId: String? = null,
    ) {
        val now = Clock.System.now()
        val data =
            RefreshTokenData(
                refreshToken = token,
                clientId = clientId,
                subject = subject,
                scope = scope,
                issuedAt = now,
                expiresAt = now + 86_400.seconds,
                authTime = authTime,
                acr = acr,
                amr = amr,
                nonce = nonce,
                loginSessionId = loginSessionId,
            )
        val storeResult = storage.storeRefreshToken(token, data)
        assertTrue(storeResult.isOk, "seedRefreshToken must succeed")
    }

    private fun refreshTokenParseStub(presentedToken: String): ParseTokenRequestCommand =
        stubParseTokenRequest {
            Ok(
                TokenRequestData(
                    grantType = GrantType.REFRESH_TOKEN,
                    clientId = "client-1",
                    clientAuthentication =
                        ClientAuthenticationConfig.Basic(
                            credentials =
                                com.sphereon.oauth2.common.model
                                    .ClientCredentials(clientId = "client-1", clientSecret = "secret"),
                        ),
                    grantParameters = GrantParameters.RefreshToken(refreshToken = presentedToken, scope = "openid"),
                    httpUrl = "https://as.example.com/token",
                ),
            )
        }

    /**
     * Verifies the orchestrator mints a rotated refresh token and atomically marks the consumed
     * token revoked when `oauth2.servers.default.refresh-token-rotation` is `true` (default).
     */
    @Test
    fun refreshTokenGrantIssuesRotatedTokenWhenRotationEnabled() =
        runTest {
            val rotatingConfigProvider =
                TestOAuth2ServersConfigProvider(
                    OAuth2ServersConfig(
                        servers =
                            mapOf(
                                "default" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://as.example.com",
                                        refreshTokenRotation = true,
                                    ),
                            ),
                    ),
                )
            val tokenStorage = newTokenStorage()
            val presentedToken = "OLD-RT-1"
            seedRefreshToken(tokenStorage, presentedToken, clientId = "client-1", subject = "alice", scope = "openid")

            var capturedTokenResponseArgs: CreateTokenResponseArgs? = null
            val service =
                serviceForRefreshTokenFlow(
                    parseStub = refreshTokenParseStub(presentedToken),
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                        },
                    verifyRefreshStub =
                        stubVerifyRefreshTokenGrant { args ->
                            Ok(
                                VerifiedRefreshTokenGrant(
                                    subject = "alice",
                                    clientId = args.clientId,
                                    scope = "openid",
                                    refreshTokenId = args.refreshToken,
                                ),
                            )
                        },
                    createAccessTokenStub = stubCreateAccessToken { Ok(StringResult(value = "AT-NEW")) },
                    createRefreshTokenStub = stubCreateRefreshToken { Ok(StringResult(value = "NEW-RT-2")) },
                    createTokenResponseStub =
                        stubCreateTokenResponse { args ->
                            capturedTokenResponseArgs = args
                            Ok(
                                TokenResponse(
                                    accessToken = args.accessToken,
                                    tokenType = args.tokenType,
                                    refreshToken = args.refreshToken,
                                    scope = args.scope,
                                ),
                            )
                        },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = rotatingConfigProvider,
                    verifyDpopProofCommand = rejectingDpopVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = tokenStorage),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody =
                            mapOf(
                                "grant_type" to listOf("refresh_token"),
                                "refresh_token" to listOf(presentedToken),
                                "scope" to listOf("openid"),
                            ),
                        requestHeaders = mapOf("Authorization" to "Basic Y2xpZW50LTE6c2VjcmV0"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isOk, "expected success but got ${if (!result.isOk) result.error else "ok"}")
            assertEquals("AT-NEW", result.value.accessToken)
            assertEquals("NEW-RT-2", result.value.refreshToken, "response must carry the rotated refresh token")
            assertEquals("NEW-RT-2", capturedTokenResponseArgs?.refreshToken, "rotated refresh token must reach the response builder")

            // Verify the stored entry for the consumed token is now both used and revoked.
            val storedAfter =
                tokenStorage
                    .getRefreshToken(presentedToken)
                    .let { lookup ->
                        assertTrue(lookup.isOk, "getRefreshToken must succeed")
                        lookup.value
                    }
            assertNotNull(storedAfter, "consumed token entry must remain in storage for audit")
            assertTrue(storedAfter.used, "consumed refresh token must be marked used after rotation")
            assertTrue(storedAfter.revoked, "consumed refresh token must be revoked after rotation")
        }

    /**
     * Verifies that when `refresh-token-rotation = false` the orchestrator returns the SAME
     * refresh token in the response and does not mark the stored entry revoked.
     */
    @Test
    fun refreshTokenGrantReusesTokenWhenRotationDisabled() =
        runTest {
            val nonRotatingConfigProvider =
                TestOAuth2ServersConfigProvider(
                    OAuth2ServersConfig(
                        servers =
                            mapOf(
                                "default" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://as.example.com",
                                        refreshTokenRotation = false,
                                    ),
                            ),
                    ),
                )
            val tokenStorage = newTokenStorage()
            val presentedToken = "STATIC-RT-1"
            seedRefreshToken(tokenStorage, presentedToken, clientId = "client-1", subject = "alice", scope = "openid")

            val service =
                serviceForRefreshTokenFlow(
                    parseStub = refreshTokenParseStub(presentedToken),
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                        },
                    verifyRefreshStub =
                        stubVerifyRefreshTokenGrant { args ->
                            Ok(
                                VerifiedRefreshTokenGrant(
                                    subject = "alice",
                                    clientId = args.clientId,
                                    scope = "openid",
                                    refreshTokenId = args.refreshToken,
                                ),
                            )
                        },
                    createAccessTokenStub = stubCreateAccessToken { Ok(StringResult(value = "AT-NEW")) },
                    // createRefreshToken MUST NOT be invoked when rotation is disabled.
                    createRefreshTokenStub =
                        stubCreateRefreshToken {
                            error("createRefreshToken must not be called when refresh-token-rotation=false")
                        },
                    createTokenResponseStub =
                        stubCreateTokenResponse { args ->
                            Ok(
                                TokenResponse(
                                    accessToken = args.accessToken,
                                    tokenType = args.tokenType,
                                    refreshToken = args.refreshToken,
                                    scope = args.scope,
                                ),
                            )
                        },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = nonRotatingConfigProvider,
                    verifyDpopProofCommand = rejectingDpopVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = tokenStorage),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody =
                            mapOf(
                                "grant_type" to listOf("refresh_token"),
                                "refresh_token" to listOf(presentedToken),
                                "scope" to listOf("openid"),
                            ),
                        requestHeaders = mapOf("Authorization" to "Basic Y2xpZW50LTE6c2VjcmV0"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isOk, "expected success but got ${if (!result.isOk) result.error else "ok"}")
            assertEquals(presentedToken, result.value.refreshToken, "response must reuse the presented refresh token when rotation is disabled")

            // The stored entry must NOT be flagged revoked or used: the same token can be
            // presented again on the next refresh.
            val storedAfter =
                tokenStorage
                    .getRefreshToken(presentedToken)
                    .let { lookup ->
                        assertTrue(lookup.isOk, "getRefreshToken must succeed")
                        lookup.value
                    }
            assertNotNull(storedAfter, "stored refresh token must persist when rotation disabled")
            assertFalse(storedAfter.revoked, "presented refresh token must NOT be revoked when rotation disabled")
            assertFalse(storedAfter.used, "presented refresh token must NOT be marked used when rotation disabled")
        }

    /**
     * OIDC Core 1.0 §12: when the original grant carried `openid`, the AS reissues a fresh
     * id_token on refresh with the original authentication context preserved (auth_time, acr,
     * amr, nonce, sid). This test verifies that:
     *
     * - `commands.createIdToken` IS invoked,
     * - `CreateIdTokenArgs` carries the values surfaced by the verifier (preserved from the
     *   AuthCode-grant issuance), not synthetic refresh-time defaults,
     * - The orchestrator threads the resulting id_token through to
     *   `CreateTokenResponseArgs.idToken`.
     */
    @Test
    fun refreshTokenGrantReissuesIdTokenWhenOpenidScopePresent() =
        runTest {
            val oidcConfigProvider =
                TestOAuth2ServersConfigProvider(
                    OAuth2ServersConfig(
                        servers =
                            mapOf(
                                "default" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://as.example.com",
                                        oidc = FeaturePolicy.SUPPORTED,
                                        refreshTokenRotation = true,
                                    ),
                            ),
                    ),
                )
            val tokenStorage = newTokenStorage()
            val presentedToken = "OIDC-RT-1"
            val originalAuthTime = 1_700_000_000L
            val originalNonce = "n-0S6_WzA2Mj"
            val originalAcr = "urn:mace:incommon:iap:silver"
            val originalAmr = listOf("pwd")
            val originalLoginSessionId = "login-sid-abc"
            seedRefreshToken(
                tokenStorage,
                presentedToken,
                clientId = "client-1",
                subject = "alice",
                scope = "openid profile",
                authTime = originalAuthTime,
                acr = originalAcr,
                amr = originalAmr,
                nonce = originalNonce,
                loginSessionId = originalLoginSessionId,
            )

            var capturedIdTokenArgs: CreateIdTokenArgs? = null
            var capturedTokenResponseArgs: CreateTokenResponseArgs? = null
            var capturedNewRefreshArgs: CreateRefreshTokenArgs? = null
            val service =
                serviceForRefreshTokenFlow(
                    parseStub = refreshTokenParseStub(presentedToken),
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                        },
                    verifyRefreshStub =
                        stubVerifyRefreshTokenGrant { args ->
                            // Real verifier impl reads RefreshTokenData straight back; mirror
                            // that here so the orchestrator sees preserved fields.
                            val stored =
                                tokenStorage
                                    .getRefreshToken(args.refreshToken)
                                    .let { it.value }
                                    ?: error("seeded refresh token must exist")
                            Ok(
                                VerifiedRefreshTokenGrant(
                                    subject = stored.subject,
                                    clientId = stored.clientId,
                                    scope = stored.scope,
                                    refreshTokenId = stored.refreshToken,
                                    authTime = stored.authTime,
                                    acr = stored.acr,
                                    amr = stored.amr,
                                    nonce = stored.nonce,
                                    loginSessionId = stored.loginSessionId,
                                ),
                            )
                        },
                    createAccessTokenStub = stubCreateAccessToken { Ok(StringResult(value = "AT-FRESH")) },
                    createRefreshTokenStub =
                        stubCreateRefreshToken { args ->
                            capturedNewRefreshArgs = args
                            Ok(StringResult(value = "RT-FRESH"))
                        },
                    createIdTokenStub =
                        stubCreateIdToken { args ->
                            capturedIdTokenArgs = args
                            Ok(StringResult(value = "IDT-FRESH-JWT"))
                        },
                    createTokenResponseStub =
                        stubCreateTokenResponse { args ->
                            capturedTokenResponseArgs = args
                            Ok(
                                TokenResponse(
                                    accessToken = args.accessToken,
                                    tokenType = args.tokenType,
                                    refreshToken = args.refreshToken,
                                    scope = args.scope,
                                    idToken = args.idToken,
                                ),
                            )
                        },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = oidcConfigProvider,
                    verifyDpopProofCommand = rejectingDpopVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = tokenStorage),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody =
                            mapOf(
                                "grant_type" to listOf("refresh_token"),
                                "refresh_token" to listOf(presentedToken),
                                "scope" to listOf("openid"),
                            ),
                        requestHeaders = mapOf("Authorization" to "Basic Y2xpZW50LTE6c2VjcmV0"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isOk, "expected success but got ${if (!result.isOk) result.error else "ok"}")
            assertEquals("IDT-FRESH-JWT", result.value.idToken, "response must carry the freshly minted id_token")

            val idTokenArgs = capturedIdTokenArgs
            assertNotNull(idTokenArgs, "createIdToken must be invoked when openid scope is present")
            assertEquals("alice", idTokenArgs.subject)
            assertEquals("client-1", idTokenArgs.clientId)
            assertEquals(originalNonce, idTokenArgs.nonce, "refreshed id_token must echo the original nonce")
            assertEquals(originalAuthTime, idTokenArgs.authTime, "auth_time MUST be preserved across refresh, not regenerated")
            assertEquals(originalAcr, idTokenArgs.acr)
            assertEquals(originalAmr, idTokenArgs.amr)
            assertEquals(originalLoginSessionId, idTokenArgs.sessionId, "sid claim must equal the original login session id")
            assertEquals("AT-FRESH", idTokenArgs.accessToken, "id_token must reference the freshly minted access_token for at_hash")

            // The rotated refresh-token row must continue to carry the OIDC fields so the
            // chain remains capable of reissuing id_tokens on the next refresh.
            val newRefreshArgs = capturedNewRefreshArgs
            assertNotNull(newRefreshArgs, "rotated refresh-token mint must be invoked")
            assertEquals(originalAuthTime, newRefreshArgs.authTime)
            assertEquals(originalAcr, newRefreshArgs.acr)
            assertEquals(originalAmr, newRefreshArgs.amr)
            assertEquals(originalNonce, newRefreshArgs.nonce)
            assertEquals(originalLoginSessionId, newRefreshArgs.loginSessionId)

            assertEquals("IDT-FRESH-JWT", capturedTokenResponseArgs?.idToken, "id_token must thread through to the response builder")
        }

    /**
     * Negative: when the refresh-grant scope does NOT include `openid`, the AS must NOT mint
     * an id_token (RFC 6749 + OIDC Core 1.0 — id_token is OIDC-specific). Verify
     * `commands.createIdToken` is NOT invoked and the response carries no id_token.
     */
    @Test
    fun refreshTokenGrantOmitsIdTokenWhenOpenidScopeAbsent() =
        runTest {
            val oidcConfigProvider =
                TestOAuth2ServersConfigProvider(
                    OAuth2ServersConfig(
                        servers =
                            mapOf(
                                "default" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://as.example.com",
                                        oidc = FeaturePolicy.SUPPORTED,
                                        refreshTokenRotation = true,
                                    ),
                            ),
                    ),
                )
            val tokenStorage = newTokenStorage()
            val presentedToken = "PLAIN-RT-1"
            seedRefreshToken(
                tokenStorage,
                presentedToken,
                clientId = "client-1",
                subject = "alice",
                scope = "read write",
            )

            var capturedTokenResponseArgs: CreateTokenResponseArgs? = null
            val service =
                serviceForRefreshTokenFlow(
                    parseStub =
                        stubParseTokenRequest {
                            Ok(
                                TokenRequestData(
                                    grantType = GrantType.REFRESH_TOKEN,
                                    clientId = "client-1",
                                    clientAuthentication =
                                        ClientAuthenticationConfig.Basic(
                                            credentials =
                                                com.sphereon.oauth2.common.model
                                                    .ClientCredentials(clientId = "client-1", clientSecret = "secret"),
                                        ),
                                    grantParameters = GrantParameters.RefreshToken(refreshToken = presentedToken, scope = "read"),
                                    httpUrl = "https://as.example.com/token",
                                ),
                            )
                        },
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                        },
                    verifyRefreshStub =
                        stubVerifyRefreshTokenGrant { args ->
                            Ok(
                                VerifiedRefreshTokenGrant(
                                    subject = "alice",
                                    clientId = args.clientId,
                                    scope = "read",
                                    refreshTokenId = args.refreshToken,
                                ),
                            )
                        },
                    createAccessTokenStub = stubCreateAccessToken { Ok(StringResult(value = "AT-NOIDC")) },
                    createRefreshTokenStub = stubCreateRefreshToken { Ok(StringResult(value = "RT-NOIDC")) },
                    createIdTokenStub =
                        stubCreateIdToken {
                            error("createIdToken must NOT be invoked when openid scope is absent")
                        },
                    createTokenResponseStub =
                        stubCreateTokenResponse { args ->
                            capturedTokenResponseArgs = args
                            Ok(
                                TokenResponse(
                                    accessToken = args.accessToken,
                                    tokenType = args.tokenType,
                                    refreshToken = args.refreshToken,
                                    scope = args.scope,
                                    idToken = args.idToken,
                                ),
                            )
                        },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = oidcConfigProvider,
                    verifyDpopProofCommand = rejectingDpopVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = tokenStorage),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody =
                            mapOf(
                                "grant_type" to listOf("refresh_token"),
                                "refresh_token" to listOf(presentedToken),
                                "scope" to listOf("read"),
                            ),
                        requestHeaders = mapOf("Authorization" to "Basic Y2xpZW50LTE6c2VjcmV0"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isOk, "expected success but got ${if (!result.isOk) result.error else "ok"}")
            assertEquals(null, result.value.idToken, "response must NOT carry an id_token when openid scope is absent")
            assertEquals(null, capturedTokenResponseArgs?.idToken, "createTokenResponse must receive idToken=null")
        }

    // ============================================================================
    // RFC 9449 §10.1 proof-jkt continuity (FAPI 2.0)
    // ============================================================================

    /**
     * Lightweight DPoP-verify stub that always Ok-returns a fixed thumbprint. Tests that need
     * proof-jkt continuity supply the thumbprint they want to assert against.
     */
    private fun acceptingDpopVerify(jkt: String): Lazy<VerifyDpopProofCommand> =
        lazyOf(object : VerifyDpopProofCommand {
            override val inputTypeToken = typeToken<VerifyDpopProofOptions>()
            override val outputTypeToken = typeToken<VerifyDpopProofResult>()
            override val isEnabled = true

            override suspend fun execute(args: VerifyDpopProofOptions): IdkResult<VerifyDpopProofResult, IdkError> =
                Ok(
                    VerifyDpopProofResult(
                        header = DpopJwtHeader(alg = "ES256", jwk = Jwk(kty = JwaKeyType.EC, kid = "test-key", alg = JwaAlgorithm.ES256)),
                        payload =
                            DpopJwtPayload(
                                jti = "jti-${Clock.System.now().epochSeconds}-${noOpSecureRandom.newToken(lengthBytes = 4)}",
                                htm = "POST",
                                htu = args.httpUrl,
                                iat = Clock.System.now().epochSeconds,
                            ),
                        jwkThumbprint = jkt,
                    ),
                )
        })

    /**
     * RFC 9449 §10.1: refresh-token grant rejects a DPoP proof with a thumbprint different from
     * the key originally pinned at auth-code time.
     */
    @Test
    fun refreshTokenGrantRejectsDpopProofWithDifferentJktForPublicClient() =
        runTest {
            // RFC 9449 §5: PUBLIC clients have no other proof of possession beyond the DPoP key
            // pinned on the original refresh token, so re-presenting the chain with a different
            // key MUST be rejected (`invalid_dpop_proof`). Confidential clients are allowed to
            // rotate the key on refresh because client-auth credentials still establish identity
            // (see [refreshTokenGrantAllowsDpopKeyRotationForConfidentialClient] for that path).
            val tokenStorage = newTokenStorage()
            val presentedToken = "DPOP-RT-1"
            val originalJkt = "jkt-original-AAAA"
            val attackerJkt = "jkt-attacker-BBBB"
            seedRefreshToken(tokenStorage, presentedToken, clientId = "public-client", subject = "alice", scope = "read")
            val seeded =
                tokenStorage
                    .getRefreshToken(presentedToken)
                    .let { it.value }
                    ?: error("seed must succeed")
            tokenStorage.storeRefreshToken(presentedToken, seeded.copy(dpopJkt = originalJkt))

            val service =
                serviceForRefreshTokenFlow(
                    parseStub =
                        stubParseTokenRequest {
                            Ok(
                                TokenRequestData(
                                    grantType = GrantType.REFRESH_TOKEN,
                                    clientId = "public-client",
                                    // Public client: no client_secret, no JWT assertion. Production gates
                                    // the strict jkt-match path on `clientAuthentication is None`.
                                    clientAuthentication = ClientAuthenticationConfig.None(clientId = "public-client"),
                                    grantParameters = GrantParameters.RefreshToken(refreshToken = presentedToken, scope = "read"),
                                    httpUrl = "https://as.example.com/token",
                                    dpopProof = "dummy.proof.token",
                                ),
                            )
                        },
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.NONE))
                        },
                    verifyRefreshStub =
                        stubVerifyRefreshTokenGrant { args ->
                            Ok(
                                VerifiedRefreshTokenGrant(
                                    subject = "alice",
                                    clientId = args.clientId,
                                    scope = "read",
                                    refreshTokenId = args.refreshToken,
                                    dpopJkt = originalJkt,
                                ),
                            )
                        },
                    createAccessTokenStub = stubCreateAccessToken { error("createAccessToken must NOT be invoked when DPoP jkt mismatches for a public client") },
                    createRefreshTokenStub = stubCreateRefreshToken { error("createRefreshToken must NOT be invoked when DPoP jkt mismatches for a public client") },
                    createTokenResponseStub = stubCreateTokenResponse { error("createTokenResponse must NOT be invoked when DPoP jkt mismatches for a public client") },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = configProvider,
                    verifyDpopProofCommand = acceptingDpopVerify(jkt = attackerJkt),
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = tokenStorage),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody =
                            mapOf(
                                "grant_type" to listOf("refresh_token"),
                                "refresh_token" to listOf(presentedToken),
                                "client_id" to listOf("public-client"),
                            ),
                        requestHeaders = mapOf("DPoP" to "dummy.proof.token"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isErr, "public-client refresh-token grant must reject DPoP proof with mismatched thumbprint")
            assertEquals("invalid_dpop_proof", result.error.code)
        }

    /**
     * RFC 9449 §5 confidential-client carve-out: a client that authenticates beyond `none`
     * (Basic / Post / SecretJwt / PrivateKeyJwt / AttestationJwt / MutualTls) MAY rotate the
     * DPoP key on refresh because client identity is independently established by the auth
     * credential. The new access token (and rotated refresh token) rebind to the freshly
     * presented proof's jkt. The FAPI2 conformance suite's `…-refresh-token` test relies on
     * this — pinning the strict-jkt-match for all clients would regress conformance.
     */
    @Test
    fun refreshTokenGrantAllowsDpopKeyRotationForConfidentialClient() =
        runTest {
            val tokenStorage = newTokenStorage()
            val presentedToken = "DPOP-RT-CONF-1"
            val originalJkt = "jkt-original-CONF"
            val rotatedJkt = "jkt-rotated-CONF"
            seedRefreshToken(tokenStorage, presentedToken, clientId = "client-1", subject = "alice", scope = "read")
            val seeded =
                tokenStorage
                    .getRefreshToken(presentedToken)
                    .let { it.value }
                    ?: error("seed must succeed")
            tokenStorage.storeRefreshToken(presentedToken, seeded.copy(dpopJkt = originalJkt))

            var capturedAccessTokenJkt: String? = null
            val service =
                serviceForRefreshTokenFlow(
                    parseStub =
                        stubParseTokenRequest {
                            Ok(
                                TokenRequestData(
                                    grantType = GrantType.REFRESH_TOKEN,
                                    clientId = "client-1",
                                    clientAuthentication =
                                        ClientAuthenticationConfig.Basic(
                                            credentials =
                                                com.sphereon.oauth2.common.model
                                                    .ClientCredentials(clientId = "client-1", clientSecret = "secret"),
                                        ),
                                    grantParameters = GrantParameters.RefreshToken(refreshToken = presentedToken, scope = "read"),
                                    httpUrl = "https://as.example.com/token",
                                    dpopProof = "dummy.proof.token",
                                ),
                            )
                        },
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                        },
                    verifyRefreshStub =
                        stubVerifyRefreshTokenGrant { args ->
                            Ok(
                                VerifiedRefreshTokenGrant(
                                    subject = "alice",
                                    clientId = args.clientId,
                                    scope = "read",
                                    refreshTokenId = args.refreshToken,
                                    dpopJkt = originalJkt,
                                ),
                            )
                        },
                    createAccessTokenStub =
                        stubCreateAccessToken { args ->
                            capturedAccessTokenJkt = args.dpopJkt
                            Ok(StringResult(value = "rotated-at-1"))
                        },
                    createRefreshTokenStub = stubCreateRefreshToken { Ok(StringResult(value = "rotated-rt-1")) },
                    createTokenResponseStub =
                        stubCreateTokenResponse { args ->
                            Ok(
                                TokenResponse(
                                    accessToken = args.accessToken,
                                    tokenType = args.tokenType,
                                    refreshToken = args.refreshToken,
                                    scope = args.scope,
                                ),
                            )
                        },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = configProvider,
                    verifyDpopProofCommand = acceptingDpopVerify(jkt = rotatedJkt),
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = tokenStorage),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody =
                            mapOf(
                                "grant_type" to listOf("refresh_token"),
                                "refresh_token" to listOf(presentedToken),
                            ),
                        requestHeaders = mapOf("Authorization" to "Basic Y2xpZW50LTE6c2VjcmV0", "DPoP" to "dummy.proof.token"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isOk, "confidential client must be allowed to rotate DPoP key on refresh: ${if (!result.isOk) result.error else ""}")
            assertEquals(rotatedJkt, capturedAccessTokenJkt, "rebinding: new access token must carry the freshly presented jkt, not the stored one")
        }

    /**
     * RFC 9449 §10.1: client_credentials carries no prior commitment; the proof at first use
     * establishes the binding. The issued access token's `cnf.jkt` MUST be the proof's thumbprint
     * and `token_type` MUST be `DPoP`.
     */
    @Test
    fun clientCredentialsGrantBindsAccessTokenWithProofJkt() =
        runTest {
            val proofJkt = "jkt-cc-bind-CCCC"
            var capturedAccessTokenArgs: CreateAccessTokenArgs? = null
            var capturedTokenResponseArgs: CreateTokenResponseArgs? = null
            val service =
                serviceForClientCredentialsFlow(
                    parseStub =
                        stubParseTokenRequest {
                            Ok(
                                TokenRequestData(
                                    grantType = GrantType.CLIENT_CREDENTIALS,
                                    clientId = "client-1",
                                    clientAuthentication =
                                        ClientAuthenticationConfig.Basic(
                                            credentials =
                                                com.sphereon.oauth2.common.model
                                                    .ClientCredentials(clientId = "client-1", clientSecret = "secret"),
                                        ),
                                    grantParameters = GrantParameters.ClientCredentials(scope = "read"),
                                    httpUrl = "https://as.example.com/token",
                                    dpopProof = "dummy.proof.token",
                                ),
                            )
                        },
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                        },
                    verifyGrantStub =
                        stubVerifyClientCredentialsGrant {
                            Ok(VerifiedClientCredentialsGrant(subject = "client-1", clientId = "client-1", scope = "read"))
                        },
                    createAccessTokenStub =
                        stubCreateAccessToken { args ->
                            capturedAccessTokenArgs = args
                            Ok(StringResult(value = "AT-CC-DPOP"))
                        },
                    createTokenResponseStub =
                        stubCreateTokenResponse { args ->
                            capturedTokenResponseArgs = args
                            Ok(TokenResponse(accessToken = args.accessToken, tokenType = args.tokenType, scope = args.scope))
                        },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = configProvider,
                    verifyDpopProofCommand = acceptingDpopVerify(jkt = proofJkt),
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = newTokenStorage()),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody = mapOf("grant_type" to listOf("client_credentials"), "scope" to listOf("read")),
                        requestHeaders = mapOf("Authorization" to "Basic Y2xpZW50LTE6c2VjcmV0", "DPoP" to "dummy.proof.token"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isOk, "client_credentials with DPoP proof must succeed")
            assertEquals(proofJkt, capturedAccessTokenArgs?.dpopJkt, "access token must carry cnf.jkt equal to the proof thumbprint")
            assertEquals("DPoP", capturedTokenResponseArgs?.tokenType, "token_type must be DPoP when proof is presented")
        }

    // ============================================================================
    // RFC 9449 §8 nonce challenges
    // ============================================================================

    /** Nonce manager that requires a fixed nonce; supports rotation tracking via mintCount. */
    private class TestNonceManager(
        private val acceptedNonces: MutableSet<String> = mutableSetOf(),
    ) : DpopNonceManager {
        var rotateCount: Int = 0
            private set
        var lastRotated: String = "INITIAL"
            private set

        fun seed(nonce: String) {
            acceptedNonces += nonce
        }

        override suspend fun currentNonce(): String = lastRotated

        override suspend fun rotate(): String {
            rotateCount += 1
            lastRotated = "rotated-$rotateCount"
            acceptedNonces += lastRotated
            return lastRotated
        }

        override suspend fun isValid(nonce: String): Boolean = nonce in acceptedNonces
    }

    /**
     * RFC 9449 §8: when the AS requires a DPoP nonce and the proof omits it, the AS returns
     * `use_dpop_nonce` carrying a fresh nonce (in error.meta) so the client can retry.
     */
    @Test
    fun dpopProofWithoutNonceWhenNonceRequiredReturnsUseDpopNonce() =
        runTest {
            val nonceConfigProvider =
                TestOAuth2ServersConfigProvider(
                    OAuth2ServersConfig(
                        servers =
                            mapOf(
                                "default" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://as.example.com",
                                        dpopNonceRequired = true,
                                    ),
                            ),
                    ),
                )
            val service =
                serviceForClientCredentialsFlow(
                    parseStub =
                        stubParseTokenRequest {
                            Ok(
                                TokenRequestData(
                                    grantType = GrantType.CLIENT_CREDENTIALS,
                                    clientId = "client-1",
                                    clientAuthentication =
                                        ClientAuthenticationConfig.Basic(
                                            credentials =
                                                com.sphereon.oauth2.common.model
                                                    .ClientCredentials(clientId = "client-1", clientSecret = "secret"),
                                        ),
                                    grantParameters = GrantParameters.ClientCredentials(scope = "read"),
                                    httpUrl = "https://as.example.com/token",
                                    dpopProof = "dummy.proof.token",
                                ),
                            )
                        },
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                        },
                    verifyGrantStub = stubVerifyClientCredentialsGrant { error("must not reach grant verification when nonce missing") },
                    createAccessTokenStub = stubCreateAccessToken { error("must not mint access token when nonce missing") },
                    createTokenResponseStub = stubCreateTokenResponse { error("must not build response when nonce missing") },
                )
            val nonceManager = TestNonceManager()
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = nonceConfigProvider,
                    verifyDpopProofCommand = acceptingDpopVerify(jkt = "jkt-test"),
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = lazyOf(nonceManager),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = newTokenStorage()),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody = mapOf("grant_type" to listOf("client_credentials")),
                        requestHeaders = mapOf("Authorization" to "Basic Y2xpZW50LTE6c2VjcmV0", "DPoP" to "dummy.proof.token"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isErr, "missing nonce when required must surface use_dpop_nonce")
            assertEquals("use_dpop_nonce", result.error.code)
            val freshNonce = result.error.meta["dpop_nonce"] as? String
            assertNotNull(freshNonce, "use_dpop_nonce error must carry the fresh nonce in meta for the HTTP layer")
            assertEquals(1, nonceManager.rotateCount, "AS must rotate exactly once per challenge")
        }

    /**
     * RFC 9449 §8: a stale nonce (not in the rolling window) yields `use_dpop_nonce` even though
     * the proof itself is otherwise valid.
     */
    @Test
    fun dpopProofWithStaleNonceReturnsUseDpopNonce() =
        runTest {
            val nonceConfigProvider =
                TestOAuth2ServersConfigProvider(
                    OAuth2ServersConfig(
                        servers =
                            mapOf(
                                "default" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://as.example.com",
                                        dpopNonceRequired = true,
                                    ),
                            ),
                    ),
                )
            // Build a verify stub that returns a payload with a stale nonce baked in.
            val staleNonce = "stale-nonce-XYZ"
            val staleNonceVerify: Lazy<VerifyDpopProofCommand> =
                lazyOf(object : VerifyDpopProofCommand {
                    override val inputTypeToken = typeToken<VerifyDpopProofOptions>()
                    override val outputTypeToken = typeToken<VerifyDpopProofResult>()
                    override val isEnabled = true

                    override suspend fun execute(args: VerifyDpopProofOptions): IdkResult<VerifyDpopProofResult, IdkError> =
                        Ok(
                            VerifyDpopProofResult(
                                header = DpopJwtHeader(alg = "ES256", jwk = Jwk(kty = JwaKeyType.EC, kid = "test-key", alg = JwaAlgorithm.ES256)),
                                payload =
                                    DpopJwtPayload(
                                        jti = "jti-stale-${Clock.System.now().epochSeconds}",
                                        htm = "POST",
                                        htu = args.httpUrl,
                                        iat = Clock.System.now().epochSeconds,
                                        nonce = staleNonce,
                                    ),
                                jwkThumbprint = "jkt-stale",
                            ),
                        )
                })

            val service =
                serviceForClientCredentialsFlow(
                    parseStub =
                        stubParseTokenRequest {
                            Ok(
                                TokenRequestData(
                                    grantType = GrantType.CLIENT_CREDENTIALS,
                                    clientId = "client-1",
                                    clientAuthentication =
                                        ClientAuthenticationConfig.Basic(
                                            credentials =
                                                com.sphereon.oauth2.common.model
                                                    .ClientCredentials(clientId = "client-1", clientSecret = "secret"),
                                        ),
                                    grantParameters = GrantParameters.ClientCredentials(scope = "read"),
                                    httpUrl = "https://as.example.com/token",
                                    dpopProof = "dummy.proof.token",
                                ),
                            )
                        },
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                        },
                    verifyGrantStub = stubVerifyClientCredentialsGrant { error("must not reach grant verification when nonce stale") },
                    createAccessTokenStub = stubCreateAccessToken { error("must not mint access token when nonce stale") },
                    createTokenResponseStub = stubCreateTokenResponse { error("must not build response when nonce stale") },
                )
            val nonceManager = TestNonceManager() // does not seed the stale value, so isValid("stale-nonce-XYZ") = false
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = nonceConfigProvider,
                    verifyDpopProofCommand = staleNonceVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = lazyOf(nonceManager),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = newTokenStorage()),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody = mapOf("grant_type" to listOf("client_credentials")),
                        requestHeaders = mapOf("Authorization" to "Basic Y2xpZW50LTE6c2VjcmV0", "DPoP" to "dummy.proof.token"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isErr, "stale nonce must surface use_dpop_nonce")
            assertEquals("use_dpop_nonce", result.error.code)
            val freshNonce = result.error.meta["dpop_nonce"] as? String
            assertNotNull(freshNonce, "use_dpop_nonce must carry a fresh nonce so the client retries")
        }

    /**
     * RFC 9449 §8 happy path: a proof with a nonce currently in the AS rolling window is
     * accepted and a normal token is minted.
     */
    @Test
    fun dpopProofWithValidNonceSucceeds() =
        runTest {
            val nonceConfigProvider =
                TestOAuth2ServersConfigProvider(
                    OAuth2ServersConfig(
                        servers =
                            mapOf(
                                "default" to
                                    OAuth2ServerInstanceConfig(
                                        issuer = "https://as.example.com",
                                        dpopNonceRequired = true,
                                    ),
                            ),
                    ),
                )
            val activeNonce = "fresh-nonce-AAA"
            val activeNonceVerify: Lazy<VerifyDpopProofCommand> =
                lazyOf(object : VerifyDpopProofCommand {
                    override val inputTypeToken = typeToken<VerifyDpopProofOptions>()
                    override val outputTypeToken = typeToken<VerifyDpopProofResult>()
                    override val isEnabled = true

                    override suspend fun execute(args: VerifyDpopProofOptions): IdkResult<VerifyDpopProofResult, IdkError> =
                        Ok(
                            VerifyDpopProofResult(
                                header = DpopJwtHeader(alg = "ES256", jwk = Jwk(kty = JwaKeyType.EC, kid = "test-key", alg = JwaAlgorithm.ES256)),
                                payload =
                                    DpopJwtPayload(
                                        jti = "jti-fresh-${Clock.System.now().epochSeconds}",
                                        htm = "POST",
                                        htu = args.httpUrl,
                                        iat = Clock.System.now().epochSeconds,
                                        nonce = activeNonce,
                                    ),
                                jwkThumbprint = "jkt-fresh",
                            ),
                        )
                })

            val service =
                serviceForClientCredentialsFlow(
                    parseStub =
                        stubParseTokenRequest {
                            Ok(
                                TokenRequestData(
                                    grantType = GrantType.CLIENT_CREDENTIALS,
                                    clientId = "client-1",
                                    clientAuthentication =
                                        ClientAuthenticationConfig.Basic(
                                            credentials =
                                                com.sphereon.oauth2.common.model
                                                    .ClientCredentials(clientId = "client-1", clientSecret = "secret"),
                                        ),
                                    grantParameters = GrantParameters.ClientCredentials(scope = "read"),
                                    httpUrl = "https://as.example.com/token",
                                    dpopProof = "dummy.proof.token",
                                ),
                            )
                        },
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                        },
                    verifyGrantStub =
                        stubVerifyClientCredentialsGrant {
                            Ok(VerifiedClientCredentialsGrant(subject = "client-1", clientId = "client-1", scope = "read"))
                        },
                    createAccessTokenStub = stubCreateAccessToken { Ok(StringResult(value = "AT-NONCE-OK")) },
                    createTokenResponseStub =
                        stubCreateTokenResponse { args ->
                            Ok(TokenResponse(accessToken = args.accessToken, tokenType = args.tokenType, scope = args.scope))
                        },
                )
            val nonceManager = TestNonceManager()
            nonceManager.seed(activeNonce)

            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = nonceConfigProvider,
                    verifyDpopProofCommand = activeNonceVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = lazyOf(nonceManager),
                    grantHandlers = grantHandlersFor(commands = service.commands, tokenStorage = newTokenStorage()),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody = mapOf("grant_type" to listOf("client_credentials"), "scope" to listOf("read")),
                        requestHeaders = mapOf("Authorization" to "Basic Y2xpZW50LTE6c2VjcmV0", "DPoP" to "dummy.proof.token"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isOk, "valid in-window nonce must result in a successful token issuance")
            assertEquals("AT-NONCE-OK", result.value.accessToken)
            assertEquals("DPoP", result.value.tokenType)
            assertEquals(0, nonceManager.rotateCount, "rotate must NOT be called when the nonce is already valid")
        }

    /**
     * RFC 6749 §10.4 / OAuth 2.1 reuse detection: replay a refresh token whose `revoked` flag
     * has been set by a prior rotation. Wire response is `invalid_grant`; the AS additionally
     * emits an [com.sphereon.oauth2.server.authorization.audit.OAuth2AuditEventType.REFRESH_TOKEN_REUSE_DETECTED]
     * audit event so SIEM / on-call rules can alert on the reuse signal separately from generic
     * `invalid_grant` noise. The signal is structured (verifier sets a meta marker on the
     * `InvalidGrant` error), not a substring match on the human-readable details.
     */
    @Test
    fun refreshTokenGrantEmitsReuseDetectedAuditEventOnRevokedTokenReplay() =
        runTest {
            val tokenStorage = newTokenStorage()
            val presentedToken = "RT-REPLAY-1"
            seedRefreshToken(tokenStorage, presentedToken, clientId = "client-1", subject = "alice", scope = "read")

            // Mark the seeded token as consumed+revoked, simulating a prior rotation. The next
            // verify call must therefore treat it as a reuse-attempt signal.
            val consumeResult = tokenStorage.consumeRefreshToken(presentedToken, revoke = true)
            assertTrue(consumeResult.isOk, "test setup: marking the token as consumed+revoked must succeed")

            val auditCapturing = CapturingOAuth2AuditEmitter()
            val service =
                serviceForRefreshTokenFlow(
                    parseStub =
                        stubParseTokenRequest {
                            Ok(
                                TokenRequestData(
                                    grantType = GrantType.REFRESH_TOKEN,
                                    clientId = "client-1",
                                    clientAuthentication =
                                        ClientAuthenticationConfig.Basic(
                                            credentials =
                                                com.sphereon.oauth2.common.model
                                                    .ClientCredentials(clientId = "client-1", clientSecret = "secret"),
                                        ),
                                    grantParameters = GrantParameters.RefreshToken(refreshToken = presentedToken, scope = "read"),
                                    httpUrl = "https://as.example.com/token",
                                    dpopProof = null,
                                ),
                            )
                        },
                    verifyClientAuthStub =
                        stubVerifyClientAuthentication {
                            Ok(VerifiedClientAuthentication(clientId = it.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC))
                        },
                    // The real verifier must run so that the revoked-flag check fires and the
                    // structured reuse-detection meta marker is emitted on the InvalidGrant.
                    verifyRefreshStub =
                        com.sphereon.oauth2.server.authorization.impl.command.token.VerifyRefreshTokenGrantCommandImpl(
                            execution = ctx.execution,
                            tokenStorage = tokenStorage,
                            configProvider = configProvider,
                            clientRegistry = com.sphereon.oauth2.server.authorization.impl.testutil.StubClientRegistry(),
                        ),
                    createAccessTokenStub = stubCreateAccessToken { error("createAccessToken must NOT be invoked when refresh token is revoked") },
                    createRefreshTokenStub = stubCreateRefreshToken { error("createRefreshToken must NOT be invoked when refresh token is revoked") },
                    createTokenResponseStub = stubCreateTokenResponse { error("createTokenResponse must NOT be invoked when refresh token is revoked") },
                )
            val command =
                HandleTokenRequestCommandImpl(
                    execution = ctx.execution,
                    parseTokenRequestCommand = service.commands.parseTokenRequest,
                    verifyClientAuthenticationCommand = lazyOf(service.commands.verifyClientAuthentication),
                    serversConfigProvider = configProvider,
                    verifyDpopProofCommand = rejectingDpopVerify,
                    dpopProofJtiCache = newDpopJtiCache(),
                    dpopNonceManager = newDpopNonceManager(),
                    grantHandlers = grantHandlersFor(
                        commands = service.commands,
                        tokenStorage = tokenStorage,
                        refreshAuditEmitter = auditCapturing,
                    ),
                )

            val result =
                command.execute(
                    HandleTokenRequestArgs(
                        requestBody =
                            mapOf(
                                "grant_type" to listOf("refresh_token"),
                                "refresh_token" to listOf(presentedToken),
                            ),
                        requestHeaders = mapOf("Authorization" to "Basic Y2xpZW50LTE6c2VjcmV0"),
                        httpUrl = "https://as.example.com/token",
                    ),
                )

            assertTrue(result.isErr, "replay of a revoked refresh token must be rejected")
            assertEquals("invalid_grant", result.error.code, "wire-visible code stays invalid_grant per RFC 6749 §5.2")
            // The audit emission is the security-meaningful side effect. Locate it from the
            // captured stream rather than asserting "exactly one event" so future intermediary
            // events (rate-limiter denials, etc.) do not destabilise the test.
            val reuseEvents =
                auditCapturing.events.filter { it.type == com.sphereon.oauth2.server.authorization.audit.OAuth2AuditEventType.REFRESH_TOKEN_REUSE_DETECTED }
            assertEquals(1, reuseEvents.size, "exactly one REFRESH_TOKEN_REUSE_DETECTED event must fire on revoked-token replay")
            val event = reuseEvents.single()
            assertEquals(ctx.execution.sessionContext.context.tenant.tenantId, event.tenantId)
            assertEquals("client-1", event.clientId)
            assertEquals("invalid_grant", event.errorCode)
            assertEquals("refresh_token", event.metadata["grant_type"])
        }

    /**
     * Capturing [com.sphereon.oauth2.server.authorization.audit.OAuth2AuditEmitter] used by the
     * reuse-detection test above. Order-preserving and append-only; not thread-safe but the
     * orchestrator runs the audit emit on a single coroutine per request.
     */
    internal class CapturingOAuth2AuditEmitter : com.sphereon.oauth2.server.authorization.audit.OAuth2AuditEmitter {
        data class Captured(
            val type: com.sphereon.oauth2.server.authorization.audit.OAuth2AuditEventType,
            val tenantId: String,
            val clientId: String?,
            val subject: String?,
            val metadata: Map<String, String>,
            val errorCode: String?,
            val errorMessage: String?,
        )

        private val _events = mutableListOf<Captured>()
        val events: List<Captured> get() = _events.toList()

        override suspend fun emit(
            type: com.sphereon.oauth2.server.authorization.audit.OAuth2AuditEventType,
            tenantId: String,
            clientId: String?,
            subject: String?,
            metadata: Map<String, String>,
            errorCode: String?,
            errorMessage: String?,
        ) {
            _events.add(Captured(type, tenantId, clientId, subject, metadata, errorCode, errorMessage))
        }
    }
}

private const val REFUSAL_TEST_SECRET = "refusal-test-secret-value"

/** Captures app-scope WARN lines so a test can count the refusal diagnostics of one request. */
private class RecordingTokenRefusalLog : LogManager {
    val warnings = mutableListOf<String>()

    override suspend fun setGlobalConfig(config: LoggerConfig): LogManager = this

    override suspend fun getGlobalConfig(): LoggerConfig = LoggerConfig.Default

    override fun withTag(
        tag: String,
        config: LoggerConfig?,
    ): LogService = throw NotImplementedError("Token refusal logging uses the async logger")

    override fun withTagAsync(
        tag: String,
        config: LoggerConfig?,
    ): AsyncLogService =
        object : AsyncLogService {
            override val sessionContext: SessionContext = NoOpSessionContext
            override val scope: IdkScope = IdkScope.APP
            override val id: String = "token-refusal-test-log"
            override val isEnabled: Boolean = true

            override suspend fun execute(args: LogMessage): IdkResult<Unit, IdkErrorType> {
                if (args.level == LogLevel.WARN) warnings += args.message
                return Ok(Unit)
            }

            override suspend fun setConfig(config: LoggerConfig): AsyncLogService = this

            override fun toSync(): LogService = throw NotImplementedError("Not used by this test")
        }
}
