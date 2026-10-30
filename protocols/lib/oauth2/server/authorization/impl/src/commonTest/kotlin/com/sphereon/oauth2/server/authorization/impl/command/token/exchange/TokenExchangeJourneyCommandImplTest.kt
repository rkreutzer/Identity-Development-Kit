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
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.defaults.random.defaultSecureRandom
import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.JwaCurve
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.KeyInfo
import com.sphereon.crypto.core.KeyType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.oauth2.common.command.VerifyDpopProofCommand
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.model.ActorClaim
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.ClientCredentials
import com.sphereon.oauth2.common.model.DpopJwtHeader
import com.sphereon.oauth2.common.model.DpopJwtPayload
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.common.model.TokenResponse
import com.sphereon.oauth2.common.model.TokenTypeIdentifier
import com.sphereon.oauth2.common.model.VerifyDpopProofOptions
import com.sphereon.oauth2.common.model.VerifyDpopProofResult
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenArgs
import com.sphereon.oauth2.server.authorization.command.CreateAccessTokenCommand
import com.sphereon.oauth2.server.authorization.command.CreateTokenResponseArgs
import com.sphereon.oauth2.server.authorization.command.CreateTokenResponseCommand
import com.sphereon.oauth2.server.authorization.command.GrantParameters
import com.sphereon.oauth2.server.authorization.command.ParseTokenRequestArgs
import com.sphereon.oauth2.server.authorization.command.ParseTokenRequestCommand
import com.sphereon.oauth2.server.authorization.command.TokenRequestData
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthentication
import com.sphereon.oauth2.server.authorization.command.VerifiedClientAuthorization
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationArgs
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationCommand
import com.sphereon.oauth2.server.authorization.command.token.AnchoredActorToken
import com.sphereon.oauth2.server.authorization.command.token.AnchoredSubjectToken
import com.sphereon.oauth2.server.authorization.command.token.AuthorizeTokenExchangeCommand
import com.sphereon.oauth2.server.authorization.command.token.AuthorizeTokenExchangeInput
import com.sphereon.oauth2.server.authorization.command.token.BoundedTokenExchange
import com.sphereon.oauth2.server.authorization.command.token.BuildTokenExchangeActorChainCommand
import com.sphereon.oauth2.server.authorization.command.token.GrantContext
import com.sphereon.oauth2.server.authorization.command.token.GrantHandler
import com.sphereon.oauth2.server.authorization.command.token.GrantHandlerKeys
import com.sphereon.oauth2.server.authorization.command.token.HandleTokenRequestArgs
import com.sphereon.oauth2.server.authorization.command.token.MapTokenExchangeClaimsCommand
import com.sphereon.oauth2.server.authorization.command.token.TokenExchangeActorChainInput
import com.sphereon.oauth2.server.authorization.command.token.TokenExchangeActorExtensions
import com.sphereon.oauth2.server.authorization.command.token.TokenExchangeAuthorization
import com.sphereon.oauth2.server.authorization.command.token.TokenExchangeClaimMapping
import com.sphereon.oauth2.server.authorization.command.token.TokenExchangeJourneySteps
import com.sphereon.oauth2.server.authorization.command.token.TokenExchangeProfile
import com.sphereon.oauth2.server.authorization.command.token.TokenExchangeResourceMapping
import com.sphereon.oauth2.server.authorization.command.token.TokenIssuerAnchor
import com.sphereon.oauth2.server.authorization.dpop.DpopNonceManager
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.command.token.CreateAccessTokenCommandImpl
import com.sphereon.oauth2.server.authorization.impl.command.token.HandleTokenRequestCommandImpl
import com.sphereon.oauth2.server.authorization.impl.command.token.grant.TokenExchangeGrantHandlerImpl
import com.sphereon.oauth2.server.authorization.impl.dpop.InMemoryDpopProofJtiCacheImpl
import com.sphereon.oauth2.server.authorization.impl.policy.StandardAuthorizeTokenExchangeCommand
import com.sphereon.oauth2.server.authorization.impl.policy.StandardTokenExchangeProfile
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryClientRegistryImpl
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryOAuth2BackingStorageImpl
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemorySigningKeyStore
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemorySingleUseObjectStore
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryTokenStorageImpl
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.RecordingJwtService
import com.sphereon.oauth2.server.authorization.impl.testutil.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.impl.testutil.fixedSigningIdentifierResolver
import com.sphereon.oauth2.server.authorization.impl.testutil.fixedAsInstanceIdProvider
import com.sphereon.oauth2.server.authorization.trust.SubjectTokenIssuerTrust
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * Executes the production token-exchange journey from the raw token request, through the token
 * endpoint and the exchange grant handler, to the minted access token.
 */
class TokenExchangeJourneyCommandImplTest {
    private val issuer = "https://as.example.test"
    private val foreignIssuer = "https://idp.example.test"
    private val tokenEndpoint = "https://as.example.test/token"
    private val audience = "https://api.example.test"
    private val resource = "https://resource.example.test"
    private val ctx = OAuth2ServerTestContext("token-exchange-journey-test", this)
    private val configProvider =
        TestOAuth2ServersConfigProvider(
            OAuth2ServersConfig(servers = mapOf("default" to OAuth2ServerInstanceConfig(issuer = issuer))),
        )
    private val client =
        VerifiedClientAuthorization(
            clientId = "exchange-client",
            grantTypes = listOf(GrantType.TOKEN_EXCHANGE),
            defaultAccessTokenAudience = audience,
            allowedAccessTokenAudiences = setOf(audience, resource),
        )

    private class Recorder {
        var parseCalls = 0
        var authenticationCalls = 0
        var trustCalls = 0
        var authorizeInputs = mutableListOf<AuthorizeTokenExchangeInput>()
        var mintedArgs: CreateAccessTokenArgs? = null
        var response: CreateTokenResponseArgs? = null
    }

    private fun jwt(claims: JsonObject, kid: String = "idp-key"): String {
        val header = """{"alg":"ES256","typ":"JWT","kid":"$kid"}"""
        val payload =
            JsonObject(
                buildMap {
                    put("iss", JsonPrimitive(foreignIssuer))
                    put("exp", JsonPrimitive(Clock.System.now().epochSeconds + 300))
                    putAll(claims)
                },
            ).toString()
        return listOf(header, payload, "signature").joinToString(".") { it.encodeToByteArray().encodeToBase64Url() }
    }

    private fun trust(recorder: Recorder): SubjectTokenIssuerTrust =
        object : SubjectTokenIssuerTrust {
            override suspend fun resolveTrustedKeys(issuer: String): List<Jwk>? {
                recorder.trustCalls++
                return if (issuer == foreignIssuer) listOf(Jwk(kty = JwaKeyType.EC, crv = JwaCurve.P_256, x = "x", y = "y", kid = "idp-key")) else null
            }
        }

    private fun parameters(
        subjectToken: String,
        actorToken: String? = null,
        audiences: List<String> = listOf(audience),
        resources: List<String> = emptyList(),
    ) = GrantParameters.TokenExchange(
        subjectToken = subjectToken,
        subjectTokenType = TokenTypeIdentifier.ACCESS_TOKEN,
        actorToken = actorToken,
        actorTokenType = actorToken?.let { TokenTypeIdentifier.ACCESS_TOKEN },
        audiences = audiences,
        resources = resources,
    )

    private fun parse(
        recorder: Recorder,
        grantParameters: GrantParameters,
        dpopProof: String? = null,
    ): ParseTokenRequestCommand =
        object : ParseTokenRequestCommand {
            override val inputTypeToken = typeToken<ParseTokenRequestArgs>()
            override val outputTypeToken = typeToken<TokenRequestData>()
            override val isEnabled = true

            override suspend fun execute(args: ParseTokenRequestArgs): IdkResult<TokenRequestData, IdkError> {
                recorder.parseCalls++
                return Ok(
                    TokenRequestData(
                        grantType = GrantType.TOKEN_EXCHANGE,
                        clientId = client.clientId,
                        clientAuthentication = ClientAuthenticationConfig.Basic(ClientCredentials(client.clientId, "secret")),
                        grantParameters = grantParameters,
                        httpUrl = tokenEndpoint,
                        dpopProof = dpopProof,
                    ),
                )
            }
        }

    private fun authenticate(
        recorder: Recorder,
        result: IdkResult<VerifiedClientAuthentication, IdkError>? = null,
    ): VerifyClientAuthenticationCommand =
        object : VerifyClientAuthenticationCommand {
            override val inputTypeToken = typeToken<VerifyClientAuthenticationArgs>()
            override val outputTypeToken = typeToken<VerifiedClientAuthentication>()
            override val isEnabled = true

            override suspend fun execute(args: VerifyClientAuthenticationArgs): IdkResult<VerifiedClientAuthentication, IdkError> {
                recorder.authenticationCalls++
                return result
                    ?: Ok(
                        VerifiedClientAuthentication(
                            clientId = args.clientId,
                            method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC,
                            clientAuthorization = client,
                        ),
                    )
            }
        }

    private fun dpop(jkt: String?, jti: String? = null): Lazy<VerifyDpopProofCommand> =
        lazyOf(
            object : VerifyDpopProofCommand {
                override val inputTypeToken = typeToken<VerifyDpopProofOptions>()
                override val outputTypeToken = typeToken<VerifyDpopProofResult>()
                override val isEnabled = true

                override suspend fun execute(args: VerifyDpopProofOptions): IdkResult<VerifyDpopProofResult, IdkError> {
                    val thumbprint = jkt ?: return Err(IdkError.fromString(code = "invalid_dpop_proof", message = "no proof expected"))
                    return Ok(
                        VerifyDpopProofResult(
                            header = DpopJwtHeader(alg = "ES256", jwk = Jwk(kty = JwaKeyType.EC, kid = "proof-key", alg = JwaAlgorithm.ES256)),
                            payload =
                                DpopJwtPayload(
                                    jti = jti ?: "jti-${defaultSecureRandom().newToken(lengthBytes = 8)}",
                                    htm = "POST",
                                    htu = args.httpUrl,
                                    iat = Clock.System.now().epochSeconds,
                                ),
                            jwkThumbprint = thumbprint,
                        ),
                    )
                }
            },
        )

    private val nonceManager: Lazy<DpopNonceManager> =
        lazyOf(
            object : DpopNonceManager {
                override suspend fun currentNonce(): String = "nonce"

                override suspend fun rotate(): String = "nonce-rotated"

                override suspend fun isValid(nonce: String): Boolean = true
            },
        )

    private fun mint(recorder: Recorder): CreateAccessTokenCommand {
        val delegate =
            CreateAccessTokenCommandImpl(
                execution = ctx.execution,
                jwtService = RecordingJwtService(mintedKid = "exchange-mint-key"),
                tokenStorage = InMemoryTokenStorageImpl(InMemoryOAuth2BackingStorageImpl()),
                secureRandom = defaultSecureRandom(),
                configProvider = configProvider,
                asInstanceIdProvider = fixedAsInstanceIdProvider(),
                signingIdentifierResolver = fixedSigningIdentifierResolver(ManagedOptsKeyInfo(
                    identifier = KeyInfo<KeyType>(
                        alias = "exchange-mint-key", kid = "exchange-mint-key", signatureAlgorithm = SignatureAlgorithm.RSA_SHA256,
                    ),
                )),
                eventService = null,
            )
        return object : CreateAccessTokenCommand {
            override val inputTypeToken = typeToken<CreateAccessTokenArgs>()
            override val outputTypeToken = delegate.outputTypeToken
            override val isEnabled = true

            override suspend fun execute(args: CreateAccessTokenArgs) = delegate.execute(args).also { recorder.mintedArgs = args }
        }
    }

    private fun respond(recorder: Recorder): CreateTokenResponseCommand =
        object : CreateTokenResponseCommand {
            override val inputTypeToken = typeToken<CreateTokenResponseArgs>()
            override val outputTypeToken = typeToken<TokenResponse>()
            override val isEnabled = true

            override suspend fun execute(args: CreateTokenResponseArgs): IdkResult<TokenResponse, IdkError> {
                recorder.response = args
                return Ok(TokenResponse(accessToken = args.accessToken, tokenType = args.tokenType, issuedTokenType = args.issuedTokenType))
            }
        }

    private fun profile(
        recorder: Recorder,
        decide: AuthorizeTokenExchangeCommand = StandardAuthorizeTokenExchangeCommand(),
        claims: JsonObject = JsonObject(emptyMap()),
        actorExtensions: JsonObject = JsonObject(emptyMap()),
    ): TokenExchangeProfile =
        object : TokenExchangeProfile {
            override val id = "test.tokenexchange.profile"
            override val authorize =
                object : AuthorizeTokenExchangeCommand {
                    override suspend fun execute(args: AuthorizeTokenExchangeInput): IdkResult<TokenExchangeAuthorization, AuthorizationServerError> {
                        recorder.authorizeInputs += args
                        return decide.execute(args)
                    }
                }
            override val mapClaims =
                object : MapTokenExchangeClaimsCommand {
                    override suspend fun execute(args: BoundedTokenExchange) = Ok(TokenExchangeClaimMapping(claims))
                }
            override val buildActorChain =
                object : BuildTokenExchangeActorChainCommand {
                    override suspend fun execute(args: TokenExchangeActorChainInput) = Ok(TokenExchangeActorExtensions(actorExtensions))
                }
        }

    private fun journey(
        recorder: Recorder,
        grantParameters: GrantParameters,
        profile: TokenExchangeProfile = profile(recorder),
        authentication: VerifyClientAuthenticationCommand = authenticate(recorder),
        dpopProof: String? = null,
        verifyDpop: Lazy<VerifyDpopProofCommand> = dpop(null),
        jtiCache: InMemoryDpopProofJtiCacheImpl = InMemoryDpopProofJtiCacheImpl(InMemorySingleUseObjectStore()),
    ): TokenExchangeJourneyCommandImpl =
        TokenExchangeJourneyCommandImpl(
            execution = ctx.execution,
            parseTokenRequestCommand = parse(recorder, grantParameters, dpopProof),
            verifyClientAuthenticationCommand = authentication,
            serversConfigProvider = configProvider,
            verifyDpopProofCommand = verifyDpop,
            dpopProofJtiCache = lazyOf(jtiCache),
            dpopNonceManager = nonceManager,
            clientRegistry = InMemoryClientRegistryImpl(InMemoryOAuth2BackingStorageImpl()),
            jwtService = RecordingJwtService(),
            signingKeyStore = InMemorySigningKeyStore(),
            subjectTokenIssuerTrust = trust(recorder),
            tokenExchangeProfile = profile,
            createAccessToken = mint(recorder),
            createTokenResponse = respond(recorder),
        )

    private fun tokenEndpoint(
        recorder: Recorder,
        journey: TokenExchangeJourneyCommandImpl,
        grantParameters: GrantParameters,
        dpopProof: String? = null,
        verifyDpop: Lazy<VerifyDpopProofCommand> = dpop(null),
    ): HandleTokenRequestCommandImpl =
        HandleTokenRequestCommandImpl(
            execution = ctx.execution,
            parseTokenRequestCommand = parse(recorder, grantParameters, dpopProof),
            verifyClientAuthenticationCommand = lazyOf(authenticate(recorder)),
            serversConfigProvider = configProvider,
            verifyDpopProofCommand = verifyDpop,
            dpopProofJtiCache = lazyOf(InMemoryDpopProofJtiCacheImpl(InMemorySingleUseObjectStore())),
            dpopNonceManager = nonceManager,
            grantHandlers = mapOf(GrantHandlerKeys.TOKEN_EXCHANGE to lazyOf<GrantHandler>(TokenExchangeGrantHandlerImpl(journey))),
        )

    private val rawRequest = HandleTokenRequestArgs(requestBody = emptyMap(), requestHeaders = emptyMap(), httpUrl = tokenEndpoint)

    private fun payloadOf(accessToken: String): JsonObject =
        Json.parseToJsonElement(accessToken.split(".")[1].decodeFromBase64Url().decodeToString()).jsonObject

    @Test
    fun contractIsTheFixedSpecificationOrderOfTheExecutedSteps() {
        val recorder = Recorder()
        val command = journey(recorder, parameters(jwt(buildJsonObject { put("sub", "alice") })))
        val contract = command.journeyContract

        assertEquals(TokenExchangeJourneySteps.ORDER, contract.steps.map { it.id })
        assertEquals(contract.steps.size, contract.steps.map { it.commandId }.toSet().size, "Every step names a distinct command")
        assertEquals(
            listOf(AuthorizeTokenExchangeCommand.COMMAND_ID, MapTokenExchangeClaimsCommand.COMMAND_ID, BuildTokenExchangeActorChainCommand.COMMAND_ID),
            contract.steps.mapNotNull { it.extensionPoint },
        )
        val order = contract.steps.map { it.id }
        val authorize = order.indexOf(TokenExchangeJourneySteps.AUTHORIZE_EXCHANGE)
        assertTrue(order.indexOf(TokenExchangeJourneySteps.AUTHENTICATE_CLIENT) == 0)
        assertTrue(order.indexOf(TokenExchangeJourneySteps.RESOLVE_ISSUER_TRUST) < order.indexOf(TokenExchangeJourneySteps.VERIFY_SUBJECT))
        assertTrue(order.indexOf(TokenExchangeJourneySteps.VERIFY_ACTOR) < authorize, "Every principal is verified before authorization")
        assertTrue(authorize < order.indexOf(TokenExchangeJourneySteps.BOUND_TARGETS))
        assertTrue(order.indexOf(TokenExchangeJourneySteps.BOUND_TARGETS) < order.indexOf(TokenExchangeJourneySteps.MINT), "Targets are bounded before minting")
        assertEquals(TokenExchangeJourneySteps.RESPOND, order.last())
        assertEquals("test.tokenexchange.profile", command.journeyProfile.id)
        assertEquals(StandardTokenExchangeProfile.PROFILE_ID, StandardTokenExchangeProfile().id)
    }

    @Test
    fun tokenEndpointIssuesThroughTheExchangeGrantHandlerAndAuthenticatesOnce() =
        runTest {
            val recorder = Recorder()
            val subject =
                jwt(
                    buildJsonObject {
                        put("sub", "delegated-user")
                        put("scope", "read write")
                        put("act", buildJsonObject { put("sub", "prior-actor"); put("act", buildJsonObject { put("sub", "root-actor") }) })
                        put("may_act", buildJsonObject { put("iss", foreignIssuer); put("sub", "current-actor") })
                    },
                )
            val actor = jwt(buildJsonObject { put("sub", "current-actor"); put("client_id", "actor-client") })
            val grant = parameters(subject, actor, audiences = listOf(audience), resources = listOf(resource))
            val profile =
                profile(
                    recorder,
                    claims =
                        buildJsonObject {
                            put("tenant_id", "tenant-a")
                            put("sub", "attacker-subject")
                            put("aud", "https://attacker.example.test")
                            put("cnf", buildJsonObject { put("jkt", "attacker-key") })
                            put("act", buildJsonObject { put("sub", "attacker-actor") })
                        },
                    actorExtensions =
                        buildJsonObject {
                            put("actor_context", "organization-a")
                            put("sub", "attacker-subject")
                            put("iss", "https://attacker.example.test")
                            put("client_id", "attacker-client")
                            put("act", buildJsonObject { put("sub", "attacker-history") })
                        },
                )
            val journey = journey(recorder, grant, profile)

            val result = tokenEndpoint(recorder, journey, grant).execute(rawRequest)

            assertTrue(result.isOk, "Exchange must issue: ${if (result.isErr) result.error.message.defaultMessage else ""}")
            assertEquals(1, recorder.authenticationCalls, "The client is authenticated once, inside the journey")
            val input = recorder.authorizeInputs.single()
            assertEquals("delegated-user", input.subject.subject)
            assertEquals("current-actor", assertNotNull(input.actor).subject)
            assertEquals(setOf(audience, resource), input.registeredTargets)

            val payload = payloadOf(assertNotNull(recorder.response).accessToken)
            assertEquals("delegated-user", payload["sub"]!!.jsonPrimitive.content)
            val grantedAudience = payload["aud"]!!
            assertEquals(setOf(audience, resource), if (grantedAudience is JsonArray) grantedAudience.map { it.jsonPrimitive.content }.toSet() else setOf(grantedAudience.jsonPrimitive.content))
            assertEquals("tenant-a", payload["tenant_id"]!!.jsonPrimitive.content)
            assertNull(payload["cnf"], "A profile cannot add a sender constraint")
            assertEquals("read write", payload["scope"]?.jsonPrimitive?.content)

            val act = payload["act"]!!.jsonObject
            assertEquals("current-actor", act["sub"]!!.jsonPrimitive.content)
            assertEquals(foreignIssuer, act["iss"]!!.jsonPrimitive.content)
            assertEquals("actor-client", act["client_id"]!!.jsonPrimitive.content)
            assertEquals("organization-a", act["actor_context"]!!.jsonPrimitive.content)
            assertEquals("prior-actor", act["act"]!!.jsonObject["sub"]!!.jsonPrimitive.content)
            assertEquals("root-actor", act["act"]!!.jsonObject["act"]!!.jsonObject["sub"]!!.jsonPrimitive.content)
            assertEquals(TokenTypeIdentifier.ACCESS_TOKEN, recorder.response?.issuedTokenType)
            assertEquals("Bearer", recorder.response?.tokenType)
        }

    @Test
    fun failedClientAuthenticationStopsBeforeEveryExchangeStep() =
        runTest {
            val recorder = Recorder()
            val grant = parameters(jwt(buildJsonObject { put("sub", "alice") }))
            val journey =
                journey(
                    recorder,
                    grant,
                    authentication = authenticate(recorder, Err(IdkError.fromDTO(AuthorizationServerError.InvalidClient(details = "bad secret")))),
                )

            val result = journey.execute(rawRequest)

            assertEquals("invalid_client", result.error.code)
            assertEquals(1, recorder.authenticationCalls)
            assertEquals(0, recorder.trustCalls)
            assertTrue(recorder.authorizeInputs.isEmpty())
            assertNull(recorder.mintedArgs)
        }

    @Test
    fun unverifiedEvidenceNeverReachesAuthorizationOrMint() =
        runTest {
            val cases =
                listOf(
                    jwt(buildJsonObject { put("iss", "https://unanchored.example.test"); put("sub", "alice") }),
                    jwt(buildJsonObject { put("sub", "alice") }, kid = "unknown-key"),
                    jwt(buildJsonObject { put("sub", "alice"); put("exp", Clock.System.now().epochSeconds - 10) }),
                    jwt(buildJsonObject { put("sub", "alice"); put("act", "not-an-object") }),
                    "not-a-jwt",
                )
            for (subject in cases) {
                val recorder = Recorder()
                val result = journey(recorder, parameters(subject)).execute(rawRequest)

                assertEquals("invalid_request", result.error.code, subject)
                assertTrue(recorder.authorizeInputs.isEmpty(), "Unverified subject must not reach authorization: $subject")
                assertNull(recorder.mintedArgs)
            }

            val recorder = Recorder()
            val actor = jwt(buildJsonObject { put("iss", "https://unanchored.example.test"); put("sub", "actor") })
            val result = journey(recorder, parameters(jwt(buildJsonObject { put("sub", "alice") }), actor)).execute(rawRequest)
            assertEquals("invalid_request", result.error.code)
            assertTrue(recorder.authorizeInputs.isEmpty(), "Unverified actor must not reach authorization")
        }

    @Test
    fun profileRefusalsAndTargetBypassesFailBeforeMint() =
        runTest {
            val subject = jwt(buildJsonObject { put("sub", "alice") })
            val refusals =
                listOf(
                    "invalid_request" to authorizeWith { Ok(TokenExchangeAuthorization(allowed = false, isDelegation = false, grantedScope = null, grantedTargets = emptyList(), denyReason = "denied")) },
                    "invalid_target" to authorizeWith { Ok(TokenExchangeAuthorization(allowed = true, isDelegation = false, grantedScope = null, grantedTargets = listOf("https://unregistered.example.test"))) },
                    "invalid_target" to authorizeWith { Ok(TokenExchangeAuthorization(allowed = true, isDelegation = false, grantedScope = null, grantedTargets = emptyList())) },
                    "invalid_request" to authorizeWith { Err(AuthorizationServerError.AccessDenied(reason = "denied")) },
                    "server_error" to authorizeWith { Err(AuthorizationServerError.StorageError(operation = "read", details = "database detail")) },
                )
            for ((expected, authorize) in refusals) {
                val recorder = Recorder()
                val result = journey(recorder, parameters(subject), profile(recorder, decide = authorize)).execute(rawRequest)

                assertEquals(expected, result.error.code)
                assertFalse(result.error.message.defaultMessage.contains("database detail"))
                assertNull(recorder.mintedArgs, "No token may be minted after a $expected refusal")
            }
        }

    @Test
    fun profileCannotReplaceTheVerifiedSubjectOrItsActorHistory() =
        runTest {
            val recorder = Recorder()
            val subject = jwt(buildJsonObject { put("sub", "alice"); put("act", buildJsonObject { put("sub", "earlier-actor") }) })
            val delegating = authorizeWith { Ok(TokenExchangeAuthorization(allowed = true, isDelegation = true, grantedScope = null, grantedTargets = listOf(audience))) }

            val result =
                journey(
                    recorder,
                    parameters(subject),
                    profile(recorder, decide = delegating, actorExtensions = buildJsonObject { put("act", buildJsonObject { put("sub", "forged") }) }),
                ).execute(rawRequest)

            assertTrue(result.isOk)
            val minted = assertNotNull(recorder.mintedArgs)
            assertEquals("alice", minted.subject)
            val act = minted.additionalClaims["act"] as ActorClaim
            assertEquals("alice", act.sub)
            assertEquals(client.clientId, (act.additionalClaims["client_id"] as JsonPrimitive).content)
            assertEquals("earlier-actor", act.act?.sub)
        }

    @Test
    fun boundSubjectRequiresTheMatchingDpopProofBeforeMint() =
        runTest {
            val subject = jwt(buildJsonObject { put("sub", "alice"); put("cnf", buildJsonObject { put("jkt", "subject-jkt") }) })

            val mismatch = Recorder()
            val rejected =
                journey(mismatch, parameters(subject), dpopProof = "proof", verifyDpop = dpop("attacker-jkt")).execute(rawRequest)
            assertEquals("invalid_dpop_proof", rejected.error.code)
            assertNull(mismatch.mintedArgs)

            val missing = Recorder()
            val unproven = journey(missing, parameters(subject)).execute(rawRequest)
            assertEquals("invalid_dpop_proof", unproven.error.code)
            assertNull(missing.mintedArgs)

            val matching = Recorder()
            val accepted = journey(matching, parameters(subject), dpopProof = "proof", verifyDpop = dpop("subject-jkt")).execute(rawRequest)
            assertTrue(accepted.isOk)
            assertEquals("subject-jkt", matching.mintedArgs?.dpopJkt)
            assertEquals("DPoP", matching.response?.tokenType)
        }

    @Test
    fun dpopProofReplayStateIsConsumedExactlyOncePerRequest() =
        runTest {
            val jtiCache = InMemoryDpopProofJtiCacheImpl(InMemorySingleUseObjectStore())
            val grant = parameters(jwt(buildJsonObject { put("sub", "alice") }))
            val verify = dpop("proof-jkt", jti = "fixed-jti")

            val first = journey(Recorder(), grant, dpopProof = "proof", verifyDpop = verify, jtiCache = jtiCache).execute(rawRequest)
            val replay = journey(Recorder(), grant, dpopProof = "proof", verifyDpop = verify, jtiCache = jtiCache).execute(rawRequest)

            assertTrue(first.isOk, "A single request consumes its proof once and succeeds")
            assertEquals("invalid_dpop_proof", replay.error.code)
        }

    @Test
    fun preAuthenticatedGrantContextIsNotAcceptedForExchange() =
        runTest {
            val recorder = Recorder()
            val grant = parameters(jwt(buildJsonObject { put("sub", "alice") }))
            val handler = TokenExchangeGrantHandlerImpl(journey(recorder, grant))
            val context =
                GrantContext(
                    tokenRequest =
                        TokenRequestData(
                            grantType = GrantType.TOKEN_EXCHANGE,
                            clientId = client.clientId,
                            clientAuthentication = ClientAuthenticationConfig.Basic(ClientCredentials(client.clientId, "secret")),
                            grantParameters = grant,
                            httpUrl = tokenEndpoint,
                        ),
                    tenantId = ctx.execution.tenantId,
                    resolvedClientId = client.clientId,
                    proofJkt = null,
                    certThumbprintS256 = null,
                    applied = rawRequest,
                    serverConfig = OAuth2ServerInstanceConfig(issuer = issuer),
                    clientAuthorization = client,
                )

            val result = handler.handle(grant, context)

            assertEquals("server_error", result.error.code)
            assertEquals(0, recorder.authenticationCalls)
            assertTrue(recorder.authorizeInputs.isEmpty())
        }

    @Test
    fun anchoredEvidenceIsAnImmutableCopyOfTheVerifiedPayload() =
        runTest {
            val recorder = Recorder()
            val actor = jwt(buildJsonObject { put("sub", "actor"); put("roles", JsonArray(listOf(JsonPrimitive("operator")))) })
            val result = journey(recorder, parameters(jwt(buildJsonObject { put("sub", "alice") }), actor)).execute(rawRequest)

            assertTrue(result.isOk)
            val input = recorder.authorizeInputs.single()
            val subject: AnchoredSubjectToken = input.subject
            val anchoredActor: AnchoredActorToken = assertNotNull(input.actor)
            assertEquals(foreignIssuer, subject.issuer.issuer)
            assertEquals(TokenIssuerAnchor.ISSUER_TRUST, subject.issuer.anchor)
            assertEquals("alice", subject.claims["sub"]!!.jsonPrimitive.content)
            val roles: JsonElement = anchoredActor.claims["roles"]!!
            assertEquals(listOf("operator"), (roles as JsonArray).map { it.jsonPrimitive.content })
        }

    @Test
    fun profileResolvedResourceIsBoundToGrantedAudiencesAndNeverIssuedItself() =
        runTest {
            val targetResource = "urn:example:target:alpha"
            val mapping = TokenExchangeResourceMapping(targetResource, listOf(audience))
            val mapped =
                authorizeWith { input ->
                    Ok(TokenExchangeAuthorization(allowed = true, isDelegation = false, grantedScope = null, grantedTargets = input.requestedAudiences, resourceMappings = listOf(mapping)))
                }
            val grant = parameters(jwt(buildJsonObject { put("sub", "alice") }), audiences = listOf(audience), resources = listOf(targetResource))

            val recorder = Recorder()
            val issued = journey(recorder, grant, profile(recorder, decide = mapped)).execute(rawRequest)
            assertTrue(issued.isOk, if (issued.isErr) issued.error.message.defaultMessage else "")
            assertEquals(listOf(audience), recorder.mintedArgs?.audience, "a resolved resource is not an issued audience")

            val refusals =
                listOf(
                    "an unmapped unregistered resource" to authorizeWith { input -> Ok(TokenExchangeAuthorization(true, false, null, input.requestedAudiences)) },
                    "a mapping onto an ungranted audience" to
                        authorizeWith { _ ->
                            Ok(TokenExchangeAuthorization(true, false, null, listOf(audience), resourceMappings = listOf(TokenExchangeResourceMapping(targetResource, listOf(resource)))))
                        },
                    "a mapping of a resource that was not requested" to
                        authorizeWith { _ ->
                            Ok(TokenExchangeAuthorization(true, false, null, listOf(audience), resourceMappings = listOf(mapping, TokenExchangeResourceMapping("urn:example:target:other", listOf(audience)))))
                        },
                    "an empty mapping" to
                        authorizeWith { _ -> Ok(TokenExchangeAuthorization(true, false, null, listOf(audience), resourceMappings = listOf(TokenExchangeResourceMapping(targetResource, emptyList())))) },
                )
            for ((case, decide) in refusals) {
                val refused = Recorder()
                val result = journey(refused, grant, profile(refused, decide = decide)).execute(rawRequest)
                assertEquals("invalid_target", result.error.code, case)
                assertNull(refused.mintedArgs, case)
            }
        }

    @Test
    fun registrationAuthorityReachesTheProfileUninterpretedAndIsNeverMinted() =
        runTest {
            val recorder = Recorder()
            val authority = mapOf("mode" to "operator-delegation", "provisioning" to "true")
            val registered = client.copy(tokenExchangeAuthority = authority)
            val grant = parameters(jwt(buildJsonObject { put("sub", "alice") }))
            val authentication =
                authenticate(
                    recorder,
                    Ok(VerifiedClientAuthentication(clientId = client.clientId, method = ClientAuthenticationMethod.CLIENT_SECRET_BASIC, clientAuthorization = registered)),
                )

            val result = journey(recorder, grant, authentication = authentication).execute(rawRequest)

            assertTrue(result.isOk)
            assertEquals(authority, recorder.authorizeInputs.single().clientExchangeAuthority)
            val payload = payloadOf(assertNotNull(recorder.response).accessToken)
            for (attribute in authority.keys + "token-exchange") {
                assertFalse(attribute in payload, "registration authority attribute $attribute must not be minted")
            }
        }

    private fun authorizeWith(decide: suspend (AuthorizeTokenExchangeInput) -> IdkResult<TokenExchangeAuthorization, AuthorizationServerError>): AuthorizeTokenExchangeCommand =
        object : AuthorizeTokenExchangeCommand {
            override suspend fun execute(args: AuthorizeTokenExchangeInput) = decide(args)
        }
}
