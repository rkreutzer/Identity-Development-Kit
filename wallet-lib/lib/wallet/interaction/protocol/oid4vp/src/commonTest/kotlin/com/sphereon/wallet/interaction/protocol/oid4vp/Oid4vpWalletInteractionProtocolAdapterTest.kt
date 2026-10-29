/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.protocol.oid4vp

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.credential.claims.mapper.impl.mapper.ClaimsMappingServiceImpl
import com.sphereon.credential.claims.mapper.impl.resolver.MdocClaimResolver
import com.sphereon.credential.claims.mapper.impl.resolver.SdJwtClaimResolver
import com.sphereon.credential.claims.mapper.api.resolver.CredentialClaimResolver
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.data.store.party.model.IdentifierType
import com.sphereon.oauth2.common.model.AuthorizationErrorResponse
import com.sphereon.wallet.interaction.WalletTrustPolicyDecision
import com.sphereon.oauth2.common.model.AuthorizationRequest
import com.sphereon.oauth2.common.model.AuthorizationResponse
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.common.ClientMetadata
import com.sphereon.openid.oid4vp.common.ResponseMode
import com.sphereon.openid.oid4vp.common.VpFormatInfo
import com.sphereon.openid.oid4vp.dcql.DcqlClaimQuery
import com.sphereon.openid.oid4vp.dcql.ClaimsPathPointer
import com.sphereon.openid.oid4vp.dcql.claimsPathPointer
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialSetQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.mdocMeta
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.dcql.w3cVcMeta
import com.sphereon.openid.oid4vp.holder.JarmOptions
import com.sphereon.openid.oid4vp.holder.DigitalCredentialsAuthorizationRequest
import com.sphereon.openid.oid4vp.holder.Oid4vpHolderService
import com.sphereon.openid.oid4vp.holder.PreparedOid4vpJweRecipientBinding
import com.sphereon.openid.oid4vp.holder.PreparedPresentation
import com.sphereon.openid.oid4vp.holder.ResolvedOid4vpRequest
import com.sphereon.openid.oid4vp.holder.credentialDisclosurePathOptions
import com.sphereon.openid.oid4vp.holder.SelectedCredential
import com.sphereon.openid.oid4vp.holder.SubmissionResult
import com.sphereon.mdoc.data.device.IssuerSignedCborCodecImpl
import com.sphereon.openid.oid4vp.holder.VerifierInfo
import com.sphereon.openid.oid4vp.holder.WalletConfig
import com.sphereon.wallet.credential.BodyStorageKind
import com.sphereon.wallet.credential.BodyStorageRef
import com.sphereon.wallet.credential.CredentialFormat
import com.sphereon.wallet.credential.CredentialInstance
import com.sphereon.wallet.credential.CredentialLifecycleState
import com.sphereon.wallet.credential.CredentialMetadata
import com.sphereon.wallet.credential.CredentialMetadataFilter
import com.sphereon.wallet.credential.CredentialRecord
import com.sphereon.wallet.credential.CredentialTypeRef
import com.sphereon.wallet.credential.CredentialTypeRefKind
import com.sphereon.wallet.credential.CredentialTypeRefSource
import com.sphereon.wallet.credential.CredentialValidityWindow
import com.sphereon.wallet.credential.IdentifierRef
import com.sphereon.wallet.credential.KeyRef
import com.sphereon.wallet.credential.WalletCredentialStore
import com.sphereon.wallet.credential.WalletHolderIdentifierKind
import com.sphereon.wallet.credential.WalletHolderVerificationMethod
import com.sphereon.wallet.WalletHolderIdentityResolver
import com.sphereon.wallet.WalletHolderVerificationMethodResolver
import com.sphereon.wallet.interaction.WalletClaimDescriptor
import com.sphereon.wallet.interaction.WalletFailureDisposition
import com.sphereon.wallet.interaction.WalletCounterpartyAssociationCandidate
import com.sphereon.wallet.interaction.WalletCounterpartyAssociationDecision
import com.sphereon.wallet.interaction.WalletCounterpartyAssociationRequest
import com.sphereon.wallet.interaction.WalletCounterpartyRole
import com.sphereon.wallet.interaction.WalletCounterpartyEncounterRegistry
import com.sphereon.wallet.interaction.WalletCounterpartyEncounterRequest
import com.sphereon.wallet.interaction.WalletCounterpartyEncounterResult
import com.sphereon.wallet.interaction.WalletCounterpartyTrustRequest
import com.sphereon.wallet.interaction.WalletCounterpartyTrustResolver
import com.sphereon.wallet.interaction.WalletCounterpartyTrustSummary
import com.sphereon.wallet.interaction.WalletCredentialRequirement
import com.sphereon.wallet.interaction.WalletCredentialSelection
import com.sphereon.wallet.interaction.WalletCredentialSelectionRequest
import com.sphereon.wallet.interaction.WalletCredentialSetRequirement
import com.sphereon.wallet.interaction.WalletCredentialSetOption
import com.sphereon.wallet.interaction.WalletDisclosureSummary
import com.sphereon.wallet.interaction.WalletEntryPoint
import com.sphereon.wallet.interaction.WalletInteractionAction
import com.sphereon.wallet.interaction.WalletInteractionCompletionTransport
import com.sphereon.wallet.interaction.WalletInteractionActivityType
import com.sphereon.wallet.interaction.WalletInteractionContext
import com.sphereon.wallet.interaction.ProtocolExecutionOwner
import com.sphereon.wallet.interaction.WalletInteractionFlowKind
import com.sphereon.wallet.interaction.WalletInteractionPrivateSessionData
import com.sphereon.wallet.interaction.WalletInteractionPrivateSessionStore
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.interaction.WalletInteractionSensitiveInputPurpose
import com.sphereon.wallet.interaction.WalletNestedPresentationExecutionResult
import com.sphereon.wallet.interaction.WalletNestedPresentationRequest
import com.sphereon.wallet.interaction.WalletProtocol
import com.sphereon.wallet.interaction.WalletProtocolExecutionDecision
import com.sphereon.wallet.interaction.WalletProtocolExecutionPlacement
import com.sphereon.wallet.interaction.WalletProtocolExecutionRequest
import com.sphereon.wallet.interaction.WalletProtocolExecutor
import com.sphereon.wallet.interaction.WalletProtocolMatchStrength
import com.sphereon.wallet.interaction.WalletSecurityAssurance
import com.sphereon.wallet.interaction.WalletAttendedAuthorizationRegistry
import com.sphereon.wallet.interaction.WalletSecurityChallenge
import com.sphereon.wallet.interaction.WalletSecurityChallengeKind
import com.sphereon.wallet.interaction.WalletSecurityGate
import com.sphereon.wallet.interaction.WalletSecurityGateRequest
import com.sphereon.wallet.interaction.WalletSecurityGateResult
import com.sphereon.wallet.interaction.WalletSecurityGrant
import com.sphereon.wallet.interaction.WalletSecurityOperation
import com.sphereon.wallet.interaction.WalletAttributeSourceKind
import com.sphereon.wallet.interaction.emittedAttributeSources
import com.sphereon.wallet.interaction.WalletTrustPolicyAction
import com.sphereon.wallet.interaction.WalletTrustPolicy
import com.sphereon.wallet.interaction.WalletTrustStatus
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Clock

class Oid4vpWalletInteractionProtocolAdapterTest {
    @Test
    fun trustedProtocolErrorPreservesFailedStateAndOneUsePrivateVerifierContinuation() = runTest {
        val completionUri = "https://verifier.example/complete#one-use-test-value"
        val holder = RecordingOid4vpHolderService(
            resolvedRequest = resolvedRequest().copy(authorizationError = AuthorizationErrorResponse("invalid_request", state = "state")),
            submissionResult = SubmissionResult.Success(redirectUri = completionUri),
        )
        val context = WalletInteractionContext(
            sessionId = WalletInteractionSessionId("error-continuation"), walletUnitId = "wallet",
            executionOwner = ProtocolExecutionOwner.WALLET_APP,
            trustResolver = object : WalletCounterpartyTrustResolver {
                override suspend fun resolve(input: WalletCounterpartyTrustRequest) = WalletCounterpartyTrustSummary(input.counterparty, WalletTrustStatus.TRUSTED)
            },
            trustPolicy = WalletTrustPolicy.warn,
        )
        val adapter = Oid4vpWalletInteractionProtocolAdapter(holder = holder, presentationExecutor = Oid4vpPresentationExecutor.notConfigured)
        val state = adapter.start(context, WalletEntryPoint.rawQr("openid4vp://?client_id=verifier")).state
        assertEquals(WalletInteractionStatus.Failed, state.status)
        assertTrue(state.terminal)
        assertEquals(WalletInteractionCompletionTransport.BROWSER_REDIRECT, state.completionHandoffTransport)
        assertFalse(Json.encodeToString(state).contains("one-use-test-value"))
        val ref = requireNotNull(state.completionHandoffRef)
        assertNull(context.sensitiveInputAuthority.consume(WalletInteractionSessionId("other-session"), WalletInteractionSensitiveInputPurpose.PROTOCOL_COMPLETION_HANDOFF, ref))
        assertEquals(completionUri, context.sensitiveInputAuthority.consume(state.sessionId, WalletInteractionSensitiveInputPurpose.PROTOCOL_COMPLETION_HANDOFF, ref))
        assertNull(context.sensitiveInputAuthority.consume(state.sessionId, WalletInteractionSensitiveInputPurpose.PROTOCOL_COMPLETION_HANDOFF, ref))
        assertEquals(1, holder.errorSubmitCalls)
    }

    @Test
    fun invalidRequestErrorRequiresValidatedClientAndTrustedAllowedCounterpartyWithoutCredentialAccess() = runTest {
        data class Case(val validClient: Boolean, val trust: WalletTrustStatus, val action: WalletTrustPolicyAction, val expectedSubmissions: Int)
        val cases = listOf(
            Case(true, WalletTrustStatus.TRUSTED, WalletTrustPolicyAction.ALLOW, 1),
            Case(false, WalletTrustStatus.TRUSTED, WalletTrustPolicyAction.ALLOW, 0),
            Case(true, WalletTrustStatus.UNKNOWN, WalletTrustPolicyAction.ALLOW, 0),
            Case(true, WalletTrustStatus.BLOCKED, WalletTrustPolicyAction.ALLOW, 0),
            Case(true, WalletTrustStatus.TRUSTED, WalletTrustPolicyAction.BLOCK, 0),
            Case(true, WalletTrustStatus.TRUSTED, WalletTrustPolicyAction.ASK_USER, 0),
        )
        for (case in cases) {
            val error = AuthorizationErrorResponse(error = "invalid_request", state = "state")
            val request = resolvedRequest().let { it.copy(authorizationError = error, verifierInfo = it.verifierInfo.copy(clientIdValid = case.validClient)) }
            val holder = RecordingOid4vpHolderService(resolvedRequest = request)
            val gate = RecordingSecurityGate()
            val adapter = Oid4vpWalletInteractionProtocolAdapter(
                presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                holder = holder,
                candidateResolver = object : Oid4vpCredentialCandidateResolver {
                    override suspend fun candidateCredentialIds(context: WalletInteractionContext, resolvedRequest: ResolvedOid4vpRequest): Map<String, List<String>> =
                        kotlin.error("Invalid requests must not discover wallet credentials")
                },
            )
            val session = adapter.start(
                WalletInteractionContext(
                    sessionId = WalletInteractionSessionId("invalid-request"), walletUnitId = "wallet",
                    executionOwner = ProtocolExecutionOwner.WALLET_APP, securityGate = gate,
                    trustResolver = object : WalletCounterpartyTrustResolver {
                        override suspend fun resolve(input: WalletCounterpartyTrustRequest) = WalletCounterpartyTrustSummary(input.counterparty, case.trust)
                    },
                    trustPolicy = object : WalletTrustPolicy {
                        override suspend fun evaluate(summary: WalletCounterpartyTrustSummary) = WalletTrustPolicyDecision(case.action)
                    },
                ),
                WalletEntryPoint.rawQr("openid4vp://?client_id=verifier"),
            )
            assertEquals(WalletInteractionStatus.Failed, session.state.status)
            assertTrue(session.state.terminal)
            assertEquals(case.expectedSubmissions, holder.errorSubmitCalls)
            assertEquals(0, holder.submitCalls)
            assertTrue(holder.createdSelectedCredentials.isEmpty())
            assertEquals(0, gate.calls)
            if (case.expectedSubmissions == 1) assertEquals(error, holder.submittedError)
        }
    }

    @Test
    fun legacyHolderSubmitOverrideRefusesPreparedRecipientBinding() = runTest {
        val holder = RecordingOid4vpHolderService()
        val request = ResolvedOid4vpRequest(
            request = AuthorizationRequest(clientId = "verifier", responseType = "vp_token", nonce = "nonce"),
            verifierInfo = VerifierInfo("verifier", ClientIdScheme.PRE_REGISTERED),
        )
        val binding = PreparedOid4vpJweRecipientBinding(
            publicJwkJson = "{}",
            rfc7638Thumbprint = "thumbprint",
            keyEncryptionAlgorithm = "ECDH-ES",
            contentEncryptionAlgorithm = "A256GCM",
            responseMode = ResponseMode.DIRECT_POST_JWT.value,
            clientId = "verifier",
            authorizationRequestNonce = "nonce",
        )

        val result = holder.submitAuthorizationResponse(
            request,
            AuthorizationResponse(code = ""),
            ResponseMode.DIRECT_POST_JWT,
            JarmOptions(issuer = "wallet"),
            binding,
        )

        assertTrue(result.isErr)
        assertEquals(0, holder.submitCalls)
    }

    private val preparedOnlyHolderBindingProvider =
        Oid4vpSdJwtHolderBindingProvider { request -> Ok(request.selectedCredentials) }

    @Test
    fun oid4vpAuthorizationRequestsAreStrongMatches() =
        runTest {
            val adapter = Oid4vpWalletInteractionProtocolAdapter(Oid4vpPresentationExecutor.notConfigured)

            val match = adapter.canHandle(WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"))

            assertEquals(WalletProtocolMatchStrength.STRONG, match.strength)
        }

    @Test
    fun `a self-asserted verifier display name is not promoted`() =
        runTest {
            val holder =
                RecordingOid4vpHolderService(
                    resolvedRequest =
                        resolvedRequest().copy(
                            verifierInfo =
                                VerifierInfo(
                                    clientId = "https://rp.example",
                                    clientIdScheme = ClientIdScheme.OPENID_FEDERATION,
                                    displayName = "Acme Relying Party",
                                    trustRoot = "https://ta.example",
                                ),
                        ),
                )
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = holder,
                )
            val state =
                adapter
                    .start(
                        WalletInteractionContext(
                            sessionId = WalletInteractionSessionId("self-asserted-not-promoted"),
                            walletUnitId = "wallet",
                            executionOwner = ProtocolExecutionOwner.WALLET_APP,
                            trustPolicy = WalletTrustPolicy.allow,
                        ),
                        WalletEntryPoint.rawQr("openid4vp://?client_id=https://rp.example"),
                    ).state
            val counterparty = requireNotNull(state.counterparty)
            assertEquals("Acme Relying Party", counterparty.displayName)
            assertEquals(WalletAttributeSourceKind.SELF_ASSERTED, counterparty.displayNameSource?.kind)
            assertNull(counterparty.displayNameSource?.authority, "display metadata is the party's own claim")
            assertNull(counterparty.detail, "VerifierInfo has no DCR contacts, federation legal name, or certificate subject")
            assertEquals("OPENID_FEDERATION", counterparty.metadata["client_id_scheme"])
        }

    @Test
    fun `x509 client_id_scheme does not mint an access-certificate legal name`() =
        runTest {
            val holder =
                RecordingOid4vpHolderService(
                    resolvedRequest =
                        resolvedRequest().copy(
                            verifierInfo =
                                VerifierInfo(
                                    clientId = "rp.example.org",
                                    clientIdScheme = ClientIdScheme.X509_SAN_DNS,
                                    displayName = "Acme Relying Party",
                                ),
                        ),
                )
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = holder,
                )
            val state =
                adapter
                    .start(
                        WalletInteractionContext(
                            sessionId = WalletInteractionSessionId("x509-not-promoted"),
                            walletUnitId = "wallet",
                            executionOwner = ProtocolExecutionOwner.WALLET_APP,
                            trustPolicy = WalletTrustPolicy.allow,
                        ),
                        WalletEntryPoint.rawQr("openid4vp://?client_id=rp.example.org"),
                    ).state
            val counterparty = requireNotNull(state.counterparty)
            assertEquals(WalletAttributeSourceKind.SELF_ASSERTED, counterparty.displayNameSource?.kind)
            assertNull(counterparty.detail)
            assertNull(counterparty.detail?.legalName)
            assertEquals("X509_SAN_DNS", counterparty.metadata["client_id_scheme"])
        }

    @Test
    fun `trust resolution receives the bare client identifier and the request object chain for x509 prefixes`() =
        runTest {
            val requests = mutableListOf<WalletCounterpartyTrustRequest>()
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder =
                        RecordingOid4vpHolderService(
                            resolvedRequest =
                                resolvedRequest().copy(
                                    verifierInfo =
                                        VerifierInfo(
                                            clientId = "x509_san_dns:rp.example.org",
                                            clientIdScheme = ClientIdScheme.X509_SAN_DNS,
                                            requestObjectCertificateChain = listOf("bGVhZg=="),
                                        ),
                                ),
                        ),
                )
            adapter.start(
                WalletInteractionContext(
                    sessionId = WalletInteractionSessionId("x509-client-authentication"),
                    walletUnitId = "wallet",
                    executionOwner = ProtocolExecutionOwner.WALLET_APP,
                    trustResolver =
                        object : WalletCounterpartyTrustResolver {
                            override suspend fun resolve(input: WalletCounterpartyTrustRequest): WalletCounterpartyTrustSummary {
                                requests += input
                                return WalletCounterpartyTrustSummary(input.counterparty, WalletTrustStatus.UNKNOWN)
                            }
                        },
                    trustPolicy = WalletTrustPolicy.allow,
                ),
                WalletEntryPoint.rawQr("openid4vp://?client_id=x509_san_dns:rp.example.org"),
            )

            val authentication = requireNotNull(requests.single().clientAuthentication)
            assertEquals("x509_san_dns", authentication.scheme)
            assertEquals("rp.example.org", authentication.identifier)
            assertEquals(listOf("bGVhZg=="), authentication.certificateChain)
        }

    @Test
    fun `pre-registered client identifier is passed without a prefix`() =
        runTest {
            val requests = mutableListOf<WalletCounterpartyTrustRequest>()
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder =
                        RecordingOid4vpHolderService(
                            resolvedRequest =
                                resolvedRequest().copy(
                                    verifierInfo = VerifierInfo(clientId = "verifier-1", clientIdScheme = ClientIdScheme.PRE_REGISTERED),
                                ),
                        ),
                )
            adapter.start(
                WalletInteractionContext(
                    sessionId = WalletInteractionSessionId("pre-registered-client-authentication"),
                    walletUnitId = "wallet",
                    executionOwner = ProtocolExecutionOwner.WALLET_APP,
                    trustResolver =
                        object : WalletCounterpartyTrustResolver {
                            override suspend fun resolve(input: WalletCounterpartyTrustRequest): WalletCounterpartyTrustSummary {
                                requests += input
                                return WalletCounterpartyTrustSummary(input.counterparty, WalletTrustStatus.UNKNOWN)
                            }
                        },
                    trustPolicy = WalletTrustPolicy.allow,
                ),
                WalletEntryPoint.rawQr("openid4vp://?client_id=verifier-1"),
            )

            val authentication = requireNotNull(requests.single().clientAuthentication)
            assertNull(authentication.scheme)
            assertEquals("verifier-1", authentication.identifier)
        }

    @Test
    fun `a DCR contact is self-asserted, not promoted by arriving on a richer protocol`() =
        runTest {
            val holder =
                RecordingOid4vpHolderService(
                    resolvedRequest =
                        resolvedRequest().copy(
                            request =
                                AuthorizationRequest(
                                    clientId = "https://rp.example",
                                    responseType = "vp_token",
                                    state = "state",
                                    additionalParameters =
                                        mapOf(
                                            "client_metadata" to
                                                buildJsonObject {
                                                    put("client_name", JsonPrimitive("Acme Relying Party"))
                                                    put("client_uri", JsonPrimitive("https://rp.example"))
                                                    put("policy_uri", JsonPrimitive("https://rp.example/privacy"))
                                                    put("contacts", JsonArray(listOf(JsonPrimitive("rp@example.com"))))
                                                },
                                        ),
                                ),
                            verifierInfo =
                                VerifierInfo(
                                    clientId = "https://rp.example",
                                    clientIdScheme = ClientIdScheme.OPENID_FEDERATION,
                                    displayName = "Acme Relying Party",
                                    trustRoot = "https://ta.example",
                                ),
                        ),
                )
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = holder,
                )
            val state =
                adapter
                    .start(
                        WalletInteractionContext(
                            sessionId = WalletInteractionSessionId("dcr-not-promoted"),
                            walletUnitId = "wallet",
                            executionOwner = ProtocolExecutionOwner.WALLET_APP,
                            trustPolicy = WalletTrustPolicy.allow,
                        ),
                        WalletEntryPoint.rawQr("openid4vp://?client_id=https://rp.example"),
                    ).state
            val counterparty = requireNotNull(state.counterparty)
            val detail = requireNotNull(counterparty.detail)
            assertEquals("rp@example.com", detail.contactEmail?.value)
            assertEquals(WalletAttributeSourceKind.SELF_ASSERTED, detail.contactEmail!!.source.kind)
            assertNull(detail.contactEmail!!.source.authority)
            assertEquals("https://rp.example", detail.websiteUri?.value)
            assertEquals(WalletAttributeSourceKind.SELF_ASSERTED, detail.websiteUri?.source?.kind)
            assertEquals("https://rp.example/privacy", detail.privacyPolicyUri?.value)
            assertEquals(WalletAttributeSourceKind.SELF_ASSERTED, detail.privacyPolicyUri?.source?.kind)
            assertNull(detail.legalName, "federation scheme does not invent a superior-attested legal name")
            assertEquals(WalletAttributeSourceKind.SELF_ASSERTED, counterparty.displayNameSource?.kind)
            assertEquals("OPENID_FEDERATION", counterparty.metadata["client_id_scheme"])
        }

    @Test
    fun `every emitted attested source names an authority`() =
        runTest {
            val holder =
                RecordingOid4vpHolderService(
                    resolvedRequest =
                        resolvedRequest().copy(
                            request =
                                AuthorizationRequest(
                                    clientId = "https://rp.example",
                                    responseType = "vp_token",
                                    state = "state",
                                    additionalParameters =
                                        mapOf(
                                            "client_metadata" to
                                                buildJsonObject {
                                                    put("contacts", JsonArray(listOf(JsonPrimitive("rp@example.com"))))
                                                    put("client_uri", JsonPrimitive("https://rp.example"))
                                                },
                                        ),
                                ),
                            verifierInfo =
                                VerifierInfo(
                                    clientId = "https://rp.example",
                                    clientIdScheme = ClientIdScheme.X509_SAN_DNS,
                                    displayName = "Acme Relying Party",
                                ),
                        ),
                )
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = holder,
                )
            val state =
                adapter
                    .start(
                        WalletInteractionContext(
                            sessionId = WalletInteractionSessionId("emitted-attested-authority"),
                            walletUnitId = "wallet",
                            executionOwner = ProtocolExecutionOwner.WALLET_APP,
                            trustPolicy = WalletTrustPolicy.allow,
                        ),
                        WalletEntryPoint.rawQr("openid4vp://?client_id=rp.example.org"),
                    ).state
            val counterparty = requireNotNull(state.counterparty)
            val emitted = counterparty.emittedAttributeSources()
            assertEquals(
                setOf(WalletAttributeSourceKind.SELF_ASSERTED),
                emitted.map { it.kind }.toSet(),
                "adapters currently emit only SELF_ASSERTED; adding an attested emission is a deliberate edit of this pin, after which the offenders check below is no longer vacuous",
            )
            val offenders =
                emitted.filter {
                    it.kind != WalletAttributeSourceKind.SELF_ASSERTED && it.authority.isNullOrBlank()
                }
            assertEquals(emptyList(), offenders)
            assertEquals(WalletAttributeSourceKind.SELF_ASSERTED, counterparty.detail?.contactEmail?.source?.kind)
            assertNull(counterparty.detail?.legalName)
        }

    @Test
    fun `identifier fallback is not copied into legalName`() =
        runTest {
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = RecordingOid4vpHolderService(),
                )
            val state =
                adapter
                    .start(
                        WalletInteractionContext(
                            sessionId = WalletInteractionSessionId("identifier-fallback"),
                            walletUnitId = "wallet",
                            executionOwner = ProtocolExecutionOwner.WALLET_APP,
                            trustPolicy = WalletTrustPolicy.allow,
                        ),
                        WalletEntryPoint.rawQr("openid4vp://?client_id=verifier"),
                    ).state
            val counterparty = requireNotNull(state.counterparty)
            assertEquals("verifier", counterparty.displayName)
            assertNull(counterparty.displayNameSource)
            assertNull(counterparty.detail)
            assertNull(counterparty.detail?.legalName)
        }

    @Test
    fun unsignedDigitalCredentialRequestIsClaimedAndParsedThroughHolder() =
        runTest {
            val holder = RecordingOid4vpHolderService()
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = holder,
                )
            val entryPoint =
                WalletEntryPoint.parsed(
                    type = Oid4vpWalletInteractionProtocolAdapter.DIGITAL_CREDENTIAL_PROTOCOL_UNSIGNED,
                    value =
                        buildJsonObject {
                            put("response_type", JsonPrimitive("vp_token"))
                            put("response_mode", JsonPrimitive("dc_api"))
                            put("dcql_query", buildJsonObject { put("credentials", JsonArray(emptyList())) })
                        },
                )

            val match = adapter.canHandle(entryPoint)
            adapter.start(
                walletContext(
                    attributes =
                        mapOf(
                            Oid4vpWalletInteractionProtocolAdapter.DIGITAL_CREDENTIAL_ORIGIN_METADATA_KEY to
                                "https://verifier.example",
                        ),
                ),
                entryPoint,
            )

            assertEquals(WalletProtocolMatchStrength.STRONG, match.strength)
            assertEquals("https://verifier.example", requireNotNull(holder.lastDigitalCredentialsRequest).origin)
            assertEquals(
                Oid4vpWalletInteractionProtocolAdapter.DIGITAL_CREDENTIAL_PROTOCOL_UNSIGNED,
                requireNotNull(holder.lastDigitalCredentialsRequest).protocol,
            )
            assertEquals("dc_api", requireNotNull(holder.lastDigitalCredentialsRequest).data["response_mode"]?.jsonPrimitive?.content)
        }

    @Test
    fun resolvedVerifierEncounterPrecedesTrustAndControlsFirstInteractionReview() =
        runTest {
            val encounterRequests = mutableListOf<WalletCounterpartyEncounterRequest>()
            val callOrder = mutableListOf<String>()
            val encounterRegistry =
                object : WalletCounterpartyEncounterRegistry {
                    override suspend fun encounter(request: WalletCounterpartyEncounterRequest): WalletCounterpartyEncounterResult {
                        callOrder += "encounter"
                        val previousCount = encounterRequests.size.toLong()
                        encounterRequests += request
                        return WalletCounterpartyEncounterResult(
                            counterparty = request.counterparty.copy(partyId = "party-verifier"),
                            resolved = true,
                            organizationCreated = false,
                            firstInteraction = previousCount == 0L,
                            previousInteractionCount = previousCount,
                            lastInteractionAtEpochSeconds = if (previousCount == 0L) null else 200L,
                        )
                    }

                    override suspend fun resolveAssociation(request: WalletCounterpartyAssociationRequest): WalletCounterpartyEncounterResult =
                        error("unexpected_counterparty_association_resolution")
                }
            val trustCounterparties = mutableListOf<String?>()
            val trustResolver =
                object : WalletCounterpartyTrustResolver {
                    override suspend fun resolve(input: WalletCounterpartyTrustRequest): WalletCounterpartyTrustSummary {
                        callOrder += "trust"
                        trustCounterparties += input.counterparty.partyId
                        return WalletCounterpartyTrustSummary(input.counterparty, WalletTrustStatus.UNKNOWN)
                    }
                }
            val holder = RecordingOid4vpHolderService()
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = holder,
                )

            val first =
                adapter.start(
                    WalletInteractionContext(
                        sessionId = WalletInteractionSessionId("first"),
                        walletUnitId = "wallet",
                        executionOwner = ProtocolExecutionOwner.WALLET_APP,
                        counterpartyEncounterRegistry = encounterRegistry,
                        trustResolver = trustResolver,
                        trustPolicy = WalletTrustPolicy.allow,
                    ),
                    WalletEntryPoint.rawQr("openid4vp://?request_uri=https://verifier.example/first"),
                ).state
            val returning =
                adapter.start(
                    WalletInteractionContext(
                        sessionId = WalletInteractionSessionId("returning"),
                        walletUnitId = "wallet",
                        executionOwner = ProtocolExecutionOwner.WALLET_APP,
                        counterpartyEncounterRegistry = encounterRegistry,
                        trustResolver = trustResolver,
                        trustPolicy = WalletTrustPolicy.allow,
                    ),
                    WalletEntryPoint.rawQr("openid4vp://?request_uri=https://verifier.example/returning"),
                ).state

            assertEquals(listOf("encounter", "trust", "encounter", "trust"), callOrder)
            assertEquals(2, encounterRequests.size)
            assertTrue(encounterRequests.all { it.protocol == WalletProtocol.OID4VP })
            assertTrue(encounterRequests.all { it.counterparty.metadata["request_uri"] == "https://verifier.example/request-object" })
            assertEquals(listOf<String?>("party-verifier", "party-verifier"), trustCounterparties)
            assertEquals(WalletInteractionStatus.TrustReview, first.status)
            assertEquals("party-verifier", first.counterparty?.partyId)
            assertTrue(first.counterpartyEncounter?.firstInteraction == true)
            assertEquals(WalletInteractionStatus.CredentialSelection, returning.status)
            assertEquals(1L, returning.counterpartyEncounter?.previousInteractionCount)
            assertEquals(200L, returning.counterpartyEncounter?.lastInteractionAtEpochSeconds)
        }

    @Test
    fun verifierUrlAssociationCandidateRequiresResolutionBeforeTrustAndSelection() =
        runTest {
            var associationRequest: WalletCounterpartyAssociationRequest? = null
            val encounterRegistry =
                object : WalletCounterpartyEncounterRegistry {
                    override suspend fun encounter(request: WalletCounterpartyEncounterRequest): WalletCounterpartyEncounterResult =
                        WalletCounterpartyEncounterResult(
                            counterparty = request.counterparty.copy(partyId = "party-new-verifier"),
                            resolved = true,
                            organizationCreated = true,
                            firstInteraction = true,
                            associationCandidates =
                                listOf(
                                    WalletCounterpartyAssociationCandidate(
                                        partyId = "party-existing-organization",
                                        displayName = "Existing Organization",
                                        relatedHosts = listOf("verifier.example.com", "issuer.example.com"),
                                    ),
                                ),
                        )

                    override suspend fun resolveAssociation(request: WalletCounterpartyAssociationRequest): WalletCounterpartyEncounterResult {
                        associationRequest = request
                        return request.encounter.copy(
                            counterparty =
                                request.encounter.counterparty.copy(
                                    partyId = "party-existing-organization",
                                    displayName = "Existing Organization",
                                ),
                            associationCandidates = emptyList(),
                        )
                    }
                }
            val context =
                WalletInteractionContext(
                    sessionId = WalletInteractionSessionId("verifier-association"),
                    walletUnitId = "wallet",
                    executionOwner = ProtocolExecutionOwner.WALLET_APP,
                    counterpartyEncounterRegistry = encounterRegistry,
                    trustPolicy = WalletTrustPolicy.allow,
                )
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = RecordingOid4vpHolderService(),
                )

            val started =
                adapter.start(
                    context,
                    WalletEntryPoint.rawQr("openid4vp://?request_uri=https://verifier.example/request"),
                ).state

            assertEquals(WalletInteractionStatus.CounterpartyNotice, started.status)
            assertEquals("party-new-verifier", started.counterparty?.partyId)
            assertEquals(1, started.counterpartyEncounter?.associationCandidates?.size)
            val bypassAttempt = adapter.handle(context, started, WalletInteractionAction.continueFlow())
            assertEquals(WalletInteractionStatus.CounterpartyNotice, bypassAttempt.status)
            assertEquals("oid4vp.counterparty_resolution_required", bypassAttempt.error?.code)

            val resolved =
                adapter.handle(
                    context,
                    started,
                    WalletInteractionAction.resolveCounterpartyContact(
                        WalletCounterpartyAssociationDecision.AssociateExisting("party-existing-organization"),
                    ),
                )

            assertEquals("wallet", associationRequest?.walletUnitId)
            assertEquals(WalletInteractionStatus.TrustReview, resolved.status)
            assertEquals("party-existing-organization", resolved.counterparty?.partyId)
            assertEquals("party-existing-organization", resolved.disclosure?.verifier?.partyId)
            assertEquals("party-existing-organization", resolved.activity?.counterparty?.partyId)
            assertTrue(resolved.counterpartyEncounter?.associationCandidates?.isEmpty() == true)
            assertEquals(WalletInteractionStatus.CredentialSelection, adapter.handle(context, resolved, WalletInteractionAction.continueFlow()).status)
        }

    @Test
    fun automaticallyAssociatedDidIdentityDoesNotPromptForContactDecision() =
        runTest {
            val didWithKey = "did:example:organization#verification-key-2"
            val encounterRegistry =
                object : WalletCounterpartyEncounterRegistry {
                    override suspend fun encounter(request: WalletCounterpartyEncounterRequest): WalletCounterpartyEncounterResult =
                        WalletCounterpartyEncounterResult(
                            counterparty = request.counterparty.copy(partyId = "party-existing-did-organization"),
                            resolved = true,
                            organizationCreated = false,
                            firstInteraction = true,
                        )

                    override suspend fun resolveAssociation(request: WalletCounterpartyAssociationRequest): WalletCounterpartyEncounterResult =
                        error("did_association_must_not_require_user_resolution")
                }
            val resolvedRequest =
                ResolvedOid4vpRequest(
                    request =
                        AuthorizationRequest(
                            clientId = didWithKey,
                            responseType = "vp_token",
                            state = "state",
                        ),
                    dcqlQuery =
                        DcqlQuery(
                            credentials =
                                listOf(
                                    DcqlCredentialQuery(
                                        id = "identity",
                                        format = "dc+sd-jwt",
                                        meta = sdJwtVcMeta("urn:test:identity"),
                                    ),
                                ),
                        ),
                    verifierInfo =
                        VerifierInfo(
                            clientId = didWithKey,
                            clientIdScheme = ClientIdScheme.DECENTRALIZED_IDENTIFIER,
                        ),
                )
            val context =
                WalletInteractionContext(
                    sessionId = WalletInteractionSessionId("did-auto-associated"),
                    walletUnitId = "wallet",
                    executionOwner = ProtocolExecutionOwner.WALLET_APP,
                    counterpartyEncounterRegistry = encounterRegistry,
                    trustPolicy = WalletTrustPolicy.allow,
                )
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = RecordingOid4vpHolderService(resolvedRequest = resolvedRequest),
                )

            val started = adapter.start(context, WalletEntryPoint.rawQr("openid4vp://?client_id=$didWithKey")).state

            assertEquals(WalletInteractionStatus.TrustReview, started.status)
            assertEquals(false, started.counterpartyEncounter?.organizationCreated)
            assertTrue(started.counterpartyEncounter?.associationCandidates?.isEmpty() == true)
        }

    @Test
    fun haipVpFinalAuthorizationRequestsAreStrongMatches() =
        runTest {
            val adapter = Oid4vpWalletInteractionProtocolAdapter(Oid4vpPresentationExecutor.notConfigured)

            val match =
                adapter.canHandle(
                    WalletEntryPoint.link(
                        "haip-vp://?client_id=x509_hash%3AWqugw4oG6VggvcQp94a-TFC7jx01I14_GM27MOXRv5A&" +
                            "request_uri=https%3A%2F%2Fverifier.example.test%2Fauthorize%2Frequest-id",
                    ),
                )

            assertEquals(WalletProtocolMatchStrength.STRONG, match.strength)
        }

    @Test
    fun iso18013MdocOpenid4vpAuthorizationRequestsAreNotRegularOid4vpMatches() =
        runTest {
            val adapter = Oid4vpWalletInteractionProtocolAdapter(Oid4vpPresentationExecutor.notConfigured)

            val match =
                adapter.canHandle(
                    WalletEntryPoint.link(
                        "mdoc-openid4vp://?client_id=verifier.example&" +
                            "request_uri=https%3A%2F%2Fverifier.example%2Fauthorize%2Frequest-id",
                    ),
                )

            assertEquals(WalletProtocolMatchStrength.NONE, match.strength)
        }

    @Test
    fun regularOid4vpDoesNotClaimInlinePresentationExchangeRequests() =
        runTest {
            val adapter = Oid4vpWalletInteractionProtocolAdapter(Oid4vpPresentationExecutor.notConfigured)

            val match =
                adapter.canHandle(
                    WalletEntryPoint.link(
                        "openid4vp://?client_id=verifier.example&response_type=vp_token&" +
                            "presentation_definition=%7B%22id%22%3A%22mDL%22%2C%22input_descriptors%22%3A%5B%5D%7D",
                    ),
                )

            assertEquals(WalletProtocolMatchStrength.NONE, match.strength)
        }

    @Test
    fun regularOid4vpFailsClosedWhenAResolvedRequestContainsPresentationExchange() =
        runTest {
            val resolved = resolvedRequest()
            val holder =
                RecordingOid4vpHolderService(
                    resolvedRequest =
                        resolved.copy(
                            request =
                                resolved.request.copy(
                                    additionalParameters =
                                        mapOf(
                                            "presentation_definition" to
                                                buildJsonObject {
                                                    put("id", JsonPrimitive("mDL"))
                                                    put("input_descriptors", JsonArray(emptyList()))
                                                },
                                        ),
                                ),
                        ),
                )
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = holder,
                )

            val session =
                adapter.start(
                    walletContext(),
                    WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"),
                )

            assertEquals(WalletInteractionStatus.Failed, session.state.status)
            assertEquals("OID4VP_PRESENTATION_EXCHANGE_UNSUPPORTED", session.state.error?.arguments?.get("providerErrorCode"))
        }

    @Test
    fun expiredRequestUriIsReportedWithoutCollapsingItIntoAGenericParseFailure() =
        runTest {
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = RecordingOid4vpHolderService(parseError = IdkError.fromString("gone", code = "HTTP_410")),
                )

            val session =
                adapter.start(
                    walletContext(),
                    WalletEntryPoint.link(
                        "openid4vp://?client_id=verifier.example&request_uri=https%3A%2F%2Fverifier.example%2Fexpired",
                    ),
                )

            assertEquals(WalletInteractionStatus.Failed, session.state.status)
            assertEquals("oid4vp.request_uri_expired", session.state.error?.code)
            assertEquals("HTTP_410", session.state.error?.arguments?.get("providerErrorCode"))
            assertEquals(WalletFailureDisposition.TERMINAL, session.state.error?.disposition)
        }

    @Test
    fun transientRequestUriFetchFailureIsTypedAndRetryable() =
        runTest {
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = RecordingOid4vpHolderService(
                        parseError = IdkError.fromString("offline", code = "HTTP_REQUEST_FAILED"),
                    ),
                )

            val session =
                adapter.start(
                    walletContext(),
                    WalletEntryPoint.link(
                        "openid4vp://?client_id=verifier.example&request_uri=https%3A%2F%2Fverifier.example%2Frequest",
                    ),
                )

            assertEquals("oid4vp.request_uri_fetch_failed", session.state.error?.code)
            assertEquals(WalletFailureDisposition.REPEATABLE, session.state.error?.disposition)
        }

    @Test
    fun loginPurposeMetadataProjectsLoginActivityAndVerifierContext() =
        runTest {
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = RecordingOid4vpHolderService(resolvedRequest = resolvedRequest()),
                )
            val context = walletContext(attributes = mapOf("interaction_purpose" to "login"))

            val session = adapter.start(context, WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"))

            assertEquals(WalletInteractionActivityType.LOGIN, session.state.activity?.type)
            assertEquals(WalletCounterpartyRole.VERIFIER, session.state.counterparty?.role)
            assertEquals(
                "login",
                session.state.counterparty
                    ?.metadata
                    ?.get("interaction_context")
            )
            assertEquals(
                "LOGIN",
                session.state.counterparty
                    ?.metadata
                    ?.get("activity_type")
            )
            assertEquals(
                "login",
                session.state.activity
                    ?.metadata
                    ?.get("interaction_context")
            )
        }

    @Test
    fun genericOid4vpPresentationKeepsPresentationActivity() =
        runTest {
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder = RecordingOid4vpHolderService(resolvedRequest = resolvedRequest()),
                )

            val session = adapter.start(walletContext(), WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"))

            assertEquals(WalletInteractionActivityType.CREDENTIAL_PRESENTATION, session.state.activity?.type)
            assertEquals(
                "presentation",
                session.state.counterparty
                    ?.metadata
                    ?.get("interaction_context")
            )
        }

    @Test
    fun authorizationRequestResolutionFailureFailsClosed() =
        runTest {
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = Oid4vpPresentationExecutor.notConfigured,
                    holder =
                        RecordingOid4vpHolderService(
                            resolveError = IdkError.ILLEGAL_ARGUMENT_ERROR(message = "invalid verifier metadata"),
                        ),
                )

            val session =
                adapter.start(
                    walletContext(),
                    WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"),
                )

            assertEquals(WalletInteractionStatus.Failed, session.state.status)
            assertTrue(session.state.terminal)
            assertEquals("oid4vp.request_resolve_failed", session.state.error?.code)
            assertNull(session.state.credentialSelection)
        }

    @Test
    fun dcqlQueryProjectsCredentialRequirementsWithoutClaimValues() {
        val request =
            DcqlQuery(
                credentials =
                    listOf(
                        DcqlCredentialQuery(
                            id = "identity",
                            format = "dc+sd-jwt",
                            meta = sdJwtVcMeta("urn:test:identity"),
                            multiple = true,
                            claims =
                                listOf(
                                    DcqlClaimQuery(path = ClaimsPathPointer(listOf(JsonPrimitive("given_name")))),
                                    DcqlClaimQuery(path = ClaimsPathPointer(listOf(JsonPrimitive("address"), JsonPrimitive("locality")))),
                                ),
                        ),
                    ),
            ).toCredentialSelectionRequest(candidateCredentialIds = mapOf("identity" to listOf("cred-1")))

        assertEquals(true, request.satisfiable)
        assertEquals(true, request.requirements.single().multipleAllowed)
        assertEquals(listOf(JsonPrimitive("address"), JsonPrimitive("locality")), request.requirements.single().requiredClaimPaths[1])
        assertTrue(request.requirements.single().candidateDisclosures.isEmpty(), "ids-only projection cannot compute per-candidate cost")
    }

    @Test
    fun dcqlQueryDoesNotCopyRequiredClaimPathsOntoEveryCandidateAsDisclosureCost() {
        val request =
            DcqlQuery(
                credentials =
                    listOf(
                        DcqlCredentialQuery(
                            id = "pid",
                            format = "dc+sd-jwt",
                            meta = sdJwtVcMeta("urn:test:pid"),
                            multiple = true,
                            claims =
                                listOf(
                                    DcqlClaimQuery(path = ClaimsPathPointer(listOf(JsonPrimitive("given_name")))),
                                    DcqlClaimQuery(path = ClaimsPathPointer(listOf(JsonPrimitive("family_name")))),
                                    DcqlClaimQuery(path = ClaimsPathPointer(listOf(JsonPrimitive("address"), JsonPrimitive("street_address")))),
                                ),
                        ),
                    ),
            ).toCredentialSelectionRequest(
                candidateCredentialIds = mapOf("pid" to listOf("lean-credential", "rich-credential")),
            )

        val projected = request.requirements.single()
        assertEquals(listOf("lean-credential", "rich-credential"), projected.candidateCredentialIds)
        assertEquals(3, projected.requiredClaimPaths.size)
        assertTrue(
            projected.candidateDisclosures.isEmpty(),
            "empty means not computed; copying requiredClaimPaths onto both candidates would hide lean vs rich",
        )
    }

    @Test
    fun dcqlCredentialSetsProjectSatisfiableOptionsFromActualCandidates() {
        val request =
            DcqlQuery(
                credentials =
                    listOf(
                        DcqlCredentialQuery(id = "pid", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:pid")),
                        DcqlCredentialQuery(id = "mdl", format = "mso_mdoc", meta = mdocMeta("org.iso.18013.5.1.mDL")),
                    ),
                credential_sets =
                    listOf(
                        DcqlCredentialSetQuery(
                            required = true,
                            options =
                                listOf(
                                    listOf("pid"),
                                    listOf("mdl"),
                                ),
                        ),
                    ),
            ).toCredentialSelectionRequest(candidateCredentialIds = mapOf("mdl" to listOf("mdl-cred-1")))

        assertEquals(true, request.satisfiable)
        assertEquals(2, request.requirements.size)
        assertEquals(emptyList(), request.requirements.single { it.id == "pid" }.candidateCredentialIds)
        assertEquals(listOf("mdl-cred-1"), request.requirements.single { it.id == "mdl" }.candidateCredentialIds)
        assertEquals(
            false,
            request.credentialSets
                .single()
                .options
                .first()
                .satisfiable
        )
        assertEquals(
            true,
            request.credentialSets
                .single()
                .options
                .last()
                .satisfiable
        )
    }

    @Test
    fun dcqlDisclosurePathMatcherHandlesArrayIndicesWildcardsAndDottedProperties() {
        val values =
            mapOf(
                "addresses" to
                    JsonArray(
                        listOf(
                            buildJsonObject { put("city", JsonPrimitive("Utrecht")) },
                            buildJsonObject { put("city", JsonPrimitive("Amsterdam")) },
                        ),
                    ),
                "a.b" to JsonPrimitive("literal dotted property"),
                "a" to buildJsonObject { put("b", JsonPrimitive("nested property")) },
            )

        assertTrue(
            values.containsDisclosurePath(
                listOf(JsonPrimitive("addresses"), JsonPrimitive(1), JsonPrimitive("city")),
            ),
        )
        assertTrue(
            values.containsDisclosurePath(
                listOf(JsonPrimitive("addresses"), JsonNull, JsonPrimitive("city")),
            ),
        )
        assertTrue(values.containsDisclosurePath(listOf(JsonPrimitive("a.b"))))
        assertTrue(
            values.containsDisclosurePath(
                listOf(JsonPrimitive("a"), JsonPrimitive("b")),
            ),
        )
        assertFalse(
            values.containsDisclosurePath(
                listOf(JsonPrimitive("a"), JsonPrimitive("c")),
            ),
        )
        assertFalse(
            mapOf("addresses" to JsonArray(listOf(buildJsonObject { put("city", JsonPrimitive("Utrecht")) }, JsonPrimitive("not-an-object"))))
                .containsDisclosurePath(listOf(JsonPrimitive("addresses"), JsonNull, JsonPrimitive("city"))),
            "a wildcard selection cannot ignore an element with an incompatible type",
        )
        assertTrue(
            mapOf("addresses" to JsonArray(listOf(buildJsonObject { put("city", JsonPrimitive("Utrecht")) }, buildJsonObject { })))
                .containsDisclosurePath(listOf(JsonPrimitive("addresses"), JsonNull, JsonPrimitive("city"))),
            "a missing property drops only that selected object",
        )
    }

    @Test
    fun dcqlRequirementsWithoutCandidateCredentialsAreUnsatisfiable() {
        val request =
            DcqlQuery(
                credentials = listOf(DcqlCredentialQuery(id = "identity", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
            ).toCredentialSelectionRequest(candidateCredentialIds = emptyMap())

        assertEquals(false, request.satisfiable)
        assertEquals(emptyList(), request.requirements.single().candidateCredentialIds)
    }

    @Test
    fun walletStoreCandidateResolverMatchesSdJwtVctWithoutOpeningBodies() =
        runTest {
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "pid-record",
                        format = CredentialFormat.SD_JWT_VC,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                    ),
                    walletCredentialRecord(
                        id = "employee-record",
                        format = CredentialFormat.JWT_VC_JSON,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.JWT_VC_JSON, CredentialTypeRefKind.W3C_VC_TYPE, "EmployeeCredential")),
                        holderKid = "https://holder.example/jwks#key-1",
                    ),
                )
            val resolver = WalletStoreOid4vpCredentialResolver(store)
            val resolved =
                resolvedRequest(
                    DcqlCredentialQuery(
                        id = "identity",
                        format = "dc+sd-jwt",
                        meta =
                            buildJsonObject {
                                put("vct_values", JsonArray(listOf(JsonPrimitive("https://example.com/pid"))))
                            },
                    ),
                )

            val candidates = resolver.candidateCredentialIds(context = walletContext(), resolvedRequest = resolved)

            assertEquals(mapOf("identity" to listOf("pid-record")), candidates)
            assertEquals(emptyList(), store.credentialReads)
            assertEquals(1, store.typeRefQueries.size)
        }

    @Test
    fun walletStoreCandidateResolverMatchesMdocDoctypeAfterCheckingConcreteValidity() =
        runTest {
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "mdl-record",
                        format = CredentialFormat.MSO_MDOC,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.MSO_MDOC, CredentialTypeRefKind.MDOC_DOCTYPE, "org.iso.18013.5.1.mDL")),
                        raw = mdocCredential("2020-01-20T12:00:00Z", "2099-12-31T23:59:59Z"),
                    ),
                )
            val resolver = WalletStoreOid4vpCredentialResolver(store)
            val resolved =
                resolvedRequest(
                    DcqlCredentialQuery(
                        id = "mdl",
                        format = "mso_mdoc",
                        meta =
                            buildJsonObject {
                                put("doctype_value", JsonPrimitive("org.iso.18013.5.1.mDL"))
                            },
                    ),
                )

            val candidates = resolver.candidateCredentialIds(context = walletContext(), resolvedRequest = resolved)

            assertEquals(mapOf("mdl" to listOf("mdl-record")), candidates)
            assertEquals(listOf("mdl-record"), store.credentialReads)
        }

    @Test
    fun walletStoreCandidateResolverExcludesMdocMissingAnyRequiredClaim() =
        runTest {
            val record =
                walletCredentialRecord(
                    id = "pid-record",
                    format = CredentialFormat.MSO_MDOC,
                    typeRefs = setOf(credentialTypeRef(CredentialFormat.MSO_MDOC, CredentialTypeRefKind.MDOC_DOCTYPE, "eu.europa.ec.eudi.pid.1")),
                    raw = mdocCredential(
                        validFrom = "2020-01-20T12:00:00Z",
                        validUntil = "2099-12-31T23:59:59Z",
                        claims = mapOf("family_name" to "Lindgren"),
                    ),
                )
            val store = RecordingWalletCredentialStore(record)
            val resolver = WalletStoreOid4vpCredentialResolver(store, credentialClaimValuesResolver = claimValuesResolver())
            val resolved =
                resolvedRequest(
                    DcqlCredentialQuery(
                        id = "pid",
                        format = "mso_mdoc",
                        meta = mdocMeta("eu.europa.ec.eudi.pid.1"),
                        claims =
                            listOf(
                                DcqlClaimQuery(path = claimsPathPointer("org.iso.18013.5.1", "family_name")),
                                DcqlClaimQuery(path = claimsPathPointer("org.iso.18013.5.1", "age_over_18")),
                            ),
                    ),
                )

            val candidates = resolver.candidateCredentialIds(walletContext(), resolved)

            assertEquals(emptyList(), candidates.getValue("pid"))
        }

    @Test
    fun walletStoreCandidateResolverUsesFirstSatisfiableClaimSetWithoutChangingOptionOrder() =
        runTest {
            val record =
                walletCredentialRecord(
                    id = "pid-record",
                    format = CredentialFormat.MSO_MDOC,
                    typeRefs = setOf(credentialTypeRef(CredentialFormat.MSO_MDOC, CredentialTypeRefKind.MDOC_DOCTYPE, "eu.europa.ec.eudi.pid.1")),
                    raw = mdocCredential(
                        validFrom = "2020-01-20T12:00:00Z",
                        validUntil = "2099-12-31T23:59:59Z",
                        claims = mapOf("family_name" to "Lindgren"),
                    ),
                )
            val store = RecordingWalletCredentialStore(record)
            val resolver = WalletStoreOid4vpCredentialResolver(store, credentialClaimValuesResolver = claimValuesResolver())
            val resolved =
                resolvedRequest(
                    DcqlCredentialQuery(
                        id = "pid",
                        format = "mso_mdoc",
                        meta = mdocMeta("eu.europa.ec.eudi.pid.1"),
                        claims =
                            listOf(
                                DcqlClaimQuery(path = claimsPathPointer("org.iso.18013.5.1", "age_over_18"), id = "age"),
                                DcqlClaimQuery(path = claimsPathPointer("org.iso.18013.5.1", "family_name"), id = "name"),
                            ),
                        claim_sets = listOf(listOf("age"), listOf("name")),
                    ),
                )

            val candidates = resolver.candidateCredentialIds(walletContext(), resolved)

            assertEquals(listOf("pid-record"), candidates.getValue("pid"))
            assertEquals(
                listOf(
                    listOf(listOf(JsonPrimitive("org.iso.18013.5.1"), JsonPrimitive("age_over_18"))),
                    listOf(listOf(JsonPrimitive("org.iso.18013.5.1"), JsonPrimitive("family_name"))),
                ),
                resolved.credentialDisclosurePathOptions("pid"),
            )
        }

    @Test
    fun walletStoreCandidateResolverDoesNotConflateMdocNamespaceAndElementBoundaries() =
        runTest {
            val record =
                walletCredentialRecord(
                    id = "pid-record",
                    format = CredentialFormat.MSO_MDOC,
                    typeRefs = setOf(credentialTypeRef(CredentialFormat.MSO_MDOC, CredentialTypeRefKind.MDOC_DOCTYPE, "eu.europa.ec.eudi.pid.1")),
                    raw =
                        mdocCredential(
                            validFrom = "2020-01-20T12:00:00Z",
                            validUntil = "2099-12-31T23:59:59Z",
                            additionalNamespaces = mapOf("a" to mapOf("b.c" to "present")),
                        ),
                )
            val store = RecordingWalletCredentialStore(record)
            val resolver = WalletStoreOid4vpCredentialResolver(store, credentialClaimValuesResolver = claimValuesResolver())
            val resolved =
                resolvedRequest(
                    DcqlCredentialQuery(
                        id = "pid",
                        format = "mso_mdoc",
                        meta = mdocMeta("eu.europa.ec.eudi.pid.1"),
                        claims = listOf(DcqlClaimQuery(path = claimsPathPointer("a.b", "c"))),
                    ),
                )

            val candidates = resolver.candidateCredentialIds(walletContext(), resolved)

            assertEquals(emptyList(), candidates.getValue("pid"))
        }

    @Test
    fun walletStoreCandidateResolverUsesStructuredParsedSdJwtClaims() =
        runTest {
            val validCredential =
                sdJwtCredential(
                    buildJsonObject {
                        put("vct", JsonPrimitive("https://example.com/pid"))
                        put("address", buildJsonObject { put("city", JsonPrimitive("Utrecht")) })
                        put(
                            "addresses",
                            JsonArray(
                                listOf(
                                    buildJsonObject { put("city", JsonPrimitive("Utrecht")) },
                                    buildJsonObject { put("city", JsonPrimitive("Amsterdam")) },
                                ),
                            ),
                        )
                    },
                )
            val mixedTypeCredential =
                sdJwtCredential(
                    buildJsonObject {
                        put("vct", JsonPrimitive("https://example.com/pid"))
                        put(
                            "addresses",
                            JsonArray(
                                listOf(
                                    buildJsonObject { put("city", JsonPrimitive("Utrecht")) },
                                    JsonPrimitive("not-an-object"),
                                ),
                            ),
                        )
                    },
                )
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "valid-pid-record",
                        format = CredentialFormat.SD_JWT_VC,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                        raw = validCredential,
                    ),
                    walletCredentialRecord(
                        id = "mixed-pid-record",
                        format = CredentialFormat.SD_JWT_VC,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                        raw = mixedTypeCredential,
                    ),
                )
            val resolver = WalletStoreOid4vpCredentialResolver(store, credentialClaimValuesResolver = claimValuesResolver())
            val nestedClaimRequest =
                resolvedRequest(
                    DcqlCredentialQuery(
                        id = "nested-address",
                        format = "dc+sd-jwt",
                        meta = sdJwtVcMeta("https://example.com/pid"),
                        claims = listOf(DcqlClaimQuery(path = claimsPathPointer("address", "city"))),
                    ),
                )
            val arrayWildcardRequest =
                resolvedRequest(
                    DcqlCredentialQuery(
                        id = "address-cities",
                        format = "dc+sd-jwt",
                        meta = sdJwtVcMeta("https://example.com/pid"),
                        claims =
                            listOf(
                                DcqlClaimQuery(
                                    path = ClaimsPathPointer(listOf(JsonPrimitive("addresses"), JsonNull, JsonPrimitive("city"))),
                                ),
                            ),
                    ),
                )
            val arrayIndexRequest =
                resolvedRequest(
                    DcqlCredentialQuery(
                        id = "first-address-city",
                        format = "dc+sd-jwt",
                        meta = sdJwtVcMeta("https://example.com/pid"),
                        claims =
                            listOf(
                                DcqlClaimQuery(
                                    path = ClaimsPathPointer(listOf(JsonPrimitive("addresses"), JsonPrimitive(0), JsonPrimitive("city"))),
                                ),
                            ),
                    ),
                )

            assertEquals(listOf("valid-pid-record"), resolver.candidateCredentialIds(walletContext(), nestedClaimRequest).getValue("nested-address"))
            assertEquals(listOf("valid-pid-record"), resolver.candidateCredentialIds(walletContext(), arrayWildcardRequest).getValue("address-cities"))
            assertEquals(listOf("valid-pid-record", "mixed-pid-record"), resolver.candidateCredentialIds(walletContext(), arrayIndexRequest).getValue("first-address-city"))
        }

    @Test
    fun walletStoreCandidateResolverMatchesW3cTypeValuesWithoutOpeningBodies() =
        runTest {
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "employee-record",
                        format = CredentialFormat.JWT_VC_JSON,
                        typeRefs =
                            setOf(
                                credentialTypeRef(CredentialFormat.JWT_VC_JSON, CredentialTypeRefKind.W3C_VC_TYPE, "VerifiableCredential"),
                                credentialTypeRef(CredentialFormat.JWT_VC_JSON, CredentialTypeRefKind.W3C_VC_TYPE, "EmployeeCredential"),
                            ),
                    ),
                )
            val resolver = WalletStoreOid4vpCredentialResolver(store)
            val resolved =
                resolvedRequest(
                    DcqlCredentialQuery(
                        id = "employee",
                        format = "jwt_vc_json",
                        meta = w3cVcMeta(listOf("EmployeeCredential")),
                    ),
                )

            val candidates = resolver.candidateCredentialIds(context = walletContext(), resolvedRequest = resolved)

            assertEquals(mapOf("employee" to listOf("employee-record")), candidates)
            assertEquals(emptyList(), store.credentialReads)
        }

    @Test
    fun walletStoreSelectedResolverOpensOnlySelectedCredentialRecords() =
        runTest {
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "pid-record",
                        format = CredentialFormat.SD_JWT_VC,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                        raw = "raw-pid",
                    ),
                    walletCredentialRecord(
                        id = "other-record",
                        format = CredentialFormat.SD_JWT_VC,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                        raw = "raw-other",
                    ),
                )
            val resolver = WalletStoreOid4vpCredentialResolver(store)

            val selected =
                resolver.resolveSelectedCredentials(
                    context = walletContext(),
                    state = credentialSelectionState(WalletCredentialSelectionRequest(emptyList(), satisfiable = true)),
                    resolvedRequest = resolvedRequest(DcqlCredentialQuery(id = "identity", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:identity"))),
                    selectedCredentialIdsByRequirement = mapOf("identity" to listOf("pid-record")),
                )

            assertEquals(listOf("pid-record"), store.credentialReads)
            assertEquals("identity", selected.single().credentialQueryId)
            assertEquals("pid-record-instance", selected.single().credentialId)
            assertEquals(JsonPrimitive("raw-pid"), selected.single().presentation)
            assertEquals("holder-pid-record", selected.single().holderKeyRef)
        }

    @Test
    fun walletStoreSelectedResolverCarriesExplicitHolderIdentityForVcdmCredential() =
        runTest {
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "employee-record",
                        format = CredentialFormat.JWT_VC_JSON,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.JWT_VC_JSON, CredentialTypeRefKind.W3C_VC_TYPE, "EmployeeCredential")),
                        holderKid = "https://holder.example/jwks#key-1",
                    ),
                )
            val resolver =
                WalletStoreOid4vpCredentialResolver(
                    credentialStore = store,
                    holderIdentityResolver =
                        WalletHolderIdentityResolver { walletUnitId, holderKeyRef ->
                            assertEquals("wallet", walletUnitId)
                            assertEquals("holder-employee-record", holderKeyRef.alias)
                            "did:example:wallet-holder"
                        },
                    holderVerificationMethodResolver =
                        WalletHolderVerificationMethodResolver { _, _ ->
                            WalletHolderVerificationMethod(
                                value = "https://holder.example/jwks#key-1",
                                controller = "did:example:wallet-holder",
                                kind = WalletHolderIdentifierKind.JWKS_KID,
                                signingAlgorithm = SignatureAlgorithm.ED25519,
                            )
                        },
                )

            val selected =
                resolver.resolveSelectedCredentials(
                    context = walletContext(),
                    state = credentialSelectionState(WalletCredentialSelectionRequest(emptyList(), satisfiable = true)),
                    resolvedRequest = resolvedRequest(DcqlCredentialQuery(id = "employee", format = "jwt_vc_json", meta = w3cVcMeta(listOf("EmployeeCredential")))),
                    selectedCredentialIdsByRequirement = mapOf("employee" to listOf("employee-record")),
                )

            assertEquals("did:example:wallet-holder", selected.single().holderId)
            assertEquals(SignatureAlgorithm.ED25519, selected.single().holderSigningAlgorithm)
        }

    @Test
    fun walletStoreSelectedResolverChoosesDataIntegritySuiteFromExactKeyAlgorithmAndVerifierMetadata() =
        runTest {
            val verificationMethod = "https://holder.example/jwks#p256"
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "employee-ldp-record",
                        format = CredentialFormat.LDP_VC,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.LDP_VC, CredentialTypeRefKind.W3C_VC_TYPE, "EmployeeCredential")),
                        raw = """{"@context":"https://www.w3.org/ns/credentials/v2","type":["VerifiableCredential","EmployeeCredential"],"issuer":"https://issuer.example","credentialSubject":{"id":"https://holder.example/id"}}""",
                        holderKid = verificationMethod,
                    ),
                )
            val resolver =
                WalletStoreOid4vpCredentialResolver(
                    credentialStore = store,
                    holderIdentityResolver = WalletHolderIdentityResolver { _, _ -> "https://holder.example/id" },
                    holderVerificationMethodResolver =
                        WalletHolderVerificationMethodResolver { _, _ ->
                            WalletHolderVerificationMethod(
                                value = verificationMethod,
                                controller = "https://holder.example/id",
                                kind = WalletHolderIdentifierKind.JWKS_KID,
                                signingAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
                            )
                        },
                )
            val request =
                resolvedRequest(DcqlCredentialQuery(id = "employee", format = "ldp_vc", meta = w3cVcMeta(listOf("EmployeeCredential"))))
                    .copy(
                        clientMetadata =
                            ClientMetadata(
                                vpFormatsSupported =
                                    mapOf(
                                        "ldp_vc" to
                                            VpFormatInfo(
                                                proofTypeValues = listOf("DataIntegrityProof"),
                                                cryptosuiteValues = listOf("eddsa-rdfc-2022", "ecdsa-rdfc-2019"),
                                            ),
                                    ),
                            ),
                    )

            val selected =
                resolver.resolveSelectedCredentials(
                    context = walletContext(),
                    state = credentialSelectionState(WalletCredentialSelectionRequest(emptyList(), satisfiable = true)),
                    resolvedRequest = request,
                    selectedCredentialIdsByRequirement = mapOf("employee" to listOf("employee-ldp-record")),
                ).single()

            assertEquals("ecdsa-rdfc-2019", selected.dataIntegrityCryptosuite)
            assertEquals(SignatureAlgorithm.ECDSA_SHA256, selected.holderSigningAlgorithm)
            assertEquals(verificationMethod, selected.holderVerificationMethod)
        }

    @Test
    fun walletStoreSelectedResolverFailsClosedWhenVcdmHolderIdentityIsAbsent() =
        runTest {
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "employee-record",
                        format = CredentialFormat.JWT_VC_JSON_LD,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.JWT_VC_JSON_LD, CredentialTypeRefKind.W3C_VC_TYPE, "EmployeeCredential")),
                        holderKid = "https://holder.example/jwks#key-1",
                    ),
                )

            val failure =
                assertFailsWith<IllegalStateException> {
                    WalletStoreOid4vpCredentialResolver(
                        credentialStore = store,
                        holderVerificationMethodResolver =
                            WalletHolderVerificationMethodResolver { _, _ ->
                                WalletHolderVerificationMethod(
                                    value = "https://holder.example/jwks#key-1",
                                    controller = "https://holder.example/id",
                                    kind = WalletHolderIdentifierKind.JWKS_KID,
                                    signingAlgorithm = SignatureAlgorithm.ED25519,
                                )
                            },
                    ).resolveSelectedCredentials(
                        context = walletContext(),
                        state = credentialSelectionState(WalletCredentialSelectionRequest(emptyList(), satisfiable = true)),
                        resolvedRequest = resolvedRequest(DcqlCredentialQuery(id = "employee", format = "jwt_vc_json-ld", meta = w3cVcMeta(listOf("EmployeeCredential")))),
                        selectedCredentialIdsByRequirement = mapOf("employee" to listOf("employee-record")),
                    )
                }

            assertTrue(failure.message.orEmpty().contains("holder identifier is missing"))
        }

    @Test
    fun walletStoreCandidateResolverExcludesSuspendedRecordsBeforeOpeningCredentialBodies() =
        runTest {
            // A SUSPENDED-lifecycle record sharing the same credentialTypeRef as an ACTIVE one
            // must never surface as a candidate, and its body must never be opened (getCredential)
            // while resolving the selection.
            val inactiveRecord =
                walletCredentialRecord(
                    id = "doc-inactive",
                    format = CredentialFormat.SD_JWT_VC,
                    typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                    lifecycleState = CredentialLifecycleState.SUSPENDED,
                )
            val activeRecord =
                walletCredentialRecord(
                    id = "doc-active",
                    format = CredentialFormat.SD_JWT_VC,
                    typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                )
            val store = RecordingWalletCredentialStore(inactiveRecord, activeRecord)
            val resolver = WalletStoreOid4vpCredentialResolver(store)
            val resolved =
                resolvedRequest(
                    DcqlCredentialQuery(
                        id = "identity",
                        format = "dc+sd-jwt",
                        meta =
                            buildJsonObject {
                                put("vct_values", JsonArray(listOf(JsonPrimitive("https://example.com/pid"))))
                            },
                    ),
                )

            val candidates = resolver.candidateCredentialIds(context = walletContext(), resolvedRequest = resolved)
            assertEquals(mapOf("identity" to listOf("doc-active")), candidates, "the SUSPENDED record must not be a candidate")
            assertEquals(emptyList(), store.credentialReads, "candidate resolution must not open credential bodies")

            val selected =
                resolver.resolveSelectedCredentials(
                    context = walletContext(),
                    state = credentialSelectionState(WalletCredentialSelectionRequest(emptyList(), satisfiable = true)),
                    resolvedRequest = resolved,
                    selectedCredentialIdsByRequirement = candidates,
                )
            assertEquals(listOf("doc-active"), store.credentialReads, "only the active record's body should be opened")
            assertEquals(JsonPrimitive("raw-doc-active"), selected.single().presentation)
        }

    @Test
    fun walletStoreBackedAdapterFactoryUsesMetadataCandidates() =
        runTest {
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "pid-record",
                        format = CredentialFormat.SD_JWT_VC,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                    ),
                )
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter.walletStoreBacked(
                    sdJwtHolderBindingProvider = preparedOnlyHolderBindingProvider,
                    holder =
                        RecordingOid4vpHolderService(
                            resolvedRequest =
                                resolvedRequest(
                                    DcqlCredentialQuery(
                                        id = "identity",
                                        format = "dc+sd-jwt",
                                        meta =
                                            buildJsonObject {
                                                put("vct_values", JsonArray(listOf(JsonPrimitive("https://example.com/pid"))))
                                            },
                                    ),
                                ),
                        ),
                    credentialStore = store,
                )

            val session =
                adapter.start(
                    context = walletContext(),
                    entryPoint = WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"),
                )

            assertEquals(WalletInteractionStatus.CredentialSelection, session.state.status)
            assertEquals(
                listOf("pid-record"),
                session.state.credentialSelection
                    ?.requirements
                    ?.single()
                    ?.candidateCredentialIds
            )
            assertEquals(emptyList(), store.credentialReads)
        }

    @Test
    fun walletStoreBackedAdapterAddsSelectedHolderKeyAndWalletUnitMetadataToSecurityRequest() =
        runTest {
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "pid-record",
                        format = CredentialFormat.SD_JWT_VC,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                    ),
                )
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter.walletStoreBacked(
                    sdJwtHolderBindingProvider = preparedOnlyHolderBindingProvider,
                    holder =
                        RecordingOid4vpHolderService(
                            resolvedRequest =
                                resolvedRequest(
                                    DcqlCredentialQuery(
                                        id = "identity",
                                        format = "dc+sd-jwt",
                                        meta =
                                            buildJsonObject {
                                                put("vct_values", JsonArray(listOf(JsonPrimitive("https://example.com/pid"))))
                                            },
                                    ),
                                ),
                        ),
                    credentialStore = store,
                )
            val privateStore = RecordingPrivateSessionStore()
            val protocolExecutor = RecordingProtocolExecutor(ProtocolExecutionOwner.WALLET_APP)
            val securityGate = RecordingSecurityGate()
            val context =
                walletContext(
                    privateSessionStore = privateStore,
                    protocolExecutor = protocolExecutor,
                    securityGate = securityGate,
                    attributes =
                        mapOf(
                            Oid4vpPresentationSecurityAttributes.WALLET_UNIT_ID to "unit-1",
                            Oid4vpPresentationSecurityAttributes.WALLET_ACCOUNT_ID to "account-1",
                            Oid4vpPresentationSecurityAttributes.ACTIVATION_DECISION_ID to "activation-1",
                            Oid4vpPresentationSecurityAttributes.OPERATION_TYPE to "wallet.sign",
                            Oid4vpPresentationSecurityAttributes.OPERATION_HASH to "hash-1",
                            Oid4vpPresentationSecurityAttributes.NONCE to "nonce-1",
                        ),
                )
            val session = adapter.start(context, WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"))

            val next =
                adapter.handle(
                    context,
                    session.state,
                    WalletInteractionAction.selectCredentials(
                        WalletCredentialSelection(mapOf("identity" to listOf("pid-record"))),
                    ),
                )

            assertEquals(WalletInteractionStatus.Completed, next.status)
            assertEquals("holder-pid-record", protocolExecutor.lastRequest?.keyRef)
            assertEquals("unit-1", protocolExecutor.lastRequest?.walletUnitId)
            assertEquals("account-1", protocolExecutor.lastRequest?.walletAccountId)
            assertEquals("activation-1", protocolExecutor.lastRequest?.activationDecisionId)
            assertEquals("wallet.sign", protocolExecutor.lastRequest?.operationType)
            assertEquals("hash-1", protocolExecutor.lastRequest?.operationHash)
            assertEquals("nonce-1", protocolExecutor.lastRequest?.nonce)
            assertEquals("holder-pid-record", securityGate.lastRequest?.keyRef)
            assertEquals("unit-1", securityGate.lastRequest?.walletUnitId)
            assertEquals("account-1", securityGate.lastRequest?.walletAccountId)
            assertEquals("activation-1", securityGate.lastRequest?.activationDecisionId)
            assertEquals("wallet.sign", securityGate.lastRequest?.operationType)
            assertEquals("hash-1", securityGate.lastRequest?.operationHash)
            assertEquals("nonce-1", securityGate.lastRequest?.nonce)
        }

    @Test
    fun walletStoreResolverDoesNotRecordBindingWhenVerifierSubmissionFails() =
        runTest {
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "pid-record",
                        format = CredentialFormat.SD_JWT_VC,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                    ),
                )
            val privateStore = RecordingPrivateSessionStore()
            privateStore.put(
                WalletInteractionSessionId("s1"),
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        mapOf(
                            "entry_point.raw" to "openid4vp://?client_id=verifier&response_type=vp_token",
                            "selected_credential_ids_by_requirement" to
                                Oid4vpWalletInteractionProtocolAdapter.json.encodeToString(mapOf("identity" to listOf("pid-record"))),
                        ),
                ),
            )
            val executor =
                Oid4vpHolderPresentationExecutor(
                    holder = RecordingOid4vpHolderService(SubmissionResult.Error("invalid_request")),
                    selectedCredentialResolver = WalletStoreOid4vpCredentialResolver(store),
                    sdJwtHolderBindingProvider = preparedOnlyHolderBindingProvider,
                )

            val result =
                executor.submitPresentation(
                    context = walletContext(privateSessionStore = privateStore),
                    state = credentialSelectionState(WalletCredentialSelectionRequest(emptyList(), satisfiable = true)),
                )

            assertTrue(result is Oid4vpPresentationExecutionResult.Failed)
            assertEquals(
                emptyList(),
                store.records
                    .getValue("pid-record")
                    .instances
                    .single()
                    .bindingRefs
            )
        }

    @Test
    fun holderPresentationExecutorPropagatesProviderErrorDetailsOnSubmissionFailure() =
        runTest {
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "pid-record",
                        format = CredentialFormat.SD_JWT_VC,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                    ),
                )
            val privateStore = RecordingPrivateSessionStore()
            privateStore.put(
                WalletInteractionSessionId("s1"),
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        mapOf(
                            "entry_point.raw" to "openid4vp://?client_id=verifier&response_type=vp_token",
                            "selected_credential_ids_by_requirement" to
                                Oid4vpWalletInteractionProtocolAdapter.json.encodeToString(mapOf("identity" to listOf("pid-record"))),
                        ),
                ),
            )
            val executor =
                Oid4vpHolderPresentationExecutor(
                    holder =
                        RecordingOid4vpHolderService(
                            submitError = IdkError.ILLEGAL_ARGUMENT_ERROR(message = "jarmOptions is required for direct_post.jwt response mode"),
                        ),
                    selectedCredentialResolver = WalletStoreOid4vpCredentialResolver(store),
                    sdJwtHolderBindingProvider = preparedOnlyHolderBindingProvider,
                )

            val result =
                executor.submitPresentation(
                    context = walletContext(privateSessionStore = privateStore),
                    state = credentialSelectionState(WalletCredentialSelectionRequest(emptyList(), satisfiable = true)),
                )

            assertTrue(result is Oid4vpPresentationExecutionResult.Failed)
            assertEquals("oid4vp.response_submission_failed", result.code)
            assertEquals("ILLEGAL_ARGUMENT_ERROR", result.arguments["providerErrorCode"])
            assertEquals("jarmOptions is required for direct_post.jwt response mode", result.arguments["providerErrorMessage"])
        }

    @Test
    fun defaultJarmOptionsProviderIssuesWalletUnitIssuer() =
        runTest {
            val options =
                Oid4vpJarmOptionsProvider.walletUnitIssuer.jarmOptions(
                    context = walletContext(),
                    state = credentialSelectionState(WalletCredentialSelectionRequest(emptyList(), satisfiable = true)),
                    resolvedRequest = resolvedRequest(),
                )

            assertEquals(JarmOptions(issuer = "wallet"), options)
        }

    @Test
    fun walletStoreResolverRecordsBindingAfterSuccessfulVerifierSubmission() =
        runTest {
            val store =
                RecordingWalletCredentialStore(
                    walletCredentialRecord(
                        id = "pid-record",
                        format = CredentialFormat.SD_JWT_VC,
                        typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                    ),
                )
            val privateStore = RecordingPrivateSessionStore()
            privateStore.put(
                WalletInteractionSessionId("s1"),
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        mapOf(
                            "entry_point.raw" to "openid4vp://?client_id=verifier&response_type=vp_token",
                            "selected_credential_ids_by_requirement" to
                                Oid4vpWalletInteractionProtocolAdapter.json.encodeToString(mapOf("identity" to listOf("pid-record"))),
                        ),
                ),
            )
            val executor =
                Oid4vpHolderPresentationExecutor(
                    holder = RecordingOid4vpHolderService(),
                    selectedCredentialResolver = WalletStoreOid4vpCredentialResolver(store),
                    sdJwtHolderBindingProvider = preparedOnlyHolderBindingProvider,
                )

            val result =
                executor.submitPresentation(
                    context = walletContext(privateSessionStore = privateStore),
                    state = credentialSelectionState(WalletCredentialSelectionRequest(emptyList(), satisfiable = true)),
                )

            assertTrue(result is Oid4vpPresentationExecutionResult.Submitted)
            val binding =
                store.records
                    .getValue("pid-record")
                    .instances
                    .single()
                    .bindingRefs
                    .single()
            assertEquals("verifier", binding.verifierRef.value)
            assertEquals("identity", binding.presentationId)
        }

    @Test
    fun walletStoreResolverDoesNotUpdateRecordsOutsideRequirementSelection() =
        runTest {
            val selectedRecord =
                walletCredentialRecord(
                    id = "selected-record",
                    format = CredentialFormat.SD_JWT_VC,
                    typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/pid")),
                )
            val otherRecord =
                walletCredentialRecord(
                    id = "other-record",
                    format = CredentialFormat.SD_JWT_VC,
                    typeRefs = setOf(credentialTypeRef(CredentialFormat.SD_JWT_VC, CredentialTypeRefKind.SD_JWT_VCT, "https://example.com/other")),
                )
            val store = RecordingWalletCredentialStore(selectedRecord, otherRecord)
            val resolver = WalletStoreOid4vpCredentialResolver(store)

            resolver.recordPresentationSubmitted(
                context = walletContext(),
                state = credentialSelectionState(WalletCredentialSelectionRequest(emptyList(), satisfiable = true)),
                resolvedRequest = resolvedRequest(),
                selectedCredentialIdsByRequirement = mapOf("identity" to listOf("other-record")),
                selectedCredentials =
                    listOf(
                        SelectedCredential(
                            credentialQueryId = "identity",
                            credentialId = selectedRecord.instances.single().id,
                            presentation = JsonPrimitive("presentation"),
                            credentialFormat = CredentialFormat.SD_JWT_VC,
                        ),
                    ),
            )

            assertTrue(store.putRecords.isEmpty())
            assertTrue(store.records.values.all { record -> record.instances.all { it.bindingRefs.isEmpty() } })
        }

    @Test
    fun blockedVerifierTrustFailsWithoutExposingProtocolRequest() =
        runTest {
            val adapter = Oid4vpWalletInteractionProtocolAdapter(Oid4vpPresentationExecutor.notConfigured)
            val session =
                adapter.start(
                    WalletInteractionContext(
                        sessionId = WalletInteractionSessionId("s1"),
                        walletUnitId = "wallet",
                        executionOwner = ProtocolExecutionOwner.WALLET_APP,
                        trustResolver =
                            object : WalletCounterpartyTrustResolver {
                                override suspend fun resolve(input: WalletCounterpartyTrustRequest): WalletCounterpartyTrustSummary =
                                    WalletCounterpartyTrustSummary(
                                        counterparty = input.counterparty,
                                        status = WalletTrustStatus.BLOCKED,
                                        policyAction = WalletTrustPolicyAction.BLOCK,
                                    )
                            },
                        trustPolicy = WalletTrustPolicy.warn,
                    ),
                    WalletEntryPoint.rawQr("openid4vp://?client_id=blocked&response_type=vp_token"),
                )

            assertEquals(WalletInteractionStatus.Failed, session.state.status)
            assertEquals(true, session.state.terminal)
            assertEquals("oid4vp.verifier_blocked", session.state.error?.code)
        }

    @Test
    fun presentationSharingUsesConfiguredSecurityGate() =
        runTest {
            val adapter = Oid4vpWalletInteractionProtocolAdapter(Oid4vpPresentationExecutor.notConfigured)
            val context =
                WalletInteractionContext(
                    sessionId = WalletInteractionSessionId("s1"),
                    walletUnitId = "wallet",
                    executionOwner = ProtocolExecutionOwner.WALLET_APP,
                    securityGate =
                        object : WalletSecurityGate {
                            override suspend fun authorize(request: WalletSecurityGateRequest): WalletSecurityGateResult =
                                WalletSecurityGateResult.ChallengeRequired(
                                    WalletSecurityChallenge(
                                        challengeId = request.operationId,
                                        kind = WalletSecurityChallengeKind.BIOMETRIC,
                                        reasonKey = "wallet.interaction.security.test",
                                    ),
                                )
                        },
                )
            val session = adapter.start(context, WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"))

            val next = adapter.handle(context, session.state, WalletInteractionAction.continueFlow())

            assertEquals(WalletInteractionStatus.SecurityUnlockRequired, next.status)
            assertEquals("wallet.interaction.security.test", next.securityChallenge?.reasonKey)
        }

    @Test
    fun optionalUnavailableCredentialSetDoesNotBlockRequiredSelection() = runTest {
        assertCredentialSetSelection(
            sets = listOf(set("required", true, listOf("identity")), set("optional", false, listOf("missing"))),
            selections = mapOf("identity" to listOf("cred-1")),
            expectedError = null,
        )
    }

    @Test
    fun requiredAlternativeCanOmitAnUnavailableQuery() = runTest {
        assertCredentialSetSelection(
            sets = listOf(set("required", true, listOf("missing"), listOf("identity"))),
            selections = mapOf("identity" to listOf("cred-1")),
            expectedError = null,
        )
    }

    @Test
    fun incompleteRequiredCompoundDoesNotReachSecurityGate() = runTest {
        assertCredentialSetSelection(
            sets = listOf(set("required", true, listOf("identity", "other"))),
            selections = mapOf("identity" to listOf("cred-1")),
            expectedError = "oid4vp.selection_missing_requirement",
        )
    }

    @Test
    fun partialOptionalSetCannotIntroduceAnExtraCredential() = runTest {
        assertCredentialSetSelection(
            sets = listOf(set("required", true, listOf("identity")), set("optional", false, listOf("other", "missing"))),
            selections = mapOf("identity" to listOf("cred-1"), "other" to listOf("cred-2")),
            expectedError = "oid4vp.selection_unsatisfiable",
        )
    }

    @Test
    fun overlappingOptionalSetDoesNotBlockRequiredSelection() = runTest {
        assertCredentialSetSelection(
            sets = listOf(set("required", true, listOf("identity")), set("optional", false, listOf("identity", "missing"))),
            selections = mapOf("identity" to listOf("cred-1")),
            expectedError = null,
        )
    }

    @Test
    fun emptyCandidateListDoesNotPermitAnInjectedRecord() = runTest {
        assertCredentialSetSelection(
            sets = listOf(set("required", true, listOf("missing"))),
            selections = mapOf("missing" to listOf("injected")),
            expectedError = "oid4vp.selection_credential_not_candidate",
        )
    }

    @Test
    fun unknownCredentialSetReferenceDoesNotReachSecurityGate() = runTest {
        assertCredentialSetSelection(
            sets = listOf(set("required", true, listOf("unknown"))),
            selections = mapOf("identity" to listOf("cred-1")),
            expectedError = "oid4vp.selection_unsatisfiable",
        )
    }

    private fun set(id: String, required: Boolean, vararg options: List<String>) = WalletCredentialSetRequirement(
        id = id,
        required = required,
        options = options.map { WalletCredentialSetOption(requirementIds = it, satisfiable = true) },
    )

    private suspend fun assertCredentialSetSelection(
        sets: List<WalletCredentialSetRequirement>,
        selections: Map<String, List<String>>,
        expectedError: String?,
    ) {
        val adapter = Oid4vpWalletInteractionProtocolAdapter(Oid4vpPresentationExecutor.notConfigured)
        val gate = RecordingSecurityGate()
        val state = credentialSelectionState(WalletCredentialSelectionRequest(
            requirements = listOf(
                WalletCredentialRequirement(id = "identity", candidateCredentialIds = listOf("cred-1")),
                WalletCredentialRequirement(id = "other", candidateCredentialIds = listOf("cred-2")),
                WalletCredentialRequirement(id = "missing", candidateCredentialIds = emptyList()),
            ),
            satisfiable = true,
            credentialSets = sets,
        ))
        val next = adapter.handle(context(gate), state, WalletInteractionAction.selectCredentials(WalletCredentialSelection(selections)))
        assertEquals(if (expectedError == null) 1 else 0, gate.calls)
        if (expectedError != null) {
            assertEquals(WalletInteractionStatus.CredentialSelection, next.status)
            assertEquals(expectedError, next.error?.code)
        }
    }

    @Test
    fun unsatisfiedDcqlSelectionStaysInCredentialSelectionWithoutSecurityGate() =
        runTest {
            val adapter = Oid4vpWalletInteractionProtocolAdapter(Oid4vpPresentationExecutor.notConfigured)
            val securityGate = RecordingSecurityGate()
            val context = context(securityGate)
            val state =
                credentialSelectionState(
                    request =
                        WalletCredentialSelectionRequest(
                            requirements =
                                listOf(
                                    WalletCredentialRequirement(
                                        id = "identity",
                                        candidateCredentialIds = emptyList(),
                                    ),
                                ),
                            satisfiable = false,
                        ),
                )

            val next =
                adapter.handle(
                    context,
                    state,
                    WalletInteractionAction.selectCredentials(
                        WalletCredentialSelection(mapOf("identity" to listOf("cred-1"))),
                    ),
                )

            assertEquals(WalletInteractionStatus.CredentialSelection, next.status)
            assertEquals("oid4vp.selection_unsatisfiable", next.error?.code)
            assertEquals(WalletFailureDisposition.RESUMABLE, next.error?.disposition)
            assertEquals(0, securityGate.calls)
        }

    @Test
    fun invalidDcqlMultipleSelectionStaysInCredentialSelectionWithoutSecurityGate() =
        runTest {
            val adapter = Oid4vpWalletInteractionProtocolAdapter(Oid4vpPresentationExecutor.notConfigured)
            val securityGate = RecordingSecurityGate()
            val context = context(securityGate)
            val state =
                credentialSelectionState(
                    request =
                        WalletCredentialSelectionRequest(
                            requirements =
                                listOf(
                                    WalletCredentialRequirement(
                                        id = "identity",
                                        multipleAllowed = false,
                                        candidateCredentialIds = listOf("cred-1", "cred-2"),
                                    ),
                                ),
                            satisfiable = true,
                        ),
                )

            val next =
                adapter.handle(
                    context,
                    state,
                    WalletInteractionAction.selectCredentials(
                        WalletCredentialSelection(mapOf("identity" to listOf("cred-1", "cred-2"))),
                    ),
                )

            assertEquals(WalletInteractionStatus.CredentialSelection, next.status)
            assertEquals("oid4vp.selection_multiple_not_allowed", next.error?.code)
            assertEquals("identity", next.error?.arguments?.get("requirementId"))
            assertEquals(0, securityGate.calls)
        }

    @Test
    fun revealClaimValuesOnlyFlipsActiveUiRevealFlagWithoutPersistingValues() =
        runTest {
            val adapter = Oid4vpWalletInteractionProtocolAdapter(Oid4vpPresentationExecutor.notConfigured)
            val state =
                WalletInteractionState(
                    sessionId = WalletInteractionSessionId("s1"),
                    walletUnitId = "wallet",
                    status = WalletInteractionStatus.DisclosureConsent,
                    flowKind = WalletInteractionFlowKind.CredentialPresent,
                    protocol = WalletProtocol.OID4VP,
                    adapterId = Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID,
                    disclosure =
                        WalletDisclosureSummary(
                            requestedClaims =
                                listOf(
                                    WalletClaimDescriptor(path = listOf(JsonPrimitive("given_name")), valueAvailable = true),
                                    WalletClaimDescriptor(path = listOf(JsonPrimitive("family_name")), valueAvailable = true),
                                ),
                            claimValuesRevealed = false,
                        ),
                )

            val next = adapter.handle(context(RecordingSecurityGate()), state, WalletInteractionAction.revealClaimValues())
            val encoded = Json.encodeToString(next)

            assertEquals(true, next.disclosure?.claimValuesRevealed)
            assertEquals(
                listOf(JsonPrimitive("given_name")),
                next.disclosure
                    ?.requestedClaims
                    ?.first()
                    ?.path
            )
            assertFalse(encoded.contains("forbidden_claim_payload"))
        }

    @Test
    fun continueWithoutPresentationExecutorDoesNotPretendPresentationWasShared() =
        runTest {
            val adapter = Oid4vpWalletInteractionProtocolAdapter(Oid4vpPresentationExecutor.notConfigured)
            val securityGate = RecordingSecurityGate()
            val context = context(securityGate)
            val session = adapter.start(context, WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"))

            val next = adapter.handle(context, session.state, WalletInteractionAction.continueFlow())

            assertEquals(WalletInteractionStatus.Failed, next.status)
            assertEquals("oid4vp.execution_not_configured", next.error?.code)
            assertEquals(WalletFailureDisposition.TERMINAL, next.error?.disposition)
            assertFalse(next.terminal)
            assertEquals(1, securityGate.calls)
        }

    @Test
    fun presentationExecutorSubmittedResultCompletesAfterFinalApproval() =
        runTest {
            val executor = RecordingPresentationExecutor(Oid4vpPresentationExecutionResult.Submitted())
            val adapter = Oid4vpWalletInteractionProtocolAdapter(presentationExecutor = executor)
            val securityGate = RecordingSecurityGate()
            val context = context(securityGate)
            val session = adapter.start(context, WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"))

            val next = adapter.handle(context, session.state, WalletInteractionAction.continueFlow())

            assertEquals(WalletInteractionStatus.Completed, next.status)
            assertEquals(true, next.terminal)
            assertEquals("wallet.interaction.status.presentation_shared", next.message?.titleKey)
            assertEquals(1, executor.submitCalls)
        }

    @Test
    fun presentationSharingUsesProtocolExecutorDecisionBeforeSecurityGate() =
        runTest {
            val executor = RecordingPresentationExecutor(Oid4vpPresentationExecutionResult.Submitted())
            val adapter = Oid4vpWalletInteractionProtocolAdapter(presentationExecutor = executor)
            val securityGate = RecordingSecurityGate()
            val context =
                WalletInteractionContext(
                    sessionId = WalletInteractionSessionId("s1"),
                    walletUnitId = "wallet",
                    executionOwner = ProtocolExecutionOwner.WALLET_APP,
                    protocolExecutor =
                        StaticDecisionProtocolExecutor(
                            WalletProtocolExecutionDecision(
                                executionOwner = ProtocolExecutionOwner.WALLET_APP,
                                placement = WalletProtocolExecutionPlacement.WALLET_APP,
                                securityOperation = WalletSecurityOperation.LOCAL_HSM_UNLOCK,
                                requiredAssurance = WalletSecurityAssurance.HARDWARE_BACKED,
                                walletUnitId = "unit-1",
                                operationHash = "hash-1",
                            ),
                        ),
                    securityGate = securityGate,
                )
            val session = adapter.start(context, WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"))

            val next = adapter.handle(context, session.state, WalletInteractionAction.continueFlow())

            assertEquals(WalletInteractionStatus.Completed, next.status)
            assertEquals(WalletSecurityOperation.LOCAL_HSM_UNLOCK, securityGate.lastRequest?.operation)
            assertEquals(WalletSecurityAssurance.HARDWARE_BACKED, securityGate.lastRequest?.requiredAssurance)
            assertEquals("unit-1", securityGate.lastRequest?.walletUnitId)
            assertEquals("hash-1", securityGate.lastRequest?.operationHash)
        }

    @Test
    fun approvingSecurityChallengeSubmitsPresentationWithoutLeakingGrant() =
        runTest {
            val privateStore = RecordingPrivateSessionStore()
            val executor = RecordingPresentationExecutor(Oid4vpPresentationExecutionResult.Submitted())
            val attendedAuthorization = RecordingAttendedAuthorizationRegistry()
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor = executor,
                    attendedAuthorizationRegistry = attendedAuthorization,
                )
            val context =
                WalletInteractionContext(
                    sessionId = WalletInteractionSessionId("s1"),
                    walletUnitId = "wallet",
                    executionOwner = ProtocolExecutionOwner.WALLET_APP,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = WalletInteractionSessionId("s1"),
                    walletUnitId = "wallet",
                    status = WalletInteractionStatus.SecurityUnlockRequired,
                    flowKind = WalletInteractionFlowKind.CredentialPresent,
                    protocol = WalletProtocol.OID4VP,
                    adapterId = Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID,
                    securityChallenge =
                        WalletSecurityChallenge(
                            "grant-secret",
                            WalletSecurityChallengeKind.PIN,
                            "wallet.interaction.security.pin",
                            arguments = mapOf("wallet_unit_id" to "wallet", "operation_binding" to "operation:s1-share"),
                        ),
                )

            val next =
                adapter.handle(
                    context,
                    state,
                    context.securityGrantAction(
                        WalletSecurityGrant(
                            grantId = "grant-secret",
                            assurance = WalletSecurityAssurance.USER_PRESENT,
                            expiresAtEpochSeconds = Long.MAX_VALUE,
                            evidence =
                                mapOf(
                                    "challenge_id" to "grant-secret",
                                    "wallet_unit_id" to "wallet",
                                    "operation_binding" to "operation:s1-share",
                                ),
                        ),
                    ),
                )
            val encoded = Json.encodeToString(next)

            assertEquals(WalletInteractionStatus.Completed, next.status)
            assertEquals("grant-secret", privateStore.get(next.sessionId, Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID)?.values?.get("security_grant_id"))
            assertEquals("grant-secret", attendedAuthorization.grant?.grantId)
            assertEquals("wallet", attendedAuthorization.walletUnitId)
            assertEquals("operation:s1-share", attendedAuthorization.operationBinding)
            assertFalse(encoded.contains("grant-secret"))
        }

    @Test
    fun holderPresentationExecutorSubmitsViaHolderServiceUsingPrivateSelection() =
        runTest {
            val privateStore = RecordingPrivateSessionStore()
            val holder = RecordingOid4vpHolderService()
            val resolver = RecordingSelectedCredentialResolver()
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    holder = holder,
                    presentationExecutor = Oid4vpHolderPresentationExecutor(holder, resolver, preparedOnlyHolderBindingProvider),
                    candidateResolver = StaticCandidateResolver(mapOf("identity" to listOf("cred-1"))),
                )
            val context =
                WalletInteractionContext(
                    sessionId = WalletInteractionSessionId("s1"),
                    walletUnitId = "wallet",
                    executionOwner = ProtocolExecutionOwner.WALLET_APP,
                    securityGate = RecordingSecurityGate(),
                    privateSessionStore = privateStore,
                )
            val session = adapter.start(context, WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"))

            val next =
                adapter.handle(
                    context,
                    session.state,
                    WalletInteractionAction.selectCredentials(
                        WalletCredentialSelection(mapOf("identity" to listOf("cred-1"))),
                    ),
                )
            val encoded = Json.encodeToString(next)

            assertEquals(WalletInteractionStatus.Completed, next.status)
            assertEquals(true, next.terminal)
            assertEquals(mapOf("identity" to listOf("cred-1")), resolver.lastSelection)
            assertEquals(listOf("cred-1"), holder.createdSelectedCredentials.map { it.credentialId })
            assertEquals(1, holder.submitCalls)
            assertFalse(encoded.contains("presentation-cred-1"))
        }

    @Test
    fun holderPresentationExecutorMapsRedirectSubmissionToCompletedHandoff() =
        runTest {
            val privateStore = RecordingPrivateSessionStore()
            val holder = RecordingOid4vpHolderService(submissionResult = SubmissionResult.Redirect("https://verifier.example/cb#vp_token=ok"))
            val resolver = RecordingSelectedCredentialResolver()
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    holder = holder,
                    presentationExecutor =
                        Oid4vpHolderPresentationExecutor(
                            holder,
                            resolver,
                            preparedOnlyHolderBindingProvider,
                            responseMode = ResponseMode.FRAGMENT,
                        ),
                    candidateResolver = StaticCandidateResolver(mapOf("identity" to listOf("cred-1"))),
                )
            val context =
                WalletInteractionContext(
                    sessionId = WalletInteractionSessionId("s1"),
                    walletUnitId = "wallet",
                    executionOwner = ProtocolExecutionOwner.WALLET_APP,
                    securityGate = RecordingSecurityGate(),
                    privateSessionStore = privateStore,
                )
            val session = adapter.start(context, WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"))

            val next =
                adapter.handle(
                    context,
                    session.state,
                    WalletInteractionAction.selectCredentials(
                        WalletCredentialSelection(mapOf("identity" to listOf("cred-1"))),
                    ),
                )

            assertEquals(WalletInteractionStatus.Completed, next.status)
            assertTrue(next.terminal)
            assertEquals(
                "https://verifier.example/cb#vp_token=ok",
                context.sensitiveInputAuthority.consume(
                    next.sessionId,
                    WalletInteractionSensitiveInputPurpose.PROTOCOL_COMPLETION_HANDOFF,
                    requireNotNull(next.completionHandoffRef),
                ),
            )
            assertEquals(ResponseMode.FRAGMENT, holder.submittedResponseMode)
        }

    @Test
    fun digitalCredentialResponseBecomesOneUseProtocolCompletionHandoff() =
        runTest {
            val privateStore = RecordingPrivateSessionStore()
            privateStore.put(
                WalletInteractionSessionId("s1"),
                WalletInteractionPrivateSessionData(
                    namespace = Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID,
                    values =
                        mapOf(
                            Oid4vpWalletInteractionProtocolAdapter.DIGITAL_CREDENTIAL_PROTOCOL_PRIVATE_KEY to
                                Oid4vpWalletInteractionProtocolAdapter.DIGITAL_CREDENTIAL_PROTOCOL_UNSIGNED,
                        ),
                ),
            )
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    presentationExecutor =
                        RecordingPresentationExecutor(
                            Oid4vpPresentationExecutionResult.DigitalCredentialResponse(
                                buildJsonObject { put("vp_token", JsonPrimitive("vp-secret")) },
                            ),
                        ),
                )
            val context = walletContext(privateSessionStore = privateStore)
            val state =
                credentialSelectionState(
                    WalletCredentialSelectionRequest(
                        requirements = listOf(WalletCredentialRequirement(id = "identity", candidateCredentialIds = listOf("cred-1"))),
                        satisfiable = true,
                    ),
                )

            val next =
                adapter.handle(
                    context,
                    state,
                    WalletInteractionAction.selectCredentials(
                        WalletCredentialSelection(mapOf("identity" to listOf("cred-1"))),
                    ),
                )
            val ref = requireNotNull(next.completionHandoffRef)
            val handoff =
                context.sensitiveInputAuthority.consume(
                    next.sessionId,
                    WalletInteractionSensitiveInputPurpose.PROTOCOL_COMPLETION_HANDOFF,
                    ref,
                )

            assertEquals(WalletInteractionStatus.Completed, next.status)
            assertTrue(next.terminal)
            assertEquals(
                "{\"protocol\":\"openid4vp-v1-unsigned\",\"data\":{\"vp_token\":\"vp-secret\"}}",
                handoff,
            )
            assertNull(
                context.sensitiveInputAuthority.consume(
                    next.sessionId,
                    WalletInteractionSensitiveInputPurpose.PROTOCOL_COMPLETION_HANDOFF,
                    ref,
                ),
            )
        }

    @Test
    fun holderPresentationExecutorForwardsDirectPostJwtJarmOptions() =
        runTest {
            val privateStore = RecordingPrivateSessionStore()
            val holder = RecordingOid4vpHolderService()
            val resolver = RecordingSelectedCredentialResolver()
            val jarmOptions = JarmOptions(issuer = "wallet-unit")
            val adapter =
                Oid4vpWalletInteractionProtocolAdapter(
                    holder = holder,
                    presentationExecutor =
                        Oid4vpHolderPresentationExecutor(
                            holder = holder,
                            selectedCredentialResolver = resolver,
                            sdJwtHolderBindingProvider = preparedOnlyHolderBindingProvider,
                            jarmOptionsProvider =
                                object : Oid4vpJarmOptionsProvider {
                                    override suspend fun jarmOptions(
                                        context: WalletInteractionContext,
                                        state: WalletInteractionState,
                                        resolvedRequest: ResolvedOid4vpRequest,
                                    ): JarmOptions = jarmOptions
                                },
                            responseMode = ResponseMode.DIRECT_POST_JWT,
                        ),
                    candidateResolver = StaticCandidateResolver(mapOf("identity" to listOf("cred-1"))),
                )
            val context =
                WalletInteractionContext(
                    sessionId = WalletInteractionSessionId("s1"),
                    walletUnitId = "wallet",
                    executionOwner = ProtocolExecutionOwner.WALLET_APP,
                    securityGate = RecordingSecurityGate(),
                    privateSessionStore = privateStore,
                )
            val session = adapter.start(context, WalletEntryPoint.rawQr("openid4vp://?client_id=verifier&response_type=vp_token"))

            val next =
                adapter.handle(
                    context,
                    session.state,
                    WalletInteractionAction.selectCredentials(
                        WalletCredentialSelection(mapOf("identity" to listOf("cred-1"))),
                    ),
                )

            assertEquals(WalletInteractionStatus.Completed, next.status)
            assertEquals(ResponseMode.DIRECT_POST_JWT, holder.submittedResponseMode)
            assertEquals(jarmOptions, holder.submittedJarmOptions)
        }

    @Test
    fun nestedPresentationExecutorCreatesIaeResponseWithoutSubmittingToVerifier() =
        runTest {
            val privateStore = RecordingPrivateSessionStore()
            val holder = RecordingOid4vpHolderService()
            val resolver = RecordingSelectedCredentialResolver()
            val executor = Oid4vpNestedPresentationExecutor(holder, resolver, preparedOnlyHolderBindingProvider)
            val context =
                WalletInteractionContext(
                    sessionId = WalletInteractionSessionId("s1"),
                    walletUnitId = "wallet",
                    executionOwner = ProtocolExecutionOwner.WALLET_APP,
                    privateSessionStore = privateStore,
                )
            val state =
                WalletInteractionState(
                    sessionId = WalletInteractionSessionId("s1"),
                    walletUnitId = "wallet",
                    status = WalletInteractionStatus.CredentialSelection,
                    flowKind = WalletInteractionFlowKind.CredentialPresent,
                    protocol = WalletProtocol.OID4VP,
                    adapterId = Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID,
                )
            val request =
                WalletNestedPresentationRequest(
                    protocol = WalletProtocol.OID4VP,
                    interactionType = "urn:openid:dcp:iae:openid4vp_presentation",
                    requestObject =
                        buildJsonObject {
                            put("client_id", JsonPrimitive("verifier"))
                            put("response_type", JsonPrimitive("vp_token"))
                            put("response_mode", JsonPrimitive("iae_post"))
                            put("state", JsonPrimitive("state"))
                        },
                )

            val challengeResult = executor.preparePresentation(context, state, request)

            assertTrue(challengeResult is WalletNestedPresentationExecutionResult.Success)
            assertEquals(
                "identity",
                challengeResult.value.credentialSelection
                    ?.requirements
                    ?.single()
                    ?.id
            )

            val responseResult =
                executor.createPresentationResponse(
                    context,
                    state.copy(credentialSelection = challengeResult.value.credentialSelection),
                    WalletInteractionAction.selectCredentials(
                        WalletCredentialSelection(mapOf("identity" to listOf("cred-1"))),
                    ),
                )

            assertTrue(responseResult is WalletNestedPresentationExecutionResult.Success)
            assertEquals(
                "vp-token-secret",
                responseResult.value.response["vp_token"]
                    ?.toString()
                    ?.trim('"')
            )
            assertEquals(null, responseResult.value.response["code"])
            assertEquals(0, holder.submitCalls)
            assertEquals(mapOf("identity" to listOf("cred-1")), resolver.lastSelection)
        }

    private fun context(securityGate: WalletSecurityGate): WalletInteractionContext =
        WalletInteractionContext(
            sessionId = WalletInteractionSessionId("s1"),
            walletUnitId = "wallet",
            executionOwner = ProtocolExecutionOwner.WALLET_APP,
            securityGate = securityGate,
        )

    private fun credentialSelectionState(request: WalletCredentialSelectionRequest): WalletInteractionState =
        WalletInteractionState(
            sessionId = WalletInteractionSessionId("s1"),
            walletUnitId = "wallet",
            status = WalletInteractionStatus.CredentialSelection,
            flowKind = WalletInteractionFlowKind.CredentialPresent,
            protocol = WalletProtocol.OID4VP,
            adapterId = Oid4vpWalletInteractionProtocolAdapter.ADAPTER_ID,
            credentialSelection = request,
        )

    private fun walletContext(
        privateSessionStore: WalletInteractionPrivateSessionStore = WalletInteractionPrivateSessionStore.none,
        protocolExecutor: WalletProtocolExecutor = WalletProtocolExecutor.walletApp,
        securityGate: WalletSecurityGate = WalletSecurityGate.allow,
        attributes: Map<String, String> = emptyMap(),
    ): WalletInteractionContext =
        WalletInteractionContext(
            sessionId = WalletInteractionSessionId("s1"),
            walletUnitId = "wallet",
            executionOwner = protocolExecutor.executionOwner,
            protocolExecutor = protocolExecutor,
            securityGate = securityGate,
            privateSessionStore = privateSessionStore,
            attributes = attributes,
        )

    private fun claimValuesResolver(): WalletCredentialClaimValuesResolver {
        val resolvers: Set<CredentialClaimResolver> =
            setOf(
                SdJwtClaimResolver(),
                MdocClaimResolver(IssuerSignedCborCodecImpl()),
            )
        return WalletCredentialClaimValuesResolver(
            claimsMappingService = ClaimsMappingServiceImpl(resolvers),
            credentialClaimResolvers = resolvers,
        )
    }

    private fun sdJwtCredential(payload: JsonObject): String {
        val header = """{"alg":"ES256","typ":"dc+sd-jwt"}""".encodeToByteArray().encodeToBase64Url()
        val encodedPayload = payload.toString().encodeToByteArray().encodeToBase64Url()
        return "$header.$encodedPayload.issuer-signature~"
    }

    private fun resolvedRequest(vararg credentials: DcqlCredentialQuery): ResolvedOid4vpRequest =
        ResolvedOid4vpRequest(
            request =
                AuthorizationRequest(
                    clientId = "verifier",
                    responseType = "vp_token",
                    state = "state",
                ),
            dcqlQuery =
                DcqlQuery(
                    credentials =
                        credentials.toList().ifEmpty {
                            listOf(
                                DcqlCredentialQuery(
                                    id = "pid",
                                    format = "dc+sd-jwt",
                                    meta = sdJwtVcMeta("https://example.com/pid"),
                                ),
                            )
                        },
                ),
            verifierInfo =
                VerifierInfo(
                    clientId = "verifier",
                    clientIdScheme = ClientIdScheme.PRE_REGISTERED,
                ),
        )

    private fun credentialTypeRef(
        format: CredentialFormat,
        kind: CredentialTypeRefKind,
        value: String,
    ): CredentialTypeRef =
        CredentialTypeRef(
            format = format,
            kind = kind,
            value = value,
            source = CredentialTypeRefSource.CREDENTIAL_PAYLOAD,
            primary = true,
        )

    private fun walletCredentialRecord(
        id: String,
        format: CredentialFormat,
        typeRefs: Set<CredentialTypeRef>,
        raw: String = "raw-$id",
        lifecycleState: CredentialLifecycleState = CredentialLifecycleState.ACTIVE,
        holderKid: String? = null,
    ): CredentialRecord {
        val now = Clock.System.now()
        return CredentialRecord(
            id = id,
            walletUnitId = "wallet",
            issuerRef = IdentifierRef(type = IdentifierType("https"), value = "https://issuer.example"),
            format = format,
            credentialTypeRefs = typeRefs,
            instances =
                listOf(
                    CredentialInstance(
                        id = "$id-instance",
                        walletUnitId = "wallet",
                        credentialRecordId = id,
                        format = format,
                        raw = raw,
                        bodyStorageRef = BodyStorageRef(kind = BodyStorageKind.WALLET_STORE, path = "wallet/$id/body"),
                        holderKeyRef = KeyRef(alias = "holder-$id", kid = holderKid),
                        lifecycleState = lifecycleState,
                        validity = CredentialValidityWindow(),
                        issuedAt = now,
                        storedAt = now,
                        updatedAt = now,
                    ),
                ),
            createdAt = now,
            updatedAt = now,
        )
    }

    private class RecordingWalletCredentialStore(
        initialRecords: List<CredentialRecord>,
    ) : WalletCredentialStore {
        constructor(vararg initialRecords: CredentialRecord) : this(initialRecords.toList())

        val records: MutableMap<String, CredentialRecord> = initialRecords.associateBy { it.id }.toMutableMap()
        val metadataQueries: MutableList<CredentialMetadataFilter> = mutableListOf()
        val typeRefQueries: MutableList<CredentialTypeRef> = mutableListOf()
        val credentialReads: MutableList<String> = mutableListOf()
        val putRecords: MutableList<CredentialRecord> = mutableListOf()

        override suspend fun putCredential(
            walletUnitId: String,
            record: CredentialRecord,
        ): IdkResult<CredentialRecord, IdkError> {
            records[record.id] = record
            putRecords += record
            return Ok(record).asResult()
        }

        override suspend fun getCredential(
            walletUnitId: String,
            credentialRecordId: String,
        ): IdkResult<CredentialRecord?, IdkError> {
            credentialReads += credentialRecordId
            return Ok(records[credentialRecordId]?.takeIf { it.walletUnitId == walletUnitId }).asResult()
        }

        override suspend fun getMetadata(
            walletUnitId: String,
            credentialRecordId: String,
        ): IdkResult<CredentialMetadata?, IdkError> = Ok(records[credentialRecordId]?.takeIf { it.walletUnitId == walletUnitId }?.metadata(Clock.System.now())).asResult()

        override suspend fun listMetadata(
            walletUnitId: String,
            filter: CredentialMetadataFilter,
        ): IdkResult<List<CredentialMetadata>, IdkError> {
            metadataQueries += filter
            return Ok(metadata(walletUnitId).filter { it.matches(filter) }).asResult()
        }

        override suspend fun findByCredentialTypeRef(
            walletUnitId: String,
            ref: CredentialTypeRef,
        ): IdkResult<List<CredentialMetadata>, IdkError> {
            typeRefQueries += ref
            return Ok(metadata(walletUnitId).filter { it.hasTypeRef(ref) && !it.lifecycleSummary.tombstone }).asResult()
        }

        override suspend fun deleteCredential(
            walletUnitId: String,
            credentialRecordId: String,
        ): IdkResult<Boolean, IdkError> = Ok(records.remove(credentialRecordId) != null).asResult()

        private fun metadata(walletUnitId: String): List<CredentialMetadata> =
            records
                .values
                .filter { it.walletUnitId == walletUnitId }
                .map { it.metadata(Clock.System.now()) }
    }

    private class RecordingSecurityGate : WalletSecurityGate {
        var calls: Int = 0
        var lastRequest: WalletSecurityGateRequest? = null

        override suspend fun authorize(request: WalletSecurityGateRequest): WalletSecurityGateResult {
            calls += 1
            lastRequest = request
            return WalletSecurityGateResult.Authorized(
                WalletSecurityGrant(
                    grantId = "grant",
                    assurance = WalletSecurityAssurance.USER_PRESENT,
                ),
            )
        }
    }

    private class StaticDecisionProtocolExecutor(
        private val decision: WalletProtocolExecutionDecision,
    ) : WalletProtocolExecutor {
        override val executionOwner: ProtocolExecutionOwner = decision.executionOwner

        override suspend fun plan(request: WalletProtocolExecutionRequest): WalletProtocolExecutionDecision = decision
    }

    private class RecordingProtocolExecutor(
        override val executionOwner: ProtocolExecutionOwner,
    ) : WalletProtocolExecutor {
        var lastRequest: WalletProtocolExecutionRequest? = null

        override suspend fun plan(request: WalletProtocolExecutionRequest): WalletProtocolExecutionDecision {
            lastRequest = request
            return WalletProtocolExecutionDecision.forOwner(executionOwner, request)
        }
    }

    private class RecordingOid4vpHolderService(
        private val submissionResult: SubmissionResult = SubmissionResult.Success(),
        private val resolvedRequest: ResolvedOid4vpRequest = defaultResolvedRequest(),
        private val parseError: IdkError? = null,
        private val resolveError: IdkError? = null,
        private val submitError: IdkError? = null,
    ) : Oid4vpHolderService {
        var errorSubmitCalls: Int = 0
        var submittedError: AuthorizationErrorResponse? = null
        var submitCalls: Int = 0
        var submittedResponseMode: ResponseMode? = null
        var submittedJarmOptions: JarmOptions? = null
        var createdSelectedCredentials: List<SelectedCredential> = emptyList()
        var lastParsedRequestUri: String? = null
        var lastDigitalCredentialsRequest: DigitalCredentialsAuthorizationRequest? = null

        private val authorizationRequest = resolvedRequest.request

        override suspend fun parseAuthorizationRequest(
            requestUri: String,
            walletConfig: WalletConfig?,
        ): IdkResult<AuthorizationRequest, IdkError> {
            lastParsedRequestUri = requestUri
            return parseError?.let { Err(it).asResult() } ?: Ok(authorizationRequest).asResult()
        }

        override suspend fun parseDigitalCredentialsAuthorizationRequest(
            request: DigitalCredentialsAuthorizationRequest,
            walletConfig: WalletConfig?,
        ): IdkResult<AuthorizationRequest, IdkError> {
            lastDigitalCredentialsRequest = request
            return parseError?.let { Err(it).asResult() } ?: Ok(authorizationRequest).asResult()
        }

        override suspend fun resolveAuthorizationRequest(request: AuthorizationRequest): IdkResult<ResolvedOid4vpRequest, IdkError> =
            resolveError?.let { Err(it).asResult() } ?: Ok(resolvedRequest).asResult()

        override suspend fun createAuthorizationResponse(
            request: ResolvedOid4vpRequest,
            selectedCredentials: List<SelectedCredential>,
            preparedPresentations: List<PreparedPresentation>,
        ): IdkResult<AuthorizationResponse, IdkError> {
            createdSelectedCredentials = selectedCredentials
            return Ok(
                AuthorizationResponse(
                    code = "vp-response",
                    state = "state",
                    additionalParameters = mapOf("vp_token" to JsonPrimitive("vp-token-secret")),
                ),
            ).asResult()
        }

        override suspend fun submitAuthorizationErrorResponse(
            resolvedRequest: ResolvedOid4vpRequest,
            error: AuthorizationErrorResponse,
            responseMode: ResponseMode?,
            jarmOptions: JarmOptions?,
        ): IdkResult<SubmissionResult, IdkError> {
            errorSubmitCalls++
            submittedError = error
            return submitError?.let { Err(it).asResult() } ?: Ok(submissionResult).asResult()
        }

        override suspend fun submitAuthorizationResponse(
            resolvedRequest: ResolvedOid4vpRequest,
            response: AuthorizationResponse,
            responseMode: ResponseMode?,
            jarmOptions: JarmOptions?,
        ): IdkResult<SubmissionResult, IdkError> {
            submitCalls += 1
            submittedResponseMode = responseMode
            submittedJarmOptions = jarmOptions
            return submitError?.let { Err(it).asResult() } ?: Ok(submissionResult).asResult()
        }

        companion object {
            private fun defaultResolvedRequest(): ResolvedOid4vpRequest {
                val authorizationRequest =
                    AuthorizationRequest(
                        clientId = "verifier",
                        responseType = "vp_token",
                        state = "state",
                        requestUri = "https://verifier.example/request-object",
                    )
                return ResolvedOid4vpRequest(
                    request = authorizationRequest,
                    dcqlQuery =
                        DcqlQuery(
                            credentials =
                                listOf(
                                    DcqlCredentialQuery(
                                        id = "identity",
                                        format = "dc+sd-jwt",
                                        meta = sdJwtVcMeta("urn:test:identity"),
                                    ),
                                ),
                        ),
                    verifierInfo =
                        VerifierInfo(
                            clientId = "verifier",
                            clientIdScheme = ClientIdScheme.PRE_REGISTERED,
                        ),
                )
            }
        }
    }

    private class RecordingSelectedCredentialResolver : Oid4vpSelectedCredentialResolver {
        var lastSelection: Map<String, List<String>> = emptyMap()

        override suspend fun resolveSelectedCredentials(
            context: WalletInteractionContext,
            state: WalletInteractionState,
            resolvedRequest: ResolvedOid4vpRequest,
            selectedCredentialIdsByRequirement: Map<String, List<String>>,
        ): List<SelectedCredential> {
            lastSelection = selectedCredentialIdsByRequirement
            return selectedCredentialIdsByRequirement.flatMap { (requirementId, credentialIds) ->
                credentialIds.map { credentialId ->
                    SelectedCredential(
                        credentialQueryId = requirementId,
                        credentialId = credentialId,
                        presentation = JsonPrimitive("presentation-$credentialId"),
                        credentialFormat = CredentialFormat.SD_JWT_VC,
                    )
                }
            }
        }
    }

    private class StaticCandidateResolver(
        private val candidates: Map<String, List<String>>,
    ) : Oid4vpCredentialCandidateResolver {
        override suspend fun candidateCredentialIds(
            context: WalletInteractionContext,
            resolvedRequest: ResolvedOid4vpRequest,
        ): Map<String, List<String>> = candidates
    }

    private class RecordingPresentationExecutor(
        private val result: Oid4vpPresentationExecutionResult,
    ) : Oid4vpPresentationExecutor {
        var submitCalls: Int = 0

        override suspend fun submitPresentation(
            context: WalletInteractionContext,
            state: WalletInteractionState,
        ): Oid4vpPresentationExecutionResult {
            submitCalls += 1
            return result
        }
    }

    private class RecordingPrivateSessionStore : WalletInteractionPrivateSessionStore {
        private val records = mutableMapOf<Pair<WalletInteractionSessionId, String>, WalletInteractionPrivateSessionData>()

        override suspend fun put(
            sessionId: WalletInteractionSessionId,
            data: WalletInteractionPrivateSessionData,
        ) {
            records[sessionId to data.namespace] = data
        }

        override suspend fun get(
            sessionId: WalletInteractionSessionId,
            namespace: String,
        ): WalletInteractionPrivateSessionData? = records[sessionId to namespace]

        override suspend fun remove(
            sessionId: WalletInteractionSessionId,
            namespace: String,
        ) {
            records.remove(sessionId to namespace)
        }

        override suspend fun removeSession(sessionId: WalletInteractionSessionId) {
            val keys = records.keys.filter { it.first == sessionId }
            keys.forEach { records.remove(it) }
        }
    }
}

private class RecordingAttendedAuthorizationRegistry : WalletAttendedAuthorizationRegistry {
    var walletUnitId: String? = null
    var operationBinding: String? = null
    var grant: WalletSecurityGrant? = null

    override suspend fun authorize(
        walletUnitId: String,
        operationBinding: String,
        grant: WalletSecurityGrant,
    ) {
        this.walletUnitId = walletUnitId
        this.operationBinding = operationBinding
        this.grant = grant
    }

    override suspend fun consume(
        walletUnitId: String,
        operationBinding: String,
    ): WalletSecurityGrant? = null
}
