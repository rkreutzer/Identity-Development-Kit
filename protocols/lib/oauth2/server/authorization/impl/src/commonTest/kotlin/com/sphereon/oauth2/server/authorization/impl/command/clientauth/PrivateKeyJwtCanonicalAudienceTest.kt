/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.oauth2.server.authorization.impl.command.clientauth

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.error.IdkError
import com.sphereon.oauth2.common.command.VerifyDpopProofCommand
import com.sphereon.oauth2.common.model.VerifyDpopProofOptions
import com.sphereon.oauth2.common.model.VerifyDpopProofResult
import com.sphereon.oauth2.server.authorization.command.ClientAuthenticationEndpoint
import com.sphereon.oauth2.server.authorization.command.par.HandlePushedAuthorizationRequestArgs
import com.sphereon.oauth2.server.authorization.impl.command.par.HandlePushedAuthorizationRequestCommandImpl
import com.sphereon.oauth2.server.authorization.impl.command.orchestration.StubAuthorizationServerService
import com.sphereon.oauth2.server.authorization.impl.command.orchestration.stubParsePushedAuthorizationRequest
import com.sphereon.oauth2.server.authorization.impl.command.orchestration.stubCreateRequestUri
import com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy
import com.sphereon.oauth2.server.authorization.storage.ClientAssertionJtiStore
import kotlin.time.Instant
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.jose.jws.JwsIdentifierMode
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.JwtServiceImpl
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsOpts
import com.sphereon.crypto.resolution.IdentifierContext
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.model.ClientAssertion
import com.sphereon.oauth2.common.model.ClientAuthenticationConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.server.authorization.command.BuildServerMetadataArgs
import com.sphereon.oauth2.server.authorization.command.VerifyClientAuthenticationArgs
import com.sphereon.oauth2.server.authorization.command.clientauth.VerifyAttestationClientAuthCommand
import com.sphereon.oauth2.server.authorization.impl.resolver.DefaultClientJwksResolver
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryClientAssertionJtiStore
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.StubClientRegistry
import com.sphereon.oauth2.server.authorization.impl.testutil.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.impl.testutil.newBuildServerMetadataCommand
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientType
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Clock

/** Real software-KMS assertions and production pinned-key verification; not durable-store or conformance evidence. */
class PrivateKeyJwtCanonicalAudienceTest {
    private val ctx = OAuth2ServerTestContext("private-key-jwt-canonical-audience", this)
    private val jwtService: JwtService = (ctx.session.graph as JwtServiceImpl.Graph).jwtService
    private companion object {
        const val CLIENT = "private-key-client"
        const val FEDERATED_CLIENT = "https://rp.example.com"
        const val ISSUER = "https://as.example.com/tenant/as/"
        const val ENDPOINT = "https://as.example.com/tenant/as/token"
        const val OTHER_ENDPOINT = "https://other-as.example.com/token"
    }
    private data class SignedAssertion(val jwt: String, val jwk: Jwk, val alg: String, val clientId: String = CLIENT)
    private fun provider(config: OAuth2ServerInstanceConfig = OAuth2ServerInstanceConfig(issuer = ISSUER)) =
        TestOAuth2ServersConfigProvider(OAuth2ServersConfig(servers = mapOf(
            "default" to config,
            "sibling" to OAuth2ServerInstanceConfig(issuer = "https://other-as.example.com"),
        ), defaultServer = "default"))

    private suspend fun mint(
        audience: JsonElement = JsonPrimitive(ISSUER),
        algorithm: SignatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
        jti: String = "assertion-${Clock.System.now()}",
        clientId: String = CLIENT,
        issuer: String = clientId,
        subject: String = clientId,
        expiresIn: Long = 300,
    ): SignedAssertion {
        val pair = ctx.keyManagerService.generateKeyAsync(alg = algorithm)
        val privateInfo: ManagedKeyInfoType<*> = pair.joseToManagedKeyInfo(KeyVisibility.PRIVATE)
        val now = Clock.System.now().epochSeconds
        val result = jwtService.createJwsCompact(CreateJwsArgs(
            issuer = ManagedOptsKeyInfo(identifier = privateInfo, context = IdentifierContext(clientId = clientId, issuer = clientId)),
            payload = buildJsonObject {
                put("iss", JsonPrimitive(issuer)); put("sub", JsonPrimitive(subject))
                put("aud", audience); put("iat", JsonPrimitive(now))
                put("exp", JsonPrimitive(now + expiresIn)); put("jti", JsonPrimitive(jti))
            },
            mode = JwsIdentifierMode.AUTO,
            opts = CreateJwsOpts(noIssPayloadUpdate = true),
        ))
        assertTrue(result.isOk, "Real assertion signing must succeed")
        val jwt = result.value.jwt
        val header = Json.parseToJsonElement(jwt.substringBefore('.').decodeFromBase64Url().decodeToString()).jsonObject
        val kid = assertNotNull(header["kid"] as? JsonPrimitive).content
        val alg = assertNotNull(header["alg"] as? JsonPrimitive).content
        val publicJson = Json.encodeToJsonElement(Jwk.serializer(), pair.jose.publicJwk).jsonObject
        val publicJwk = Json.decodeFromJsonElement(Jwk.serializer(), JsonObject(publicJson + ("kid" to JsonPrimitive(kid))))
        return SignedAssertion(jwt, publicJwk, alg, clientId)
    }

    private fun command(
        signed: SignedAssertion,
        config: OAuth2ServerInstanceConfig = OAuth2ServerInstanceConfig(issuer = ISSUER),
        proofPolicy: AuthorizationRequestProofPolicy = AuthorizationRequestProofPolicy.NONE,
        assertionJtis: ClientAssertionJtiStore = InMemoryClientAssertionJtiStore(),
    ) =
        VerifyClientAuthenticationCommandImpl(
            execution = ctx.execution,
            clientRegistry = StubClientRegistry(mapOf(signed.clientId to ClientRegistration(
                clientId = signed.clientId, clientType = ClientType.CONFIDENTIAL,
                grantTypes = if (proofPolicy == AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC) listOf(GrantType.AUTHORIZATION_CODE) else listOf(GrantType.CLIENT_CREDENTIALS),
                tokenEndpointAuthMethod = ClientAuthenticationMethod.PRIVATE_KEY_JWT,
                tokenEndpointAuthSigningAlg = listOf(signed.alg), jwks = listOf(signed.jwk),
                authorizationRequestProofPolicy = proofPolicy,
            ))),
            jwtService = lazyOf(jwtService), configProvider = provider(config),
            clientJwksResolver = lazyOf(DefaultClientJwksResolver()),
            jtiStore = lazyOf(assertionJtis),
            verifyAttestationClientAuthCommand = lazy<VerifyAttestationClientAuthCommand> { error("Private-key authentication must not use attestation") },
        )
    private fun args(
        signed: SignedAssertion,
        requestEndpoint: String = ENDPOINT,
        endpoint: ClientAuthenticationEndpoint = ClientAuthenticationEndpoint.OTHER,
    ) = VerifyClientAuthenticationArgs(
        clientAuthentication = ClientAuthenticationConfig.PrivateKeyJwt(ClientAssertion(signed.clientId,
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", signed.jwt)),
        clientId = signed.clientId, tokenEndpointUrl = requestEndpoint, endpoint = endpoint,
    )
    private suspend fun acceptsDiscoveredEndpoint(algorithm: SignatureAlgorithm, expectedAlg: String) {
        val metadata = ctx.newBuildServerMetadataCommand(provider()).execute(BuildServerMetadataArgs(includeSignedMetadata = false))
        assertTrue(metadata.isOk, "Actual metadata generation must succeed")
        assertEquals(ENDPOINT, metadata.value.tokenEndpoint)
        val issuerControl = mint(algorithm = algorithm)
        assertEquals(expectedAlg, issuerControl.alg)
        assertTrue(command(issuerControl).execute(args(issuerControl)).isOk, "Issuer compatibility and real signature control")
        val signed = mint(JsonPrimitive(assertNotNull(metadata.value.tokenEndpoint)), algorithm)
        assertEquals(expectedAlg, signed.alg)
        assertTrue(command(signed).execute(args(signed, OTHER_ENDPOINT)).isOk, "Trusted discovered endpoint wins over incoming argument")
    }
    @Test fun rs256AcceptsCanonicalDiscoveredEndpoint() = runTest { acceptsDiscoveredEndpoint(SignatureAlgorithm.RSA_SHA256, "RS256") }
    @Test fun es256AcceptsCanonicalDiscoveredEndpoint() = runTest { acceptsDiscoveredEndpoint(SignatureAlgorithm.ECDSA_SHA256, "ES256") }
    @Test fun es384AcceptsCanonicalDiscoveredEndpoint() = runTest { acceptsDiscoveredEndpoint(SignatureAlgorithm.ECDSA_SHA384, "ES384") }
    @Test fun es512AcceptsCanonicalDiscoveredEndpoint() = runTest { acceptsDiscoveredEndpoint(SignatureAlgorithm.ECDSA_SHA512, "ES512") }
    @Test fun singletonEndpointArrayAccepts() = runTest {
        val signed = mint(JsonArray(listOf(JsonPrimitive(ENDPOINT))))
        assertTrue(command(signed).execute(args(signed)).isOk)
    }
    @Test fun repeatedEndpointAssertionRejects() = runTest {
        val signed = mint(JsonPrimitive(ENDPOINT)); val verifier = command(signed)
        assertTrue(verifier.execute(args(signed)).isOk)
        assertTrue(verifier.execute(args(signed)).isErr)
    }
    @Test fun repeatedIssuerAssertionRejects() = runTest {
        val signed = mint(); val verifier = command(signed)
        assertTrue(verifier.execute(args(signed)).isOk)
        assertTrue(verifier.execute(args(signed)).isErr)
    }
    @Test fun siblingEndpointAndSpoofedIncomingArgumentReject() = runTest {
        val signed = mint(JsonPrimitive(OTHER_ENDPOINT))
        assertTrue(command(signed).execute(args(signed, OTHER_ENDPOINT)).isErr)
    }
    @Test fun absentFixedIssuerCannotTrustIncomingEndpoint() = runTest {
        val signed = mint(JsonPrimitive(ENDPOINT))
        assertTrue(command(signed, OAuth2ServerInstanceConfig(issuer = null)).execute(args(signed)).isErr)
    }
    @Test fun blankFixedIssuerCannotTrustIncomingEndpoint() = runTest {
        val signed = mint(JsonPrimitive(ENDPOINT))
        assertTrue(command(signed, OAuth2ServerInstanceConfig(issuer = " ")).execute(args(signed)).isErr)
    }
    @Test fun templateOnlyIssuerCannotTrustIncomingEndpoint() = runTest {
        val signed = mint(JsonPrimitive(ENDPOINT))
        assertTrue(command(signed, OAuth2ServerInstanceConfig(issuer = null, issuerTemplate = "https://as.example.com/{tenant-id}")).execute(args(signed)).isErr)
    }
    @Test fun issuerPlusEndpointArrayRejects() = runTest {
        val signed = mint(JsonArray(listOf(JsonPrimitive(ISSUER), JsonPrimitive(ENDPOINT))))
        assertTrue(command(signed).execute(args(signed)).isErr)
    }
    @Test fun duplicatedEndpointArrayRejects() = runTest {
        val signed = mint(JsonArray(listOf(JsonPrimitive(ENDPOINT), JsonPrimitive(ENDPOINT))))
        assertTrue(command(signed).execute(args(signed)).isErr)
    }
    @Test fun malformedAudienceArrayRejects() = runTest {
        val signed = mint(JsonArray(listOf(JsonPrimitive(ISSUER), JsonPrimitive(17))))
        assertTrue(command(signed).execute(args(signed)).isErr)
    }
    @Test fun wrongSignatureRejectsEvenWithRegisteredKid() = runTest {
        val registered = mint(); val attacker = mint()
        val registeredJson = Json.encodeToJsonElement(Jwk.serializer(), registered.jwk).jsonObject
        val registeredWithAttackerKid = Json.decodeFromJsonElement(Jwk.serializer(),
            JsonObject(registeredJson + ("kid" to JsonPrimitive(assertNotNull(attacker.jwk.kid)))))
        val verifier = command(registered.copy(jwk = registeredWithAttackerKid))
        assertTrue(verifier.execute(args(attacker)).isErr)
    }
    @Test fun foreignIssuerRejects() = runTest {
        val signed = mint(issuer = "other-client")
        assertTrue(command(signed).execute(args(signed)).isErr)
    }
    @Test fun foreignSubjectRejects() = runTest {
        val signed = mint(subject = "other-client")
        assertTrue(command(signed).execute(args(signed)).isErr)
    }
    @Test fun expiredAssertionRejects() = runTest {
        val signed = mint(expiresIn = -1)
        assertTrue(command(signed).execute(args(signed)).isErr)
    }
    private class CountingAssertionJtiStore : ClientAssertionJtiStore {
        var calls = 0
        private val delegate = InMemoryClientAssertionJtiStore()
        override suspend fun recordIfNew(clientId: String, jti: String, expiresAt: Instant): Boolean {
            calls++
            return delegate.recordIfNew(clientId, jti, expiresAt)
        }
    }

    /** Real signature/registered RP keys, with observing downstream ports rather than a fabricated PAR success. */
    private suspend fun rejectsFederatedParTokenEndpoint(algorithm: SignatureAlgorithm, expectedAlg: String) {
        val signed = mint(JsonPrimitive(ENDPOINT), algorithm, clientId = FEDERATED_CLIENT)
        assertEquals(expectedAlg, signed.alg)
        val jtis = CountingAssertionJtiStore()
        val verifier = command(signed, proofPolicy = AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC, assertionJtis = jtis)
        var parses = 0
        var parWrites = 0
        val service = StubAuthorizationServerService(
            verifyClientAuthenticationStub = verifier,
            parsePushedAuthorizationRequestStub = stubParsePushedAuthorizationRequest {
                parses++
                Err(IdkError.fromString(code = "unexpected_par_parse", message = "Rejected federation assertion reached PAR parsing"))
            },
            createRequestUriStub = stubCreateRequestUri {
                parWrites++
                Err(IdkError.fromString(code = "unexpected_par_write", message = "Rejected federation assertion reached PAR persistence"))
            },
        )
        val dpop = object : VerifyDpopProofCommand {
            override val inputTypeToken = typeToken<VerifyDpopProofOptions>()
            override val outputTypeToken = typeToken<VerifyDpopProofResult>()
            override val isEnabled = true
            override suspend fun execute(args: VerifyDpopProofOptions): IdkResult<VerifyDpopProofResult, IdkError> =
                error("No DPoP header is supplied")
        }
        val result = HandlePushedAuthorizationRequestCommandImpl(ctx.execution, service, dpop).execute(
            HandlePushedAuthorizationRequestArgs(
                requestBody = mapOf(
                    "client_id" to listOf(signed.clientId),
                    "client_assertion_type" to listOf("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
                    "client_assertion" to listOf(signed.jwt),
                ),
                requestHeaders = emptyMap(),
                parEndpointUrl = "https://as.example.com/tenant/as/par",
            ),
        )
        assertTrue(result.isErr)
        assertEquals("invalid_client", result.error.code)
        assertTrue(result.error.message.defaultMessage.contains("audience"))
        assertEquals(0, jtis.calls, "Audience refusal precedes replay-store effects")
        assertEquals(0, parses, "Audience refusal precedes PAR parsing")
        assertEquals(0, parWrites, "Audience refusal precedes PAR persistence")
    }

    @Test fun rs256FederatedParTokenEndpointAudienceRejectsBeforeEffects() = runTest {
        rejectsFederatedParTokenEndpoint(SignatureAlgorithm.RSA_SHA256, "RS256")
    }
    @Test fun es256FederatedParTokenEndpointAudienceRejectsBeforeEffects() = runTest {
        rejectsFederatedParTokenEndpoint(SignatureAlgorithm.ECDSA_SHA256, "ES256")
    }
    @Test fun es384FederatedParTokenEndpointAudienceRejectsBeforeEffects() = runTest {
        rejectsFederatedParTokenEndpoint(SignatureAlgorithm.ECDSA_SHA384, "ES384")
    }
    @Test fun es512FederatedParTokenEndpointAudienceRejectsBeforeEffects() = runTest {
        rejectsFederatedParTokenEndpoint(SignatureAlgorithm.ECDSA_SHA512, "ES512")
    }
    @Test fun federatedParIssuerAudienceAcceptsForAllFourAlgorithms() = runTest {
        for (algorithm in listOf(SignatureAlgorithm.RSA_SHA256, SignatureAlgorithm.ECDSA_SHA256, SignatureAlgorithm.ECDSA_SHA384, SignatureAlgorithm.ECDSA_SHA512)) {
            val signed = mint(algorithm = algorithm, clientId = FEDERATED_CLIENT)
            val jtis = CountingAssertionJtiStore()
            val verifier = command(signed, proofPolicy = AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC, assertionJtis = jtis)
            assertTrue(verifier.execute(args(signed, endpoint = ClientAuthenticationEndpoint.PAR)).isOk)
            assertEquals(1, jtis.calls)
            assertTrue(verifier.execute(args(signed, endpoint = ClientAuthenticationEndpoint.PAR)).isErr, "Accepted federation assertion must still reject replay")
        }
    }
    @Test fun ordinaryParCanonicalAudienceAcceptsForAllFourAlgorithms() = runTest {
        for (algorithm in listOf(SignatureAlgorithm.RSA_SHA256, SignatureAlgorithm.ECDSA_SHA256, SignatureAlgorithm.ECDSA_SHA384, SignatureAlgorithm.ECDSA_SHA512)) {
            val signed = mint(JsonPrimitive(ENDPOINT), algorithm, clientId = FEDERATED_CLIENT)
            assertTrue(command(signed).execute(args(signed, endpoint = ClientAuthenticationEndpoint.PAR)).isOk)
        }
    }
    @Test fun federatedNonParCanonicalAudienceRemainsAccepted() = runTest {
        for (endpoint in listOf(ClientAuthenticationEndpoint.TOKEN, ClientAuthenticationEndpoint.INTROSPECTION, ClientAuthenticationEndpoint.REVOCATION, ClientAuthenticationEndpoint.OTHER)) {
            val signed = mint(JsonPrimitive(ENDPOINT), clientId = FEDERATED_CLIENT)
            assertTrue(command(signed, proofPolicy = AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC).execute(args(signed, endpoint = endpoint)).isOk)
        }
    }
    @Test fun federatedParSingletonIssuerAudienceAccepts() = runTest {
        val signed = mint(JsonArray(listOf(JsonPrimitive(ISSUER))), clientId = FEDERATED_CLIENT)
        assertTrue(command(signed, proofPolicy = AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC).execute(args(signed, endpoint = ClientAuthenticationEndpoint.PAR)).isOk)
    }
    @Test fun federatedParSingletonTokenEndpointAudienceRejectsBeforeJti() = runTest {
        val signed = mint(JsonArray(listOf(JsonPrimitive(ENDPOINT))), clientId = FEDERATED_CLIENT)
        val jtis = CountingAssertionJtiStore()
        val result = command(signed, proofPolicy = AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC, assertionJtis = jtis).execute(args(signed, endpoint = ClientAuthenticationEndpoint.PAR))
        assertTrue(result.isErr)
        assertEquals("invalid_client", result.error.code)
        assertEquals(0, jtis.calls)
    }
    @Test fun federatedParIssuerPlusEndpointAudienceRejectsBeforeJti() = runTest {
        val signed = mint(JsonArray(listOf(JsonPrimitive(ISSUER), JsonPrimitive(ENDPOINT))), clientId = FEDERATED_CLIENT)
        val jtis = CountingAssertionJtiStore()
        val result = command(signed, proofPolicy = AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC, assertionJtis = jtis).execute(args(signed, endpoint = ClientAuthenticationEndpoint.PAR))
        assertTrue(result.isErr)
        assertEquals("invalid_client", result.error.code)
        assertEquals(0, jtis.calls)
    }
}
