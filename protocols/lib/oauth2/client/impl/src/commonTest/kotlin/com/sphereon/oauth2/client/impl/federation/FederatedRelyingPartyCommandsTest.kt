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

package com.sphereon.oauth2.client.impl.federation

import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.random.SecureRandom
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.generic.ManagedKeyPair
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.jose.jws.JwsCompact
import com.sphereon.crypto.jose.jws.JwsIdentifierMode
import com.sphereon.crypto.jose.jws.command.VerifyJwsArgs
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsOpts
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.di.session.SessionScope
import com.sphereon.ktor.http.client.provider.HttpClientEngineType
import com.sphereon.ktor.http.client.provider.HttpClientFactory
import com.sphereon.ktor.http.client.provider.HttpClientOptions
import com.sphereon.oauth2.client.command.CompleteFederatedAuthenticationArgs
import com.sphereon.oauth2.client.command.CreatePkceCommand
import com.sphereon.oauth2.client.command.FederatedAuthenticationRequestTransport
import com.sphereon.oauth2.client.command.FederatedAuthenticationTransaction
import com.sphereon.oauth2.client.command.FederatedOpenIdProvider
import com.sphereon.oauth2.client.command.FederatedRelyingParty
import com.sphereon.oauth2.client.command.ParseAuthorizationResponseCommand
import com.sphereon.oauth2.client.command.StartFederatedAuthenticationArgs
import com.sphereon.oauth2.client.testutil.OAuth2ClientTestContext
import com.sphereon.oauth2.common.command.ValidateIdTokenCommand
import com.sphereon.oauth2.common.model.AuthorizationServerMetadata
import dev.zacsweers.metro.ContributesTo
import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.MockRequestHandleScope
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.client.request.HttpResponseData
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.Url
import io.ktor.http.encodeURLParameter
import io.ktor.http.content.OutgoingContent
import io.ktor.http.headersOf
import io.ktor.http.parseQueryString
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
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

@ContributesTo(SessionScope::class)
interface FederatedRelyingPartyTestGraph {
    val federatedRpJwtService: JwtService
    val federatedRpSecureRandom: SecureRandom
    val federatedRpCreatePkce: CreatePkceCommand
    val federatedRpParseAuthorizationResponse: ParseAuthorizationResponseCommand
    val federatedRpValidateIdToken: ValidateIdTokenCommand
}

/**
 * Relying Party side of OpenID Federation for OpenID Connect 1.1 §12.1 against an in-memory OP: the pushed and the
 * by-value Request Object, `private_key_jwt` with the OP's Entity Identifier as audience, and ID Token verification
 * with the OP's federation keys only.
 */
class FederatedRelyingPartyCommandsTest {
    private val ctx = OAuth2ClientTestContext("federated-rp-test", this)
    private val graph = ctx.session.graph as FederatedRelyingPartyTestGraph

    private val opId = "https://op.example.org"
    private val rpId = "https://rp.example.com"
    private val anchor = "https://ta.example.net"
    private val redirectUri = "$rpId/callback"

    private class Recorded(val url: String, val form: Map<String, String>)

    private class Keys(val pair: ManagedKeyPair, val publicJwk: Jwk) {
        val kid: String get() = requireNotNull(publicJwk.kid ?: pair.kid)
    }

    private suspend fun newKeys(): Keys {
        val pair = ctx.keyManagerService.generateKeyAsync(alg = SignatureAlgorithm.ECDSA_SHA256)
        return Keys(pair, requireNotNull(pair.jose.publicJwk))
    }

    private fun metadata(automatic: Boolean = true, issuer: String = opId): AuthorizationServerMetadata {
        val json = buildJsonObject {
            put("issuer", issuer)
            put("authorization_endpoint", "$opId/authorize")
            put("token_endpoint", "$opId/token")
            put("pushed_authorization_request_endpoint", "$opId/par")
            put("response_types_supported", JsonArray(listOf(JsonPrimitive("code"))))
            put("code_challenge_methods_supported", JsonArray(listOf(JsonPrimitive("S256"))))
            put("token_endpoint_auth_methods_supported", JsonArray(listOf("private_key_jwt", "client_secret_basic").map(::JsonPrimitive)))
            put("token_endpoint_auth_signing_alg_values_supported", JsonArray(listOf(JsonPrimitive("ES256"))))
            put("request_object_signing_alg_values_supported", JsonArray(listOf(JsonPrimitive("ES256"))))
            put("id_token_signing_alg_values_supported", JsonArray(listOf(JsonPrimitive("ES256"))))
            put("authorization_response_iss_parameter_supported", true)
            if (automatic) put("client_registration_types_supported", JsonArray(listOf("automatic", "explicit").map(::JsonPrimitive)))
        }
        return Json.decodeFromJsonElement(AuthorizationServerMetadata.serializer(), json)
    }

    private fun provider(opKeys: Keys, md: AuthorizationServerMetadata = metadata(), validFor: Long = 3600) = FederatedOpenIdProvider(
        entityIdentifier = opId,
        trustAnchor = anchor,
        metadata = md,
        signingKeys = listOf(opKeys.publicJwk),
        validUntilEpochSeconds = Clock.System.now().epochSeconds + validFor,
    )

    private fun rp(keys: Keys) = FederatedRelyingParty(
        entityIdentifier = rpId,
        redirectUri = redirectUri,
        signingKey = keys.pair.joseToManagedKeyInfo(KeyVisibility.PRIVATE),
        signingKeyId = keys.kid,
        signingAlgorithm = "ES256",
        idTokenSignedResponseAlg = "ES256",
    )

    private fun factory(recorded: MutableList<Recorded>, handler: suspend MockRequestHandleScope.(Recorded) -> HttpResponseData): HttpClientFactory {
        val engine = MockEngine { request: HttpRequestData ->
            val body = (request.body as? OutgoingContent.ByteArrayContent)?.bytes()?.decodeToString()
                ?: (request.body as? io.ktor.http.content.TextContent)?.text
                ?: ""
            val form = parseQueryString(body).entries().associate { it.key to it.value.single() }
            val r = Recorded(request.url.toString(), form)
            recorded += r
            handler(r)
        }
        return object : HttpClientFactory {
            override fun createClient(options: HttpClientOptions): HttpClient = HttpClient(engine)
            override fun isSupportedOptions(options: HttpClientOptions): Boolean = true
            override fun getEngineTypesSupported(): List<HttpClientEngineType> = emptyList()
            override fun getEngineTypeDefault(): HttpClientEngineType = HttpClientEngineType.CIO
        }
    }

    private fun json(content: String, status: HttpStatusCode = HttpStatusCode.OK): suspend MockRequestHandleScope.() -> HttpResponseData = {
        respond(content, status, headersOf(HttpHeaders.ContentType, ContentType.Application.Json.toString()))
    }

    private fun start(httpClientFactory: HttpClientFactory) = StartFederatedAuthenticationCommandImpl(
        execution = ctx.execution,
        createPkceCommand = graph.federatedRpCreatePkce,
        httpClientFactory = httpClientFactory,
        jwtService = graph.federatedRpJwtService,
        secureRandom = graph.federatedRpSecureRandom,
    )

    private fun complete(httpClientFactory: HttpClientFactory) = CompleteFederatedAuthenticationCommandImpl(
        execution = ctx.execution,
        parseAuthorizationResponseCommand = graph.federatedRpParseAuthorizationResponse,
        validateIdTokenCommand = graph.federatedRpValidateIdToken,
        httpClientFactory = httpClientFactory,
        jwtService = graph.federatedRpJwtService,
        secureRandom = graph.federatedRpSecureRandom,
    )

    private fun part(jwt: String, index: Int): JsonObject =
        Json.parseToJsonElement(jwt.split('.')[index].decodeFromBase64Url().decodeToString()).jsonObject

    private fun JsonObject.str(name: String): String? = (this[name] as? JsonPrimitive)?.content

    private suspend fun verifies(jwt: String, keys: Keys): Boolean {
        val result = graph.federatedRpJwtService.verifyJws(
            VerifyJwsArgs(jws = JwsCompact(jwt), identifier = ManagedOptsKeyInfo(identifier = keys.pair.joseToManagedKeyInfo(KeyVisibility.PUBLIC))),
        )
        return result.isOk && result.value.isValid
    }

    @Test
    fun startPushesTheSignedRequestObjectWithPrivateKeyJwtForTheOpEntityIdentifier() = runTest {
        val rpKeys = newKeys()
        val opKeys = newKeys()
        val recorded = mutableListOf<Recorded>()
        val result = start(factory(recorded) { json("""{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}""", HttpStatusCode.Created)() })
            .execute(StartFederatedAuthenticationArgs(provider = provider(opKeys), relyingParty = rp(rpKeys), scope = "openid profile"))

        assertTrue(result.isOk, "start failed: ${if (result.isErr) result.error.message.defaultMessage else ""}")
        val par = recorded.single()
        assertEquals("$opId/par", par.url)
        assertEquals(setOf("client_id", "request", "client_assertion_type", "client_assertion"), par.form.keys)
        assertEquals(rpId, par.form["client_id"])
        assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", par.form["client_assertion_type"])

        val request = par.form.getValue("request")
        assertTrue(verifies(request, rpKeys), "Request Object must verify with the RP protocol key")
        val header = part(request, 0)
        assertEquals("oauth-authz-req+jwt", header.str("typ"))
        assertEquals("ES256", header.str("alg"))
        assertEquals(rpKeys.kid, header.str("kid"))
        assertNull(header["jwk"])
        assertNull(header["x5c"])
        val claims = part(request, 1)
        assertEquals(JsonPrimitive(opId), claims["aud"], "aud is the OP Entity Identifier only")
        assertEquals(rpId, claims.str("iss"))
        assertEquals(rpId, claims.str("client_id"))
        assertNull(claims["sub"], "a Request Object must not carry sub")
        assertNotNull(claims.str("jti"))
        assertTrue((claims.str("exp")!!.toLong()) > Clock.System.now().epochSeconds)
        assertEquals("code", claims.str("response_type"))
        assertEquals("openid profile", claims.str("scope"))
        assertEquals(redirectUri, claims.str("redirect_uri"))
        assertEquals("S256", claims.str("code_challenge_method"))
        assertEquals(result.value.transaction.state, claims.str("state"))
        assertEquals(result.value.transaction.nonce, claims.str("nonce"))

        val assertion = par.form.getValue("client_assertion")
        assertTrue(verifies(assertion, rpKeys), "client assertion must verify with the RP protocol key")
        val assertionClaims = part(assertion, 1)
        assertEquals(JsonPrimitive(opId), assertionClaims["aud"], "PAR client assertion aud is the OP Entity Identifier (§12.1.1.2)")
        assertEquals(rpId, assertionClaims.str("iss"))
        assertEquals(rpId, assertionClaims.str("sub"))
        assertTrue(assertionClaims.str("jti") != claims.str("jti"))

        val url = Url(result.value.authorizationUrl)
        assertEquals("$opId/authorize", url.toString().substringBefore('?'))
        assertEquals(setOf("client_id", "request_uri"), url.parameters.names())
        assertEquals("urn:ietf:params:oauth:request_uri:abc", result.value.requestUri)
        assertTrue(result.value.transaction.pushed)
    }

    @Test
    fun startPassesTheRequestObjectByValueWhenAsked() = runTest {
        val rpKeys = newKeys()
        val recorded = mutableListOf<Recorded>()
        val result = start(factory(recorded) { error("no HTTP expected") })
            .execute(
                StartFederatedAuthenticationArgs(
                    provider = provider(newKeys()),
                    relyingParty = rp(rpKeys),
                    transport = FederatedAuthenticationRequestTransport.REQUEST_OBJECT,
                    trustChain = rpTrustChain(),
                ),
            )
        assertTrue(result.isOk, "start failed: ${if (result.isErr) result.error.message.defaultMessage else ""}")
        assertTrue(recorded.isEmpty())
        val url = Url(result.value.authorizationUrl)
        assertEquals(rpId, url.parameters["client_id"])
        assertEquals("code", url.parameters["response_type"])
        assertEquals("openid", url.parameters["scope"])
        val request = assertNotNull(url.parameters["request"])
        assertTrue(verifies(request, rpKeys))
        assertEquals(JsonArray(rpTrustChain().map(::JsonPrimitive)), part(request, 0)["trust_chain"])
        assertFalse(result.value.transaction.pushed)
    }

    /** The RP's Trust Chain as the caller supplies it: RP Entity Configuration first, Trust Anchor last (§4). */
    private fun statement(iss: String, sub: String): String {
        fun b64(value: String) = value.encodeToByteArray().encodeToBase64Url()
        return b64("""{"typ":"entity-statement+jwt","alg":"ES256","kid":"k"}""") + "." + b64("""{"iss":"$iss","sub":"$sub"}""") + ".c2ln"
    }

    private fun rpTrustChain(trustAnchor: String = anchor, subject: String = rpId) =
        listOf(statement(subject, subject), statement(trustAnchor, subject), statement(trustAnchor, trustAnchor))

    // OpenID Federation for OpenID Connect 1.1 §12.1.1.1: the RP MUST select a Trust Anchor it has in common with the
    // OP. The trust_chain it sends must be its own chain to the Trust Anchor the OP was resolved under.
    @Test
    fun startRefusesATrustChainThatEndsAtAnotherTrustAnchor() = runTest {
        val result = start(factory(mutableListOf()) { error("no HTTP expected") }).execute(
            StartFederatedAuthenticationArgs(
                provider = provider(newKeys()),
                relyingParty = rp(newKeys()),
                transport = FederatedAuthenticationRequestTransport.REQUEST_OBJECT,
                trustChain = rpTrustChain(trustAnchor = "https://other-anchor.example.org"),
            ),
        )
        assertTrue(result.isErr, "a Trust Chain to a Trust Anchor the OP does not share must be refused")
        assertEquals("invalid_request", result.error.code)
    }

    @Test
    fun startRefusesATrustChainOfAnotherEntity() = runTest {
        val result = start(factory(mutableListOf()) { error("no HTTP expected") }).execute(
            StartFederatedAuthenticationArgs(
                provider = provider(newKeys()),
                relyingParty = rp(newKeys()),
                transport = FederatedAuthenticationRequestTransport.REQUEST_OBJECT,
                trustChain = rpTrustChain(subject = "https://someone-else.example.org"),
            ),
        )
        assertTrue(result.isErr, "the trust_chain must start with the RP's own Entity Configuration")
        assertEquals("invalid_request", result.error.code)
    }

    @Test
    fun startRefusesAnOpThatDoesNotSupportAutomaticRegistration() = runTest {
        val result = start(factory(mutableListOf()) { error("no HTTP expected") })
            .execute(StartFederatedAuthenticationArgs(provider = provider(newKeys(), metadata(automatic = false)), relyingParty = rp(newKeys())))
        assertTrue(result.isErr)
        assertEquals("invalid_provider_metadata", result.error.code)
    }

    @Test
    fun startRefusesAnOpWhoseIssuerIsNotItsEntityIdentifierOrWhoseChainExpired() = runTest {
        val rpKeys = newKeys()
        val wrongIssuer = start(factory(mutableListOf()) { error("no HTTP expected") })
            .execute(StartFederatedAuthenticationArgs(provider = provider(newKeys(), metadata(issuer = "https://other.example.org")), relyingParty = rp(rpKeys)))
        assertTrue(wrongIssuer.isErr)
        assertEquals("invalid_provider_metadata", wrongIssuer.error.code)

        val expired = start(factory(mutableListOf()) { error("no HTTP expected") })
            .execute(StartFederatedAuthenticationArgs(provider = provider(newKeys(), validFor = -1), relyingParty = rp(rpKeys)))
        assertTrue(expired.isErr)
        assertEquals("invalid_provider_metadata", expired.error.code)
    }

    @Test
    fun startRefusesAnOpWithoutPrivateKeyJwtOrTheRegisteredIdTokenAlgorithm() = runTest {
        val rpKeys = newKeys()
        val noPkJwt = metadata().copy(tokenEndpointAuthMethodsSupported = listOf("client_secret_basic"))
        val r1 = start(factory(mutableListOf()) { error("no HTTP expected") })
            .execute(StartFederatedAuthenticationArgs(provider = provider(newKeys(), noPkJwt), relyingParty = rp(rpKeys)))
        assertTrue(r1.isErr)
        assertEquals("invalid_provider_metadata", r1.error.code)

        val rsOnly = metadata().copy(idTokenSigningAlgValuesSupported = listOf("RS256"))
        val r2 = start(factory(mutableListOf()) { error("no HTTP expected") })
            .execute(StartFederatedAuthenticationArgs(provider = provider(newKeys(), rsOnly), relyingParty = rp(rpKeys)))
        assertTrue(r2.isErr)
        assertEquals("invalid_provider_metadata", r2.error.code)
    }

    @Test
    fun startReturnsTheFederationErrorOfThePushedAuthorizationRequest() = runTest {
        val result = start(
            factory(mutableListOf()) {
                json("""{"error":"invalid_trust_chain","error_description":"No Trust Chain to an accepted anchor"}""", HttpStatusCode.BadRequest)()
            },
        ).execute(StartFederatedAuthenticationArgs(provider = provider(newKeys()), relyingParty = rp(newKeys())))
        assertTrue(result.isErr)
        assertEquals("invalid_trust_chain", result.error.code)
        assertEquals("No Trust Chain to an accepted anchor", result.error.message.defaultMessage)
    }

    private suspend fun idToken(opKeys: Keys, claims: JsonObject, kid: String = opKeys.kid): String =
        graph.federatedRpJwtService.createJwsCompact(
            CreateJwsArgs(
                issuer = ManagedOptsKeyInfo(identifier = opKeys.pair.joseToManagedKeyInfo(KeyVisibility.PRIVATE)),
                payload = Json.encodeToString(JsonObject.serializer(), claims),
                mode = JwsIdentifierMode.AUTO,
                opts = CreateJwsOpts(noIssPayloadUpdate = true, noIdentifierInHeader = true, protectedHeader = buildJsonObject { put("typ", "JWT"); put("kid", kid) }),
            ),
        ).value.jwt

    private fun transaction(pushed: Boolean = true) = FederatedAuthenticationTransaction(
        providerEntityIdentifier = opId,
        clientId = rpId,
        redirectUri = redirectUri,
        state = "state-1",
        nonce = "nonce-1",
        codeVerifier = "verifier-0123456789-0123456789-0123456789-abc",
        pushed = pushed,
        createdAtEpochSeconds = Clock.System.now().epochSeconds,
    )

    private fun idClaims(nonce: String = "nonce-1", aud: String = rpId) = buildJsonObject {
        val now = Clock.System.now().epochSeconds
        put("iss", opId)
        put("sub", "user-1")
        put("aud", aud)
        put("iat", now)
        put("exp", now + 300)
        put("nonce", nonce)
    }

    @Test
    fun completeRedeemsTheCodeWithPrivateKeyJwtAndVerifiesTheIdTokenWithFederationKeys() = runTest {
        val rpKeys = newKeys()
        val opKeys = newKeys()
        val token = idToken(opKeys, idClaims())
        val recorded = mutableListOf<Recorded>()
        val result = complete(
            factory(recorded) {
                json("""{"access_token":"at-1","token_type":"Bearer","expires_in":300,"id_token":"$token"}""")()
            },
        ).execute(
            CompleteFederatedAuthenticationArgs(
                provider = provider(opKeys),
                relyingParty = rp(rpKeys),
                transaction = transaction(),
                callbackUrl = "$redirectUri?code=code-1&state=state-1&iss=${opId.encodeURLParameter()}",
            ),
        )
        assertTrue(result.isOk, "complete failed: ${if (result.isErr) "${result.error.code} ${result.error.message.defaultMessage}" else ""}")
        assertEquals("user-1", result.value.idTokenClaims.sub)
        assertEquals(anchor, result.value.trustAnchor)

        val tokenRequest = recorded.single()
        assertEquals("$opId/token", tokenRequest.url)
        assertEquals("authorization_code", tokenRequest.form["grant_type"])
        assertEquals("code-1", tokenRequest.form["code"])
        assertEquals(redirectUri, tokenRequest.form["redirect_uri"])
        assertEquals(transaction().codeVerifier, tokenRequest.form["code_verifier"])
        assertEquals(rpId, tokenRequest.form["client_id"])
        assertNull(tokenRequest.form["client_secret"])
        val assertion = tokenRequest.form.getValue("client_assertion")
        assertTrue(verifies(assertion, rpKeys))
        assertEquals(JsonPrimitive(opId), part(assertion, 1)["aud"])
    }

    @Test
    fun completeRefusesAnIdTokenNotSignedWithTheOpFederationKeys() = runTest {
        val opKeys = newKeys()
        val attacker = newKeys()
        // Signed by another key but claiming the OP key id.
        val forged = idToken(attacker, idClaims(), kid = opKeys.kid)
        val result = complete(factory(mutableListOf()) { json("""{"access_token":"at","token_type":"Bearer","id_token":"$forged"}""")() })
            .execute(
                CompleteFederatedAuthenticationArgs(
                    provider = provider(opKeys),
                    relyingParty = rp(newKeys()),
                    transaction = transaction(),
                    callbackUrl = "$redirectUri?code=c&state=state-1&iss=${opId.encodeURLParameter()}",
                ),
            )
        assertTrue(result.isErr)
    }

    @Test
    fun completeRefusesANonceMismatchAWrongStateAndAWrongResponseIssuer() = runTest {
        val opKeys = newKeys()
        val rpKeys = newKeys()
        val wrongNonce = idToken(opKeys, idClaims(nonce = "other"))
        val r1 = complete(factory(mutableListOf()) { json("""{"access_token":"at","token_type":"Bearer","id_token":"$wrongNonce"}""")() })
            .execute(CompleteFederatedAuthenticationArgs(provider(opKeys), rp(rpKeys), transaction(), "$redirectUri?code=c&state=state-1&iss=${opId.encodeURLParameter()}"))
        assertTrue(r1.isErr)

        val recorded = mutableListOf<Recorded>()
        val r2 = complete(factory(recorded) { error("no token request expected") })
            .execute(CompleteFederatedAuthenticationArgs(provider(opKeys), rp(rpKeys), transaction(), "$redirectUri?code=c&state=forged&iss=${opId.encodeURLParameter()}"))
        assertTrue(r2.isErr)
        val r3 = complete(factory(recorded) { error("no token request expected") })
            .execute(CompleteFederatedAuthenticationArgs(provider(opKeys), rp(rpKeys), transaction(), "$redirectUri?code=c&state=state-1&iss=https%3A%2F%2Fevil.example"))
        assertTrue(r3.isErr)
        assertTrue(recorded.isEmpty(), "nothing is redeemed after a state or issuer mismatch")
    }

    @Test
    fun completeReturnsTheOpErrorResponse() = runTest {
        val result = complete(factory(mutableListOf()) { error("no token request expected") })
            .execute(
                CompleteFederatedAuthenticationArgs(
                    provider(newKeys()),
                    rp(newKeys()),
                    transaction(),
                    "$redirectUri?error=access_denied&error_description=denied&state=state-1&iss=${opId.encodeURLParameter()}",
                ),
            )
        assertTrue(result.isErr)
        assertEquals("access_denied", result.error.code)
    }
}
