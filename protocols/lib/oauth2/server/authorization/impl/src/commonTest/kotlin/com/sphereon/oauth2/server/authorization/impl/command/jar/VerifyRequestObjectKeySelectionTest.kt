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

package com.sphereon.oauth2.server.authorization.impl.command.jar

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.jose.jws.JwsIdentifierMode
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.JwtServiceImpl
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsOpts
import com.sphereon.crypto.jose.jws.command.VerifyJwsCommand
import com.sphereon.crypto.resolution.IdentifierContext
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.ktor.http.client.FetchRequestUriArgs
import com.sphereon.ktor.http.client.FetchRequestUriCommand
import com.sphereon.ktor.http.client.FetchedRequestUri
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceConfig
import com.sphereon.oauth2.common.config.OAuth2ServersConfig
import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import com.sphereon.oauth2.common.model.GrantType
import com.sphereon.oauth2.server.authorization.command.jar.VerifyRequestObjectArgs
import com.sphereon.oauth2.server.authorization.command.jar.VerifyRequestObjectCommand
import com.sphereon.oauth2.server.authorization.error.AuthorizationServerError
import com.sphereon.oauth2.server.authorization.impl.testutil.OAuth2ServerTestContext
import com.sphereon.oauth2.server.authorization.impl.testutil.StubClientRegistry
import com.sphereon.oauth2.server.authorization.impl.testutil.TestOAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.model.ClientType
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import com.sphereon.oauth2.server.authorization.impl.storage.memory.InMemoryClientAssertionJtiStore
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Clock

/**
 * Security regression tests for [VerifyRequestObjectCommandImpl]'s STRICT key-selection
 * precedence on the RFC 9101 JAR (`request` object JWS) verification path:
 *
 *  1. inline `jwks` present -> pinned mode (resolvers disabled; inline always wins);
 *  2. else `jwks_uri` -> identifier-resolution path, but ONLY after two fail-closed guards:
 *       (2a) `jwks_uri` MUST be https (SSRF / scheme-downgrade guard);
 *       (2b) the JAR JWS header MUST carry a `kid` (so the resolver binds to that exact key);
 *  3. else (no jwks and no jwks_uri) -> fail closed with `invalid_request_object`.
 *
 * The command is wired with the REAL [VerifyJwsCommand] resolved from the session graph so the
 * pinned-JWKS verification path and the identifier-resolution system are genuine, not stubbed.
 * JARs are minted with the real [JwtService] (software KMS key) so signatures actually verify.
 *
 * Case E (a jwks_uri-only client whose JWKS is served over HTTP by a Ktor MockEngine) is NOT
 * implemented: this AS test harness ([OAuth2ServerTestContext]) constructs its AppGraph through
 * the Metro graph factory and exposes no hook to substitute the `HttpClientFactory` with a
 * MockEngine, so the JWKS HTTP fetch cannot be cleanly stubbed here. The two guards (2a/2b) plus
 * the pinned-vs-fail-closed precedence (cases A-D below) already prove the security-critical
 * selection logic; the resolver's own HTTP-fetch path is covered by the crypto resolver tests.
 */
class VerifyRequestObjectKeySelectionTest {
    private val ctx = OAuth2ServerTestContext("verify-request-object-key-selection-test", this)
    private val jwtService: JwtService = (ctx.session.graph as JwtServiceImpl.Graph).jwtService
    private val verifyJwsCommand: VerifyJwsCommand = jwtService.commands.verifyJws

    private companion object {
        const val ISSUER = "https://as.example.com"
        const val CLIENT_ID = "jar-test-client"
        const val INVALID_REQUEST_OBJECT_CODE = "invalid_request_object"
    }

    /**
     * Build a [VerifyRequestObjectCommandImpl] wired with the real JWS verifier and a single-client
     * registry. The `request_uri` fetch command is a fail-loud stub: every JAR in these tests is
     * supplied inline via `request`, so the fetch path is never legitimately reached.
     */
    private fun createCommand(client: ClientRegistration, mode: com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode = com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.PAR_ONLY): VerifyRequestObjectCommandImpl {
        val serverConfig = OAuth2ServerInstanceConfig(issuer = ISSUER, federationAutomaticRegistrationMode = mode)
        val servers = OAuth2ServersConfig(servers = mapOf("default" to serverConfig), defaultServer = "default")
        return VerifyRequestObjectCommandImpl(
            execution = ctx.execution,
            clientRegistry = StubClientRegistry(mapOf(client.clientId to client)),
            verifyJwsCommand = verifyJwsCommand,
            fetchRequestUriCommand = FailingFetchRequestUriCommand(ctx.execution),
            serversConfigProvider = TestOAuth2ServersConfigProvider(servers),
            jtiStore = lazy { jtiStore },
            actualAsSelection = com.sphereon.oauth2.server.authorization.impl.testutil.fixedAsInstanceIdProvider(),
        )
    }

    private val jtiStore = InMemoryClientAssertionJtiStore()

    private fun client(
        jwks: List<Jwk>? = null,
        jwksUri: String? = null,
    ): ClientRegistration =
        ClientRegistration(
            clientId = CLIENT_ID,
            clientName = "JAR Key Selection Test Client",
            clientType = ClientType.CONFIDENTIAL,
            grantTypes = listOf(GrantType.AUTHORIZATION_CODE),
            tokenEndpointAuthMethod = ClientAuthenticationMethod.PRIVATE_KEY_JWT,
            jwks = jwks,
            jwksUri = jwksUri,
        )

    /**
     * Mint a freshly-generated software KMS key, sign a valid JAR with it, and return the compact
     * JWS together with the public JWK (kid-stamped to match the JWS header). [includeKid] controls
     * whether the JWS protected header carries a `kid` (off => the kid-guard should fire on the
     * jwks_uri path).
     */
    private suspend fun mintJar(
        includeKid: Boolean = true,
        nowSeconds: Long = Clock.System.now().epochSeconds,
        extraClaims: Map<String, JsonElement> = emptyMap(),
        audience: JsonElement = JsonPrimitive(ISSUER),
        includeIssuerClaim: Boolean = true,
        includeClientIdClaim: Boolean = true,
        algorithm: SignatureAlgorithm = SignatureAlgorithm.ECDSA_SHA256,
        typ: String? = VerifyRequestObjectCommand.JAR_JWT_TYP,
    ): SignedJar {
        val managedKeyPair = ctx.keyManagerService.generateKeyAsync(alg = algorithm)
        val keyInfo: ManagedKeyInfoType<*> = managedKeyPair.joseToManagedKeyInfo(KeyVisibility.PRIVATE)

        val issuer =
            ManagedOptsKeyInfo(
                identifier = keyInfo,
                context = IdentifierContext(clientId = CLIENT_ID.takeIf { includeClientIdClaim }, issuer = CLIENT_ID.takeIf { includeIssuerClaim }),
            )

        // typ MUST be the JAR media type (RFC 9101 §10.8); iss/client_id are filled by the
        // issuer context, aud/exp/iat are valid for the AS issuer.
        val payload =
            buildJsonObject {
                if (includeIssuerClaim) put("iss", JsonPrimitive(CLIENT_ID))
                if (includeClientIdClaim) put("client_id", JsonPrimitive(CLIENT_ID))
                put("aud", audience)
                put("exp", JsonPrimitive(nowSeconds + 600))
                put("iat", JsonPrimitive(nowSeconds))
                put("response_type", JsonPrimitive("code"))
                put("scope", JsonPrimitive("openid"))
                extraClaims.forEach { (name, value) -> put(name, value) }
            }

        val opts =
            CreateJwsOpts(
                // Exact omission fixture: sign this payload without automatic issuer/client-id enrichment.
                noIssPayloadUpdate = true,
                protectedHeader = buildJsonObject { typ?.let { put("typ", JsonPrimitive(it)) } },
                // includeKid=false: suppress all identifier hints in the header (alg still set),
                // so the produced JWS carries no `kid`.
                noIdentifierInHeader = !includeKid,
            )

        val createResult =
            jwtService.createJwsCompact(
                CreateJwsArgs(issuer = issuer, payload = payload, mode = JwsIdentifierMode.AUTO, opts = opts),
            )
        check(createResult.isOk) { "Failed to mint JAR: ${createResult.error}" }
        val jwt = createResult.value.jwt

        val headerKid = readHeaderKid(jwt)
        val publicJwk = stampKid(managedKeyPair.jose.publicJwk, headerKid)
        return SignedJar(jwt = jwt, publicJwk = publicJwk, headerKid = headerKid,
            privateJwk = managedKeyPair.jose.privateJwk?.let { stampKid(it, headerKid) })
    }

    private fun readHeaderKid(jwt: String): String? {
        val headerJson =
            Json.parseToJsonElement(jwt.substringBefore('.').decodeFromBase64Url().decodeToString()) as? JsonObject
                ?: return null
        return (headerJson["kid"] as? JsonPrimitive)?.content
    }

    /** Round-trip the JWK through JSON to stamp the header `kid` (so pinned-mode selection matches). */
    private fun stampKid(
        jwk: Jwk,
        kid: String?,
    ): Jwk {
        if (kid == null) return jwk
        val asJson = Json.encodeToJsonElement(Jwk.serializer(), jwk).jsonObject
        val withKid = JsonObject(asJson + ("kid" to JsonPrimitive(kid)))
        return Json.decodeFromJsonElement(Jwk.serializer(), withKid)
    }

    private fun argsFor(jwt: String): VerifyRequestObjectArgs =
        VerifyRequestObjectArgs(
            requestJwt = jwt,
            clientIdHint = CLIENT_ID,
            issuer = ISSUER,
            queryParameters = mapOf("client_id" to CLIENT_ID),
        )

    private fun errorCode(result: IdkResult<*, *>): String? = if (result.isErr) (result.error as? IdkError)?.code else null

    @Test
    fun federationRequestObjectRequiresSignedClientIdAlongsideIssuer() = runTest {
        val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("connect-issuer-only")), includeClientIdClaim = false)
        val claims = Json.parseToJsonElement(jar.jwt.split('.')[1].decodeFromBase64Url().decodeToString()).jsonObject
        assertEquals(CLIENT_ID, (claims["iss"] as? JsonPrimitive)?.content)
        assertTrue("client_id" !in claims, "real signed fixture must omit client_id")
        val strict = createCommand(client(jwks = listOf(jar.publicJwk)).copy(singleUseRequestObjects = true))
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(strict.execute(argsFor(jar.jwt))))
    }

    @Test
    fun federationRequestObjectRequiresSignedIssuerAlongsideClientId() = runTest {
        val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("connect-client-id-only")), includeIssuerClaim = false)
        val claims = Json.parseToJsonElement(jar.jwt.split('.')[1].decodeFromBase64Url().decodeToString()).jsonObject
        assertEquals(CLIENT_ID, (claims["client_id"] as? JsonPrimitive)?.content)
        assertTrue("iss" !in claims, "real signed fixture must omit iss")
        val strict = createCommand(client(jwks = listOf(jar.publicJwk)).copy(singleUseRequestObjects = true))
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(strict.execute(argsFor(jar.jwt))))
    }

    @Test
    fun federationRequestObjectWithBothSignedIdentifiersRemainsValid() = runTest {
        val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("connect-both-identifiers")))
        val claims = Json.parseToJsonElement(jar.jwt.split('.')[1].decodeFromBase64Url().decodeToString()).jsonObject
        assertEquals(CLIENT_ID, (claims["iss"] as? JsonPrimitive)?.content)
        assertEquals(CLIENT_ID, (claims["client_id"] as? JsonPrimitive)?.content)
        assertTrue(createCommand(client(jwks = listOf(jar.publicJwk)).copy(singleUseRequestObjects = true)).execute(argsFor(jar.jwt)).isOk)
    }

    @Test
    fun genericRequestObjectKeepsItsExistingSingleIdentifierRules() = runTest {
        for (issuerOnly in listOf(true, false)) {
            val jar = mintJar(includeIssuerClaim = issuerOnly, includeClientIdClaim = !issuerOnly)
            val claims = Json.parseToJsonElement(jar.jwt.split('.')[1].decodeFromBase64Url().decodeToString()).jsonObject
            assertEquals(issuerOnly, "iss" in claims, "generic fixture must retain the chosen signed identity")
            assertEquals(!issuerOnly, "client_id" in claims, "generic fixture must retain the chosen signed identity")
            assertTrue(createCommand(client(jwks = listOf(jar.publicJwk))).execute(argsFor(jar.jwt)).isOk)
        }
    }
    // ─── Single-use Request Objects ─────────────────────────────────────────────────────────────

    @Test
    fun singleUseRequestObjectsRequireAFreshJtiNoSubAndOnlyThisAudience() =
        runTest {
            suspend fun verify(jar: SignedJar) =
                createCommand(client(jwks = listOf(jar.publicJwk)).copy(singleUseRequestObjects = true)).execute(argsFor(jar.jwt))

            val once = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("jar-1")))
            assertTrue(verify(once).isOk, "a fresh jti must verify")
            assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(verify(once)), "a replayed jti must be refused")

            assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(verify(mintJar())), "a missing jti must be refused")
            assertEquals(
                INVALID_REQUEST_OBJECT_CODE,
                errorCode(verify(mintJar(extraClaims = mapOf("jti" to JsonPrimitive("jar-2"), "sub" to JsonPrimitive(CLIENT_ID))))),
                "sub must be refused",
            )
            val twoAudiences = JsonArray(listOf(JsonPrimitive(ISSUER), JsonPrimitive("https://other.example.com")))
            assertEquals(
                INVALID_REQUEST_OBJECT_CODE,
                errorCode(verify(mintJar(extraClaims = mapOf("jti" to JsonPrimitive("jar-3")), audience = twoAudiences))),
                "a second audience must be refused",
            )

            val ordinary = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("jar-4")))
            val regular = createCommand(client(jwks = listOf(ordinary.publicJwk)))
            assertTrue(regular.execute(argsFor(ordinary.jwt)).isOk)
            assertTrue(regular.execute(argsFor(ordinary.jwt)).isOk, "other clients keep their existing rules")
        }

    // ─── Case A: pinned (inline jwks) mode unchanged ──────────────────────────────────────────

    @Test
    fun pinnedMode_jarSignedByPinnedKey_verifies() =
        runTest {
            val jar = mintJar()
            val cmd = createCommand(client(jwks = listOf(jar.publicJwk)))

            val result = cmd.execute(argsFor(jar.jwt))

            assertTrue(
                result.isOk,
                "A JAR signed by the client's inline jwks key must verify (pinned mode). " +
                    "error=${errorCode(result)}",
            )
            assertEquals(CLIENT_ID, result.value.clientId)
        }

    @Test
    fun pinnedMode_jarSignedByDifferentKey_isRejected_resolversNeverConsulted() =
        runTest {
            // Pin one key, sign with a completely different freshly-generated key. Pinned mode
            // disables resolvers, so there is no fallback that could rescue the wrong signature.
            val pinned = mintJar()
            val attacker = mintJar()
            val cmd = createCommand(client(jwks = listOf(pinned.publicJwk)))

            val result = cmd.execute(argsFor(attacker.jwt))

            assertTrue(result.isErr, "A JAR signed by a key NOT in the client's inline jwks must be rejected")
            assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(result))
        }

    // ─── Case B: https guard on jwks_uri ──────────────────────────────────────────────────────

    @Test
    fun jwksUriMode_insecureHttpUri_isRejectedBeforeResolution() =
        runTest {
            val jar = mintJar(includeKid = true)
            // No inline jwks; jwks_uri is http:// (not https) -> the SSRF/scheme guard must fire
            // BEFORE any resolution is attempted.
            val cmd = createCommand(client(jwksUri = "http://insecure.example.com/jwks"))

            val result = cmd.execute(argsFor(jar.jwt))

            assertTrue(result.isErr, "An http:// jwks_uri must be rejected for JAR verification")
            assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(result))
            val message = (result.error as? IdkError)?.message?.defaultMessage ?: ""
            assertTrue(
                message.contains("https", ignoreCase = true),
                "Rejection message must indicate the https requirement, got: $message",
            )
        }

    // ─── Case C: kid guard on jwks_uri ────────────────────────────────────────────────────────

    @Test
    fun jwksUriMode_jarWithoutKid_isRejectedBeforeResolution() =
        runTest {
            // Valid https jwks_uri, but the JAR header carries NO kid -> the kid guard must fire
            // so the resolver cannot fall back to a kid-absent first()-pick.
            val jar = mintJar(includeKid = false)
            assertNotNull(jar) // sanity
            check(jar.headerKid == null) { "Test setup error: expected a JAR without a kid header" }
            val cmd = createCommand(client(jwksUri = "https://secure.example.com/jwks"))

            val result = cmd.execute(argsFor(jar.jwt))

            assertTrue(result.isErr, "A JAR without a kid must be rejected on the jwks_uri path")
            assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(result))
            val message = (result.error as? IdkError)?.message?.defaultMessage ?: ""
            assertTrue(
                message.contains("kid", ignoreCase = true),
                "Rejection message must indicate the kid requirement, got: $message",
            )
        }

    // ─── Case D: fail closed when neither jwks nor jwks_uri is configured ─────────────────────

    @Test
    fun noKeySource_failsClosed() =
        runTest {
            val jar = mintJar()
            val cmd = createCommand(client(jwks = null, jwksUri = null))

            val result = cmd.execute(argsFor(jar.jwt))

            assertTrue(result.isErr, "A client with neither jwks nor jwks_uri must fail closed")
            assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(result))
        }

    private fun federationClient(jar: SignedJar): ClientRegistration =
        client(jwks = listOf(jar.publicJwk)).copy(
            singleUseRequestObjects = true,
            authorizationRequestProofPolicy = com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC,
        )

    private fun headerTyp(jwt: String): String? =
        (Json.parseToJsonElement(jwt.substringBefore('.').decodeFromBase64Url().decodeToString()).jsonObject["typ"] as? JsonPrimitive)?.content

    // OpenID Federation 1.1 §12.1.1.1 does not require `typ` on the Request Object, and RFC 9101
    // §10.8 notes that requiring it breaks OpenID Connect deployments. Federation RPs may omit it.
    @Test
    fun untypedFederationRequestObjectWithoutSubIsAccepted() = runTest {
        val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("untyped-federation")), typ = null)
        assertEquals(null, headerTyp(jar.jwt), "fixture must carry no typ")
        val result = createCommand(federationClient(jar)).execute(argsFor(jar.jwt))
        assertTrue(result.isOk, "An untyped federation Request Object must verify: ${if (result.isErr) result.error else ""}")
        assertNotNull(result.value.authorizationEvidence)
    }

    @Test
    fun untypedFederationRequestObjectWithSubIsRejected() = runTest {
        val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("untyped-federation-sub"), "sub" to JsonPrimitive(CLIENT_ID)), typ = null)
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(createCommand(federationClient(jar)).execute(argsFor(jar.jwt))))
    }

    @Test
    fun federationRequestObjectWithAnotherTypIsRejected() = runTest {
        for (typ in listOf("JWT", "jwt", "dpop+jwt", "")) {
            val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("wrong-typ-$typ")), typ = typ)
            assertEquals(typ, headerTyp(jar.jwt))
            assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(createCommand(federationClient(jar)).execute(argsFor(jar.jwt))), "typ '$typ'")
        }
    }

    @Test
    fun untypedRequestObjectIsRejectedOutsideFederation() = runTest {
        val plain = mintJar(typ = null)
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(createCommand(client(jwks = listOf(plain.publicJwk))).execute(argsFor(plain.jwt))))
        val singleUse = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("untyped-single-use")), typ = null)
        val strict = client(jwks = listOf(singleUse.publicJwk)).copy(singleUseRequestObjects = true)
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(createCommand(strict).execute(argsFor(singleUse.jwt))))
    }

    @Test
    fun federationSignedParametersNeverInheritUnsignedQueryFallback() = runTest {
        val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("signed-only-parameters")))
        val registration = client(jwks = listOf(jar.publicJwk)).copy(
            singleUseRequestObjects = true,
            authorizationRequestProofPolicy = com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC,
        )
        val result = createCommand(registration).execute(argsFor(jar.jwt).copy(queryParameters = mapOf(
            "client_id" to CLIENT_ID, "redirect_uri" to "https://unsigned.example/callback",
            "resource" to "https://unsigned.example/resource", "code_challenge" to "a".repeat(43),
            "scope" to "unsigned_scope",
        )))
        assertTrue(result.isOk, "The real signed fixture must verify")
        assertEquals("openid", result.value.mergedParameters["scope"])
        for (name in listOf("redirect_uri", "resource", "code_challenge")) {
            assertTrue(name !in result.value.mergedParameters, "Unsigned $name must not become signed authorization data")
        }
    }

    @Test
    fun actualFederationSignatureProducesProcessOnlyEvidence() = runTest {
        val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("actual-process-evidence")))
        val registration = client(jwks = listOf(jar.publicJwk)).copy(
            singleUseRequestObjects = true,
            authorizationRequestProofPolicy = com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC,
        )
        val result = createCommand(registration).execute(argsFor(jar.jwt))
        assertTrue(result.isOk)
        assertNotNull(result.value.authorizationEvidence, "Only actual signature and claim verification may mint process evidence")
    }

    @Test
    fun signedFutureNotBeforeIsRejectedBeforeReplayConsumption() = runTest {
        assertNotBeforeRejected(JsonPrimitive(Clock.System.now().epochSeconds + 3600), "future-nbf")
    }

    @Test
    fun signedMalformedNotBeforeIsRejectedBeforeReplayConsumption() = runTest {
        assertNotBeforeRejected(JsonPrimitive("not-a-date"), "malformed-nbf")
    }

    private suspend fun assertNotBeforeRejected(nbf: JsonPrimitive, jti: String) {
        val rejected = mintJar(extraClaims = mapOf("jti" to JsonPrimitive(jti), "nbf" to nbf))
        val registration = client(jwks = listOf(rejected.publicJwk)).copy(singleUseRequestObjects = true)
        val result = createCommand(registration).execute(argsFor(rejected.jwt))
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(result), "A signed nbf must be enforced by the real verifier")
        val corrected = mintJar(extraClaims = mapOf("jti" to JsonPrimitive(jti), "nbf" to JsonPrimitive(Clock.System.now().epochSeconds - 1)))
        assertTrue(createCommand(registration.copy(jwks = listOf(corrected.publicJwk))).execute(argsFor(corrected.jwt)).isOk,
            "Temporal refusal must precede replay insertion")
    }

    @Test
    fun signedStringExpNumericDateMustBeRejectedBeforeReplayConsumption() = runTest {
        assertMalformedNumericDateRejected("exp", JsonPrimitive((Clock.System.now().epochSeconds + 600).toString()), "exp-string-date")
    }

    @Test
    fun signedObjectExpNumericDateMustBeRejectedBeforeReplayConsumption() = runTest {
        assertMalformedNumericDateRejected("exp", JsonObject(emptyMap()), "exp-object-date")
    }

    @Test
    fun signedMalformedExpNumericDateMustBeRejectedBeforeReplayConsumption() = runTest {
        assertMalformedNumericDateRejected("exp", JsonPrimitive("not-a-date"), "exp-malformed-date")
    }

    @Test
    fun signedStringIatNumericDateMustBeRejectedBeforeReplayConsumption() = runTest {
        assertMalformedNumericDateRejected("iat", JsonPrimitive((Clock.System.now().epochSeconds - 1).toString()), "iat-string-date")
    }

    @Test
    fun signedObjectIatNumericDateMustBeRejectedBeforeReplayConsumption() = runTest {
        assertMalformedNumericDateRejected("iat", JsonObject(emptyMap()), "iat-object-date")
    }

    @Test
    fun signedMalformedIatNumericDateMustBeRejectedBeforeReplayConsumption() = runTest {
        assertMalformedNumericDateRejected("iat", JsonPrimitive("not-a-date"), "iat-malformed-date")
    }

    private suspend fun assertMalformedNumericDateRejected(claim: String, value: JsonElement, jti: String) {
        val rejected = mintJar(extraClaims = mapOf("jti" to JsonPrimitive(jti), claim to value))
        val registration = client(jwks = listOf(rejected.publicJwk)).copy(singleUseRequestObjects = true)
        val result = try { createCommand(registration).execute(argsFor(rejected.jwt)) }
            catch (unexpected: IllegalArgumentException) { kotlin.test.fail("Untrusted $claim must return controlled invalid_request_object, not ${unexpected::class.simpleName}") }
            catch (unexpected: IllegalStateException) { kotlin.test.fail("Untrusted $claim must return controlled invalid_request_object, not ${unexpected::class.simpleName}") }
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(result))
        val corrected = mintJar(extraClaims = mapOf("jti" to JsonPrimitive(jti), claim to JsonPrimitive(
            Clock.System.now().epochSeconds + if (claim == "exp") 600 else -1)))
        assertTrue(createCommand(registration.copy(jwks = listOf(corrected.publicJwk))).execute(argsFor(corrected.jwt)).isOk,
            "Malformed date rejection must not consume the real replay entry")
    }

    @Test
    fun signedFractionalNumericDatesRemainValidJsonNumbers() = runTest {
        val now = Clock.System.now().epochSeconds
        val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("fractional-numeric-dates"),
            "exp" to JsonPrimitive(now + 600.5), "iat" to JsonPrimitive(now - 1.5), "nbf" to JsonPrimitive(now - 0.5)))
        val registration = client(jwks = listOf(jar.publicJwk)).copy(singleUseRequestObjects = true)
        assertTrue(createCommand(registration).execute(argsFor(jar.jwt)).isOk, "NumericDate permits finite fractional JSON numbers")
    }

    @Test
    fun federationRs256ProofIsBoundToRealSignatureAndImmutableSignedRequest() = runTest {
        assertFederationProof(SignatureAlgorithm.RSA_SHA256, "RS256")
    }

    @Test
    fun federationEs256ProofIsBoundToRealSignatureAndImmutableSignedRequest() = runTest {
        assertFederationProof(SignatureAlgorithm.ECDSA_SHA256, "ES256")
    }

    @Test
    fun federationEs384ProofIsBoundToRealSignatureAndImmutableSignedRequest() = runTest {
        assertFederationProof(SignatureAlgorithm.ECDSA_SHA384, "ES384")
    }

    @Test
    fun federationEs512ProofIsBoundToRealSignatureAndImmutableSignedRequest() = runTest {
        assertFederationProof(SignatureAlgorithm.ECDSA_SHA512, "ES512")
    }

    private suspend fun assertFederationProof(algorithm: SignatureAlgorithm, joseAlgorithm: String) {
        val jar = mintJar(algorithm = algorithm, extraClaims = mapOf(
            "jti" to JsonPrimitive("actual-proof-$joseAlgorithm"),
            "state" to JsonPrimitive("signed-state"),
            "redirect_uri" to JsonPrimitive("https://rp.example/callback"),
            "code_challenge" to JsonPrimitive("a".repeat(43)),
            "code_challenge_method" to JsonPrimitive("S256"),
        ))
        val registration = client(jwks = listOf(jar.publicJwk)).copy(
            requestObjectSigningAlg = joseAlgorithm,
            redirectUris = listOf("https://rp.example/callback"),
            responseTypes = listOf(com.sphereon.oauth2.common.model.ResponseType.CODE),
            singleUseRequestObjects = true,
            authorizationRequestProofPolicy = com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC,
        )
        val command = createCommand(registration, com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.SIGNED_JAR_OR_AUTHENTICATED_PAR)
        val unsigned = mutableMapOf("client_id" to CLIENT_ID, "state" to "unsigned-state")
        val result = command.execute(argsFor(jar.jwt).copy(queryParameters = unsigned))
        assertTrue(result.isOk, "$joseAlgorithm must use the actual SoftwareKMS/JwtService verifier: ${errorCode(result)}")
        assertEquals(joseAlgorithm, result.value.signingAlg)
        val proof = assertNotNull(result.value.authorizationEvidence)
        val scope = com.sphereon.oauth2.server.authorization.impl.command.authorization.FederationAuthorizationScope(
            ctx.execution.tenantId, "default", ISSUER,
            com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.SIGNED_JAR_OR_AUTHENTICATED_PAR,
        )
        val parsed = com.sphereon.oauth2.server.authorization.impl.command.authorization.parseAuthorizationParameters(result.value.mergedParameters)
        assertTrue(parsed.isOk)
        val request = parsed.value.copy(authorizationEvidence = proof)
        fun accepted(candidate: com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData = request,
                     selected: com.sphereon.oauth2.server.authorization.impl.command.authorization.FederationAuthorizationScope = scope,
                     currentClient: ClientRegistration = registration) =
            com.sphereon.oauth2.server.authorization.impl.command.authorization.validFederationAuthorizationEvidence(proof, selected, candidate, currentClient)
        assertTrue(accepted(), "Only the fully verified signed parameters match")
        suspend fun authorize(client: ClientRegistration = registration,
                              mode: com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode = com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.SIGNED_JAR_OR_AUTHENTICATED_PAR,
                              par: com.sphereon.oauth2.common.config.FeaturePolicy = com.sphereon.oauth2.common.config.FeaturePolicy.SUPPORTED,
                              evidence: com.sphereon.oauth2.server.authorization.command.jar.AuthorizationRequestEvidence? = proof): IdkResult<*, *> {
            val config = OAuth2ServerInstanceConfig(issuer = ISSUER, federationAutomaticRegistrationMode = mode, par = par,
                responseTypesSupported = setOf("code"))
            val verifier = com.sphereon.oauth2.server.authorization.impl.command.authorization.VerifyAuthorizationRequestCommandImpl(
                ctx.execution, StubClientRegistry(mapOf(client.clientId to client)),
                TestOAuth2ServersConfigProvider(OAuth2ServersConfig(servers = mapOf("default" to config), defaultServer = "default")),
                emptySet(), com.sphereon.oauth2.server.authorization.impl.provider.NoCredentialIssuerAudienceResolver(),
                com.sphereon.oauth2.server.authorization.impl.command.authorization.Oid4vciUnregisteredWalletAdmissionRule(),
                com.sphereon.oauth2.server.authorization.impl.testutil.fixedAsInstanceIdProvider(),
            )
            return verifier.execute(request.copy(authorizationEvidence = evidence))
        }
        val authorized = authorize()
        assertTrue(authorized.isOk, "$joseAlgorithm real signed proof must reach normal authorization: ${errorCode(authorized)}")
        val counterfeit = authorize(evidence = object : com.sphereon.oauth2.server.authorization.command.jar.AuthorizationRequestEvidence {})
        assertTrue(counterfeit.isErr)
        assertEquals("Invalid request: A client-bound signed federation Request Object is required", (counterfeit.error as IdkError).message.defaultMessage)
        assertTrue(authorize(mode = com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.PAR_ONLY).isErr)
        assertTrue(authorize(par = com.sphereon.oauth2.common.config.FeaturePolicy.REQUIRED).isErr)
        assertTrue(authorize(client = registration.copy(requirePushedAuthorizationRequests = true)).isErr)

        unsigned["state"] = "changed-after-verification"
        assertTrue(accepted(), "Evidence must not retain the mutable outer query map")
        assertEquals("signed-state", request.state)
        assertTrue(!accepted(request.copy(state = "changed")), "A parser/applyDuring substitution must fail")
        assertTrue(!accepted(selected = scope.copy(tenantId = "another-tenant")))
        assertTrue(!accepted(selected = scope.copy(serverKey = "another-server")))
        assertTrue(!accepted(selected = scope.copy(issuer = "https://another-as.example")))
        assertTrue(!accepted(currentClient = registration.copy(clientId = "another-client")))
        assertTrue(!accepted(currentClient = registration.copy(jwks = null)), "Losing resolved keys must refuse safely")
        val replacement = mintJar(algorithm = algorithm, extraClaims = mapOf("jti" to JsonPrimitive("replacement-$joseAlgorithm")))
        assertTrue(!accepted(currentClient = registration.copy(jwks = listOf(replacement.publicJwk))), "Rotated keys require fresh verified evidence")
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(command.execute(argsFor(replacement.jwt))), "A real signature from an unregistered key must fail")
        assertTrue(createCommand(registration.copy(jwks = listOf(replacement.publicJwk)),
            com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.SIGNED_JAR_OR_AUTHENTICATED_PAR).execute(argsFor(replacement.jwt)).isOk,
            "The matching current key must verify the same real token; signature refusal must not consume jti")
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(command.execute(argsFor(jar.jwt))), "The real replay store must refuse another verification")
    }

    @Test
    fun fabricatedEvidenceCannotSatisfyCurrentFederationProof() = runTest {
        val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("fabrication-negative")))
        val registration = client(jwks = listOf(jar.publicJwk)).copy(
            authorizationRequestProofPolicy = com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC,
        )
        val real = createCommand(registration).execute(argsFor(jar.jwt))
        assertTrue(real.isOk)
        val parsed = com.sphereon.oauth2.server.authorization.impl.command.authorization.parseAuthorizationParameters(real.value.mergedParameters)
        assertTrue(parsed.isOk)
        val scope = com.sphereon.oauth2.server.authorization.impl.command.authorization.FederationAuthorizationScope(
            ctx.execution.tenantId, "default", ISSUER,
            com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode.PAR_ONLY,
        )
        assertTrue(!com.sphereon.oauth2.server.authorization.impl.command.authorization.validFederationAuthorizationEvidence(
            object : com.sphereon.oauth2.server.authorization.command.jar.AuthorizationRequestEvidence {}, scope, parsed.value, registration,
        ))
    }


    @Test
    fun realHmacRequestObjectCannotMintFederationPublicProof() = runTest {
        val signed = mintRealHmacJar("asymmetric-hmac-negative")
        assertNotNull(signed.secretJwk.k, "Fixture must contain the actual generated HMAC material")
        val registration = client(jwks = listOf(signed.secretJwk)).copy(singleUseRequestObjects = true,
            authorizationRequestProofPolicy = com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC)
        val result = createCommand(registration).execute(argsFor(signed.jwt))
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(result), "Actual pinned public JWK selection must refuse HS256")
    }

    @Test
    fun realOctetMaterialCannotActAsFederationAsymmetricPublicKey() = runTest {
        val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("asymmetric-octet-negative")))
        val octet = mintRealHmacJar("octet-material-negative")
        val registration = client(jwks = listOf(octet.publicProjection.copy(kid = jar.headerKid))).copy(singleUseRequestObjects = true,
            authorizationRequestProofPolicy = com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC)
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(createCommand(registration).execute(argsFor(jar.jwt))))
        val publicControl = createCommand(registration.copy(jwks = listOf(jar.publicJwk))).execute(argsFor(jar.jwt))
        assertTrue(publicControl.isOk, "The same actual EC signature must work with its public asymmetric material")
        assertNotNull(publicControl.value.authorizationEvidence)
    }

    @Test
    fun matchingPrivateAsymmetricKeyCannotEnterFederationPublicVerificationSet() = runTest {
        val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("asymmetric-private-negative")))
        val privateMaterial = assertNotNull(jar.privateJwk)
        assertNotNull(privateMaterial.d, "Fixture must contain the actual private EC component")
        val registration = client(jwks = listOf(privateMaterial)).copy(singleUseRequestObjects = true,
            authorizationRequestProofPolicy = com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC)
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(createCommand(registration).execute(argsFor(jar.jwt))))
        val publicControl = createCommand(registration.copy(jwks = listOf(jar.publicJwk))).execute(argsFor(jar.jwt))
        assertTrue(publicControl.isOk, "Refusing private material must not consume the replay entry")
        assertNotNull(publicControl.value.authorizationEvidence)
    }

    private suspend fun mintRealHmacJar(jti: String): HmacJar {
        val provider = (ctx.app as com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderFactoryImpl.Graph)
            .softwareKmsProvider.create(com.sphereon.crypto.kms.provider.software.SoftwareKmsProviderConfig(
                id = "federation-negative-hmac", persistKeysDuringGeneration = true, exposePrivateKeysDuringGeneration = true,
            ), ctx.execution)
        val generated = provider.generateKeyAsync(alg = SignatureAlgorithm.HMAC_SHA256)
        val kid = assertNotNull(generated.kid)
        val secret = assertNotNull(generated.jose.privateJwk).copy(kid = kid)
        val now = Clock.System.now().epochSeconds
        val header = buildJsonObject {
            put("alg", JsonPrimitive("HS256")); put("kid", JsonPrimitive(kid))
            put("typ", JsonPrimitive(VerifyRequestObjectCommand.JAR_JWT_TYP))
        }
        val payload = buildJsonObject {
            put("iss", JsonPrimitive(CLIENT_ID)); put("client_id", JsonPrimitive(CLIENT_ID))
            put("aud", JsonPrimitive(ISSUER)); put("exp", JsonPrimitive(now + 600)); put("iat", JsonPrimitive(now))
            put("jti", JsonPrimitive(jti)); put("response_type", JsonPrimitive("code")); put("scope", JsonPrimitive("openid"))
        }
        val input = header.toString().encodeToByteArray().encodeToBase64Url() + "." + payload.toString().encodeToByteArray().encodeToBase64Url()
        val mac = provider.generateMac(keyId = kid, message = input.encodeToByteArray(), digestAlgorithm = com.sphereon.crypto.core.generic.DigestAlg.SHA256)
        assertTrue(provider.verifyMac(keyId = kid, message = input.encodeToByteArray(), mac = mac,
            digestAlgorithm = com.sphereon.crypto.core.generic.DigestAlg.SHA256), "Fixture must have a genuine provider-verified HMAC")
        return HmacJar(input + "." + mac.encodeToBase64Url(), secret, generated.jose.publicJwk.copy(kid = kid))
    }

    private data class HmacJar(val jwt: String, val secretJwk: Jwk, val publicProjection: Jwk)

    @Test
    fun legacyConsumedJarRemainsRejectedAfterFederationProofPolicyUpgrade() = runTest {
        val jar = mintJar(extraClaims = mapOf("jti" to JsonPrimitive("legacy-to-federation-policy-upgrade")))
        val legacy = client(jwks = listOf(jar.publicJwk)).copy(singleUseRequestObjects = true)
        val consumed = createCommand(legacy).execute(argsFor(jar.jwt))
        assertTrue(consumed.isOk, "The genuine signed JAR must first be consumed by the legacy single-use policy")
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(createCommand(legacy).execute(argsFor(jar.jwt))),
            "The same store must already reject the consumed JAR before the policy upgrade")
        val upgraded = legacy.copy(
            authorizationRequestProofPolicy = com.sphereon.oauth2.server.authorization.model.AuthorizationRequestProofPolicy.FEDERATED_RP_ASYMMETRIC,
        )
        assertEquals(INVALID_REQUEST_OBJECT_CODE, errorCode(createCommand(upgraded).execute(argsFor(jar.jwt))),
            "Enabling federation proof must preserve the existing replay address for the same client and signed JAR")
    }

    private data class SignedJar(
        val jwt: String,
        val publicJwk: Jwk,
        val headerKid: String?,
        val privateJwk: Jwk? = null,
    )

    /**
     * Fail-loud [FetchRequestUriCommand] stub. Every test supplies the JAR inline via `request`,
     * so a fetch attempt signals a wiring/logic error rather than a legitimate `request_uri` flow.
     */
    private class FailingFetchRequestUriCommand(
        execution: SessionExecution,
    ) : TypedServiceCommandAdapter<FetchRequestUriArgs, FetchedRequestUri, IdkError>(
            commandId = FetchRequestUriCommand.COMMAND_ID,
            execution = execution,
            inputTypeToken = typeToken<FetchRequestUriArgs>(),
            outputTypeToken = typeToken<FetchedRequestUri>(),
        ),
        FetchRequestUriCommand {
        override suspend fun supports(args: Any): Boolean = args is FetchRequestUriArgs

        override suspend fun doExecute(
            args: FetchRequestUriArgs,
            applyDuring: (FetchRequestUriArgs) -> FetchRequestUriArgs,
        ): IdkResult<FetchedRequestUri, IdkError> = Err(IdkError.fromString(code = "stub", message = "FailingFetchRequestUriCommand must never be called in these tests"))
    }
}
