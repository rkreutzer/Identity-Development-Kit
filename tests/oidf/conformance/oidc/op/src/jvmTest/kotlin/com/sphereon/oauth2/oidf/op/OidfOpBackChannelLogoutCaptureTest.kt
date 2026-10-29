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

package com.sphereon.oauth2.oidf.op

import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.request.forms.submitForm
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.statement.bodyAsText
import io.ktor.http.HttpStatusCode
import io.ktor.http.Parameters
import io.ktor.http.isSuccess
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.RSAPublicKeySpec
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * Real-delivery Back-Channel Logout 1.0 capture test. Complements the failure-path coverage
 * in [OidfOpLogoutTest.backChannelLogoutDeliveryDoesNotBlockEndSessionResponse]: that test
 * pins the registered `backchannel_logout_uri` to the unreachable conformance host so the
 * orchestrator's fire-and-forget path is exercised end to end. Here, the registered URI is
 * rewritten to a localhost capture server so the actual minted `logout_token` JWT is
 * inspected against the spec's wire-shape requirements.
 *
 * Override mechanism: [DefaultPrincipalMapPropertySource] is a globally mirrored
 * `MEDIUM`-priority source that wins over the file-backed `LOW`-priority source the
 * harness's `application.properties` populates. Publishing
 * `oauth2.clients.oidf-op-basic.backchannel-logout-uri=<localhost>` before the fixture is
 * built feeds the override through `OAuth2ClientsConfigBinder` so the per-session
 * `ConfigAwareClientRegistry` picks it up at lazy-load time. The override is removed in
 * `tearDown` so the singleton state does not leak into other tests.
 *
 * Spec assertions per OIDC Back-Channel Logout 1.0 §2.4:
 *   - Header: `typ=logout+jwt`, `alg=RS256`, `kid` matches the AS's published JWKS kid.
 *   - Payload: `iss` matches the AS issuer, `aud` matches the RP's client_id, `iat` is
 *     recent, `jti` is non-empty, `events` is the single-key object
 *     `{ "http://schemas.openid.net/event/backchannel-logout": {} }`, `sub` matches
 *     the alice subject, `sid` is present (the harness pins
 *     `backchannel_logout_session_required=true` for `oidf-op-basic`), and `nonce` is
 *     absent.
 *   - Signature verifies against the AS's RS256 public key from `/.well-known/jwks.json`.
 */
class OidfOpBackChannelLogoutCaptureTest {
    private val overrideKey = "oauth2.clients.oidf-op-basic.backchannel-logout-uri"

    private lateinit var capture: BackChannelCaptureServer
    private lateinit var fixture: OidfOpServerFixture
    private lateinit var client: HttpClient
    private val json = Json { ignoreUnknownKeys = true }
    private val overrides = HarnessPropertyOverride()

    @BeforeTest
    fun setUp() {
        // 1. Allocate the capture server first so its URL is known before the fixture spins up.
        // 2. Publish the override on the principal-scoped default-map source. PropertySources
        //    sort ascending by order: MEDIUM (default-map) precedes LOW (application.properties),
        //    so the per-session ClientRegistry sees the localhost URL when it lazy-loads.
        // 3. Build the fixture, which runs OidfOpBootstrap.seed and starts the AS Netty server.
        //    Bootstrap does not touch the client registry, so the lazy load is deferred until the
        //    first request session, by which time the override is in place.
        capture = BackChannelCaptureServer.start()
        overrides.publish(overrideKey, capture.url)
        fixture = OidfOpServerFixture()
        // Register the actual owning AS issuer before minting any logout token.
        overrides.publish("oauth2.servers.default.issuer", fixture.baseUrl)
        client = HttpClient(CIO) { followRedirects = false }
    }

    @AfterTest
    fun tearDown() {
        client.close()
        fixture.stop()
        overrides.close()
        capture.stop()
    }

    @Test
    fun backChannelLogoutDeliversValidSignedLogoutTokenToRp() =
        runBlocking {
            // Step 1: drive a happy-path login + token exchange so the AS has a live OidcLoginSession
            // bound to oidf-op-basic for alice. The id_token captures the sid we expect to round-trip
            // through the logout_token.
            val login = drivePkceLogin(state = "bc-capture", nonce = "bc-capture-nonce")
            val idTokenPayload = decodeJwsPayload(login.idToken)
            val expectedSid =
                idTokenPayload["sid"]?.jsonPrimitive?.contentOrNull
                    ?: error("id_token must carry sid (oidf-op-basic has backchannel_logout_session_required=true)")
            val expectedSub =
                idTokenPayload["sub"]?.jsonPrimitive?.contentOrNull
                    ?: error("id_token must carry sub")

            // Step 2: trigger end-session. Posting id_token_hint plus the login cookie causes the
            // orchestrator to fan out Back-Channel logout to every participating RP.
            val logoutResponse =
                client.get(
                    "${fixture.baseUrl}/logout?id_token_hint=${urlEncode(login.idToken)}" +
                        "&post_logout_redirect_uri=${urlEncode("http://localhost:8080/post-logout")}" +
                        "&state=bc-capture-state",
                ) {
                    header("Cookie", login.loginCookie)
                }
            assertTrue(
                logoutResponse.status == HttpStatusCode.Found || logoutResponse.status == HttpStatusCode.OK,
                "end-session response must be 200 or 302; got ${logoutResponse.status}",
            )

            // Step 3: wait for the capture server to receive the POST. A 5s budget covers Ktor
            // engine warm-up and the IDK fire-and-forget dispatch path; failure to receive within
            // the budget surfaces as TimeoutCancellationException so the test fails loudly rather
            // than silently passing on a misconfigured override.
            val capturedToken = withTimeout(5.seconds) { capture.logoutToken.await() }

            // Step 4a: verify JOSE header.
            val header = decodeJwsHeader(capturedToken)
            assertEquals(
                "logout+jwt",
                header["typ"]?.jsonPrimitive?.contentOrNull,
                "OIDC BC §2.4: logout_token JOSE header typ MUST be logout+jwt",
            )
            assertEquals(
                "RS256",
                header["alg"]?.jsonPrimitive?.contentOrNull,
                "harness signs id_tokens with RS256; logout_token MUST share the alg",
            )
            val tokenKid =
                header["kid"]?.jsonPrimitive?.contentOrNull
                    ?: error("logout_token JOSE header must carry kid")

            // Step 4b: cross-reference the kid against the AS's published JWKS.
            val jwk = fetchSigningJwk(tokenKid)
            assertEquals("RSA", jwk["kty"]?.jsonPrimitive?.contentOrNull, "advertised key must be RSA for RS256")
            assertEquals("sig", jwk["use"]?.jsonPrimitive?.contentOrNull, "advertised key must declare use=sig")

            // Step 4c: verify payload claims per BC §2.4.
            val payload = decodeJwsPayload(capturedToken)
            assertEquals(
                fixture.baseUrl,
                payload["iss"]?.jsonPrimitive?.contentOrNull,
                "iss MUST equal the AS issuer URL the RP sees in discovery",
            )
            assertEquals(
                "oidf-op-basic",
                payload["aud"]?.jsonPrimitive?.contentOrNull,
                "aud MUST equal the receiving RP's client_id",
            )
            val iat =
                payload["iat"]?.jsonPrimitive?.contentOrNull?.toLongOrNull()
                    ?: error("iat MUST be present and numeric")
            val nowEpochSeconds = System.currentTimeMillis() / 1000
            assertTrue(
                iat in (nowEpochSeconds - 60)..(nowEpochSeconds + 5),
                "iat MUST be recent (within 60s); iat=$iat now=$nowEpochSeconds",
            )
            val jti = payload["jti"]?.jsonPrimitive?.contentOrNull
            assertNotNull(jti, "jti MUST be present")
            assertTrue(jti.isNotBlank(), "jti MUST NOT be blank")
            assertEquals(
                expectedSub,
                payload["sub"]?.jsonPrimitive?.contentOrNull,
                "sub MUST match the original id_token sub",
            )
            assertEquals(
                expectedSid,
                payload["sid"]?.jsonPrimitive?.contentOrNull,
                "sid MUST match the original id_token sid (oidf-op-basic requires session-bound logout)",
            )
            assertNull(
                payload["nonce"],
                "BC §2.4 explicitly forbids nonce in logout_token",
            )
            val events =
                payload["events"]?.jsonObject
                    ?: error("events MUST be present and a JSON object")
            val backchannelEventKey = "http://schemas.openid.net/event/backchannel-logout"
            assertTrue(
                events.containsKey(backchannelEventKey),
                "events MUST carry the BC §2.4 event key '$backchannelEventKey'",
            )
            val eventValue = events[backchannelEventKey]?.jsonObject
            assertNotNull(eventValue, "events.<key> MUST be a JSON object")
            assertTrue(eventValue.isEmpty(), "BC §2.4: the event value MUST be an empty JSON object")

            // Step 4d: cryptographically verify the signature against the JWKS public key.
            assertTrue(
                verifyRs256(capturedToken, jwk),
                "logout_token signature MUST verify against the AS's published JWKS RS256 key",
            )
        }

    private suspend fun drivePkceLogin(
        state: String,
        nonce: String,
        username: String = "alice",
    ): LoginResult {
        val pkce = SimpleBackChannelPkceFixture(suffix = state)
        val authorizeUrl =
            "${fixture.baseUrl}/authorize?response_type=code" +
                "&client_id=oidf-op-basic" +
                "&redirect_uri=${urlEncode("http://localhost:8080/test-callback")}" +
                "&scope=openid" +
                "&state=$state" +
                "&nonce=$nonce" +
                "&code_challenge=${pkce.challenge}" +
                "&code_challenge_method=S256"
        val authorizeResponse = client.get(authorizeUrl)
        assertEquals(HttpStatusCode.Found, authorizeResponse.status)
        val loginRedirect = authorizeResponse.headers["Location"] ?: error("missing Location")
        val loginUrl = if (loginRedirect.startsWith("http")) loginRedirect else "${fixture.baseUrl}$loginRedirect"
        val sessionId = extractQueryParam(loginUrl, "session_id") ?: error("missing session_id")
        val returnUrl = extractQueryParam(loginUrl, "return_url") ?: error("missing return_url")

        val loginResponse =
            submitLoginWithCsrf(
                client = client,
                baseUrl = fixture.baseUrl,
                loginUrl = loginUrl,
                sessionId = sessionId,
                returnUrl = returnUrl,
                username = username,
                password = OidfOpBootstrap.FIXTURE_PASSWORD,
            )
        assertEquals(HttpStatusCode.Found, loginResponse.status)
        val loginCookie = loginResponse.headers["Set-Cookie"] ?: error("POST /login must Set-Cookie")

        val resumed =
            client.get(loginResponse.headers["Location"]!!) {
                header("Cookie", loginCookie)
            }
        assertEquals(HttpStatusCode.Found, resumed.status)
        val callback = resumed.headers["Location"] ?: error("missing callback")
        val code = extractQueryParam(callback, "code") ?: error("missing code")

        val basicAuth =
            java.util.Base64
                .getEncoder()
                .encodeToString("oidf-op-basic:oidf-op-basic-secret-2026".encodeToByteArray())
        val tokenResponse =
            client.submitForm(
                url = "${fixture.baseUrl}/token",
                formParameters =
                    Parameters.build {
                        append("grant_type", "authorization_code")
                        append("code", code)
                        append("redirect_uri", "http://localhost:8080/test-callback")
                        append("code_verifier", pkce.verifier)
                    },
            ) {
                header("Authorization", "Basic $basicAuth")
            }
        assertTrue(
            tokenResponse.status.isSuccess(),
            "POST /token must succeed; got ${tokenResponse.status} body=${tokenResponse.bodyAsText()}",
        )
        val idToken =
            json
                .parseToJsonElement(tokenResponse.bodyAsText())
                .jsonObject["id_token"]
                ?.jsonPrimitive
                ?.content
                ?: error("missing id_token")
        return LoginResult(loginCookie = loginCookie, idToken = idToken)
    }

    private suspend fun fetchSigningJwk(kid: String): JsonObject {
        val discovery =
            json
                .parseToJsonElement(client.get("${fixture.baseUrl}/.well-known/openid-configuration").bodyAsText())
                .jsonObject
        val jwksUri =
            discovery["jwks_uri"]?.jsonPrimitive?.contentOrNull
                ?: error("discovery must advertise jwks_uri")
        val jwks = json.parseToJsonElement(client.get(jwksUri).bodyAsText()).jsonObject
        val keys = jwks["keys"] as? JsonArray ?: error("JWKS must include keys array")
        return keys
            .map { it.jsonObject }
            .firstOrNull { it["kid"]?.jsonPrimitive?.contentOrNull == kid }
            ?: error("JWKS does not advertise the kid '$kid' the logout_token header carried")
    }

    private fun verifyRs256(
        compactJws: String,
        jwk: JsonObject,
    ): Boolean {
        val segments = compactJws.split(".")
        require(segments.size == 3) { "compact JWS must have three segments" }
        val signingInput = "${segments[0]}.${segments[1]}".encodeToByteArray()
        val signature =
            java.util.Base64
                .getUrlDecoder()
                .decode(padBase64Url(segments[2]))
        val nB64 = jwk["n"]?.jsonPrimitive?.contentOrNull ?: error("JWK missing n")
        val eB64 = jwk["e"]?.jsonPrimitive?.contentOrNull ?: error("JWK missing e")
        val modulusBytes =
            java.util.Base64
                .getUrlDecoder()
                .decode(padBase64Url(nB64))
        val exponentBytes =
            java.util.Base64
                .getUrlDecoder()
                .decode(padBase64Url(eB64))
        val modulus = BigInteger(1, modulusBytes)
        val exponent = BigInteger(1, exponentBytes)
        val publicKey =
            KeyFactory
                .getInstance("RSA")
                .generatePublic(RSAPublicKeySpec(modulus, exponent))
        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(publicKey)
        verifier.update(signingInput)
        return verifier.verify(signature)
    }

    private fun decodeJwsHeader(jws: String): JsonObject {
        val headerSegment = jws.split(".").getOrNull(0) ?: error("JWS must have three segments")
        val decoded =
            java.util.Base64
                .getUrlDecoder()
                .decode(padBase64Url(headerSegment))
                .decodeToString()
        return json.parseToJsonElement(decoded).jsonObject
    }

    private fun decodeJwsPayload(jws: String): JsonObject {
        val payloadSegment = jws.split(".").getOrNull(1) ?: error("JWS must have three segments")
        val decoded =
            java.util.Base64
                .getUrlDecoder()
                .decode(padBase64Url(payloadSegment))
                .decodeToString()
        return json.parseToJsonElement(decoded).jsonObject
    }

    private fun padBase64Url(segment: String): String =
        when (segment.length % 4) {
            0 -> segment
            2 -> "$segment=="
            3 -> "$segment="
            else -> error("Invalid base64url length: ${segment.length}")
        }

    private fun extractQueryParam(
        url: String,
        key: String,
    ): String? {
        val q = url.substringAfter('?', missingDelimiterValue = "")
        return q
            .split("&")
            .map { it.split("=", limit = 2) }
            .firstOrNull { it.firstOrNull() == key }
            ?.getOrNull(1)
            ?.let { java.net.URLDecoder.decode(it, "UTF-8") }
    }

    private fun urlEncode(value: String): String = java.net.URLEncoder.encode(value, "UTF-8")

    private data class LoginResult(
        val loginCookie: String,
        val idToken: String,
    )

    /**
     * Fixed S256 PKCE pair for the BC capture flow. Mirrors the helper used in the sibling
     * logout / happy-path tests: the harness shouldn't pull in a kotlinx-crypto provider for a
     * test fixture and JCA SHA-256 is sufficient.
     */
    private class SimpleBackChannelPkceFixture(
        suffix: String,
    ) {
        // RFC 7636 §4.1: code_verifier is 43-128 chars from the unreserved set. Pad the suffix so
        // the final length always lands in-spec regardless of the suffix's length.
        val verifier: String = ("oidf-op-bc-capture-$suffix-2026" + "-padding-padding-padding-padding").take(64)
        val challenge: String =
            java.util.Base64
                .getUrlEncoder()
                .withoutPadding()
                .encodeToString(
                    java.security.MessageDigest
                        .getInstance("SHA-256")
                        .digest(verifier.encodeToByteArray()),
                )
    }
}
