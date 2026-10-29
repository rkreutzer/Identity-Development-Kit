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
 *
 */

package com.sphereon.openid.oid4vp.universal.impl

import com.sphereon.core.api.conf.DefaultPrincipalMapPropertySource
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.crypto.core.KeyVisibility
import com.sphereon.crypto.core.ManagedKeyInfoType
import com.sphereon.crypto.core.ResolvedKeyInfo
import com.sphereon.crypto.core.generic.KeyOperations
import com.sphereon.crypto.core.generic.SignatureAlgorithm
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkSet
import com.sphereon.crypto.core.jose.JwkUse
import com.sphereon.crypto.core.kms.asKeyManagerServiceGraph
import com.sphereon.crypto.resolution.IdentifierContext
import com.sphereon.di.context.PrincipalType
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.openid.oid4vp.dcql.DcqlClaimQuery
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.openid.oid4vp.dcql.claimsPathPointer
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import com.sphereon.openid.oid4vp.universal.AuthorizationRequestMethod
import com.sphereon.openid.oid4vp.universal.CreateAuthorizationRequestInput
import com.sphereon.openid.oid4vp.universal.CreateAuthorizationRequestOutput
import com.sphereon.openid.oid4vp.universal.GetAuthorizationRequestStatusOutput
import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import com.sphereon.sdjwt.IssueSdJwtArgs
import com.sphereon.sdjwt.PresentSdJwtArgs
import com.sphereon.sdjwt.SdField
import com.sphereon.sdjwt.SdJwtServiceImpl
import com.sphereon.sdjwt.SdMap
import com.sphereon.sdjwt.dsl.sdJwtPayload
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.TestScope
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Test
import java.io.File
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyFactory
import java.security.KeyStore
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.AlgorithmParameters
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.util.Base64
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * A full presentation against a verifier that runs as a separate local process, addressed through the route that
 * names verifier A. Nothing in the process under test is faked: the request is created over HTTP, its signed request
 * object is fetched and checked against A's public signer identity, a holder-bound response is posted to the
 * advertised response endpoint, and the status endpoint is read until it is verified.
 *
 * The test is selected explicitly (`oid4vp.localStackTest=true`) and reads a private JSON file named by the
 * `OID4VP_LOCAL_STACK_CONFIG` environment variable. It never skips: a missing file, a missing field, a target that
 * is not local or an unreachable service is a failure, because a skipped live test would read as a pass.
 *
 * ```json
 * {
 *   "createUrl": "https://<local edge>/<route naming verifier A>/oid4vp/backend/auth/requests",
 *   "statusUrl": "https://<local edge>/<route naming verifier A>/oid4vp/backend/auth/requests/{correlationId}",
 *   "bearerToken": "<token that may call both routes>",
 *   "caCertificateFile": "<PEM of the local edge certificate authority>",
 *   "expectedSignerDid": "<did:jwk of verifier A's request-object signing key>",
 *   "issuerJwksFile": "<JWK set file whose first key is the private key of an issuer that the stack trusts>",
 *   "issuerIss": "<the iss the stack's trust anchors expect>",
 *   "credentialType": "<vct the issued credential carries>"
 * }
 * ```
 */
class NamedVerifierLocalStackTest {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }

    private class StackConfig(
        val createUrl: String,
        val statusUrl: String,
        val bearerToken: String?,
        val caCertificateFile: String?,
        val expectedSignerDid: String,
        val issuerJwksFile: String,
        val issuerIss: String,
        val credentialType: String,
    )

    private fun loadConfig(): StackConfig {
        val path = System.getenv(CONFIG_ENV)?.takeIf { it.isNotBlank() } ?: error("$CONFIG_ENV is not set: the local-stack proof cannot run without its fixture")
        val file = File(path)
        check(file.isFile) { "$CONFIG_ENV names a file that does not exist: $path" }
        val config = json.parseToJsonElement(file.readText()).jsonObject

        fun text(name: String): String = config[name]?.jsonPrimitive?.content?.takeIf { it.isNotBlank() } ?: error("The local-stack config has no '$name'")
        val loaded =
            StackConfig(
                createUrl = text("createUrl"),
                statusUrl = text("statusUrl"),
                bearerToken = config["bearerToken"]?.jsonPrimitive?.content?.takeIf { it.isNotBlank() },
                caCertificateFile = config["caCertificateFile"]?.jsonPrimitive?.content?.takeIf { it.isNotBlank() },
                expectedSignerDid = text("expectedSignerDid"),
                issuerJwksFile = text("issuerJwksFile"),
                issuerIss = text("issuerIss"),
                credentialType = text("credentialType"),
            )
        listOf(loaded.createUrl, loaded.statusUrl).forEach { url ->
            val host = URI(url).host ?: error("Not a URL: $url")
            check(host == "localhost" || host == "127.0.0.1" || host.endsWith(".localhost")) {
                "The local-stack proof only runs against a local target, not '$host'"
            }
        }
        return loaded
    }

    private fun httpClient(config: StackConfig): HttpClient {
        val builder = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER)
        config.caCertificateFile?.let { pem ->
            val certificate = File(pem).inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) }
            val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("local-edge", certificate) }
            val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
            builder.sslContext(SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) })
        }
        return builder.build()
    }

    private fun request(config: StackConfig, url: String): HttpRequest.Builder =
        HttpRequest.newBuilder(URI(url)).also { builder -> config.bearerToken?.let { builder.header("Authorization", "Bearer $it") } }

    private fun decodeSegment(segment: String): JsonObject = json.parseToJsonElement(String(Base64.getUrlDecoder().decode(segment))).jsonObject

    /** Checks an ES256 compact JWS against the P-256 key that a did:jwk names. */
    private fun verifyEs256(compact: String, did: String): Boolean {
        val jwk = decodeSegment(did.removePrefix("did:jwk:"))
        val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
        val point = ECPoint(java.math.BigInteger(1, Base64.getUrlDecoder().decode(jwk.getValue("x").jsonPrimitive.content)), java.math.BigInteger(1, Base64.getUrlDecoder().decode(jwk.getValue("y").jsonPrimitive.content)))
        val key = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, parameters))
        val parts = compact.split('.')
        val raw = Base64.getUrlDecoder().decode(parts[2])
        val half = raw.size / 2
        fun der(value: ByteArray): ByteArray = java.math.BigInteger(1, value).toByteArray().let { if (it.size > 1 && it[0] == 0.toByte() && it[1] >= 0) it.copyOfRange(1, it.size) else it }
        val r = der(raw.copyOfRange(0, half))
        val s = der(raw.copyOfRange(half, raw.size))
        val body = byteArrayOf(0x02, r.size.toByte()) + r + byteArrayOf(0x02, s.size.toByte()) + s
        val sequence = byteArrayOf(0x30, body.size.toByte()) + body
        return Signature.getInstance("SHA256withECDSA").apply { initVerify(key); update("${parts[0]}.${parts[1]}".toByteArray()) }.verify(sequence)
    }

    private fun query(requireClaim: String, credentialType: String): DcqlQuery =
        DcqlQuery(
            credentials = listOf(
                DcqlCredentialQuery(
                    id = "pid",
                    format = "dc+sd-jwt",
                    meta = sdJwtVcMeta(credentialType),
                    claims = listOf(DcqlClaimQuery(claimsPathPointer("given_name")), DcqlClaimQuery(claimsPathPointer(requireClaim))),
                ),
            ),
        )

    @Test
    fun shouldVerifyACompletePresentationAgainstTheNamedVerifierAndRefuseAnIncompleteOne() =
        // runBlocking, not runTest: the status poll needs real delays against a live process.
        runBlocking {
            val config = loadConfig()
            val client = httpClient(config)

            // A holder with a real software KMS: the issuer key the stack trusts, and a fresh holder key.
            val app = createUniversalOid4vpTestAppGraph(TestScope(), appId = "named-verifier-local-stack", profile = "test", version = "1.0.0")
            DefaultPrincipalMapPropertySource.addProperties(
                mapOf(
                    "kms.providers.test-software.type" to "software",
                    "kms.providers.test-software.id" to "test-software",
                    "kms.providers.test-software.keystore.type" to "memory",
                    "kms.providers.test-software.keystore.id" to "test-memory-keystore",
                    "kms.providers.test-software.keystore.keyVisibility" to "private",
                    "kms.providers.test-software.keystore.overwriteAlias" to "true",
                ),
            )
            app.userContextManager.destroyAll()
            val holderGraph = app.userContextManager.getAnonymous().sessionContextManager.createOrGetFromId("local-stack-holder", principalType = PrincipalType.USER).graph
            val kms = holderGraph.asKeyManagerServiceGraph().keyManagerService
            val sdJwtService = (holderGraph as SdJwtServiceImpl.Graph).sdJwtService

            val issuerKey = JwkSet.fromJsonString(File(config.issuerJwksFile).readText()).keys.first()
            val storedIssuer: ManagedKeyInfoType<*> = kms.storeKey(ResolvedKeyInfo.fromKey(issuerKey), "test-software", "local-stack-issuer", null)
            val issuer = ManagedOptsKeyInfo(identifier = storedIssuer, context = IdentifierContext(clientId = "local-stack-issuer", clientIdScheme = "jwt_vc_json", issuer = config.issuerIss))
            val holderPair =
                kms.generateKeyAsync(
                    providerId = "test-software",
                    alias = "local-stack-holder",
                    use = JwkUse.sig,
                    keyOperations = arrayOf(KeyOperations.SIGN, KeyOperations.VERIFY),
                    alg = SignatureAlgorithm.ECDSA_SHA256,
                )
            val holder = ManagedOptsKeyInfo(identifier = holderPair.joseToManagedKeyInfo(KeyVisibility.PRIVATE), context = IdentifierContext(clientId = "local-stack-holder", clientIdScheme = "jwt_vc_json", issuer = "https://holder.example"))
            val holderCnf = buildJsonObject { put("jwk", (holderPair.joseToManagedKeyInfo(KeyVisibility.PUBLIC).key as Jwk).toMinimalJwk().toJsonObject()) }

            suspend fun present(withNationality: Boolean, nonce: String, audience: String): String {
                val payload =
                    sdJwtPayload {
                        iss(config.issuerIss)
                        claim("vct", config.credentialType)
                        claimSd("given_name", "Ada")
                        claimSd("phone", "0612345678")
                        claimSd("age", 30)
                        claimSd("address", buildJsonObject { put("street", "Main") })
                        if (withNationality) claimSd("nationality", "NL")
                        claim("cnf", holderCnf)
                    }
                val vc = sdJwtService.issueSdJwt(IssueSdJwtArgs(issuer = issuer, payload = payload)).getOrThrow().sdJwt
                val disclosed = mutableMapOf("given_name" to SdField(sd = true), "phone" to SdField(sd = true), "age" to SdField(sd = true), "address" to SdField(sd = true))
                if (withNationality) disclosed["nationality"] = SdField(sd = true)
                return sdJwtService.presentSdJwt(PresentSdJwtArgs(sdJwt = vc, disclosureSelection = SdMap(disclosed), holderKey = holder, audience = audience, nonce = nonce)).getOrThrow().presentation
            }

            suspend fun createRequest(requireClaim: String): CreateAuthorizationRequestOutput {
                val body = json.encodeToString(CreateAuthorizationRequestInput.serializer(), CreateAuthorizationRequestInput(dcqlQuery = query(requireClaim, config.credentialType), authorizationRequestMethod = AuthorizationRequestMethod.REQUEST_URI))
                val response = client.send(request(config, config.createUrl).header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString())
                assertEquals(201, response.statusCode(), "create on the named-verifier route: ${response.body()}")
                return json.decodeFromString(CreateAuthorizationRequestOutput.serializer(), response.body())
            }

            suspend fun requestObject(created: CreateAuthorizationRequestOutput): JsonObject {
                val uri = assertNotNull(created.requestUri, "the created request must advertise a request_uri")
                val response = client.send(HttpRequest.newBuilder(URI(uri)).GET().build(), HttpResponse.BodyHandlers.ofString())
                assertEquals(200, response.statusCode(), "request_uri fetch: ${response.body()}")
                val compact = response.body().trim()
                assertTrue(verifyEs256(compact, config.expectedSignerDid), "the request object must be signed by verifier A's expected signer")
                val payload = decodeSegment(compact.split('.')[1])
                assertTrue(payload.getValue("client_id").jsonPrimitive.content.contains(config.expectedSignerDid), "client_id must name verifier A's signer: ${payload["client_id"]}")
                return payload
            }

            suspend fun respond(payload: JsonObject, presentation: String) {
                val vpToken = json.encodeToString(JsonObject.serializer(), buildJsonObject { put("pid", buildJsonArray { add(JsonPrimitive(presentation)) }) })
                val form = mapOf("vp_token" to vpToken, "state" to payload.getValue("state").jsonPrimitive.content).entries.joinToString("&") { (k, v) -> "$k=${URLEncoder.encode(v, Charsets.UTF_8)}" }
                client.send(HttpRequest.newBuilder(URI(payload.getValue("response_uri").jsonPrimitive.content)).header("Content-Type", "application/x-www-form-urlencoded").POST(HttpRequest.BodyPublishers.ofString(form)).build(), HttpResponse.BodyHandlers.ofString())
            }

            suspend fun finalStatus(created: CreateAuthorizationRequestOutput): GetAuthorizationRequestStatusOutput {
                val deadline = System.nanoTime() + 60_000_000_000L
                while (true) {
                    val response = client.send(request(config, config.statusUrl.replace("{correlationId}", created.correlationId)).GET().build(), HttpResponse.BodyHandlers.ofString())
                    assertEquals(200, response.statusCode(), "status: ${response.body()}")
                    val status = json.decodeFromString(GetAuthorizationRequestStatusOutput.serializer(), response.body())
                    if (status.status == AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED || status.status == AuthorizationSessionStatus.ERROR) return status
                    check(System.nanoTime() < deadline) { "The session did not settle within 60 seconds: ${status.status}" }
                    delay(500)
                }
            }

            // A complete response is verified, and its claims keep the types they were issued with.
            val complete = createRequest("nationality")
            val completePayload = requestObject(complete)
            respond(completePayload, present(true, completePayload.getValue("nonce").jsonPrimitive.content, completePayload.getValue("client_id").jsonPrimitive.content))
            val verified = finalStatus(complete)
            assertEquals(AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED, verified.status, "complete response: ${verified.error}")
            val claims = assertNotNull(verified.verifiedData?.credentialClaims?.singleOrNull(), "exactly one verified credential entry").claims!!
            assertEquals(JsonPrimitive("0612345678"), claims.getValue("phone"))
            assertFalse((claims.getValue("age") as JsonPrimitive).isString, "a number stays a number")
            assertEquals(JsonPrimitive(30), claims.getValue("age"))
            assertEquals(buildJsonObject { put("street", "Main") }, claims.getValue("address"))

            // A response that lacks a requested claim is refused and exposes no verified data.
            val incomplete = createRequest("nationality")
            val incompletePayload = requestObject(incomplete)
            respond(incompletePayload, present(false, incompletePayload.getValue("nonce").jsonPrimitive.content, incompletePayload.getValue("client_id").jsonPrimitive.content))
            val refused = finalStatus(incomplete)
            assertTrue(refused.status != AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED, "an incomplete response must not verify")
            assertNull(refused.verifiedData, "an incomplete response exposes no verified data")
        }

    private companion object {
        const val CONFIG_ENV = "OID4VP_LOCAL_STACK_CONFIG"
    }
}
