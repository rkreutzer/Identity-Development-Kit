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

package com.sphereon.openid.oid4vp.holder.impl

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.encodeToBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.jose.jws.JwsJsonGeneral
import com.sphereon.crypto.jose.jws.JwsJsonGeneralWithIdentifiers
import com.sphereon.crypto.jose.jws.JwsJsonSignature
import com.sphereon.crypto.jose.jws.JwsValidationResult
import com.sphereon.openid.oid4vp.common.ClientIdScheme
import com.sphereon.openid.oid4vp.common.Oid4vpJson
import com.sphereon.openid.oid4vp.common.ParsedTransactionDataEntry
import com.sphereon.openid.oid4vp.common.TransactionDataEntry
import com.sphereon.openid.oid4vp.common.qualifyDidJarVerificationMethodId
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.DcqlQuery
import com.sphereon.ktor.http.client.getOptional
import com.sphereon.ktor.http.client.getOrDefault
import com.sphereon.ktor.http.client.getRequired
import io.ktor.http.Parameters
import io.ktor.http.Url
import io.ktor.http.parametersOf
import io.ktor.http.parseQueryString
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Tests for ParseAuthorizationRequestCommandImpl focusing on parameter extraction.
 *
 * These tests verify the Parameters extension functions used by the command implementation.
 * Full integration tests with DI, HTTP mocking, and JWT parsing would require additional setup.
 */
class ParseAuthorizationRequestCommandImplTest {
    @Test
    fun `unsigned DC API request ignores client id and expected origins in favor of platform origin`() {
        val requestData =
            buildJsonObject {
                put("client_id", "attacker.example")
                put("expected_origins", "not-an-origin-list")
                put("response_type", "vp_token")
                put("response_mode", "dc_api")
            }

        val normalized = unsignedDigitalCredentialsRequestData(requestData, "https://verified.example")

        assertEquals("origin:https://verified.example", normalized["client_id"]?.jsonPrimitive?.content)
        assertFalse("expected_origins" in normalized)
        assertEquals("vp_token", normalized["response_type"]?.jsonPrimitive?.content)
        assertEquals("dc_api", normalized["response_mode"]?.jsonPrimitive?.content)
    }

    @Test
    fun `transaction data request is rejected when referenced query disables holder binding`() {
        val dcqlQuery =
            DcqlQuery(
                credentials =
                    listOf(
                        DcqlCredentialQuery(
                            id = "pid",
                            format = "dc+sd-jwt",
                            meta =
                                JsonObject(
                                    mapOf(
                                        "vct_values" to JsonArray(listOf(JsonPrimitive("https://credentials.example/pid"))),
                                    ),
                                ),
                            require_cryptographic_holder_binding = false,
                        ),
                    ),
            )
        val transactionData =
            listOf(
                ParsedTransactionDataEntry(
                    transactionData = TransactionDataEntry(type = "payment", credentialIds = listOf("pid")),
                    transactionDataIndex = 0,
                    encoded = "encoded-transaction-data",
                ),
            )

        val result = validateTransactionDataHolderBinding(dcqlQuery, transactionData)

        assertIs<Err<*>>(result)
        assertTrue(result.error.message.defaultMessage.contains("require_cryptographic_holder_binding is false"))
    }

    @Test
    fun `test parse URI with all required parameters`() =
        runTest {
            val uri = "openid4vp://?client_id=test-client&redirect_uri=https://example.com/callback&response_type=vp_token&nonce=abc123"

            val params = parseQueryString(uri.substringAfter('?'))

            assertEquals("test-client", params["client_id"])
            assertEquals("https://example.com/callback", params["redirect_uri"])
            assertEquals("vp_token", params["response_type"])
            assertEquals("abc123", params["nonce"])
        }

    @Test
    fun `test Parameters getRequired extension`() =
        runTest {
            val params =
                parametersOf(
                    "client_id" to listOf("test-client"),
                    "redirect_uri" to listOf("https://example.com/callback"),
                )

            val result = params.getRequired("client_id")
            assertTrue(result is Ok)
        }

    @Test
    fun `test Parameters getRequired with missing parameter`() =
        runTest {
            val params = Parameters.Empty

            val result = params.getRequired("client_id")
            assertTrue(result is Err)
        }

    @Test
    fun `test Parameters getOptional with present parameter`() =
        runTest {
            val params = parametersOf("scope" to listOf("openid"))

            val value = params.getOptional("scope")
            assertEquals("openid", value)
        }

    @Test
    fun `test Parameters getOptional with missing parameter`() =
        runTest {
            val params = Parameters.Empty

            val value = params.getOptional("scope")
            assertNull(value)
        }

    @Test
    fun `test Parameters getOrDefault with present parameter`() =
        runTest {
            val params = parametersOf("response_type" to listOf("vp_token"))

            val value = params.getOrDefault("response_type", "code")
            assertEquals("vp_token", value)
        }

    @Test
    fun `test Parameters getOrDefault with missing parameter`() =
        runTest {
            val params = Parameters.Empty

            val value = params.getOrDefault("response_type", "vp_token")
            assertEquals("vp_token", value)
        }

    @Test
    fun `test parse URI with optional scope parameter`() =
        runTest {
            val uri = "openid4vp://?client_id=test-client&redirect_uri=https://example.com/callback&response_type=vp_token&nonce=abc&scope=openid"

            val params = parseQueryString(uri.substringAfter('?'))

            assertEquals("openid", params["scope"])
        }

    @Test
    fun `test parse URI with dcql_query in parameters`() =
        runTest {
            val dcqlQuery = """{"credentials":[{"format":"dc+sd-jwt"}]}"""
            val uri = "openid4vp://?client_id=test-client&redirect_uri=https://example.com/callback&response_type=vp_token&nonce=abc&dcql_query=$dcqlQuery"

            val params = parseQueryString(uri.substringAfter('?'))

            assertNotNull(params["dcql_query"])
            assertTrue(params["dcql_query"]!!.contains("credentials"))
        }

    @Test
    fun `test parse URI with state parameter`() =
        runTest {
            val uri = "openid4vp://?client_id=test-client&redirect_uri=https://example.com/callback&response_type=vp_token&nonce=abc&state=xyz789"

            val params = parseQueryString(uri.substringAfter('?'))

            assertEquals("xyz789", params["state"])
        }

    @Test
    fun `test parse URI with response_mode parameter`() =
        runTest {
            val uri = "openid4vp://?client_id=test-client&redirect_uri=https://example.com/callback&response_type=vp_token&nonce=abc&response_mode=direct_post"

            val params = parseQueryString(uri.substringAfter('?'))

            assertEquals("direct_post", params["response_mode"])
        }

    @Test
    fun `test parse URI with URL encoded parameters`() =
        runTest {
            val uri = "openid4vp://?client_id=test%20client&redirect_uri=https://example.com/callback&response_type=vp_token&nonce=abc"

            val params = parseQueryString(uri.substringAfter('?'))

            // Ktor automatically decodes URL-encoded parameters
            assertEquals("test client", params["client_id"])
        }

    @Test
    fun `test parse URI with multiple custom parameters`() =
        runTest {
            val uri = "openid4vp://?client_id=test-client&redirect_uri=https://example.com/callback&response_type=vp_token&nonce=abc&custom_param=value1&another_param=value2"

            val params = parseQueryString(uri.substringAfter('?'))

            assertEquals("value1", params["custom_param"])
            assertEquals("value2", params["another_param"])
        }

    @Test
    fun `test parse URI without optional parameters`() =
        runTest {
            val uri = "openid4vp://?client_id=test-client&redirect_uri=https://example.com/callback&response_type=vp_token&nonce=abc"

            val params = parseQueryString(uri.substringAfter('?'))

            assertNull(params["scope"])
            assertNull(params["state"])
        }

    @Test
    fun `test parse HTTPS URI with path`() =
        runTest {
            val uri = "https://wallet.example.com/authorize?client_id=test-client&redirect_uri=https://example.com/callback&response_type=vp_token&nonce=abc"

            val params = parseQueryString(uri.substringAfter('?'))

            assertEquals("test-client", params["client_id"])
        }

    @Test
    fun `test parse custom scheme URI`() =
        runTest {
            val uri = "custom-scheme://?client_id=test-client&redirect_uri=https://example.com/callback&response_type=vp_token&nonce=abc"

            val params = parseQueryString(uri.substringAfter('?'))

            assertEquals("test-client", params["client_id"])
        }

    @Test
    fun `signed x509_san_dns declaration selects x5c verification for bare ISO client id`() {
        assertEquals(
            ClientIdScheme.X509_SAN_DNS,
            jarVerificationScheme(
                clientId = "api.playground.france-identite.gouv.fr",
                clientIdSchemeHint = "x509_san_dns",
            ),
        )
    }

    @Test
    fun `DID-bound JAR kid is qualified from client_id DID including relative fragments`() {
        val did = "did:jwk:eyJhbGciOiJFUzI1NiJ9"
        val clientId = "decentralized_identifier:$did"
        assertEquals(ClientIdScheme.DECENTRALIZED_IDENTIFIER, jarVerificationScheme(clientId, null))
        val bareDid = ClientIdScheme.extractClientIdWithoutScheme(clientId)
        assertEquals("$did#0", qualifyDidJarVerificationMethodId(bareDid, "#0"))
        assertEquals("$did#0", qualifyDidJarVerificationMethodId(bareDid, "$did#0"))
        assertNull(qualifyDidJarVerificationMethodId(bareDid, "did:web:other#0"))
    }

    @Test
    fun `multi-signed request accepts a later valid signature and rejects an all-invalid set`() =
        runTest {
            val payload =
                buildJsonObject {
                    put("response_type", "vp_token")
                    put("response_mode", "dc_api.jwt")
                    put("nonce", "nonce-12345678")
                }
            val general =
                JwsJsonGeneral(
                    payload = payload.toString().encodeToByteArray().encodeToBase64Url(),
                    signatures =
                        listOf(
                            testDigitalCredentialSignature("x509_hash:first", "invalid"),
                            testDigitalCredentialSignature("x509_hash:second", "valid"),
                        ),
                )
            val element = Oid4vpJson.wire.encodeToJsonElement(JwsJsonGeneral.serializer(), general).let { it as JsonObject }

            val accepted = verifyDigitalCredentialsSignatures(element, ::testSignatureVerification)

            assertTrue(accepted is Ok, accepted.toString())
            assertEquals("x509_hash:second", (accepted as Ok).value.clientId)

            val allInvalid =
                general.copy(
                    signatures = general.signatures.map { it.copy(signature = "invalid") },
                )
            val rejected =
                verifyDigitalCredentialsSignatures(
                    Oid4vpJson.wire.encodeToJsonElement(JwsJsonGeneral.serializer(), allInvalid) as JsonObject,
                    ::testSignatureVerification,
                )
            assertTrue(rejected is Err, rejected.toString())
        }

    @Test
    fun `ISO mdoc presentation definition is normalized to the wallet credential query`() {
        val presentationDefinition =
            Json.parseToJsonElement(
                """
                {
                  "id":"eu.europa.ec.eudi.pid.1",
                  "input_descriptors":[{
                    "id":"eu.europa.ec.eudi.pid.1",
                    "format":{"mso_mdoc":{"alg":["ES256"]}},
                    "constraints":{
                      "limit_disclosure":"required",
                      "fields":[
                        {"path":["${'$'}['eu.europa.ec.eudi.pid.1']['family_name']"],"intent_to_retain":false},
                        {"path":["${'$'}['eu.europa.ec.eudi.pid.1']['given_name']"],"intent_to_retain":false}
                      ]
                    }
                  }]
                }
                """.trimIndent(),
            )

        val result = presentationDefinitionToDcql(presentationDefinition)

        assertTrue(result is Ok, result.toString())
        val query = (result as Ok).value.credentials.single()
        assertEquals("presentation_credential_0", query.id)
        assertEquals("mso_mdoc", query.format)
        assertEquals("eu.europa.ec.eudi.pid.1", query.meta["doctype_value"]!!.jsonPrimitive.content)
        assertEquals(
            listOf(
                listOf("eu.europa.ec.eudi.pid.1", "family_name"),
                listOf("eu.europa.ec.eudi.pid.1", "given_name"),
            ),
            query.claims!!.map { claim -> claim.path.components.map { it.jsonPrimitive.content } },
        )
        assertTrue(query.claims!!.all { it.intent_to_retain == false })
    }
}

private fun testDigitalCredentialSignature(
    clientId: String,
    signature: String,
): JwsJsonSignature =
    JwsJsonSignature(
        protected =
            buildJsonObject {
                put("alg", "ES256")
                put("typ", "oauth-authz-req+jwt")
                put("client_id", clientId)
            }.toString().encodeToByteArray().encodeToBase64Url(),
        signature = signature,
    )

private suspend fun testSignatureVerification(jws: JwsJsonGeneral): IdkResult<JwsValidationResult, IdkError> =
    jws.signatures.single().signature.let { signature ->
        Ok(
            JwsValidationResult(
                jws = JwsJsonGeneralWithIdentifiers(payload = jws.payload, signatures = emptyList()),
                isValid = signature == "valid",
                parsedPayload = JsonObject(emptyMap()),
                trustEstablished = true,
                cryptoVerified = signature == "valid",
            ),
        )
    }
