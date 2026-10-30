/*
 * Copyright 2023-2026 Sphereon International B.V.
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

package com.sphereon.openid.oid4vp.common

import com.sphereon.crypto.core.jose.JwaAlgorithm
import com.sphereon.crypto.core.jose.JwaCurve
import com.sphereon.crypto.core.jose.JwaKeyType
import com.sphereon.crypto.core.jose.JoseKeyOperations
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkSet
import kotlinx.serialization.SerializationException
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Tests for [ClientMetadata] — the OID4VP 1.0 final §11.1 / §5.1 / §8.3 verifier
 * client_metadata wire shape. Verifies the spec-defined fields are emitted with the
 * correct names and that OAuth2 RFC 7591 / JARM-RFC fields are NOT emitted.
 *
 * Authoritative parameter list (per spec source verified during refactor):
 *  - `jwks`, `jwks_uri`, `vp_formats_supported`, `encrypted_response_enc_values_supported`.
 *
 * Anything else is non-canonical and the wallet "MUST ignore unrecognized parameters".
 */
class ClientMetadataSerializationTest {
    private val json =
        Json {
            prettyPrint = false
            encodeDefaults = false
            ignoreUnknownKeys = false
        }

    private fun encJwk(kid: String = "test-enc-1") =
        Jwk(
            kty = JwaKeyType.EC,
            crv = JwaCurve.P_256,
            x = "0_3S7HedSywaxlekdt6Or8pkcR13hQaCPMqt9cuZBVc",
            y = "ZVXSCL3HlnMQWKrwMyIAe5wsAIWd3Eu1misKFr3POdA",
            use = "enc",
            alg = JwaAlgorithm.ECDH_ES,
            kid = kid,
        )

    @Test
    fun wireMetadataKeepsUsableEncryptionKeyBetweenUnsupportedKeyTypes() {
        val keys =
            JsonArray(
                listOf(
                    Json.parseToJsonElement("""{"kty":"AKP","alg":"ML-KEM-9999","kid":"future","use":"enc","pub":"unsupported"}"""),
                    Json.encodeToJsonElement(Jwk.serializer(), encJwk("usable")),
                    Json.parseToJsonElement("""{"kty":"unknown-key-type","alg":"unknown-alg","kid":"unknown","use":"enc"}"""),
                ),
            )
        val wire = buildJsonObject { put("jwks", buildJsonObject { put("keys", keys) }) }
        val decoded = Oid4vpJson.wire.decodeFromJsonElement(ClientMetadata.serializer(), wire)

        assertEquals(listOf("usable"), decoded.jwks?.keys?.map { it.kid })
        assertEquals("usable", decoded.selectEncryptedResponseJwk()?.kid)
        val roundTrip = Oid4vpJson.wire.decodeFromString<ClientMetadata>(Oid4vpJson.wire.encodeToString(decoded))
        assertEquals(decoded.jwks, roundTrip.jwks)
    }

    @Test
    fun metadataWithOnlyUnsupportedKeysHasNoEncryptionKey() {
        val decoded =
            Oid4vpJson.wire.decodeFromString<ClientMetadata>(
                """{"jwks":{"keys":[{"kty":"AKP","alg":"ML-KEM-9999","use":"enc"}]}}""",
            )
        assertTrue(requireNotNull(decoded.jwks).keys.isEmpty())
        assertNull(decoded.selectEncryptedResponseJwk())
    }

    @Test
    fun metadataStillRejectsMalformedJwkSetStructure() {
        for (jwks in listOf("[]", "{}", """{"keys":{}}""", """{"keys":["not-a-key-object"]}""")) {
            assertFailsWith<SerializationException> {
                Oid4vpJson.wire.decodeFromString<ClientMetadata>("""{"jwks":$jwks}""")
            }
        }
    }

    @Test
    fun `empty ClientMetadata serialises to an empty JSON object`() {
        val metadata = ClientMetadata()
        val obj = json.encodeToJsonElement(ClientMetadata.serializer(), metadata).jsonObject
        assertTrue(obj.isEmpty(), "Expected empty object, got: $obj")
    }

    @Test
    fun vpFormatsSupportedUsesOid4vpFinalWireNameNotVpFormats() {
        val metadata =
            ClientMetadata(
                vpFormatsSupported =
                    mapOf(
                        "dc+sd-jwt" to
                            VpFormatInfo(
                                sdJwtAlgValuesSupported = listOf("ES256"),
                                kbJwtAlgValuesSupported = listOf("ES256"),
                            ),
                    ),
            )
        val obj = json.encodeToJsonElement(ClientMetadata.serializer(), metadata).jsonObject
        assertNotNull(obj["vp_formats_supported"], "vp_formats_supported MUST be the wire name per OID4VP §11.1")
        assertNull(obj["vp_formats"], "Pre-final draft name vp_formats MUST NOT be emitted")
    }

    @Test
    fun ldpVcUsesFinalProofTypeAndCryptosuiteWireNames() {
        val metadata =
            ClientMetadata(
                vpFormatsSupported =
                    mapOf(
                        "ldp_vc" to
                            VpFormatInfo(
                                proofTypeValues = listOf("DataIntegrityProof", "Ed25519Signature2020"),
                                cryptosuiteValues = listOf("eddsa-rdfc-2022", "ecdsa-rdfc-2019"),
                            ),
                    ),
            )

        val ldpVc =
            json.encodeToJsonElement(ClientMetadata.serializer(), metadata)
                .jsonObject["vp_formats_supported"]!!.jsonObject["ldp_vc"]!!.jsonObject

        assertEquals("[\"DataIntegrityProof\",\"Ed25519Signature2020\"]", ldpVc["proof_type_values"].toString())
        assertEquals("[\"eddsa-rdfc-2022\",\"ecdsa-rdfc-2019\"]", ldpVc["cryptosuite_values"].toString())
        assertFalse(ldpVc.containsKey("proof_types_supported"))
    }

    @Test
    fun ldpVcBuilderPopulatesFinalDataIntegrityFields() {
        val ldpVc =
            buildVpFormats {
                ldpVc(
                    proofTypeValues = listOf("DataIntegrityProof"),
                    cryptosuiteValues = listOf("eddsa-rdfc-2022"),
                )
            }["ldp_vc"]

        assertEquals(listOf("DataIntegrityProof"), ldpVc?.proofTypeValues)
        assertEquals(listOf("eddsa-rdfc-2022"), ldpVc?.cryptosuiteValues)
    }

    @Test
    fun vpFormatInfoBuilderPopulatesFinalDataIntegrityFields() {
        val info =
            buildVpFormatInfo {
                proofTypeValues("DataIntegrityProof")
                cryptosuiteValues("eddsa-rdfc-2022")
            }

        assertEquals(listOf("DataIntegrityProof"), info.proofTypeValues)
        assertEquals(listOf("eddsa-rdfc-2022"), info.cryptosuiteValues)
    }

    @Test
    fun `jwks emits standard RFC 7517 keys array with the JWK alg field set`() {
        val metadata = ClientMetadata(jwks = JwkSet(arrayOf(encJwk())))
        val obj = json.encodeToJsonElement(ClientMetadata.serializer(), metadata).jsonObject

        val jwks = obj["jwks"]?.jsonObject ?: error("jwks missing")
        val keys = jwks["keys"]?.jsonArray ?: error("jwks.keys missing")
        assertEquals(1, keys.size)
        val key = keys[0].jsonObject
        assertNotNull(key["alg"], "OID4VP §8.3: alg MUST be present on the JWK")
        assertEquals("\"ECDH-ES\"", key["alg"].toString())
        assertEquals("\"enc\"", key["use"].toString())
        assertNotNull(key["kid"])
    }

    @Test
    fun encryptedResponseKeyMayOmitOptionalUseWhenAlgIdentifiesEncryption() {
        val key = encJwk().copy(use = null)
        val metadata = ClientMetadata(jwks = JwkSet(arrayOf(key)))

        assertEquals(key, metadata.selectEncryptedResponseJwk())
    }

    @Test
    fun explicitSigningIntentRejectsEncryptionAlgorithmKey() {
        val signingUse = encJwk().copy(use = "sig")
        val signingOperations = encJwk().copy(use = null, key_ops = arrayOf(JoseKeyOperations.SIGN))

        assertNull(ClientMetadata(jwks = JwkSet(arrayOf(signingUse))).selectEncryptedResponseJwk())
        assertNull(ClientMetadata(jwks = JwkSet(arrayOf(signingOperations))).selectEncryptedResponseJwk())
    }

    @Test
    fun `encrypted_response_enc_values_supported emits the HAIP plural form`() {
        val metadata =
            ClientMetadata(
                encryptedResponseEncValuesSupported = listOf("A128GCM", "A256GCM"),
            )
        val obj = json.encodeToJsonElement(ClientMetadata.serializer(), metadata).jsonObject
        val encs = obj["encrypted_response_enc_values_supported"]?.jsonArray
        assertNotNull(encs)
        assertEquals(2, encs.size)
    }

    @Test
    fun `serialised metadata does NOT include OAuth2 RFC 7591 client-registration fields`() {
        // Sanity check that the typed model can no longer leak OAuth2 noise. Even a
        // fully-populated ClientMetadata must not surface client_id, grant_types,
        // redirect_uris, token_endpoint_auth_method, etc., per OID4VP §11.1's narrow set.
        val metadata =
            ClientMetadata(
                jwks = JwkSet(arrayOf(encJwk())),
                vpFormatsSupported =
                    mapOf("dc+sd-jwt" to VpFormatInfo(sdJwtAlgValuesSupported = listOf("ES256"))),
                encryptedResponseEncValuesSupported = listOf("A128GCM"),
            )
        val obj = json.encodeToJsonElement(ClientMetadata.serializer(), metadata).jsonObject
        val forbidden =
            setOf(
                "client_id",
                "client_secret",
                "client_name",
                "client_type",
                "client_uri",
                "logo_uri",
                "grant_types",
                "response_types",
                "redirect_uris",
                "token_endpoint_auth_method",
                "scope",
                "contacts",
                "tos_uri",
                "policy_uri",
                "software_id",
                "software_version",
                "software_statement",
                // JARM-RFC singulars that aren't in OID4VP §11.1
                "authorization_signed_response_alg",
                "authorization_encrypted_response_alg",
                "authorization_encrypted_response_enc",
                // Plural alg list not in OID4VP §8.3 (alg comes from JWK.alg)
                "encrypted_response_alg_values_supported",
                // Pre-final draft field
                "client_purpose",
            )
        for (k in forbidden) {
            assertFalse(obj.containsKey(k), "Forbidden OID4VP §11.1 field present: $k. Object was: $obj")
        }
    }

    @Test
    fun `round-trip preserves OID4VP fields`() {
        val original =
            ClientMetadata(
                jwks = JwkSet(arrayOf(encJwk("k1"))),
                jwksUri = "https://verifier.example.com/.well-known/jwks.json",
                vpFormatsSupported =
                    mapOf(
                        "dc+sd-jwt" to
                            VpFormatInfo(
                                sdJwtAlgValuesSupported = listOf("ES256", "ES384"),
                                kbJwtAlgValuesSupported = listOf("ES256"),
                            ),
                        "mso_mdoc" to
                            VpFormatInfo(
                                issuerAuthAlgValuesSupported = listOf(-7),
                                deviceAuthAlgValuesSupported = listOf(-7),
                            ),
                    ),
                encryptedResponseEncValuesSupported = listOf("A128GCM", "A256GCM"),
            )

        val str = json.encodeToString(original)
        val decoded = json.decodeFromString(ClientMetadata.serializer(), str)

        assertEquals(original.jwksUri, decoded.jwksUri)
        assertEquals(2, decoded.vpFormatsSupported?.size)
        assertEquals(listOf("ES256", "ES384"), decoded.vpFormatsSupported?.get("dc+sd-jwt")?.sdJwtAlgValuesSupported)
        assertEquals(listOf(-7), decoded.vpFormatsSupported?.get("mso_mdoc")?.issuerAuthAlgValuesSupported)
        assertEquals(listOf("A128GCM", "A256GCM"), decoded.encryptedResponseEncValuesSupported)
        assertEquals(1, decoded.jwks?.keys?.size)
    }

    @Test
    fun `wire decoder ignores unrecognized verifier metadata parameters`() {
        val decoded =
            Oid4vpJson.wire.decodeFromString<ClientMetadata>(
                """
                {
                  "vp_formats_supported": {
                    "dc+sd-jwt": {
                      "sd-jwt_alg_values": ["ES256"],
                      "kb-jwt_alg_values": ["ES256"]
                    }
                  },
                  "encrypted_response_enc_values_supported": ["A128GCM", "A256GCM"],
                  "client_name": "Verifier Playground",
                  "authorization_encrypted_response_alg": "ECDH-ES",
                  "authorization_encrypted_response_enc": "A256GCM"
                }
                """.trimIndent(),
            )

        assertEquals(setOf("dc+sd-jwt"), decoded.vpFormatsSupported?.keys)
        assertEquals(listOf("A128GCM", "A256GCM"), decoded.encryptedResponseEncValuesSupported)
    }

    @Test
    fun `VP format builders keep IETF and W3C SD-JWT identifiers distinct`() {
        val verifierFormats =
            buildVpFormats {
                sdJwtVc()
                w3cVcSdJwt()
            }
        val walletMetadata =
            buildWalletMetadata {
                supportSdJwtVc()
                supportW3cVcSdJwt()
            }

        assertEquals(setOf("dc+sd-jwt", "vc+sd-jwt"), verifierFormats.keys)
        assertEquals(setOf("dc+sd-jwt", "vc+sd-jwt"), walletMetadata.vpFormatsSupported.keys)
    }
}

class ClientMetadataValidationTest {
    @Test
    fun emptyClientMetadataIsValidEveryFieldOptionalInIsolation() {
        val result = validateClientMetadata(ClientMetadata())
        assertTrue(result.isValid, "Empty metadata should be valid in isolation. Errors: ${result.errors}")
    }

    @Test
    fun `vp_formats_supported empty map fails validation`() {
        val metadata = ClientMetadata(vpFormatsSupported = emptyMap())
        val result = validateClientMetadata(metadata)
        assertFalse(result.isValid, "Empty vp_formats_supported should fail")
    }

    @Test
    fun `vp_formats_supported with valid entries passes`() {
        val metadata =
            ClientMetadata(
                vpFormatsSupported =
                    mapOf(
                        "dc+sd-jwt" to VpFormatInfo(sdJwtAlgValuesSupported = listOf("ES256")),
                    ),
            )
        val result = validateClientMetadata(metadata)
        assertTrue(result.isValid, "Errors: ${result.errors}")
    }

    @Test
    fun `encrypted_response_enc_values_supported empty list fails validation`() {
        val metadata = ClientMetadata(encryptedResponseEncValuesSupported = emptyList())
        val result = validateClientMetadata(metadata)
        assertFalse(result.isValid, "Empty enc list should fail")
    }

    @Test
    fun `ldp_vc final proof type and cryptosuite lists must not be empty`() {
        val emptyProofTypes =
            validateClientMetadata(
                ClientMetadata(
                    vpFormatsSupported =
                        mapOf("ldp_vc" to VpFormatInfo(proofTypeValues = emptyList())),
                ),
            )
        val emptyCryptosuites =
            validateClientMetadata(
                ClientMetadata(
                    vpFormatsSupported =
                        mapOf("ldp_vc" to VpFormatInfo(cryptosuiteValues = emptyList())),
                ),
            )

        assertFalse(emptyProofTypes.isValid)
        assertFalse(emptyCryptosuites.isValid)
    }
}
