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

package com.sphereon.openid.oid4vp.verifier.impl

import com.sphereon.cbor.CborArray
import com.sphereon.cbor.CborByteString
import com.sphereon.cbor.CborItem
import com.sphereon.cbor.CborMap
import com.sphereon.cbor.CborNull
import com.sphereon.cbor.CborParserImpl
import com.sphereon.cbor.CborString
import com.sphereon.cbor.CborTagged
import com.sphereon.cbor.CborUInt
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import com.sphereon.openid.oid4vp.verifier.claimValueToJson
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CredentialClaimProjectionTest {
    private val address =
        buildJsonObject {
            put("street", "Main")
            put("geo", buildJsonArray { add(JsonPrimitive(1)); add(JsonPrimitive(2.5)) })
        }

    private fun parse(text: String): JsonObject = Json.parseToJsonElement(text) as JsonObject

    @Test
    fun shouldKeepEverySdJwtClaimAtItsIssuedJsonType() {
        val payload =
            buildJsonObject {
                put("name", "Alice")
                put("phone", "0612345678")
                put("flag_text", "true")
                put("nan_text", "NaN")
                put("json_text", "{\"x\":1}")
                put("age", 30)
                put("score", 1.5)
                put("active", true)
                put("address", address)
                put("tags", buildJsonArray { add(JsonPrimitive("a")); add(JsonPrimitive("b")) })
                put("none", JsonNull)
            }

        val projection = sdJwtClaimProjection(payload)

        assertEquals(payload.toMap(), projection.claims)
        assertTrue((projection.claims.getValue("phone") as JsonPrimitive).isString)
        assertTrue((projection.claims.getValue("flag_text") as JsonPrimitive).isString)
        assertTrue((projection.claims.getValue("nan_text") as JsonPrimitive).isString)
        assertFalse((projection.claims.getValue("age") as JsonPrimitive).isString)
        assertIs<JsonObject>(projection.claims.getValue("address"))
        assertIs<JsonArray>(projection.claims.getValue("tags"))
        assertEquals(JsonNull, projection.claims.getValue("none"))
    }

    @Test
    fun shouldKeepSdJwtRegistrationClaimsOutOfTheResponseClaimsButInTheQueryRoot() {
        val payload =
            parse(
                """{"iss":"https://issuer","iat":1,"exp":2,"nbf":1,"vct":"urn:example:pid","cnf":{"jwk":{}},
                    "status":{"x":1},"_sd_alg":"sha-256","given_name":"Alice"}""",
            )

        val projection = sdJwtClaimProjection(payload)

        assertEquals(setOf("given_name"), projection.claims.keys)
        assertEquals(payload, projection.queryRoot)
        assertEquals("urn:example:pid", projection.credentialType)
    }

    @Test
    fun shouldReportNoSdJwtTypeWhenVctIsMissingOrNotText() {
        assertNull(sdJwtClaimProjection(parse("""{"given_name":"Alice"}""")).credentialType)
        assertNull(sdJwtClaimProjection(parse("""{"vct":7,"given_name":"Alice"}""")).credentialType)
    }

    @Test
    fun shouldUseTheCredentialSubjectMembersAsW3cClaimsWithoutTheSubjectId() {
        val credential =
            buildJsonObject {
                put("type", buildJsonArray { add(JsonPrimitive("VerifiableCredential")); add(JsonPrimitive("Diploma")) })
                put(
                    "credentialSubject",
                    buildJsonObject {
                        put("id", "did:example:holder")
                        put("degree", "MSc")
                        put("gpa", 3.5)
                        put("honors", true)
                        put("address", address)
                    },
                )
            }

        val projection = vcdmClaimProjection(credential, "Diploma")

        assertEquals(setOf("degree", "gpa", "honors", "address"), projection.claims.keys)
        assertEquals(address, projection.claims.getValue("address"))
        assertEquals(credential, projection.queryRoot)
        assertEquals("Diploma", projection.credentialType)
    }

    @Test
    fun shouldKeepTheW3cSubjectIdOnlyWhenAskedFor() {
        val credential = buildJsonObject { put("credentialSubject", buildJsonObject { put("id", "did:example:holder"); put("degree", "MSc") }) }

        assertEquals(setOf("id", "degree"), vcdmClaimProjection(credential, null, includeSubjectId = true).claims.keys)
        assertEquals(setOf("degree"), vcdmClaimProjection(credential, null).claims.keys)
    }

    @Test
    fun shouldReportNoW3cClaimsWhenTheSubjectIsNotASingleObject() {
        val withList = buildJsonObject { put("credentialSubject", buildJsonArray { add(buildJsonObject { put("a", 1) }) }) }

        assertTrue(vcdmClaimProjection(withList, null).claims.isEmpty())
        assertTrue(vcdmClaimProjection(buildJsonObject { }, null).claims.isEmpty())
    }

    @Test
    fun shouldQualifyMdocClaimKeysWithTheirNamespaceAndNestTheQueryRootByNamespace() {
        val projection =
            mdocDocumentProjection(
                docType = "org.iso.18013.5.1.mDL",
                elements =
                    listOf(
                        MdocElement("org.iso.18013.5.1", "given_name", JsonPrimitive("Jane")),
                        MdocElement("org.iso.18013.5.1", "age_over_18", JsonPrimitive(true)),
                        MdocElement("org.iso.18013.5.1.aamva", "given_name", JsonPrimitive("Janet")),
                    ),
            )

        assertEquals(
            mapOf<String, JsonElement>(
                "org.iso.18013.5.1.given_name" to JsonPrimitive("Jane"),
                "org.iso.18013.5.1.age_over_18" to JsonPrimitive(true),
                "org.iso.18013.5.1.aamva.given_name" to JsonPrimitive("Janet"),
            ),
            projection.claims,
        )
        assertEquals(
            parse("""{"org.iso.18013.5.1":{"given_name":"Jane","age_over_18":true},"org.iso.18013.5.1.aamva":{"given_name":"Janet"}}"""),
            projection.queryRoot,
        )
        assertEquals("org.iso.18013.5.1.mDL", projection.credentialType)
    }

    @Test
    fun shouldTurnJsonStringsIntoStringsAndNeverIntoNumbersOrBooleans() {
        assertEquals("0612345678", JsonPrimitive("0612345678").toClaimValue())
        assertEquals("true", JsonPrimitive("true").toClaimValue())
        assertEquals("NaN", JsonPrimitive("NaN").toClaimValue())
        assertEquals("", JsonPrimitive("").toClaimValue())
    }

    @Test
    fun shouldTurnJsonNumbersAndBooleansIntoNativeValuesWhenExact() {
        assertEquals(30L, JsonPrimitive(30).toClaimValue())
        assertEquals(true, JsonPrimitive(true).toClaimValue())
        assertEquals(1.5, JsonPrimitive(1.5).toClaimValue())
        assertNull(JsonNull.toClaimValue())
    }

    @Test
    fun shouldKeepANumberThatCannotBeANativeValueExactly() {
        val huge = parse("""{"n":12345678901234567890}""").getValue("n")

        assertEquals(huge, huge.toClaimValue())
    }

    @Test
    fun shouldKeepObjectsAndArraysAsJson() {
        assertEquals(address, address.toClaimValue())
        val list = buildJsonArray { add(JsonPrimitive("a")) }
        assertEquals(list, list.toClaimValue())
    }

    @Test
    fun shouldTurnEveryClaimValueKindIntoItsJsonForm() {
        assertEquals(JsonNull, claimValueToJson(null))
        assertEquals(JsonPrimitive("0612345678"), claimValueToJson("0612345678"))
        assertEquals(JsonPrimitive(30), claimValueToJson(30L))
        assertEquals(JsonPrimitive(1.5), claimValueToJson(1.5))
        assertEquals(JsonPrimitive(true), claimValueToJson(true))
        assertEquals(address, claimValueToJson(address))
        assertEquals(parse("""{"a":"1","b":[1,null]}"""), claimValueToJson(mapOf("a" to "1", "b" to listOf(1L, null))))
        assertTrue((claimValueToJson("true") as JsonPrimitive).isString)
        assertFalse((claimValueToJson(30L) as JsonPrimitive).isString)
    }

    @Test
    fun shouldRefuseAClaimValueThatHasNoJsonForm() {
        assertFailsWith<IllegalArgumentException> { claimValueToJson(Any()) }
        assertFailsWith<IllegalArgumentException> { claimValueToJson(mapOf(1 to "numeric key")) }
    }

    @Test
    fun shouldTurnAnArrayOfClaimValuesIntoAJsonArray() {
        assertEquals(
            claimValueToJson(listOf("a", 2L, true)),
            claimValueToJson(arrayOf<Any?>("a", 2L, true)),
        )
    }

    @Test
    fun shouldReadBackWhatWasWrittenAsAClaimValue() {
        listOf<Any?>("0612345678", "true", 30L, 1.5, true, null, address).forEach { value ->
            assertEquals(value, claimValueToJson(value).toClaimValue())
        }
    }

    @Test
    fun shouldConvertAClaimMapPreservingKeysAndOrder() {
        val claims = linkedMapOf<String, JsonElement>("b" to JsonPrimitive("1"), "a" to JsonPrimitive(1), "c" to address)

        val values = claims.toClaimValues()

        assertEquals(listOf("b", "a", "c"), values.keys.toList())
        assertEquals("1", values["b"])
        assertEquals(1L, values["a"])
        assertEquals(address, values["c"])
    }

    private fun elementBytes(value: CborItem<*>?): ByteArray =
        CborMap<CborItem<*>, CborItem<*>?>(
            mutableMapOf(
                CborString("digestID") to CborUInt(1),
                CborString("random") to CborByteString(byteArrayOf(9, 9)),
                CborString("elementIdentifier") to CborString("portrait"),
                CborString("elementValue") to value,
            ),
        ).encodeCbor()

    private val parser = CborParserImpl()

    @Test
    fun shouldReadAnMdocByteStringElementAsBase64UrlText() {
        val result = mdocElementValue(elementBytes(CborByteString(byteArrayOf(0xfb.toByte(), 0xff.toByte()))), parser)

        assertEquals(JsonPrimitive("-_8"), result.value)
    }

    @Test
    fun shouldReadAnMdocTaggedDateElementAsItsText() {
        val result = mdocElementValue(elementBytes(CborTagged(1004, CborString("1990-05-17"))), parser)

        assertEquals(JsonPrimitive("1990-05-17"), result.value)
    }

    @Test
    fun shouldReadNestedMdocElementsAsJsonObjectsAndArrays() {
        val nested =
            CborMap<CborItem<*>, CborItem<*>?>(
                mutableMapOf(
                    CborString("street") to CborString("Main"),
                    CborString("numbers") to CborArray<CborItem<*>>(mutableListOf(CborUInt(1), CborString("2"))),
                    CborString("missing") to CborNull(),
                ),
            )

        val result = mdocElementValue(elementBytes(nested), parser)

        assertEquals(parse("""{"street":"Main","numbers":[1,"2"],"missing":null}"""), result.value)
    }

    @Test
    fun shouldKeepAnMdocTextElementThatLooksLikeANumberAsText() {
        val result = mdocElementValue(elementBytes(CborString("0612345678")), parser)

        assertEquals(JsonPrimitive("0612345678"), result.value)
    }

    @Test
    fun shouldReadAnMdocNullElementAsJsonNull() {
        assertEquals(JsonNull, mdocElementValue(elementBytes(CborNull()), parser).value)
    }

    @Test
    fun shouldRefuseAnMdocItemWithoutAnElementValueOrThatIsNotAMap() {
        val withoutValue = CborMap<CborItem<*>, CborItem<*>?>(mutableMapOf(CborString("digestID") to CborUInt(1))).encodeCbor()

        assertTrue(mdocElementValue(withoutValue, parser).isErr)
        assertTrue(mdocElementValue(CborString("not a map").encodeCbor(), parser).isErr)
        assertTrue(mdocElementValue(byteArrayOf(0x1c), parser).isErr)
    }
}
