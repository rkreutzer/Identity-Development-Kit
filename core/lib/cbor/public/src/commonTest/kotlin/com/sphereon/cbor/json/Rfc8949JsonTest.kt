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

package com.sphereon.cbor.json

import com.sphereon.cbor.CborArray
import com.sphereon.cbor.CborByteString
import com.sphereon.cbor.CborByteStringIndefLength
import com.sphereon.cbor.CborDouble
import com.sphereon.cbor.CborEncodedItem
import com.sphereon.cbor.CborFloat16
import com.sphereon.cbor.CborFloat32
import com.sphereon.cbor.CborItem
import com.sphereon.cbor.CborMap
import com.sphereon.cbor.CborNInt
import com.sphereon.cbor.CborSimple
import com.sphereon.cbor.CborString
import com.sphereon.cbor.CborStringIndefLength
import com.sphereon.cbor.CborTagged
import com.sphereon.cbor.CborUInt
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Rfc8949JsonTest {
    private fun convert(item: CborItem<*>): JsonElement {
        val result = item.toRfc8949Json()
        assertTrue(result.isOk, "Expected a JSON value but got ${if (result.isErr) result.error.toString() else ""}")
        return result.value
    }

    private fun array(vararg items: CborItem<*>) = CborArray<CborItem<*>>(mutableListOf(*items))

    private fun map(vararg entries: Pair<CborItem<*>, CborItem<*>?>) = CborMap<CborItem<*>, CborItem<*>?>(mutableMapOf(*entries))

    // 0xfb 0xff encodes to "-_8" in base64url, "+/8=" in base64 and "FBFF" in base16
    private val urlUnsafeBytes = byteArrayOf(0xfb.toByte(), 0xff.toByte())

    @Test
    fun shouldKeepTextAsTextWhenItLooksLikeOtherJsonTypes() {
        listOf("0612345678", "true", "false", "null", "NaN", "Infinity", "{\"x\":1}", "[1]", "1e3", "").forEach { text ->
            val json = convert(CborString(text))
            assertEquals(JsonPrimitive(text), json)
            assertTrue((json as JsonPrimitive).isString, "'$text' must stay a JSON string")
        }
    }

    @Test
    fun shouldConvertBooleansAndNullAndNil() {
        assertEquals(JsonPrimitive(true), convert(CborSimple.TRUE))
        assertEquals(JsonPrimitive(false), convert(CborSimple.FALSE))
        assertEquals(JsonNull, convert(CborSimple.NULL))
    }

    @Test
    fun shouldConvertUndefinedToTheSubstituteNull() {
        assertEquals(JsonNull, convert(CborSimple.UNDEFINED))
    }

    @Test
    fun shouldConvertIntegersToJsonNumbersNotText() {
        assertEquals("0", Json.encodeToString(JsonElement.serializer(), convert(CborUInt(0))))
        assertEquals("42", Json.encodeToString(JsonElement.serializer(), convert(CborUInt(42))))
        assertEquals("-42", Json.encodeToString(JsonElement.serializer(), convert(CborNInt(42))))
        assertFalse((convert(CborUInt(42)) as JsonPrimitive).isString)
    }

    @Test
    fun shouldKeepIntegersAboveTwoToThe53ExactWithoutDoubleNarrowing() {
        val value = 9007199254740993L // 2^53 + 1, not representable as a Double
        assertEquals("9007199254740993", Json.encodeToString(JsonElement.serializer(), convert(CborUInt(value))))
        assertEquals("-9007199254740993", Json.encodeToString(JsonElement.serializer(), convert(CborNInt(value))))
        assertEquals("9223372036854775807", Json.encodeToString(JsonElement.serializer(), convert(CborUInt(Long.MAX_VALUE))))
    }

    @Test
    fun shouldReadAnUnsignedValueAboveLongMaxAsUnsigned() {
        // The decoder stores a major type 0 value of 2^64-1 as the Long -1
        assertEquals("18446744073709551615", Json.encodeToString(JsonElement.serializer(), convert(CborUInt(-1L))))
    }

    @Test
    fun shouldConvertFloatsWithoutWideningArtifacts() {
        assertEquals("1.5", Json.encodeToString(JsonElement.serializer(), convert(CborFloat32(1.5f))))
        assertEquals("1.1", Json.encodeToString(JsonElement.serializer(), convert(CborFloat32(1.1f))))
        assertEquals("0.5", Json.encodeToString(JsonElement.serializer(), convert(CborFloat16(0.5f))))
        assertEquals("0.1", Json.encodeToString(JsonElement.serializer(), convert(CborDouble(0.1))))
    }

    @Test
    fun shouldConvertNonFiniteFloatsToTheSubstituteNullButKeepTheText() {
        assertEquals(JsonNull, convert(CborFloat32(Float.NaN)))
        assertEquals(JsonNull, convert(CborFloat32(Float.POSITIVE_INFINITY)))
        assertEquals(JsonNull, convert(CborFloat16(Float.NEGATIVE_INFINITY)))
        assertEquals(JsonNull, convert(CborDouble(Double.NaN)))
        assertEquals(JsonNull, convert(CborDouble(Double.POSITIVE_INFINITY)))
        assertEquals(JsonPrimitive("NaN"), convert(CborString("NaN")))
    }

    @Test
    fun shouldConvertByteStringsToUnpaddedBase64Url() {
        assertEquals(JsonPrimitive("-_8"), convert(CborByteString(urlUnsafeBytes)))
        assertEquals(JsonPrimitive(""), convert(CborByteString(byteArrayOf())))
        assertEquals(JsonPrimitive("AQID"), convert(CborByteString(byteArrayOf(1, 2, 3))))
        assertEquals(JsonPrimitive("AQI"), convert(CborByteString(byteArrayOf(1, 2))))
    }

    @Test
    fun shouldConcatenateIndefiniteLengthByteStringChunks() {
        val item = CborByteStringIndefLength(listOf(byteArrayOf(1, 2), byteArrayOf(3), byteArrayOf()))
        assertEquals(JsonPrimitive("AQID"), convert(item))
    }

    @Test
    fun shouldConcatenateIndefiniteLengthTextChunks() {
        assertEquals(JsonPrimitive("abcdef"), convert(CborStringIndefLength(listOf("abc", "", "def"))))
    }

    @Test
    fun shouldEncodeBytesWithTheExpectedEncodingHintTags() {
        val bytes = CborByteString(urlUnsafeBytes)
        assertEquals(JsonPrimitive("-_8"), convert(CborTagged(21, bytes)))
        assertEquals(JsonPrimitive("+/8="), convert(CborTagged(22, bytes)))
        assertEquals(JsonPrimitive("FBFF"), convert(CborTagged(23, bytes)))
    }

    @Test
    fun shouldApplyAnEncodingHintToByteStringsNestedInAContainer() {
        val tagged = CborTagged(22, array(CborByteString(urlUnsafeBytes), map(CborString("k") to CborByteString(urlUnsafeBytes))))
        val expected = JsonArray(listOf(JsonPrimitive("+/8="), JsonObject(mapOf("k" to JsonPrimitive("+/8=")))))
        assertEquals(expected, convert(tagged))
    }

    @Test
    fun shouldLetAnInnerHintReplaceTheOuterHint() {
        val tagged = CborTagged(22, array(CborTagged(23, CborByteString(urlUnsafeBytes)), CborByteString(urlUnsafeBytes)))
        assertEquals(JsonArray(listOf(JsonPrimitive("FBFF"), JsonPrimitive("+/8="))), convert(tagged))
    }

    @Test
    fun shouldNotApplyAnEncodingHintToNonByteContent() {
        assertEquals(JsonPrimitive("text"), convert(CborTagged(22, CborString("text"))))
        assertEquals(JsonPrimitive(7), convert(CborTagged(23, CborUInt(7))))
    }

    @Test
    fun shouldConvertPositiveBignumToBase64UrlText() {
        val bignum = CborTagged(2, CborByteString(byteArrayOf(1, 0)))
        assertEquals(JsonPrimitive("AQA"), convert(bignum))
    }

    @Test
    fun shouldConvertNegativeBignumToBase64UrlTextWithTildePrefix() {
        val bignum = CborTagged(3, CborByteString(byteArrayOf(1, 0)))
        assertEquals(JsonPrimitive("~AQA"), convert(bignum))
    }

    @Test
    fun shouldIgnoreHintsOnBignumContent() {
        val bignum = CborTagged(22, CborTagged(2, CborByteString(urlUnsafeBytes)))
        assertEquals(JsonPrimitive("-_8"), convert(bignum))
    }

    @Test
    fun shouldRepresentOtherTagsByTheirContentAndIgnoreTheNumber() {
        assertEquals(JsonPrimitive("2026-10-26"), convert(CborTagged(1004, CborString("2026-10-26"))))
        assertEquals(JsonPrimitive(1), convert(CborTagged(1, CborUInt(1))))
        assertEquals(JsonPrimitive("x"), convert(CborTagged(9999, CborTagged(8888, CborString("x")))))
    }

    @Test
    fun shouldConvertEncodedCborDataItemToBase64UrlOfItsBytes() {
        assertEquals(JsonPrimitive("-_8"), convert(CborEncodedItem<Any>(CborByteString(urlUnsafeBytes))))
    }

    @Test
    fun shouldConvertNestedMapsAndArraysRecursively() {
        val item =
            map(
                CborString("name") to CborString("Alice"),
                CborString("age") to CborUInt(30),
                CborString("active") to CborSimple.TRUE,
                CborString("address") to
                    map(
                        CborString("street") to CborString("Main"),
                        CborString("geo") to array(CborDouble(1.5), CborNInt(2)),
                    ),
                CborString("tags") to array(CborString("a"), CborString("b")),
                CborString("none") to CborSimple.NULL,
            )
        val expected =
            "{\"name\":\"Alice\",\"age\":30,\"active\":true," +
                "\"address\":{\"street\":\"Main\",\"geo\":[1.5,-2]},\"tags\":[\"a\",\"b\"],\"none\":null}"
        assertEquals(expected, Json.encodeToString(JsonElement.serializer(), convert(item)))
    }

    @Test
    fun shouldConvertEmptyContainers() {
        assertEquals(JsonObject(emptyMap()), convert(map()))
        assertEquals(JsonArray(emptyList()), convert(array()))
    }

    @Test
    fun shouldConvertAMapEntryWithoutAValueToNull() {
        assertEquals(JsonObject(mapOf("k" to JsonNull)), convert(map(CborString("k") to null)))
    }

    @Test
    fun shouldTreatIndefiniteLengthContainersLikeDefiniteOnes() {
        val list = CborArray<CborItem<*>>(mutableListOf(CborUInt(1), CborUInt(2)), indefiniteLength = true)
        val obj = CborMap<CborItem<*>, CborItem<*>?>(mutableMapOf(CborString("a") to CborUInt(1)), indefiniteLength = true)
        assertEquals(JsonArray(listOf(JsonPrimitive(1), JsonPrimitive(2))), convert(list))
        assertEquals(JsonObject(mapOf("a" to JsonPrimitive(1))), convert(obj))
    }

    @Test
    fun shouldConvertIntegerAndByteStringKeysToText() {
        val item = map(CborUInt(1) to CborString("one"), CborNInt(2) to CborString("minus two"), CborByteString(urlUnsafeBytes) to CborString("bytes"))
        val expected = JsonObject(mapOf("1" to JsonPrimitive("one"), "-2" to JsonPrimitive("minus two"), "-_8" to JsonPrimitive("bytes")))
        assertEquals(expected, convert(item))
    }

    @Test
    fun shouldRejectMapKeysThatCannotBecomeUnambiguousText() {
        listOf<CborItem<*>>(array(CborUInt(1)), map(), CborSimple.TRUE, CborSimple.NULL, CborDouble(1.5)).forEach { key ->
            val result = map(key to CborString("v")).toRfc8949Json()
            assertTrue(result.isErr, "Key $key must be rejected")
        }
    }

    @Test
    fun shouldRejectMapKeysThatCollideAfterConversion() {
        val result = map(CborUInt(1) to CborString("a"), CborString("1") to CborString("b")).toRfc8949Json()
        assertTrue(result.isErr)
    }

    @Test
    fun shouldRejectACollisionInsideANestedMap() {
        val nested = map(CborString("outer") to array(map(CborNInt(1) to CborString("a"), CborString("-1") to CborString("b"))))
        assertTrue(nested.toRfc8949Json().isErr)
    }

    @Test
    fun shouldProduceSerializableJsonForEveryScalar() {
        val items =
            listOf<CborItem<*>>(
                CborString("t"),
                CborUInt(1),
                CborNInt(1),
                CborFloat32(Float.NaN),
                CborDouble(Double.NEGATIVE_INFINITY),
                CborSimple.UNDEFINED,
                CborByteString(urlUnsafeBytes),
            )
        items.forEach { Json.encodeToString(JsonElement.serializer(), convert(it)) }
    }
}
