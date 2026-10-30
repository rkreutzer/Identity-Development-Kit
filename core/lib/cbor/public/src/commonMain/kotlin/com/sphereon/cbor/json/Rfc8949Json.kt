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

@file:OptIn(ExperimentalSerializationApi::class)

package com.sphereon.cbor.json

import com.sphereon.cbor.CDDL
import com.sphereon.cbor.CborArray
import com.sphereon.cbor.CborByteString
import com.sphereon.cbor.CborByteStringIndefLength
import com.sphereon.cbor.CborDouble
import com.sphereon.cbor.CborEncodedItem
import com.sphereon.cbor.CborError
import com.sphereon.cbor.CborFloat
import com.sphereon.cbor.CborInt
import com.sphereon.cbor.CborItem
import com.sphereon.cbor.CborMap
import com.sphereon.cbor.CborNInt
import com.sphereon.cbor.CborSimple
import com.sphereon.cbor.CborString
import com.sphereon.cbor.CborStringIndefLength
import com.sphereon.cbor.CborTagged
import com.sphereon.cbor.CborUInt
import com.sphereon.core.api.Encoding
import com.sphereon.core.api.IdkErrorResult
import com.sphereon.core.api.IdkOkResult
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.encodeTo
import com.sphereon.core.api.error.IdkError
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonUnquotedLiteral

private const val TAG_POSITIVE_BIGNUM = 2
private const val TAG_NEGATIVE_BIGNUM = 3
private const val TAG_EXPECT_BASE64URL = 21
private const val TAG_EXPECT_BASE64 = 22
private const val TAG_EXPECT_BASE16 = 23
private const val NEGATIVE_BIGNUM_PREFIX = "~"

/**
 * Converts a CBOR data item to JSON following the generic conversion rules of RFC 8949 section 6.1.
 *
 * This is deliberately separate from [CborItem.toJsonSimple]: that method reads the already decoded
 * Kotlin value, which has dropped the tags, and it cannot represent every item. This conversion works
 * on the item as decoded, so it can honour them:
 *
 * - Byte strings become unpadded base64url text, or the encoding named by an enclosing expected
 *   conversion tag (21 base64url, 22 base64 with padding, 23 base16 in upper case). The tag applies
 *   to every byte string below it until another such tag replaces it.
 * - Bignums (tags 2 and 3) become the base64url text of their bytes, with a leading `~` for tag 3.
 * - Any other tag is represented by its content and the tag number is ignored.
 * - Non-finite floats and `undefined` become the substitute value `null`. The text `"NaN"` stays text.
 * - Integers stay JSON numbers at full precision. A major type 0 value above [Long.MAX_VALUE], which
 *   the decoder stores as a negative [Long], is read as unsigned.
 * - Map keys that are not text become text only when that is unambiguous: integers in decimal and
 *   byte strings in the encoding in effect. Other keys, and keys that become equal after conversion,
 *   are refused rather than overwritten.
 * - Indefinite-length strings are concatenated.
 * - A negative integer below -2^63 cannot be read: the decoder keeps its magnitude plus one in a [Long], which wraps.
 */
fun CborItem<*>.toRfc8949Json(): IdkResult<JsonElement, IdkError> =
    try {
        IdkOkResult(toJson(Encoding.BASE64URL))
    } catch (refused: Rfc8949ConversionRefused) {
        IdkErrorResult(CborError.DECODE_ERROR(refused.reason))
    }

private class Rfc8949ConversionRefused(
    val reason: String,
) : RuntimeException(reason)

private fun refuse(message: String): Nothing = throw Rfc8949ConversionRefused(message)

private fun CborItem<*>.toJson(bytesEncoding: Encoding): JsonElement =
    when (this) {
        is CborEncodedItem<*> -> bytesToJson(value.taggedItem.value, bytesEncoding)
        is CborByteString -> bytesToJson(value, bytesEncoding)
        is CborByteStringIndefLength -> bytesToJson(value.fold(ByteArray(0)) { all, chunk -> all + chunk }, bytesEncoding)
        is CborString -> JsonPrimitive(value)
        is CborStringIndefLength -> JsonPrimitive(value.joinToString(""))
        is CborTagged<*> -> taggedToJson(bytesEncoding)
        is CborSimple<*> -> (value as? Boolean)?.let { JsonPrimitive(it) } ?: JsonNull
        is CborUInt, is CborNInt, is CborInt -> JsonUnquotedLiteral(integerText())
        is CborFloat -> floatToJson(value)
        is CborDouble -> doubleToJson(value)
        is CborArray<*> -> JsonArray(value.map { it.toJson(bytesEncoding) })
        is CborMap<*, *> -> mapToJson(bytesEncoding)
        else -> refuse("Unsupported CBOR item ${this::class.simpleName} cannot be converted to JSON")
    }

private fun bytesToJson(
    bytes: ByteArray,
    encoding: Encoding,
): JsonPrimitive = JsonPrimitive(bytesText(bytes, encoding))

private fun bytesText(
    bytes: ByteArray,
    encoding: Encoding,
): String =
    when (encoding) {
        Encoding.HEX -> bytes.encodeTo(Encoding.HEX).uppercase()
        else -> bytes.encodeTo(encoding)
    }

private fun CborTagged<*>.taggedToJson(bytesEncoding: Encoding): JsonElement =
    when (tagNumber) {
        TAG_POSITIVE_BIGNUM -> bignumToJson("")
        TAG_NEGATIVE_BIGNUM -> bignumToJson(NEGATIVE_BIGNUM_PREFIX)
        TAG_EXPECT_BASE64URL -> taggedItem.toJson(Encoding.BASE64URL)
        TAG_EXPECT_BASE64 -> taggedItem.toJson(Encoding.BASE64)
        TAG_EXPECT_BASE16 -> taggedItem.toJson(Encoding.HEX)
        else -> taggedItem.toJson(bytesEncoding)
    }

private fun CborTagged<*>.bignumToJson(prefix: String): JsonElement {
    val content = taggedItem
    val bytes =
        when (content) {
            is CborByteString -> content.value
            is CborByteStringIndefLength -> content.value.fold(ByteArray(0)) { all, chunk -> all + chunk }
            else -> refuse("A bignum (tag $tagNumber) must contain a byte string")
        }
    return JsonPrimitive(prefix + bytesText(bytes, Encoding.BASE64URL))
}

/**
 * Decimal text of an integer item. The decoder stores a major type 0 value above [Long.MAX_VALUE] as a
 * negative [Long] and a negative integer as its positive magnitude, so both are read unsigned.
 */
private fun CborItem<*>.integerText(): String {
    val raw = value as Long
    val negative = this is CborNInt || (this is CborInt && cddl == CDDL.nint)
    return (if (negative) "-" else "") + raw.toULong().toString()
}

private fun floatToJson(value: Float): JsonElement = if (value.isFinite()) JsonPrimitive(value.toString().toDouble()) else JsonNull

private fun doubleToJson(value: Double): JsonElement = if (value.isFinite()) JsonPrimitive(value) else JsonNull

private fun CborMap<*, *>.mapToJson(bytesEncoding: Encoding): JsonObject {
    val entries = LinkedHashMap<String, JsonElement>()
    for ((key, entry) in value) {
        val name = key.keyText(bytesEncoding)
        if (entries.containsKey(name)) {
            refuse("Two map keys become the same JSON member name '$name'")
        }
        entries[name] = entry?.toJson(bytesEncoding) ?: JsonNull
    }
    return JsonObject(entries)
}

private fun CborItem<*>.keyText(bytesEncoding: Encoding): String =
    when (this) {
        is CborString -> value
        is CborUInt, is CborNInt, is CborInt -> integerText()
        is CborByteString -> bytesText(value, bytesEncoding)
        else -> refuse("A ${this::class.simpleName} map key cannot become an unambiguous JSON member name")
    }
