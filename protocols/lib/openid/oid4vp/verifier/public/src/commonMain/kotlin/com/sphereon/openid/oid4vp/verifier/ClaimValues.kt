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

package com.sphereon.openid.oid4vp.verifier

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * The JSON form of one value of [MatchedCredential.disclosedClaims].
 *
 * Text stays a JSON string whatever it looks like, so a phone number or the text `"true"` is never turned
 * into a number or a boolean. A [JsonElement] is kept as it is, and maps and lists become JSON objects and
 * arrays, as do arrays of such values. A value that has no JSON form is refused instead of being written as its `toString()`.
 *
 * @throws IllegalArgumentException if [value] is not null, text, a boolean, a number, a [JsonElement], a map
 * with text keys, or a list or array of such values. Producers of [MatchedCredential.disclosedClaims] must stay within
 * these types, because this runs when a session is stored and when its verified data is read.
 */
fun claimValueToJson(value: Any?): JsonElement =
    when (value) {
        null -> JsonNull
        is JsonElement -> value
        is String -> JsonPrimitive(value)
        is Boolean -> JsonPrimitive(value)
        is Number -> JsonPrimitive(value)
        is Map<*, *> ->
            JsonObject(
                value.entries.associate { (key, entry) ->
                    require(key is String) { "A claim object key must be text" }
                    key to claimValueToJson(entry)
                },
            )
        is Iterable<*> -> JsonArray(value.map(::claimValueToJson))
        is Array<*> -> JsonArray(value.map(::claimValueToJson))
        else -> throw IllegalArgumentException("A claim value of type ${value::class.simpleName} has no JSON form")
    }
