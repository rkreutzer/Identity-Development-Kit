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

package com.sphereon.jsonld.processor

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.error.IdkError
import com.sphereon.jsonld.loader.LinkedDataDocumentLoader
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.coroutines.cancellation.CancellationException

/**
 * Expands the types of a JSON-LD node through its `@context`.
 *
 * Only the context and the type of the root node are expanded, so types carried by nested nodes, such as a
 * credential subject or a proof, never end up in the result. A type that no context defines stays as written.
 * A context that cannot be loaded is an error and never a fallback to the types as written.
 */
class JsonLdTypeExpander(
    private val processor: JsonLdProcessor,
) {
    constructor(loader: LinkedDataDocumentLoader) : this(JsonLdProcessor(loader))

    /**
     * @param context the `@context` of the node, or null when it has none
     * @param type the node's type: a string or an array of strings
     * @return the fully expanded type identifiers of the root node
     */
    suspend fun expandedRootTypes(
        context: JsonElement?,
        type: JsonElement,
    ): IdkResult<Set<String>, IdkError> {
        val document =
            buildJsonObject {
                context?.let { put("@context", it) }
                put("@type", type)
            }
        val expanded: JsonArray =
            try {
                processor.expand(document)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The types could not be expanded: ${failure.message}", throwable = failure))
            }
        val root = expanded.singleOrNull() as? JsonObject ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The types expanded to no single node"))
        val types = (root["@type"] as? JsonArray)?.map { typeName(it) }
        if (types.isNullOrEmpty() || types.any { it == null }) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "The node has no determinable types"))
        }
        return Ok(types.filterNotNull().toSet())
    }

    private fun typeName(element: JsonElement): String? =
        if (element is JsonNull) null else (element as? JsonPrimitive)?.takeIf { it.isString }?.content
}
