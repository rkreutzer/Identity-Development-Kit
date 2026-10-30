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
import com.sphereon.core.api.Ok
import com.sphereon.jsonld.JsonLdError
import com.sphereon.jsonld.LinkedDataDocument
import com.sphereon.jsonld.loader.LinkedDataDocumentLoader
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class JsonLdTypeExpanderTest {
    private val examples = "https://example.org/contexts/v1"
    private val vocab = "https://example.org/vocab#"

    private val contexts: Map<String, JsonElement> =
        mapOf(examples to buildJsonObject { put("@context", buildJsonObject { put("@vocab", vocab) }) })

    private val requested = mutableListOf<String>()

    private val loader =
        LinkedDataDocumentLoader { iri ->
            requested += iri
            contexts[iri]?.let { Ok(LinkedDataDocument(iri, it)) } ?: Err(JsonLdError.LoadingDocumentFailed(iri, "not served"))
        }

    private fun types(vararg names: String) = JsonArray(names.map(::JsonPrimitive))

    @Test
    fun shouldExpandATypeThroughTheContext() =
        runTest {
            val result = JsonLdTypeExpander(loader).expandedRootTypes(JsonPrimitive(examples), types("Degree"))

            assertEquals(setOf("${vocab}Degree"), result.getOrNull())
        }

    @Test
    fun shouldExpandATypeGivenAsASingleString() =
        runTest {
            val result = JsonLdTypeExpander(loader).expandedRootTypes(JsonPrimitive(examples), JsonPrimitive("Degree"))

            assertEquals(setOf("${vocab}Degree"), result.getOrNull())
        }

    @Test
    fun shouldKeepATypeNoContextDefinesAsWritten() =
        runTest {
            val result = JsonLdTypeExpander(loader).expandedRootTypes(null, types("IdentityCredential"))

            assertEquals(setOf("IdentityCredential"), result.getOrNull())
            assertTrue(requested.isEmpty())
        }

    @Test
    fun shouldFailWhenAContextCannotBeLoadedEvenIfTheLiteralTypeWouldMatch() =
        runTest {
            val result = JsonLdTypeExpander(loader).expandedRootTypes(JsonPrimitive("https://example.org/missing"), types("Degree"))

            assertTrue(result.isErr)
        }

    @Test
    fun shouldFailForAnEmptyTypeList() =
        runTest {
            assertTrue(JsonLdTypeExpander(loader).expandedRootTypes(null, JsonArray(emptyList())).isErr)
        }

    @Test
    fun shouldFailForATypeThatIsNotAString() =
        runTest {
            assertTrue(JsonLdTypeExpander(loader).expandedRootTypes(null, JsonArray(listOf(JsonPrimitive(1)))).isErr)
        }

    @Test
    fun shouldFailForANullType() =
        runTest {
            assertTrue(JsonLdTypeExpander(loader).expandedRootTypes(null, JsonNull).isErr)
        }
}
