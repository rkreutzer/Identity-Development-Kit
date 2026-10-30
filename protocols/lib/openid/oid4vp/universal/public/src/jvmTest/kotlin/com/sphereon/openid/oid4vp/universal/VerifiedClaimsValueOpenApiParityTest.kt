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

package com.sphereon.openid.oid4vp.universal

import it.krzeminski.snakeyaml.engine.kmp.api.Load
import it.krzeminski.snakeyaml.engine.kmp.api.LoadSettings
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The claims of a verified credential are a map from claim name to any JSON value. This keeps the
 * serialized `VerifiedClaimsValue` and every OpenAPI mirror in this repository saying the same thing, so a
 * client generated from a mirror does not read a nested claim as text.
 */
class VerifiedClaimsValueOpenApiParityTest {
    private val json = Json { encodeDefaults = true }

    private val claims: Map<String, JsonElement> =
        linkedMapOf(
            "text" to JsonPrimitive("0612345678"),
            "number" to JsonPrimitive(30),
            "boolean" to JsonPrimitive(true),
            "object" to buildJsonObject { put("street", "Main"); put("geo", buildJsonArray { add(JsonPrimitive(1)); add(JsonPrimitive(2.5)) }) },
            "list" to buildJsonArray { add(JsonPrimitive("a")); add(JsonPrimitive(2)) },
            "nothing" to JsonNull,
        )

    @Test
    fun shouldSerializeEveryClaimAtItsJsonType() {
        val serialized = json.encodeToJsonElement(VerifiedClaimsValue.serializer(), VerifiedClaimsValue(id = "q", type = "t", claims = claims))

        assertEquals(claims, serialized.jsonObject.getValue("claims").jsonObject.toMap())
        val written = serialized.jsonObject.getValue("claims").jsonObject
        assertTrue((written.getValue("text") as JsonPrimitive).isString)
        assertFalse((written.getValue("number") as JsonPrimitive).isString)
        assertIs<kotlinx.serialization.json.JsonObject>(written.getValue("object"))
        assertIs<kotlinx.serialization.json.JsonArray>(written.getValue("list"))
    }

    @Test
    fun shouldDescribeClaimsAsAMapToAnyJsonValueInEveryOwnedMirror() {
        val mirrors = openApiMirrors()
        assertEquals(6, mirrors.size, "Every pack owns one mirror of the Universal OID4VP components")

        for (mirror in mirrors) {
            val claimsSchema = parseSchemas(mirror).mapValue("VerifiedClaimsValue").mapValue("properties").mapValue("claims")

            assertEquals("object", claimsSchema.stringValue("type"), "claims must be an object in $mirror")
            val values = claimsSchema["additionalProperties"]
            assertIs<Map<*, *>>(values, "claims values must be described by a schema, not a flag, in $mirror")
            assertFalse(values.containsKey("type"), "claims values must not be restricted to one JSON type in $mirror")
            assertFalse(values.containsKey("enum"), "claims values must not be restricted to a value set in $mirror")
            assertFalse(values.containsKey("oneOf"), "claims values must not be restricted to a few shapes in $mirror")
        }
    }

    /**
     * The openapi repository owns the published contract and sits next to the IDK in the infra checkout. Its `claims`
     * schema must say the same as the mirrors. A standalone IDK checkout has no sibling repository, so this check
     * then has nothing to read and the mirror test above is the only guard.
     */
    @Test
    fun shouldDescribeClaimsInTheOpenapiRepositoryLikeTheMirrors() {
        val idkRoot = requireNotNull(System.getProperty("sphereon.test.idkRoot")) { "The JVM test task must supply the IDK root" }
        val published = java.io.File(idkRoot, "../openapi/oid4vp-universal-components.yml")
        if (!published.isFile) return

        val mirror = parseSchemas(java.io.File(idkRoot, "protocols/openapi/oid4vp-universal-components.yml").canonicalPath)
        val repo = parseSchemas(published.canonicalPath)
        fun claims(schemas: Map<String, Any?>) = schemas.mapValue("VerifiedClaimsValue").mapValue("properties").mapValue("claims")

        assertEquals(claims(mirror), claims(repo), "the openapi repository and the IDK mirrors must describe claims identically")
    }

    private fun openApiMirrors(): List<String> =
        listOf(
            // Every standalone pack owns this mirror; no sibling repository is required.
            "core/openapi/oid4vp-universal-components.yml",
            "infra/openapi/oid4vp-universal-components.yml",
            "identity-security/openapi/oid4vp-universal-components.yml",
            "protocols/openapi/oid4vp-universal-components.yml",
            "wallet-lib/openapi/oid4vp-universal-components.yml",
            "platform/openapi/oid4vp-universal-components.yml",
        ).map { relative ->
            val idkRoot = requireNotNull(System.getProperty("sphereon.test.idkRoot")) {
                "The JVM test task must supply the IDK root for OpenAPI mirror validation"
            }
            java.io.File(idkRoot, relative).canonicalPath
        }.onEach { path ->
            assertTrue(java.io.File(path).isFile, "Missing OpenAPI mirror: $path")
        }

    private fun parseSchemas(path: String): Map<String, Any?> {
        val document =
            Load(LoadSettings()).loadOne(java.io.File(path).readText()) as? Map<*, *>
                ?: error("OpenAPI document is not a YAML map: $path")
        return (document["components"] as? Map<*, *>)
            ?.get("schemas")
            .let { it as? Map<*, *> }
            ?.mapKeys { it.key.toString() }
            ?: error("Component schemas missing from $path")
    }

    private fun Map<String, Any?>.mapValue(key: String): Map<String, Any?> =
        (this[key] as? Map<*, *>)?.mapKeys { it.key.toString() }
            ?: error("Expected map property '$key'")

    private fun Map<String, Any?>.stringValue(key: String): String =
        this[key] as? String ?: error("Expected string property '$key'")
}
