/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.openid.oid4vp.universal

import com.sphereon.openid.oid4vp.verifier.model.AuthorizationSessionStatus
import it.krzeminski.snakeyaml.engine.kmp.api.Load
import it.krzeminski.snakeyaml.engine.kmp.api.LoadSettings
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * `CallbackOpts` belongs to the Universal OID4VP specification, which FIDES publishes and other
 * vendors implement. Existing property names and shapes are therefore fixed: this deployment may
 * add properties (`secret_ref`, `signing`) but may never rename or retype `status` or
 * `verified_data`. These assertions exist to catch a local rename before it reaches the wire.
 *
 * @see <a href="https://github.com/FIDEScommunity/universal-oid4vp">Universal OID4VP spec</a>
 */
class CallbackOptsOpenApiParityTest {
    private val json = Json { encodeDefaults = true }

    @Test
    fun callbackSerializationMatchesAllOwnedOpenApiMirrors() {
        val serialized =
            json.encodeToString(
                CallbackConfig.serializer(),
                CallbackConfig(
                    url = "https://callback.example.test/status",
                    statuses = listOf(AuthorizationSessionStatus.AUTHORIZATION_RESPONSE_VERIFIED),
                    verifiedData = VerifiedDataOpts(modes = listOf(VerifiedDataMode.CREDENTIAL_CLAIMS_DESERIALIZED)),
                ),
            )
        val callbackJson = json.parseToJsonElement(serialized).jsonObject

        assertEquals(
            setOf("url", "status", "verified_data", "secret_ref", "signing"),
            callbackJson.keys,
        )
        assertTrue(callbackJson["status"] is JsonArray)
        val serializedModes =
            callbackJson.getValue("verified_data").jsonObject.getValue("modes").jsonArray
                .map { mode -> mode.jsonPrimitive.content }
        assertEquals(listOf("credential_claims_deserialized"), serializedModes)
        assertFalse(callbackJson.containsKey("statuses"), "The spec property is the singular status array")
        assertFalse(callbackJson.containsKey("include_verified_data"), "The spec carries verified_data modes, not a flag")

        for (spec in openApiMirrors()) {
            val schemas = parseSchemas(spec)
            val properties = schemas.mapValue("CallbackOpts").mapValue("properties")

            assertEquals(
                setOf("url", "status", "verified_data", "secret_ref", "signing"),
                properties.keys,
                "CallbackOpts properties drifted in $spec",
            )
            assertFalse(properties.containsKey("statuses"), "Renaming the spec property status is not allowed in $spec")
            assertFalse(
                properties.containsKey("include_verified_data"),
                "Replacing the spec property verified_data with a flag is not allowed in $spec",
            )

            val status = properties.mapValue("status")
            assertEquals("array", status.stringValue("type"))
            assertEquals(
                "#/components/schemas/AuthorizationStatus",
                status.mapValue("items").stringValue("\$ref"),
            )
            assertEquals(
                "#/components/schemas/VerifiedDataOpts",
                properties.mapValue("verified_data").stringValue("\$ref"),
            )

            val modes = schemas.mapValue("VerifiedDataOpts").mapValue("properties").mapValue("modes")
            assertEquals(
                "#/components/schemas/VerifiedDataMode",
                modes.mapValue("items").stringValue("\$ref"),
            )
            assertEquals(
                VerifiedDataMode.entries.map { mode -> json.encodeToString(mode).trim('"') }.toSet(),
                (schemas.mapValue("VerifiedDataMode")["enum"] as List<*>).map { it.toString() }.toSet(),
                "VerifiedDataMode drifted from the spec enum in $spec",
            )
        }
    }

    @Test
    fun shouldDocumentOnlyDefinedVerifiedDataModesInEveryMirror() {
        val definedModes = setOf("authorization_response", "vp_token", "credential_claims_deserialized")

        for (spec in openApiMirrors()) {
            val schemas = parseSchemas(spec)
            val modeEnum = (schemas.mapValue("VerifiedDataMode")["enum"] as List<*>).map { it.toString() }.toSet()
            assertEquals(definedModes, modeEnum, "VerifiedDataMode must name exactly the defined modes in $spec")

            val description = schemas.mapValue("VerifiedDataOpts").stringValue("description")
            assertFalse(
                Regex("""\bcredentials_deserialized\b""").containsMatchIn(description),
                "The description names an undefined mode in $spec",
            )
            for (mode in definedModes) {
                assertTrue(description.contains(mode), "The description must name $mode in $spec")
            }
        }
    }

    @Test
    fun shouldUseAValidVerifiedDataOptsObjectExample() {
        val definedModes = setOf("authorization_response", "vp_token", "credential_claims_deserialized")

        for (spec in openApiMirrors()) {
            val opts = parseSchemas(spec).mapValue("VerifiedDataOpts")
            assertEquals("object", opts.stringValue("type"), "VerifiedDataOpts must be an object in $spec")

            val example = opts["example"] as? Map<*, *> ?: error("VerifiedDataOpts example must be an object in $spec")
            assertEquals(setOf("modes"), example.keys.map { it.toString() }.toSet(), "Example members drifted in $spec")
            val exampleModes = (example["modes"] as? List<*>)?.map { it.toString() } ?: error("Example modes must be an array in $spec")
            assertEquals(definedModes, exampleModes.toSet(), "Example must use only defined modes in $spec")

            val decoded = json.decodeFromString(
                VerifiedDataOpts.serializer(),
                JsonObject(mapOf("modes" to JsonArray(exampleModes.map { JsonPrimitive(it) }))).toString(),
            )
            assertEquals(3, decoded.modes.size, "Example must deserialize as VerifiedDataOpts in $spec")
        }
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

    @Suppress("UNCHECKED_CAST")
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

    @Suppress("UNCHECKED_CAST")
    private fun Map<String, Any?>.mapValue(key: String): Map<String, Any?> =
        (this[key] as? Map<*, *>)?.mapKeys { it.key.toString() }
            ?: error("Expected map property '$key'")

    private fun Map<String, Any?>.stringValue(key: String): String =
        this[key] as? String ?: error("Expected string property '$key'")
}
