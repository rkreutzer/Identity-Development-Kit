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

package com.sphereon.sdjwt.vc

import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SdJwtVcClaimsTest {
    @Test
    fun shouldReadTheVctOfAPayload() {
        assertEquals("urn:test:pid", SdJwtVcClaims.vct(buildJsonObject { put("vct", "urn:test:pid") }))
    }

    @Test
    fun shouldReturnNullWhenTheVctIsMissing() {
        assertNull(SdJwtVcClaims.vct(JsonObject(emptyMap())))
    }

    @Test
    fun shouldReturnNullWhenTheVctIsBlank() {
        assertNull(SdJwtVcClaims.vct(buildJsonObject { put("vct", "  ") }))
    }

    @Test
    fun shouldReturnNullWhenTheVctIsNotAString() {
        assertNull(SdJwtVcClaims.vct(buildJsonObject { put("vct", 1) }))
    }

    @Test
    fun shouldReturnNullWhenTheVctIsNull() {
        assertNull(SdJwtVcClaims.vct(JsonObject(mapOf("vct" to JsonNull))))
    }

    @Test
    fun shouldTreatAnAbsentIntegrityClaimAsNoPin() {
        assertNull(SdJwtVcClaims.vctIntegrity(JsonObject(emptyMap())).getOrNull())
        assertTrue(SdJwtVcClaims.vctIntegrity(JsonObject(emptyMap())).isOk)
    }

    @Test
    fun shouldReadAnIntegrityExpression() {
        assertEquals("sha256-abc", SdJwtVcClaims.vctIntegrity(buildJsonObject { put("vct#integrity", "sha256-abc") }).getOrNull())
    }

    @Test
    fun shouldRefuseAnIntegrityClaimThatIsNotAString() {
        assertTrue(SdJwtVcClaims.vctIntegrity(buildJsonObject { put("vct#integrity", 1) }).isErr)
    }

    @Test
    fun shouldRefuseABlankIntegrityClaim() {
        assertTrue(SdJwtVcClaims.vctIntegrity(buildJsonObject { put("vct#integrity", " ") }).isErr)
    }

    @Test
    fun shouldRefuseANullIntegrityClaim() {
        assertTrue(SdJwtVcClaims.vctIntegrity(JsonObject(mapOf("vct#integrity" to JsonPrimitive(null as String?)))).isErr)
    }
}
