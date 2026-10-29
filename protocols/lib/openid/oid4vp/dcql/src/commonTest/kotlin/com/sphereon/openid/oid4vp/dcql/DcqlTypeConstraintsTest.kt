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

package com.sphereon.openid.oid4vp.dcql

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DcqlTypeConstraintsTest {
    private fun w3c(vararg alternatives: List<String>) =
        DcqlCredentialQuery(
            id = "q",
            format = "ldp_vc",
            meta = buildJsonObject { put("type_values", JsonArray(alternatives.map { JsonArray(it.map(::JsonPrimitive)) })) },
        )

    @Test
    fun shouldReadTheVctValuesOfAnSdJwtQuery() {
        val query = DcqlCredentialQuery(id = "q", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:a", "urn:b"))

        assertEquals(listOf("urn:a", "urn:b"), query.vctValues())
    }

    @Test
    fun shouldReturnNoVctValuesForAQueryWithoutThem() {
        assertNull(w3c(listOf("A")).vctValues())
    }

    @Test
    fun shouldReadTheTypeValueAlternativesOfAW3cQuery() {
        assertEquals(listOf(listOf("A", "B"), listOf("C")), w3c(listOf("A", "B"), listOf("C")).typeValueAlternatives())
    }

    @Test
    fun shouldReturnNoAlternativesForAQueryWithoutTypeValues() {
        val query = DcqlCredentialQuery(id = "q", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:a"))

        assertNull(query.typeValueAlternatives())
    }

    @Test
    fun shouldBeSatisfiedWhenOneAlternativeIsContained() {
        assertTrue(listOf(listOf("X"), listOf("A", "B")).anyAlternativeSatisfiedBy(setOf("A", "B", "extra")))
    }

    @Test
    fun shouldNotBeSatisfiedByAPartialAlternative() {
        assertFalse(listOf(listOf("A", "B")).anyAlternativeSatisfiedBy(setOf("A")))
    }

    @Test
    fun shouldNotCombineAlternatives() {
        assertFalse(listOf(listOf("A", "X"), listOf("B", "Y")).anyAlternativeSatisfiedBy(setOf("A", "B")))
    }

    @Test
    fun shouldNeverBeSatisfiedByAnEmptyAlternative() {
        assertFalse(listOf(emptyList<String>()).anyAlternativeSatisfiedBy(setOf("A")))
    }

    @Test
    fun shouldNeverBeSatisfiedWithNoAlternatives() {
        assertFalse(emptyList<List<String>>().anyAlternativeSatisfiedBy(setOf("A")))
    }
}
