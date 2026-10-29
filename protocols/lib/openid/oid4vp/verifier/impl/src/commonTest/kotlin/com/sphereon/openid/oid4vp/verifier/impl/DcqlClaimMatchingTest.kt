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

import com.sphereon.openid.oid4vp.dcql.ClaimsPathPointer
import com.sphereon.openid.oid4vp.dcql.DcqlClaimQuery
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import com.sphereon.openid.oid4vp.dcql.sdJwtVcMeta
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DcqlClaimMatchingTest {
    private fun root(text: String): JsonObject = Json.parseToJsonElement(text) as JsonObject

    private fun path(vararg components: Any?): ClaimsPathPointer =
        ClaimsPathPointer(
            components.map {
                when (it) {
                    null -> JsonNull
                    is Int -> JsonPrimitive(it)
                    is Long -> JsonPrimitive(it)
                    else -> JsonPrimitive(it.toString())
                }
            },
        )

    private fun claim(id: String?, vararg components: Any?, values: List<JsonElement>? = null) = DcqlClaimQuery(path = path(*components), id = id, values = values)

    private fun query(claims: List<DcqlClaimQuery>?, claimSets: List<List<String>>? = null) =
        DcqlCredentialQuery(id = "q", format = "dc+sd-jwt", meta = sdJwtVcMeta("urn:test:type"), claims = claims, claim_sets = claimSets)

    private fun satisfied(claims: List<DcqlClaimQuery>?, document: String, claimSets: List<List<String>>? = null) =
        satisfiesRequestedClaims(query(claims, claimSets), root(document))

    @Test
    fun shouldAcceptACredentialWhenNoClaimsAreRequested() {
        assertTrue(satisfied(null, """{}"""))
        assertTrue(satisfied(null, """{"a":1}"""))
    }

    @Test
    fun shouldRequireEveryRequestedClaimWhenThereAreNoClaimSets() {
        val claims = listOf(claim(null, "a"), claim(null, "b"))

        assertTrue(satisfied(claims, """{"a":1,"b":2}"""))
        assertFalse(satisfied(claims, """{"a":1}"""))
        assertFalse(satisfied(claims, """{"b":2}"""))
        assertFalse(satisfied(claims, """{}"""))
    }

    @Test
    fun shouldTreatAPartialPathAsMissing() {
        val claims = listOf(claim(null, "address", "street"))

        assertTrue(satisfied(claims, """{"address":{"street":"Main"}}"""))
        assertFalse(satisfied(claims, """{"address":{}}"""))
        assertFalse(satisfied(claims, """{"address":"Main"}"""))
        assertFalse(satisfied(claims, """{"address":null}"""))
        assertFalse(satisfied(claims, """{"address":[{"street":"Main"}]}"""))
    }

    @Test
    fun shouldTreatAnExplicitNullLeafAsPresent() {
        assertTrue(satisfied(listOf(claim(null, "a")), """{"a":null}"""))
        assertFalse(satisfied(listOf(claim(null, "a")), """{"b":null}"""))
    }

    @Test
    fun shouldTreatAnEmptyWildcardResultAsAbsent() {
        val claims = listOf(claim(null, "items", null, "name"))

        assertTrue(satisfied(claims, """{"items":[{"name":"a"}]}"""))
        assertFalse(satisfied(claims, """{"items":[]}"""))
        assertFalse(satisfied(claims, """{"items":[{"other":1}]}"""))
        assertFalse(satisfied(claims, """{"items":{"name":"a"}}"""))
        assertFalse(satisfied(claims, """{"items":"name"}"""))
    }

    @Test
    fun shouldResolveArrayIndexesAndRefuseOutOfRangeOnes() {
        val first = listOf(claim(null, "items", 0))
        val second = listOf(claim(null, "items", 1))

        assertTrue(satisfied(first, """{"items":["a","b"]}"""))
        assertTrue(satisfied(second, """{"items":["a","b"]}"""))
        assertFalse(satisfied(second, """{"items":["a"]}"""))
        assertFalse(satisfied(first, """{"items":[]}"""))
        assertFalse(satisfied(listOf(claim(null, "items", Long.MAX_VALUE)), """{"items":["a","b"]}"""))
        assertFalse(satisfied(first, """{"items":{"0":"a"}}"""))
    }

    @Test
    fun shouldKeepAnObjectKeyOfOneApartFromArrayIndexOne() {
        assertTrue(satisfied(listOf(claim(null, "m", "1")), """{"m":{"1":"x"}}"""))
        assertFalse(satisfied(listOf(claim(null, "m", "1")), """{"m":["a","b"]}"""))
        assertFalse(satisfied(listOf(claim(null, "m", 1)), """{"m":{"1":"x"}}"""))
    }

    @Test
    fun shouldResolveANameWithDotsAsOneKeyNotAsNestedKeys() {
        val claims = listOf(claim(null, "org.iso.18013.5.1", "given_name"))

        assertTrue(satisfied(claims, """{"org.iso.18013.5.1":{"given_name":"Jane"}}"""))
        assertFalse(satisfied(claims, """{"org":{"iso":{"18013":{"5":{"1":{"given_name":"Jane"}}}}}}"""))
    }

    @Test
    fun shouldWalkNestedWildcardsAcrossArrays() {
        val claims = listOf(claim(null, "a", null, "b", null, "c"))

        assertTrue(satisfied(claims, """{"a":[{"b":[{"c":1}]}]}"""))
        assertFalse(satisfied(claims, """{"a":[{"b":[{"d":1}]}]}"""))
        assertFalse(satisfied(claims, """{"a":[{"b":[]}]}"""))
    }

    @Test
    fun shouldCompareAllowedValuesWithoutCoercingTheirType() {
        val text = listOf(claim(null, "v", values = listOf(JsonPrimitive("true"))))
        val boolean = listOf(claim(null, "v", values = listOf(JsonPrimitive(true))))
        val number = listOf(claim(null, "v", values = listOf(JsonPrimitive(1))))
        val numeric = listOf(claim(null, "v", values = listOf(JsonPrimitive("1"))))

        assertTrue(satisfied(text, """{"v":"true"}"""))
        assertFalse(satisfied(text, """{"v":true}"""))
        assertTrue(satisfied(boolean, """{"v":true}"""))
        assertFalse(satisfied(boolean, """{"v":"true"}"""))
        assertTrue(satisfied(number, """{"v":1}"""))
        assertFalse(satisfied(number, """{"v":"1"}"""))
        assertTrue(satisfied(numeric, """{"v":"1"}"""))
        assertFalse(satisfied(numeric, """{"v":1}"""))
    }

    @Test
    fun shouldAcceptAnyOfSeveralAllowedValuesAndRejectOthers() {
        val claims = listOf(claim(null, "country", values = listOf(JsonPrimitive("NL"), JsonPrimitive("BE"))))

        assertTrue(satisfied(claims, """{"country":"NL"}"""))
        assertTrue(satisfied(claims, """{"country":"BE"}"""))
        assertFalse(satisfied(claims, """{"country":"DE"}"""))
        assertFalse(satisfied(claims, """{"country":null}"""))
        assertFalse(satisfied(claims, """{}"""))
    }

    @Test
    fun shouldAcceptAWildcardClaimWhenAtLeastOneResolvedValueIsAllowed() {
        val claims = listOf(claim(null, "nationalities", null, values = listOf(JsonPrimitive("NL"))))

        assertTrue(satisfied(claims, """{"nationalities":["DE","NL"]}"""))
        assertFalse(satisfied(claims, """{"nationalities":["DE","BE"]}"""))
        assertFalse(satisfied(claims, """{"nationalities":[]}"""))
    }

    @Test
    fun shouldAcceptTheFirstCompleteClaimSet() {
        val claims = listOf(claim("a", "a"), claim("b", "b"), claim("c", "c"))
        val sets = listOf(listOf("a", "b"), listOf("c"))

        assertTrue(satisfied(claims, """{"a":1,"b":2}""", sets))
    }

    @Test
    fun shouldAcceptTheSecondClaimSetWhenOnlyItIsComplete() {
        val claims = listOf(claim("a", "a"), claim("b", "b"), claim("c", "c"))
        val sets = listOf(listOf("a", "b"), listOf("c"))

        assertTrue(satisfied(claims, """{"c":3}""", sets))
    }

    @Test
    fun shouldRejectAnEmptyClaimSetInsteadOfAcceptingEverything() {
        val claims = listOf(claim("a", "a"))

        // An empty claim set option would accept every credential; the query model refuses it, so no
        // request can carry one and matching never sees it (OID4VP 1.0 section 6.4.1).
        assertFailsWith<IllegalArgumentException> { query(claims, listOf(emptyList())) }
        assertFailsWith<IllegalArgumentException> { query(claims, listOf(emptyList(), listOf("a"))) }
        assertTrue(satisfied(claims, """{"a":1}""", listOf(listOf("a"))))
    }

    @Test
    fun shouldRefuseDecimalAllowedValuesAndMatchIntegersByValue() {
        // OID4VP 1.0 section 6.3: values holds only strings, integers or booleans.
        assertFailsWith<IllegalArgumentException> { claim(null, "ratio", values = listOf(JsonPrimitive(1.5))) }

        val claims = listOf(claim(null, "count", values = listOf(JsonPrimitive(15))))
        assertTrue(satisfied(claims, """{"count":15}"""))
        assertFalse(satisfied(claims, """{"count":16}"""))
        assertFalse(satisfied(claims, """{"count":"15"}"""))
    }

    @Test
    fun shouldRejectWhenNoClaimSetIsComplete() {
        val claims = listOf(claim("a", "a"), claim("b", "b"), claim("c", "c"))
        val sets = listOf(listOf("a", "b"), listOf("c"))

        assertFalse(satisfied(claims, """{"a":1}""", sets))
        assertFalse(satisfied(claims, """{}""", sets))
    }

    @Test
    fun shouldAcceptTheSecondClaimSetWhenTheFirstFailsOnAValueOutsideTheAllowedValues() {
        val claims =
            listOf(
                claim("country", "country", values = listOf(JsonPrimitive("NL"))),
                claim("age", "age_over_18"),
                claim("fallback", "residence"),
            )
        val sets = listOf(listOf("country", "age"), listOf("fallback"))

        assertTrue(satisfied(claims, """{"country":"DE","age_over_18":true,"residence":"Berlin"}""", sets))
        assertFalse(satisfied(claims, """{"country":"DE","age_over_18":true}""", sets))
        assertTrue(satisfied(claims, """{"country":"NL","age_over_18":true}""", sets))
    }

    @Test
    fun shouldNotLetOneSatisfiedSetHideAnUnsatisfiedClaimInTheSameSet() {
        val claims = listOf(claim("a", "a"), claim("b", "b", values = listOf(JsonPrimitive(2))))
        val sets = listOf(listOf("a", "b"))

        assertTrue(satisfied(claims, """{"a":1,"b":2}""", sets))
        assertFalse(satisfied(claims, """{"a":1,"b":3}""", sets))
    }

    @Test
    fun shouldEvaluateMdocStyleNamespacedRoots() {
        val claims = listOf(claim(null, "org.iso.18013.5.1", "given_name"), claim(null, "org.iso.18013.5.1", "age_over_18", values = listOf(JsonPrimitive(true))))

        assertTrue(satisfied(claims, """{"org.iso.18013.5.1":{"given_name":"Jane","age_over_18":true}}"""))
        assertFalse(satisfied(claims, """{"org.iso.18013.5.1":{"given_name":"Jane","age_over_18":false}}"""))
        assertFalse(satisfied(claims, """{"org.iso.18013.5.1.aamva":{"given_name":"Jane","age_over_18":true}}"""))
    }
}
