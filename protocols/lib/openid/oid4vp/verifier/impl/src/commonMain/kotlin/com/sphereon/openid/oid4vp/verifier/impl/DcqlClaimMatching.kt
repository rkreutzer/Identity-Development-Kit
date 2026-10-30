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

import com.sphereon.openid.oid4vp.dcql.DcqlClaimQuery
import com.sphereon.openid.oid4vp.dcql.DcqlCredentialQuery
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

/**
 * Whether one verified credential contains the claims its [query] asks for, so that the verifier, and not the
 * wallet, enforces the request.
 *
 * [root] is the structure the claim paths address: the disclosed SD-JWT payload, the W3C credential document, or the
 * mdoc elements nested by namespace. Without `claim_sets` every requested claim is required. With `claim_sets` one
 * complete set is enough, and a set that fails on a claim, including a value outside the claim's `values`, does not
 * stop a later set from being complete. An empty set is never complete. A claim id that no claim declares can never be satisfied.
 *
 * A claim is present when its path resolves to at least one value, and a JSON null is a value. When the claim lists
 * `values`, at least one resolved value must equal one of them without coercion: the text `"1"` is not the number 1,
 * and the text `"true"` is not the boolean true. A value that is not allowed counts as not present.
 */
internal fun satisfiesRequestedClaims(
    query: DcqlCredentialQuery,
    root: JsonObject,
): Boolean {
    val claims = query.claims.orEmpty()
    if (claims.isEmpty()) return true
    val claimSets = query.claim_sets
    if (claimSets.isNullOrEmpty()) return claims.all { it.isSatisfiedBy(root) }
    val claimsById = claims.filter { it.id != null }.associateBy { it.id }
    return claimSets.any { claimSet -> claimSet.isNotEmpty() && claimSet.all { id -> claimsById[id]?.isSatisfiedBy(root) == true } }
}

private fun DcqlClaimQuery.isSatisfiedBy(root: JsonObject): Boolean {
    val resolved = resolvePath(root, path.components)
    if (resolved.isEmpty()) return false
    val allowed = values ?: return true
    return resolved.any { value -> allowed.any { sameValue(value, it) } }
}

/** A string component selects an object member, a non-negative integer an array element and null every array element. */
private fun resolvePath(
    root: JsonElement,
    components: List<JsonElement>,
): List<JsonElement> {
    var nodes = listOf(root)
    for (component in components) {
        nodes = nodes.flatMap { select(it, component) }
        if (nodes.isEmpty()) return nodes
    }
    return nodes
}

private fun select(
    node: JsonElement,
    component: JsonElement,
): List<JsonElement> =
    when {
        component is JsonNull -> (node as? JsonArray)?.toList().orEmpty()
        component !is JsonPrimitive -> emptyList()
        component.isString -> listOfNotNull((node as? JsonObject)?.get(component.content))
        else -> {
            val index = component.longOrNull
            val array = node as? JsonArray
            if (index == null || array == null || index < 0 || index >= array.size) emptyList() else listOf(array[index.toInt()])
        }
    }

private fun sameValue(
    actual: JsonElement,
    allowed: JsonElement,
): Boolean {
    if (actual !is JsonPrimitive || allowed !is JsonPrimitive || actual is JsonNull || allowed is JsonNull) return false
    if (actual.isString != allowed.isString) return false
    if (actual.isString) return actual.content == allowed.content
    val actualInteger = actual.longOrNull
    val allowedInteger = allowed.longOrNull
    if (actualInteger != null && allowedInteger != null) return actualInteger == allowedInteger
    val actualDecimal = actual.doubleOrNull
    val allowedDecimal = allowed.doubleOrNull
    return if (actualDecimal != null && allowedDecimal != null) actualDecimal == allowedDecimal else actual.content == allowed.content
}
