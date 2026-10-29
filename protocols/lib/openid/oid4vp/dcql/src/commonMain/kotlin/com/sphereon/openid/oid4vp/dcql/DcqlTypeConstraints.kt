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

/** The `vct_values` of a `dc+sd-jwt` query, or null when absent or when an entry is not a string. */
fun DcqlCredentialQuery.vctValues(): List<String>? = stringArray(meta["vct_values"] as? JsonArray)

/**
 * The `type_values` of a W3C query (`jwt_vc_json`, `ldp_vc`): each inner list is one alternative, or null
 * when the shape is wrong.
 */
fun DcqlCredentialQuery.typeValueAlternatives(): List<List<String>>? {
    val outer = meta["type_values"] as? JsonArray ?: return null
    return outer.map { alternative -> stringArray(alternative as? JsonArray) ?: return null }
}

/**
 * Whether at least one non-empty alternative is fully contained in [types]: OR between alternatives, AND
 * within one (OpenID4VP 1.0 Appendix B.1.1). Extra types on the credential are allowed.
 */
fun List<List<String>>.anyAlternativeSatisfiedBy(types: Set<String>): Boolean =
    any { alternative -> alternative.isNotEmpty() && types.containsAll(alternative) }

private fun stringArray(array: JsonArray?): List<String>? =
    array?.map { (it as? JsonPrimitive)?.takeIf { primitive -> primitive.isString }?.content ?: return null }
