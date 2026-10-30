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

import com.sphereon.cbor.CborMap
import com.sphereon.cbor.CborParser
import com.sphereon.cbor.CborString
import com.sphereon.cbor.json.toRfc8949Json
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkOkResult
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.mdoc.data.device.IssuerSignedItem
import com.sphereon.openid.oid4vp.verifier.MatchedCredential
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

/**
 * The claims of one verified credential, typed as the credential issued them.
 *
 * [claims] is what the verifier reports: SD-JWT VC top-level claim names, W3C `credentialSubject`
 * members and mdoc `namespace.element` keys, each holding the JSON value at its issued type.
 * [queryRoot] is the structure the credential query's claim paths are evaluated against, which is a
 * different shape for W3C and mdoc, and is never reported.
 */
internal data class CredentialClaimProjection(
    val claims: Map<String, JsonElement>,
    val queryRoot: JsonObject,
    val credentialType: String?,
)

/** One disclosed mdoc data element with its value already converted to JSON. */
internal data class MdocElement(
    val nameSpace: String,
    val identifier: String,
    val value: JsonElement,
)

/** SD-JWT claims that describe the token, not the subject, and are not reported as disclosed claims. */
private val SD_JWT_REGISTRATION_CLAIMS = setOf("_sd", "_sd_alg", "cnf", "iss", "iat", "exp", "nbf", "vct", "status")

/** [payload] is the SD-JWT payload with every disclosure resolved. */
internal fun sdJwtClaimProjection(payload: JsonObject): CredentialClaimProjection =
    CredentialClaimProjection(
        claims = payload.filterKeys { it !in SD_JWT_REGISTRATION_CLAIMS },
        queryRoot = payload,
        credentialType = (payload["vct"] as? JsonPrimitive)?.takeIf { it.isString }?.content,
    )

/** A credential that was accepted, with the structure its query claim paths are evaluated against. */
internal class AcceptedCredential(
    val matched: MatchedCredential,
    val queryRoot: JsonObject,
)

/**
 * [credential] is a verified W3C credential. A `credentialSubject` that is not a single object has no
 * members to report, and members of several subjects are not merged into one map. The subject `id` is a
 * binding artefact and is left out unless [includeSubjectId] asks for it. Only a standalone Data Integrity credential asks
 * for it, so the same credential type reports the subject `id` by that route alone, as it did before. A subject array
 * reports no claims, though the query root still holds the whole credential for claim matching.
 */
internal fun vcdmClaimProjection(
    credential: JsonObject,
    credentialType: String?,
    includeSubjectId: Boolean = false,
): CredentialClaimProjection =
    CredentialClaimProjection(
        claims = (credential["credentialSubject"] as? JsonObject)?.filterKeys { includeSubjectId || it != "id" }.orEmpty(),
        queryRoot = credential,
        credentialType = credentialType,
    )

internal fun mdocDocumentProjection(
    docType: String,
    elements: List<MdocElement>,
): CredentialClaimProjection =
    CredentialClaimProjection(
        claims = elements.associate { "${it.nameSpace}.${it.identifier}" to it.value },
        queryRoot =
            JsonObject(
                elements.groupBy { it.nameSpace }.mapValues { (_, inNameSpace) ->
                    JsonObject(inNameSpace.associate { it.identifier to it.value })
                },
            ),
        credentialType = docType,
    )

/**
 * The value of an mdoc `IssuerSignedItem` as JSON, read from the item's original CBOR bytes. The decoded
 * Kotlin value has already lost the tags, so it cannot be converted faithfully.
 */
internal fun mdocElementValue(
    encodedItem: ByteArray,
    parser: CborParser,
): IdkResult<JsonElement, IdkError> {
    val item = parser.parse(encodedItem).getOrElse { return Err(it) }
    val entries =
        (item as? CborMap<*, *>)?.value
            ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "An mdoc IssuerSignedItem must be a CBOR map"))
    val elementValue =
        entries.entries.firstOrNull { (key, _) -> (key as? CborString)?.value == IssuerSignedItem.ELEMENT_VALUE.value }
            ?: return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "An mdoc IssuerSignedItem has no element value"))
    return elementValue.value?.toRfc8949Json() ?: IdkOkResult(JsonNull)
}

/**
 * The value reported to callers that hold `Map<String, Any?>`: text stays [String] whatever it looks like,
 * a JSON boolean or an integer that fits becomes [Boolean] or [Long], a decimal that survives the round trip
 * becomes [Double], and everything else stays the exact [JsonElement].
 */
internal fun JsonElement.toClaimValue(): Any? =
    when (this) {
        is JsonNull -> null
        is JsonPrimitive ->
            when {
                isString -> content
                booleanOrNull != null -> booleanOrNull
                longOrNull != null -> longOrNull
                doubleOrNull?.toString() == content -> doubleOrNull
                else -> this
            }
        else -> this
    }

internal fun Map<String, JsonElement>.toClaimValues(): Map<String, Any?> = mapValues { (_, value) -> value.toClaimValue() }
