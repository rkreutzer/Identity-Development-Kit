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
 */

package com.sphereon.openid.oid4vci.rest.impl.command

import com.sphereon.core.api.encodeToHex
import com.sphereon.core.api.json.jcs.Jcs
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.hash
import com.sphereon.openid.oid4vci.rest.CreateCredentialOfferInput
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

/**
 * What a create request asks for, as a digest of its canonical JSON (RFC 8785). Two requests with the same digest ask for
 * the same offer. Member order and whitespace do not matter, a number keeps the spelling the caller sent because the
 * canonicalizer passes fractional numbers through, so a caller that spells one number two ways is refused as a different
 * request, which is the safe side.
 *
 * The digest covers the issuer instance the request is bound to ([instanceId]), because the route selects it and the body
 * usually omits it, and the template attribution an internal caller sets, which is not part of the JSON a client sends.
 * The callback is part of the intent: a repeat that names another callback is a different request, not a silent retry
 * that keeps the first one. The identity of the request (its correlation id), the caller's own state and how the offer is rendered
 * (QR options) are not part of the intent, so a retry that differs only in those is the same request.
 */
internal fun CreateCredentialOfferInput.intentDigest(instanceId: String): String {
    val intent = copy(correlationId = null, state = null, qrCodeOptions = null, issuerInstanceId = instanceId)
    val resolved =
        buildJsonObject {
            Json.encodeToJsonElement(intent).jsonObject.forEach { (name, value) -> put(name, value) }
            put(TEMPLATE_ID, templateId)
            put(TEMPLATE_AUTHORIZATION_SERVER_ID, templateAuthorizationServerId)
            put(
                TEMPLATE_ALLOWED_GRANTS,
                templateAuthorizationServerAllowedGrants?.let { grants ->
                    buildJsonArray { grants.map { it.name }.sorted().forEach { add(it) } }
                } ?: JsonNull,
            )
        }
    return hash(Jcs.canonicalize(resolved), DigestAlg.SHA256).encodeToHex()
}

private const val TEMPLATE_ID = "templateId"
private const val TEMPLATE_AUTHORIZATION_SERVER_ID = "templateAuthorizationServerId"
private const val TEMPLATE_ALLOWED_GRANTS = "templateAuthorizationServerAllowedGrants"
