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

package com.sphereon.oauth2.server.authorization.impl.command.authorization

import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.json.jsonSerializer
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.oauth2.common.config.FederatedAuthorizationRequestMode
import com.sphereon.oauth2.common.config.OAuth2ServerInstanceIdProvider
import com.sphereon.oauth2.common.config.OAuth2ServersConfigProvider
import com.sphereon.oauth2.server.authorization.command.AuthorizationRequestData
import com.sphereon.oauth2.server.authorization.command.jar.AuthorizationRequestEvidence
import com.sphereon.oauth2.server.authorization.command.jar.VerifyRequestObjectCommand
import com.sphereon.oauth2.server.authorization.model.ClientRegistration
import com.sphereon.oauth2.server.authorization.signing.CapturedAsServerConfig
import kotlinx.serialization.json.*
import kotlin.time.Clock

/** Captured solely from trusted session/configuration selection; never request parameters. */
internal data class FederationAuthorizationScope(
    val tenantId: String,
    val serverKey: String,
    val issuer: String,
    val mode: FederatedAuthorizationRequestMode,
)

internal fun captureFederationAuthorizationScope(
    execution: SessionExecution,
    config: OAuth2ServersConfigProvider,
    selection: OAuth2ServerInstanceIdProvider,
): FederationAuthorizationScope {
    val tenant = execution.tenantId
    require(tenant.isNotBlank()) { "Federation authorization requires an exact session tenant" }
    val captured = CapturedAsServerConfig.select(config.getConfig(),
        selection.currentAsInstanceId())
    val server = requireNotNull(captured.server) { "A hosted AS configuration is required" }
    val key = requireNotNull(captured.serverKey)
    return FederationAuthorizationScope(tenant, key, server.resolveIssuer(key, tenant), server.federationAutomaticRegistrationMode)
}

/** The only accepted implementation. No serializer, public constructor, Boolean or mutable input references. */
internal class VerifiedFederationAuthorizationEvidence private constructor(
    private val scope: FederationAuthorizationScope,
    private val clientId: String,
    private val publicKeys: String,
    private val signedParameters: String,
    private val expiresAt: kotlin.time.Instant,
) : AuthorizationRequestEvidence {
    internal fun matches(
        actualScope: FederationAuthorizationScope,
        request: AuthorizationRequestData,
        client: ClientRegistration,
    ): Boolean {
        if (scope != actualScope || clientId != client.clientId || clientId != request.clientId ||
            publicKeys != publicKeySnapshot(client)) return false
        if (Clock.System.now() >= expiresAt) return false
        val parameters = Json.parseToJsonElement(signedParameters).jsonObject
            .mapValues { (_, value) -> value.jsonPrimitive.content }
        val parsed = parseAuthorizationParameters(parameters)
        return parsed.isOk && parsed.value == request.copy(authorizationEvidence = null)
    }

    companion object {
        /** Called only after the real JAR signature, envelope claims and one-use jti succeeded. */
        internal fun mint(
            scope: FederationAuthorizationScope,
            client: ClientRegistration,
            parameters: Map<String, String>,
            expiresAt: kotlin.time.Instant,
        ): AuthorizationRequestEvidence {
            require(parameters["client_id"] == client.clientId)
            val snapshot = JsonObject(parameters.entries.sortedBy { it.key }
                .associate { it.key to JsonPrimitive(it.value) }).toString()
            return VerifiedFederationAuthorizationEvidence(scope.copy(), client.clientId,
                publicKeySnapshot(client), snapshot, expiresAt)
        }

        private fun publicKeySnapshot(client: ClientRegistration): String {
            val keys = requireNotNull(client.jwks) { "Federation clients require resolved RP signing keys" }
            require(keys.isNotEmpty()) { "Federation RP signing keys are empty" }
            return JsonArray(keys.map { jsonSerializer.encodeToJsonElement(Jwk.serializer(), it) }
                .sortedBy { it.toString() }).toString()
        }
    }
}

internal fun validFederationAuthorizationEvidence(
    evidence: AuthorizationRequestEvidence?,
    scope: FederationAuthorizationScope,
    request: AuthorizationRequestData,
    client: ClientRegistration,
): Boolean = try {
    (evidence as? VerifiedFederationAuthorizationEvidence)?.matches(scope, request, client) == true
} catch (expected: IllegalArgumentException) {
    false
} catch (expected: IllegalStateException) {
    false
}
