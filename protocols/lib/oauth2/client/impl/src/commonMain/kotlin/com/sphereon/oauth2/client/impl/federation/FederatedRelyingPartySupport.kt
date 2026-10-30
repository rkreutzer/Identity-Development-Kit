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

package com.sphereon.oauth2.client.impl.federation

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.decodeFromBase64Url
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.random.SecureRandom
import com.sphereon.crypto.jose.jws.JwsIdentifierMode
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.crypto.jose.jws.command.CreateJwsOpts
import com.sphereon.crypto.resolution.managed.ManagedOptsKeyInfo
import com.sphereon.oauth2.client.command.FederatedOpenIdProvider
import com.sphereon.oauth2.client.command.FederatedRelyingParty
import com.sphereon.oauth2.common.error.Oauth2Error
import io.ktor.http.Url
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

internal const val CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
internal const val REQUEST_OBJECT_TYP = "oauth-authz-req+jwt"
internal const val PRIVATE_KEY_JWT = "private_key_jwt"
internal const val AUTOMATIC_REGISTRATION = "automatic"
internal const val MAX_LIFETIME_SECONDS = 300L

internal val federatedRpJson = Json { ignoreUnknownKeys = true; isLenient = true }

internal fun <T> federationFailure(error: String, description: String): IdkResult<T, IdkError> =
    Err(IdkError.fromDTO(Oauth2Error.ErrorResponse(error = error, errorDescription = description)))

internal fun isHttpsUrl(value: String): Boolean =
    runCatching { Url(value) }.getOrNull()?.let { url ->
        url.protocol.name == "https" && url.host.isNotBlank() && url.fragment.isEmpty() && url.user == null
    } ?: false

/**
 * Checks that the resolved OP can take an Automatic Registration request from this RP (§12.1, §12.1.4): the Entity
 * Identifier is the issuer, `automatic` is a supported registration type, and the RP's registered algorithms and
 * `private_key_jwt` are mutually supported. Returns an error description, or null when the OP is usable.
 */
internal fun providerProblem(provider: FederatedOpenIdProvider, rp: FederatedRelyingParty, nowEpochSeconds: Long): String? {
    val metadata = provider.metadata
    if (!isHttpsUrl(provider.entityIdentifier)) return "The OP Entity Identifier must be an https URL"
    if (metadata.issuer != provider.entityIdentifier) return "The OP issuer '${metadata.issuer}' is not its Entity Identifier"
    if (provider.validUntilEpochSeconds <= nowEpochSeconds) return "The OP Trust Chain has expired"
    val registrationTypes = metadata.additionalMetadata["client_registration_types_supported"].stringList()
    if (registrationTypes == null || AUTOMATIC_REGISTRATION !in registrationTypes) {
        return "The OP does not list 'automatic' in client_registration_types_supported"
    }
    if (metadata.authorizationEndpoint.isNullOrBlank()) return "The OP has no authorization_endpoint"
    metadata.responseTypesSupported?.let { if ("code" !in it) return "The OP does not support response_type code" }
    metadata.codeChallengeMethodsSupported?.let { if ("S256" !in it) return "The OP does not support PKCE S256" }
    val authMethods = metadata.tokenEndpointAuthMethodsSupported
    if (authMethods == null || PRIVATE_KEY_JWT !in authMethods) {
        return "The OP does not list private_key_jwt in token_endpoint_auth_methods_supported"
    }
    metadata.tokenEndpointAuthSigningAlgValuesSupported?.let {
        if (rp.signingAlgorithm !in it) return "The OP does not accept ${rp.signingAlgorithm} client assertions"
    }
    metadata.requestObjectSigningAlgValuesSupported?.let {
        if (rp.signingAlgorithm !in it) return "The OP does not accept ${rp.signingAlgorithm} Request Objects"
    }
    metadata.idTokenSigningAlgValuesSupported?.let {
        if (rp.idTokenSignedResponseAlg !in it) return "The OP does not sign ID Tokens with ${rp.idTokenSignedResponseAlg}"
    }
    if (rp.signingAlgorithm.startsWith("HS") || rp.signingAlgorithm == "none") {
        return "Automatic Registration requires an asymmetric signing algorithm"
    }
    if (rp.idTokenSignedResponseAlg.startsWith("HS") || rp.idTokenSignedResponseAlg == "none") {
        return "The registered ID Token algorithm must be asymmetric"
    }
    return null
}

internal fun JsonElement?.stringList(): List<String>? =
    (this as? JsonArray)?.mapNotNull { (it as? JsonPrimitive)?.takeIf { primitive -> primitive.isString }?.content }

internal fun JsonObject.text(name: String): String? = (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.contentOrNull

/** Signs the RP's JWTs with its protocol key, with `kid` in the header and no embedded key material. */
internal class FederatedRpJwtSigner(
    private val jwtService: JwtService,
    private val secureRandom: SecureRandom,
) {
    suspend fun newToken(): String = secureRandom.newToken(lengthBytes = 32)

    suspend fun sign(rp: FederatedRelyingParty, header: JsonObject, claims: JsonObject): IdkResult<String, IdkError> {
        val protectedHeader = buildJsonObject {
            header.forEach { (name, value) -> put(name, value) }
            put("kid", rp.signingKeyId)
        }
        val created = jwtService.createJwsCompact(
            CreateJwsArgs(
                issuer = ManagedOptsKeyInfo(identifier = rp.signingKey),
                payload = federatedRpJson.encodeToString(JsonObject.serializer(), claims),
                mode = JwsIdentifierMode.AUTO,
                opts = CreateJwsOpts(
                    noIssPayloadUpdate = true,
                    noIdentifierInHeader = true,
                    protectedHeader = protectedHeader,
                ),
            ),
        )
        if (created.isErr) return Err(created.error)
        val jwt = created.value.jwt
        val alg = runCatching {
            federatedRpJson.parseToJsonElement(jwt.substringBefore('.').decodeFromBase64Url().decodeToString())
                .jsonObject["alg"]?.jsonPrimitive?.contentOrNull
        }.getOrNull()
        if (alg != rp.signingAlgorithm) {
            return federationFailure("invalid_client", "The RP signing key produced alg '$alg', not the registered ${rp.signingAlgorithm}")
        }
        return Ok(jwt)
    }

    /** `private_key_jwt` client assertion (OpenID Connect Core 1.0 §9) with the OP's Entity Identifier as sole `aud`. */
    suspend fun clientAssertion(rp: FederatedRelyingParty, providerEntityIdentifier: String, nowEpochSeconds: Long, lifetimeSeconds: Long): IdkResult<String, IdkError> =
        sign(
            rp,
            JsonObject(emptyMap()),
            buildJsonObject {
                put("iss", rp.entityIdentifier)
                put("sub", rp.entityIdentifier)
                put("aud", providerEntityIdentifier)
                put("jti", newToken())
                put("iat", nowEpochSeconds)
                put("exp", nowEpochSeconds + lifetimeSeconds)
            },
        )
}
