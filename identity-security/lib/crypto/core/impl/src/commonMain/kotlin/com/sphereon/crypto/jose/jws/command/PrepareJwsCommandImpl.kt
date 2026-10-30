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

package com.sphereon.crypto.jose.jws.command

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.asOkResult
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.jose.Jwk
import com.sphereon.crypto.core.jose.JwkType
import com.sphereon.crypto.core.jose.JwtHeader
import com.sphereon.crypto.core.json.cryptoJsonSerializer
import com.sphereon.crypto.jose.jws.Base64UrlEncoded
import com.sphereon.crypto.jose.jws.JwsIdentifierMode
import com.sphereon.crypto.jose.jws.JwsUtils
import com.sphereon.crypto.jose.jws.PreparedJws
import com.sphereon.crypto.jose.jws.PreparedJwsObject
import com.sphereon.crypto.jose.jws.command.CreateJwsJsonArgs
import com.sphereon.crypto.jose.jws.command.PrepareJwsCommand
import com.sphereon.crypto.resolution.managed.ManagedIdentifierKeyResult
import com.sphereon.crypto.resolution.managed.MultiManagedIdentifierService
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.experimental.ExperimentalObjCName
import kotlin.native.ObjCName

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Command implementation for preparing JWS objects
 */
@Inject
@SingleIn(SessionScope::class)
@OptIn(ExperimentalObjCName::class)
@ObjCName("PrepareJwsCommandImpl", exact = true)
@ExposeImplBinding
class PrepareJwsCommandImpl(
    execution: SessionExecution,
    private val identifierService: MultiManagedIdentifierService,
) : TypedServiceCommandAdapter<CreateJwsJsonArgs, PreparedJwsObject, IdkError>(
        commandId = PrepareJwsCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CreateJwsJsonArgs>(),
        outputTypeToken = typeToken<PreparedJwsObject>(),
    ),
    PrepareJwsCommand {
    override val commandId: String get() = PrepareJwsCommand.COMMAND_ID

    override suspend fun doExecute(
        args: CreateJwsJsonArgs,
        applyDuring: (CreateJwsJsonArgs) -> CreateJwsJsonArgs,
    ): IdkResult<PreparedJwsObject, IdkError> {
        val appliedArgs = applyDuring(args)

        // Validate required fields
        val issuer = appliedArgs.issuer ?: return IdkResult.err(IdkError.fromString("Issuer is required"))
        val payload = appliedArgs.payload ?: return IdkResult.err(IdkError.fromString("Payload is required"))

        // Resolve the identifier
        val identifierResult = identifierService.resolve(issuer)
        if (identifierResult.isErr) {
            log.error("JWS preparation failed command=$commandId stage=identifier-resolution idk_code=${identifierResult.error.code}")
            return IdkResult.err(IdkError.fromDTO(identifierResult.error))
        }

        val resolvedIdentifier = identifierResult.value as ManagedIdentifierKeyResult

        // Process payload
        val payloadBytes = JwsUtils.payloadToBytes(payload)
        val base64UrlPayload = JwsUtils.encodeBytesToBase64Url(payloadBytes)

        // Update protected header with identifier information
        val protectedHeader = (appliedArgs.opts.protectedHeader ?: JsonObject(emptyMap())).toMutableMap()

        // Update header based on mode and identifier
        updateHeaderWithIdentifier(
            header = protectedHeader,
            identifier = resolvedIdentifier,
            mode = appliedArgs.mode,
            noIdentifierInHeader = appliedArgs.opts.noIdentifierInHeader,
        )

        // Update payload if needed
        // clientId and clientIdScheme come from issuer.context
        val updatedPayload =
            if (!appliedArgs.opts.noIssPayloadUpdate && payload !is ByteArray) {
                updatePayloadWithIssuer(
                    payload = payload,
                    issuer = resolvedIdentifier,
                    clientId = issuer.context.clientId,
                    clientIdScheme = issuer.context.clientIdScheme,
                )
            } else {
                payloadBytes
            }

        val protectedHeaderJson = JsonObject(protectedHeader)
        val base64UrlHeader = JwsUtils.encodeJsonToBase64Url(protectedHeaderJson)
        val base64UrlUpdatedPayload = JwsUtils.encodeBytesToBase64Url(updatedPayload)

        val preparedJws =
            PreparedJws(
                protectedHeader = JwtHeader(protectedHeaderJson),
                payload = updatedPayload,
                unprotectedHeader = appliedArgs.opts.unprotectedHeader?.let { JwtHeader(it) },
                existingSignatures = appliedArgs.existingSignatures,
            )

        val b64Encoded =
            Base64UrlEncoded(
                protectedHeader = base64UrlHeader,
                payload = base64UrlUpdatedPayload,
            )
        val signingInput = JwsUtils.createSigningInput(base64UrlHeader, base64UrlUpdatedPayload)

        val result =
            PreparedJwsObject(
                jws = preparedJws,
                b64 = b64Encoded,
                identifier = resolvedIdentifier,
                signingInput = signingInput,
            )

        return result.asOkResult()
    }

    private fun updateHeaderWithIdentifier(
        header: MutableMap<String, kotlinx.serialization.json.JsonElement>,
        identifier: ManagedIdentifierKeyResult,
        mode: JwsIdentifierMode,
        noIdentifierInHeader: Boolean,
    ) {
        // RFC 7515 §4.1.1 makes `alg` REQUIRED in every JWS protected header — independent of
        // whether the caller wants identifier hints (kid/x5c/jwk) included. Set it first, then
        // skip the rest when `noIdentifierInHeader` is on.
        if (!header.containsKey("alg")) {
            val sigAlg = identifier.keyInfo.key.getSignatureAlgorithm()
            val joseAlg = sigAlg?.jose
            if (joseAlg != null) {
                header["alg"] = JsonPrimitive(joseAlg.value)
            }
        }

        if (noIdentifierInHeader) {
            return
        }

        when (mode) {
            JwsIdentifierMode.DID -> {
                val kid = identifier.keyInfo.kid
                if (kid != null && kid.startsWith("did:")) {
                    header["kid"] = JsonPrimitive(kid)
                }
            }

            JwsIdentifierMode.X5C -> {
                val x5cChain = identifier.keyInfo.key.getX509CertificateChain()
                if (x5cChain != null) {
                    header["x5c"] =
                        JsonArray(
                            x5cChain.toList().map { JsonPrimitive(it) },
                        )
                }
            }

            JwsIdentifierMode.JWK -> {
                val jwk = identifier.keyInfo.key as? JwkType
                if (jwk != null) {
                    // Get public key only for header (never include private key in JWS header)
                    val publicJwk = jwk.toPublicKey()
                    val jwkJson =
                        cryptoJsonSerializer.encodeToJsonElement(
                            Jwk.serializer(),
                            publicJwk as Jwk,
                        )
                    header["jwk"] = jwkJson
                } else {
                    log.warn("JWK mode requested but key is not a JwkType")
                }
            }

            JwsIdentifierMode.KID -> {
                // An explicit protected-header kid is a protocol coordinate and may differ from
                // the resolved provider/KMS key kid: an authorization server publishes its
                // signing-key-store kid while KMS resolves the key by alias. With a kid already in
                // the header the identifier only has to sign; otherwise it must carry the kid.
                if (!header.containsKey("kid")) {
                    val kid = identifier.keyInfo.kid
                    require(kid != null) { "Kid mode without an kid value is not possible" }
                    header["kid"] = JsonPrimitive(kid)
                }
            }

            JwsIdentifierMode.AUTO -> {
                // Auto-detect based on identifier type
                when {
                    identifier.keyInfo.kid?.startsWith("did:") == true -> {
                        header["kid"] = JsonPrimitive(identifier.keyInfo.kid!!)
                    }

                    identifier.keyInfo.key.getX509CertificateChain() != null -> {
                        val x5cChain = identifier.keyInfo.key.getX509CertificateChain()!!
                        header["x5c"] =
                            JsonArray(
                                x5cChain.toList().map { kotlinx.serialization.json.JsonPrimitive(it) },
                            )
                    }

                    else -> {
                        val kid = identifier.keyInfo.kid
                        if (kid != null) {
                            header["kid"] = JsonPrimitive(kid)
                        }
                    }
                }
            }
        }
    }

    private fun updatePayloadWithIssuer(
        payload: Any?,
        issuer: ManagedIdentifierKeyResult,
        clientId: String?,
        clientIdScheme: String?,
    ): ByteArray {
        if (payload == null || payload is ByteArray || payload is String) {
            // Can't update non-JSON payloads
            return JwsUtils.payloadToBytes(payload ?: JsonObject(emptyMap()))
        }

        val payloadJson = (payload as? JsonObject)?.toMutableMap() ?: mutableMapOf()

        // Add issuer if present and not already set
        if (!payloadJson.containsKey("iss")) {
            val iss = issuer.context.issuer ?: issuer.keyInfo.kid
            if (iss != null) {
                payloadJson["iss"] = JsonPrimitive(iss)
            }
        }

        // Add client_id if provided
        if (clientId != null && !payloadJson.containsKey("client_id")) {
            payloadJson["client_id"] = JsonPrimitive(clientId)
        }

        // Add client_id_scheme if provided
        if (clientIdScheme != null && !payloadJson.containsKey("client_id_scheme")) {
            payloadJson["client_id_scheme"] = JsonPrimitive(clientIdScheme)
        }

        val updatedPayloadJson = JsonObject(payloadJson)
        // Convert JSON to bytes - do NOT base64url encode here, that happens later in the caller
        return JwsUtils.payloadToBytes(updatedPayloadJson)
    }
}
