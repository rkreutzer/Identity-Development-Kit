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

package com.sphereon.oauth2.common.jarm

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Ok
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.jose.jwe.CreateJweCompactArgs
import com.sphereon.crypto.jose.jwe.CreateJweOpts
import com.sphereon.crypto.jose.jwe.JweService
import com.sphereon.crypto.jose.jwe.PrepareJweArgs
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import io.konform.validation.Invalid
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlin.time.Clock

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of CreateJarmResponseCommand.
 *
 * Creates JARM (JWT Secured Authorization Response) for OAuth 2.0.
 *
 * Reference: OpenID Foundation JARM spec, JWT Secured Authorization Response Mode for OAuth 2.0 (https://openid.net/specs/oauth-v2-jarm.html)
 *
 * Supports three modes:
 * - SIGNED: Creates a JWS compact serialization
 * - ENCRYPTED: Creates a JWE compact serialization
 * - SIGNED_ENCRYPTED: Creates a nested JWT (JWS inside JWE)
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class CreateJarmResponseCommandImpl(
    execution: SessionExecution,
    private val jwtService: JwtService,
    private val jweService: JweService,
) : TypedServiceCommandAdapter<CreateJarmResponseArgs, CreateJarmResponseResult, IdkError>(
        commandId = CreateJarmResponseCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<CreateJarmResponseArgs>(),
        outputTypeToken = typeToken<CreateJarmResponseResult>(),
    ),
    CreateJarmResponseCommand {
    override val commandId: String get() = CreateJarmResponseCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is CreateJarmResponseArgs

    private val json =
        Json {
            encodeDefaults = true
            ignoreUnknownKeys = true
        }

    override suspend fun doExecute(
        args: CreateJarmResponseArgs,
        applyDuring: (CreateJarmResponseArgs) -> CreateJarmResponseArgs,
    ): IdkResult<CreateJarmResponseResult, IdkError> {
        val processedArgs = applyDuring(args)
        val config = processedArgs.jarmConfig
        if (processedArgs.appendStandardJwtClaims && processedArgs.issuer.isNullOrBlank()) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "JARM issuer is required when standard JWT claims are included"))
        }
        if (!processedArgs.appendStandardJwtClaims && config.mode != JarmMode.ENCRYPTED) {
            return Err(IdkError.ILLEGAL_ARGUMENT_ERROR(message = "Signed JARM responses require standard JWT claims"))
        }

        // Validate JARM configuration
        val configValidation = validateJarmConfig(config)
        if (configValidation is Invalid) {
            val errors = configValidation.errors.map { "${it.dataPath}: ${it.message}" }
            return Err(
                IdkError.ILLEGAL_ARGUMENT_ERROR(
                    message = "Invalid JARM configuration: ${errors.joinToString(", ")}",
                ),
            )
        }

        // Validate required keys based on mode
        when (config.mode) {
            JarmMode.SIGNED -> {
                if (processedArgs.signingKey == null) {
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Signing key is required for SIGNED mode",
                        ),
                    )
                }
            }

            JarmMode.ENCRYPTED -> {
                if (processedArgs.encryptionRecipient == null) {
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Encryption recipient is required for ENCRYPTED mode",
                        ),
                    )
                }
            }

            JarmMode.SIGNED_ENCRYPTED -> {
                if (processedArgs.signingKey == null) {
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Signing key is required for SIGNED_ENCRYPTED mode",
                        ),
                    )
                }
                if (processedArgs.encryptionRecipient == null) {
                    return Err(
                        IdkError.ILLEGAL_ARGUMENT_ERROR(
                            message = "Encryption recipient is required for SIGNED_ENCRYPTED mode",
                        ),
                    )
                }
            }
        }

        log.debug("Creating JARM response with mode: ${config.mode}")

        return when (config.mode) {
            JarmMode.SIGNED -> createSignedResponse(processedArgs)
            JarmMode.ENCRYPTED -> createEncryptedResponse(processedArgs)
            JarmMode.SIGNED_ENCRYPTED -> createSignedEncryptedResponse(processedArgs)
        }
    }

    /**
     * Creates a signed-only JARM response (JWS compact serialization).
     */
    private suspend fun createSignedResponse(args: CreateJarmResponseArgs): IdkResult<CreateJarmResponseResult, IdkError> {
        val payload = buildJarmPayload(args)

        val jwsArgs =
            CreateJwsArgs(
                issuer = args.signingKey,
                payload = payload,
            )

        val jwsResult =
            jwtService.createJwsCompact(jwsArgs).getOrElse { error ->
                log.error("Failed to create signed JARM response: ${error.message}")
                return Err(error)
            }

        log.info("Created signed JARM response")
        return Ok(
            CreateJarmResponseResult(
                jarmJwt = jwsResult.jwt,
                mode = JarmMode.SIGNED,
            ),
        )
    }

    /**
     * Creates an encrypted-only JARM response (JWE compact serialization).
     * The payload is encrypted directly without signing.
     */
    private suspend fun createEncryptedResponse(args: CreateJarmResponseArgs): IdkResult<CreateJarmResponseResult, IdkError> {
        val payload = buildJarmPayload(args)
        val payloadBytes = json.encodeToString(payload).encodeToByteArray()

        val encAlg =
            args.jarmConfig.encryptionAlgorithm
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Encryption algorithm is required for ENCRYPTED mode",
                    ),
                )

        val contentEncAlg =
            args.jarmConfig.contentEncryptionAlgorithm
                ?: JarmConfig.DEFAULT_CONTENT_ENCRYPTION_ALG

        // Prepare JWE
        val prepareArgs =
            PrepareJweArgs(
                plaintext = payloadBytes,
                recipient = args.encryptionRecipient,
                keyEncryptionAlg = encAlg,
                contentEncryptionAlg = contentEncAlg,
                opts = CreateJweOpts(protectedHeaderOverrides = args.protectedHeaderOverrides),
            )

        val preparedJwe =
            jweService.prepareJwe(prepareArgs).getOrElse { error ->
                log.error("Failed to prepare JWE for JARM response: ${error.message}")
                return Err(error)
            }

        // Create JWE compact serialization
        val createArgs = CreateJweCompactArgs(preparedJwe = preparedJwe)
        val jweResult =
            jweService.createJweCompact(createArgs).getOrElse { error ->
                log.error("Failed to create encrypted JARM response: ${error.message}")
                return Err(error)
            }

        log.info("Created encrypted JARM response")
        return Ok(
            CreateJarmResponseResult(
                jarmJwt = jweResult.serialize(),
                mode = JarmMode.ENCRYPTED,
            ),
        )
    }

    /**
     * Creates a signed-then-encrypted JARM response (nested JWT).
     * First signs the payload as JWS, then encrypts the JWS as JWE.
     */
    private suspend fun createSignedEncryptedResponse(args: CreateJarmResponseArgs): IdkResult<CreateJarmResponseResult, IdkError> {
        // Step 1: Create signed JWT
        val payload = buildJarmPayload(args)

        val jwsArgs =
            CreateJwsArgs(
                issuer = args.signingKey,
                payload = payload,
            )

        val jwsResult =
            jwtService.createJwsCompact(jwsArgs).getOrElse { error ->
                log.error("Failed to create signed JWT for nested JARM response: ${error.message}")
                return Err(error)
            }

        // Step 2: Encrypt the signed JWT
        val encAlg =
            args.jarmConfig.encryptionAlgorithm
                ?: return Err(
                    IdkError.ILLEGAL_ARGUMENT_ERROR(
                        message = "Encryption algorithm is required for SIGNED_ENCRYPTED mode",
                    ),
                )

        val contentEncAlg =
            args.jarmConfig.contentEncryptionAlgorithm
                ?: JarmConfig.DEFAULT_CONTENT_ENCRYPTION_ALG

        val prepareArgs =
            PrepareJweArgs(
                plaintext = jwsResult.jwt.encodeToByteArray(),
                recipient = args.encryptionRecipient,
                keyEncryptionAlg = encAlg,
                contentEncryptionAlg = contentEncAlg,
                opts = CreateJweOpts(protectedHeaderOverrides = args.protectedHeaderOverrides),
            )

        val preparedJwe =
            jweService.prepareJwe(prepareArgs).getOrElse { error ->
                log.error("Failed to prepare JWE for nested JARM response: ${error.message}")
                return Err(error)
            }

        val createArgs = CreateJweCompactArgs(preparedJwe = preparedJwe)
        val jweResult =
            jweService.createJweCompact(createArgs).getOrElse { error ->
                log.error("Failed to create encrypted wrapper for nested JARM response: ${error.message}")
                return Err(error)
            }

        log.info("Created signed-then-encrypted JARM response")
        return Ok(
            CreateJarmResponseResult(
                jarmJwt = jweResult.serialize(),
                mode = JarmMode.SIGNED_ENCRYPTED,
            ),
        )
    }

    /**
     * Builds the JARM payload as a JsonObject.
     *
     * Per the JARM spec, the JWT payload contains:
     * - Standard claims: iss, aud, exp, iat
     * - Authorization response parameters as additional claims
     */
    private fun buildJarmPayload(args: CreateJarmResponseArgs): JsonObject {
        val now = Clock.System.now().epochSeconds
        val exp = now + args.expirationSeconds

        return buildJsonObject {
            // Standard JWT claims
            if (args.appendStandardJwtClaims) {
                put("iss", JsonPrimitive(args.issuer))
                put("aud", JsonPrimitive(args.audience))
                put("exp", JsonPrimitive(exp))
                put("iat", JsonPrimitive(now))
            }

            // State parameter
            args.state?.let { put("state", JsonPrimitive(it)) }

            // Add all response parameters as claims
            args.responseParameters.forEach { (key, value) ->
                put(key, value)
            }
        }
    }
}
