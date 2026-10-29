/*
 * Copyright (c) 2026 Sphereon International B.V.
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

@file:Suppress("TooGenericExceptionCaught")

package com.sphereon.crypto.kms.command

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.asErrorResult
import com.sphereon.core.api.asOkResult
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.generic.DigestAlg
import com.sphereon.crypto.core.generic.MultibaseEncoding
import com.sphereon.crypto.core.generic.MultihashAlgorithm
import com.sphereon.crypto.core.generic.MultihashCodec
import com.sphereon.crypto.core.kms.KmsProviderRegistry
import com.sphereon.crypto.core.kms.command.GenerateMacArgs
import com.sphereon.crypto.core.kms.command.GenerateMacCommand
import com.sphereon.crypto.core.kms.command.GenerateMacResult
import com.sphereon.crypto.core.kms.command.VerifyMacArgs
import com.sphereon.crypto.core.kms.command.VerifyMacCommand
import com.sphereon.crypto.core.kms.command.VerifyMacResult
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of GenerateMacCommand.
 *
 * Dispatches to the appropriate KMS provider to compute the MAC.
 * On cloud KMS (AWS, Azure), the key never leaves the HSM.
 * On software KMS, the provider handles local HMAC computation.
 *
 * MAC output is multihash-encoded (self-describing hash format).
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class GenerateMacCommandImpl(
    execution: SessionExecution,
    private val providerRegistry: KmsProviderRegistry,
) : TypedServiceCommandAdapter<GenerateMacArgs, GenerateMacResult, IdkError>(
        commandId = GenerateMacCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<GenerateMacArgs>(),
        outputTypeToken = typeToken<GenerateMacResult>(),
    ),
    GenerateMacCommand {
    override val commandId: String get() = GenerateMacCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is GenerateMacArgs

    override suspend fun doExecute(
        args: GenerateMacArgs,
        applyDuring: (GenerateMacArgs) -> GenerateMacArgs,
    ): IdkResult<GenerateMacResult, IdkError> {
        val applied = applyDuring(args)

        val algorithm = applied.digestAlgorithm
        if (algorithm != DigestAlg.SHA256 && algorithm != DigestAlg.SHA384 && algorithm != DigestAlg.SHA512) {
            return IdkError
                .ILLEGAL_ARGUMENT_ERROR(
                    message = "Unsupported HMAC digest algorithm: ${algorithm.name}. Supported: SHA256, SHA384, SHA512",
                ).asErrorResult()
        }

        return try {
            // Resolve the KMS provider for this key
            val provider = providerRegistry.getProvider(applied.providerId)

            // Delegate MAC computation to the provider
            // On cloud KMS: this makes an API call (key never leaves HSM)
            // On software KMS: this resolves the key and computes locally
            val rawMac = provider.generateMac(applied.keyId, applied.message, algorithm)

            // Wrap in multihash format (self-describing)
            val multihashAlg =
                MultihashAlgorithm.fromDigestAlg(algorithm)
                    ?: return IdkError
                        .ILLEGAL_ARGUMENT_ERROR(
                            message = "No multihash algorithm for ${algorithm.name}",
                        ).asErrorResult()

            val multihash = MultihashCodec.encode(rawMac, multihashAlg)
            val multibase = MultihashCodec.encodeToMultibase(rawMac, multihashAlg, MultibaseEncoding.BASE16)

            log.debug("Generated MAC for key ${applied.keyId}, algorithm: ${algorithm.name}")

            GenerateMacResult(
                mac = multihash,
                macMultibase = multibase,
                digestAlgorithm = algorithm,
            ).asOkResult()
        } catch (e: UnsupportedOperationException) {
            log.warn("KMS_MAC_REFUSED stage=generate code=MAC_NOT_SUPPORTED exception_type=UnsupportedOperationException")
            IdkError
                .fromString(
                    message = "Provider does not support MAC operations: ${e.message}",
                    code = "MAC_NOT_SUPPORTED",
                ).asErrorResult()
        } catch (expected: Exception) {
            val exceptionType = expected::class.simpleName?.takeIf { it.matches(Regex("[A-Za-z0-9_]{1,160}")) } ?: "Exception"
            log.warn("KMS_MAC_REFUSED stage=generate code=MAC_GENERATION_FAILED exception_type=$exceptionType")
            IdkError
                .fromString(
                    message = "Failed to generate MAC: ${expected.message}",
                    code = "MAC_GENERATION_FAILED",
                    exception = expected,
                ).asErrorResult()
        }
    }
}

/**
 * Implementation of VerifyMacCommand.
 *
 * Dispatches to the KMS provider for MAC verification.
 * Uses constant-time comparison when done locally.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class VerifyMacCommandImpl(
    execution: SessionExecution,
    private val providerRegistry: KmsProviderRegistry,
) : TypedServiceCommandAdapter<VerifyMacArgs, VerifyMacResult, IdkError>(
        commandId = VerifyMacCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<VerifyMacArgs>(),
        outputTypeToken = typeToken<VerifyMacResult>(),
    ),
    VerifyMacCommand {
    override val commandId: String get() = VerifyMacCommand.COMMAND_ID

    override suspend fun supports(args: Any): Boolean = args is VerifyMacArgs

    override suspend fun doExecute(
        args: VerifyMacArgs,
        applyDuring: (VerifyMacArgs) -> VerifyMacArgs,
    ): IdkResult<VerifyMacResult, IdkError> {
        val applied = applyDuring(args)

        return try {
            // Decode the provided multihash MAC to extract the raw digest
            val (expectedAlg, expectedDigest) = MultihashCodec.decode(applied.mac)

            // Resolve the KMS provider
            val provider = providerRegistry.getProvider(applied.providerId)

            // Delegate verification to the provider
            val isValid = provider.verifyMac(applied.keyId, applied.message, expectedDigest, expectedAlg.digestAlg)

            log.debug("Verified MAC for key ${applied.keyId}: $isValid")
            VerifyMacResult(isValid = isValid).asOkResult()
        } catch (e: UnsupportedOperationException) {
            log.warn("Provider does not support MAC operations: ${e.message}")
            IdkError
                .fromString(
                    message = "Provider does not support MAC operations: ${e.message}",
                    code = "MAC_NOT_SUPPORTED",
                ).asErrorResult()
        } catch (expected: Exception) {
            log.warn("Failed to verify MAC: ${expected.message}")
            IdkError
                .fromString(
                    message = "Failed to verify MAC: ${expected.message}",
                    code = "MAC_VERIFICATION_FAILED",
                    exception = expected,
                ).asErrorResult()
        }
    }
}
