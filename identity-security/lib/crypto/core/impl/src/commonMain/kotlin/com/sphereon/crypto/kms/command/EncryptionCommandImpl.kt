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
 *
 */

@file:Suppress("TooGenericExceptionCaught")

package com.sphereon.crypto.kms.command

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.asErrorResult
import com.sphereon.core.api.asOkResult
import com.sphereon.core.api.binary.typeToken
import com.sphereon.core.api.context.SessionExecution
import kotlinx.coroutines.CancellationException
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.kms.KmsProviderOperation
import com.sphereon.crypto.core.kms.KmsProviderRegistry
import com.sphereon.crypto.core.kms.command.DecryptArgs
import com.sphereon.crypto.core.kms.command.DecryptCommand
import com.sphereon.crypto.core.kms.command.DecryptResult
import com.sphereon.crypto.core.kms.command.EcPointMultiplyArgs
import com.sphereon.crypto.core.kms.command.EcPointMultiplyCommand
import com.sphereon.crypto.core.kms.command.EcPointMultiplyResult
import com.sphereon.crypto.core.kms.command.EcdhDeriveArgs
import com.sphereon.crypto.core.kms.command.EcdhDeriveCommand
import com.sphereon.crypto.core.kms.command.EcdhDeriveMode
import com.sphereon.crypto.core.kms.command.EcdhDeriveResult
import com.sphereon.crypto.core.kms.command.EncryptArgs
import com.sphereon.crypto.core.kms.command.EncryptCommand
import com.sphereon.crypto.core.kms.command.EncryptResult
import com.sphereon.crypto.core.kms.command.PerformKeyAgreementArgs
import com.sphereon.crypto.core.kms.command.PerformKeyAgreementCommand
import com.sphereon.crypto.core.kms.command.PerformKeyAgreementResult
import com.sphereon.crypto.core.kms.command.UnwrapKeyArgs
import com.sphereon.crypto.core.kms.command.UnwrapKeyCommand
import com.sphereon.crypto.core.kms.command.UnwrapKeyResult
import com.sphereon.crypto.core.kms.command.WrapKeyArgs
import com.sphereon.crypto.core.kms.command.WrapKeyCommand
import com.sphereon.crypto.core.kms.command.WrapKeyResult
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of EncryptCommand.
 * Encrypts plaintext using authenticated encryption (AEAD).
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class EncryptCommandImpl(
    execution: SessionExecution,
    private val providerRegistry: KmsProviderRegistry,
) : TypedServiceCommandAdapter<EncryptArgs, EncryptResult, IdkError>(
        commandId = EncryptCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<EncryptArgs>(),
        outputTypeToken = typeToken<EncryptResult>(),
    ),
    EncryptCommand {
    override val commandId: String get() = EncryptCommand.COMMAND_ID

    override suspend fun doExecute(
        args: EncryptArgs,
        applyDuring: (EncryptArgs) -> EncryptArgs,
    ): IdkResult<EncryptResult, IdkError> {
        val appliedArgs = applyDuring(args)
        val keyInfo =
            appliedArgs.keyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "keyInfo is required").asErrorResult()

        log.debug("Encrypting data with algorithm: ${appliedArgs.algorithm}")

        return try {
            val provider = providerRegistry.getProvider(keyInfo.providerId, keyInfo.signatureAlgorithm)
            val result =
                provider.encrypt(
                    keyInfo,
                    appliedArgs.plaintext,
                    appliedArgs.algorithm,
                    appliedArgs.additionalAuthenticatedData,
                )
            log.debug("Encryption successful, ciphertext length: ${result.ciphertext.size} bytes")
            EncryptResult(
                ciphertext = result.ciphertext,
                iv = result.iv,
                authTag = result.authTag,
            ).asOkResult()
        } catch (expected: Exception) {
            if (expected is CancellationException) throw expected
            log.warn("Encryption failed stage=provider-encrypt")
            IdkError.fromString(message = "Encryption failed").asErrorResult()
        }
    }

    override suspend fun supports(args: Any): Boolean = args is EncryptArgs && args.keyInfo != null
}

/**
 * Implementation of DecryptCommand.
 * Decrypts ciphertext encrypted with authenticated encryption.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class DecryptCommandImpl(
    execution: SessionExecution,
    private val providerRegistry: KmsProviderRegistry,
) : TypedServiceCommandAdapter<DecryptArgs, DecryptResult, IdkError>(
        commandId = DecryptCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<DecryptArgs>(),
        outputTypeToken = typeToken<DecryptResult>(),
    ),
    DecryptCommand {
    override val commandId: String get() = DecryptCommand.COMMAND_ID

    override suspend fun doExecute(
        args: DecryptArgs,
        applyDuring: (DecryptArgs) -> DecryptArgs,
    ): IdkResult<DecryptResult, IdkError> {
        val appliedArgs = applyDuring(args)
        val keyInfo =
            appliedArgs.keyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "keyInfo is required").asErrorResult()

        log.debug("Decrypting data with algorithm: ${appliedArgs.algorithm}")

        return try {
            val provider = providerRegistry.getProvider(keyInfo.providerId, keyInfo.signatureAlgorithm)
            val plaintext =
                provider.decrypt(
                    keyInfo,
                    appliedArgs.ciphertext,
                    appliedArgs.algorithm,
                    appliedArgs.iv,
                    appliedArgs.authTag,
                    appliedArgs.additionalAuthenticatedData,
                )
            log.debug("Decryption successful, plaintext length: ${plaintext.size} bytes")
            DecryptResult(plaintext).asOkResult()
        } catch (expected: Exception) {
            if (expected is CancellationException) throw expected
            log.warn("Decryption failed stage=provider-decrypt")
            IdkError.fromString(message = "Decryption failed").asErrorResult()
        }
    }

    override suspend fun supports(args: Any): Boolean = args is DecryptArgs && args.keyInfo != null
}

/**
 * Implementation of WrapKeyCommand.
 * Wraps (encrypts) a symmetric key using the specified algorithm.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class WrapKeyCommandImpl(
    execution: SessionExecution,
    private val providerRegistry: KmsProviderRegistry,
) : TypedServiceCommandAdapter<WrapKeyArgs, WrapKeyResult, IdkError>(
        commandId = WrapKeyCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<WrapKeyArgs>(),
        outputTypeToken = typeToken<WrapKeyResult>(),
    ),
    WrapKeyCommand {
    override val commandId: String get() = WrapKeyCommand.COMMAND_ID

    override suspend fun doExecute(
        args: WrapKeyArgs,
        applyDuring: (WrapKeyArgs) -> WrapKeyArgs,
    ): IdkResult<WrapKeyResult, IdkError> {
        val appliedArgs = applyDuring(args)
        val wrappingKeyInfo =
            appliedArgs.wrappingKeyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "wrappingKeyInfo is required").asErrorResult()

        log.debug("Wrapping key with algorithm: ${appliedArgs.algorithm}")

        return try {
            val provider = providerRegistry.getProvider(wrappingKeyInfo.providerId, wrappingKeyInfo.signatureAlgorithm)
            val wrappedKey =
                provider.wrapKey(
                    wrappingKeyInfo,
                    appliedArgs.keyToWrap,
                    appliedArgs.algorithm,
                )
            log.debug("Key wrap successful, wrapped key length: ${wrappedKey.size} bytes")
            WrapKeyResult(wrappedKey).asOkResult()
        } catch (expected: Exception) {
            log.warn("Key wrap failed: ${expected.message}")
            IdkError.fromString(message = "Key wrap failed: ${expected.message}").asErrorResult()
        }
    }

    override suspend fun supports(args: Any): Boolean = args is WrapKeyArgs && args.wrappingKeyInfo != null
}

/**
 * Implementation of UnwrapKeyCommand.
 * Unwraps (decrypts) a wrapped symmetric key.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class UnwrapKeyCommandImpl(
    execution: SessionExecution,
    private val providerRegistry: KmsProviderRegistry,
) : TypedServiceCommandAdapter<UnwrapKeyArgs, UnwrapKeyResult, IdkError>(
        commandId = UnwrapKeyCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<UnwrapKeyArgs>(),
        outputTypeToken = typeToken<UnwrapKeyResult>(),
    ),
    UnwrapKeyCommand {
    override val commandId: String get() = UnwrapKeyCommand.COMMAND_ID

    override suspend fun doExecute(
        args: UnwrapKeyArgs,
        applyDuring: (UnwrapKeyArgs) -> UnwrapKeyArgs,
    ): IdkResult<UnwrapKeyResult, IdkError> {
        val appliedArgs = applyDuring(args)
        val unwrappingKeyInfo =
            appliedArgs.unwrappingKeyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "unwrappingKeyInfo is required").asErrorResult()

        log.debug("Unwrapping key with algorithm: ${appliedArgs.algorithm}")

        return try {
            val provider = providerRegistry.getProvider(unwrappingKeyInfo.providerId, unwrappingKeyInfo.signatureAlgorithm)
            val unwrappedKey =
                provider.unwrapKey(
                    unwrappingKeyInfo,
                    appliedArgs.wrappedKey,
                    appliedArgs.algorithm,
                )
            log.debug("Key unwrap successful, unwrapped key length: ${unwrappedKey.size} bytes")
            UnwrapKeyResult(unwrappedKey).asOkResult()
        } catch (expected: Exception) {
            if (expected is CancellationException) throw expected
            log.warn("Key unwrap failed stage=provider-key-unwrap")
            IdkError.fromString(message = "Key unwrap failed").asErrorResult()
        }
    }

    override suspend fun supports(args: Any): Boolean = args is UnwrapKeyArgs && args.unwrappingKeyInfo != null
}

/**
 * Implementation of PerformKeyAgreementCommand.
 * Performs ECDH key agreement to derive a shared secret.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class PerformKeyAgreementCommandImpl(
    execution: SessionExecution,
    private val providerRegistry: KmsProviderRegistry,
) : TypedServiceCommandAdapter<PerformKeyAgreementArgs, PerformKeyAgreementResult, IdkError>(
        commandId = PerformKeyAgreementCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<PerformKeyAgreementArgs>(),
        outputTypeToken = typeToken<PerformKeyAgreementResult>(),
    ),
    PerformKeyAgreementCommand {
    override val commandId: String get() = PerformKeyAgreementCommand.COMMAND_ID

    override suspend fun doExecute(
        args: PerformKeyAgreementArgs,
        applyDuring: (PerformKeyAgreementArgs) -> PerformKeyAgreementArgs,
    ): IdkResult<PerformKeyAgreementResult, IdkError> {
        val appliedArgs = applyDuring(args)
        val privateKeyInfo =
            appliedArgs.privateKeyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "privateKeyInfo is required").asErrorResult()
        val publicKeyInfo =
            appliedArgs.publicKeyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "publicKeyInfo is required").asErrorResult()

        log.debug("Performing key agreement with algorithm: ${appliedArgs.algorithm}")

        return try {
            val provider = providerRegistry.getProvider(privateKeyInfo.providerId, privateKeyInfo.signatureAlgorithm)
            val sharedSecret =
                provider.performKeyAgreement(
                    privateKeyInfo = privateKeyInfo,
                    publicKeyInfo = publicKeyInfo,
                    algorithm = appliedArgs.algorithm,
                    keyDataLen = appliedArgs.keyDataLen,
                )
            log.debug("Key agreement successful, shared secret length: ${sharedSecret.size} bytes")
            PerformKeyAgreementResult(sharedSecret).asOkResult()
        } catch (expected: Exception) {
            log.warn("Key agreement failed: ${expected.message}")
            IdkError.fromString(message = "Key agreement failed: ${expected.message}").asErrorResult()
        }
    }

    override suspend fun supports(args: Any): Boolean =
        args is PerformKeyAgreementArgs &&
            args.privateKeyInfo != null &&
            args.publicKeyInfo != null
}

/**
 * Implementation of EcdhDeriveCommand.
 * Dispatches provider-backed ECDH derivation so the private key is not exported to the caller.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class EcdhDeriveCommandImpl(
    execution: SessionExecution,
    private val providerRegistry: KmsProviderRegistry,
) : TypedServiceCommandAdapter<EcdhDeriveArgs, EcdhDeriveResult, IdkError>(
        commandId = EcdhDeriveCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<EcdhDeriveArgs>(),
        outputTypeToken = typeToken<EcdhDeriveResult>(),
    ),
    EcdhDeriveCommand {
    override val commandId: String get() = EcdhDeriveCommand.COMMAND_ID

    override suspend fun doExecute(
        args: EcdhDeriveArgs,
        applyDuring: (EcdhDeriveArgs) -> EcdhDeriveArgs,
    ): IdkResult<EcdhDeriveResult, IdkError> {
        val appliedArgs = applyDuring(args)
        val privateKeyInfo =
            appliedArgs.privateKeyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "privateKeyInfo is required").asErrorResult()
        val publicKeyInfo =
            appliedArgs.publicKeyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "publicKeyInfo is required").asErrorResult()

        if (appliedArgs.mode == EcdhDeriveMode.CONCAT_KDF) {
            if (appliedArgs.keyDataLen == null) {
                return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "keyDataLen is required when mode is CONCAT_KDF").asErrorResult()
            }
            if (appliedArgs.algorithmId.isNullOrBlank()) {
                return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "algorithmId is required when mode is CONCAT_KDF").asErrorResult()
            }
        }

        return try {
            val provider = providerRegistry.getProvider(privateKeyInfo.providerId, privateKeyInfo.signatureAlgorithm)
            val operation =
                if (appliedArgs.mode == EcdhDeriveMode.RAW_X) {
                    KmsProviderOperation.ECDH_DERIVE_RAW_X
                } else {
                    KmsProviderOperation.ECDH_DERIVE_KDF
                }
            if (!provider.getCapabilities().supportsOperation(operation)) {
                return IdkError
                    .UNSUPPORTED_OPERATION_ERROR(
                        operation = operation.name,
                        reason = "Provider ${provider.id} does not advertise $operation",
                    ).asErrorResult()
            }
            provider
                .ecdhDerive(
                    privateKeyInfo = privateKeyInfo,
                    publicKeyInfo = publicKeyInfo,
                    algorithm = appliedArgs.algorithm,
                    mode = appliedArgs.mode,
                    keyDataLen = appliedArgs.keyDataLen,
                    algorithmId = appliedArgs.algorithmId,
                    partyUInfo = appliedArgs.partyUInfo,
                    partyVInfo = appliedArgs.partyVInfo,
                ).asOkResult()
        } catch (expected: Exception) {
            log.warn("ECDH derive failed: ${expected.message}")
            IdkError.fromString(message = "ECDH derive failed: ${expected.message}", code = "CRYPTO_ERROR", exception = expected).asErrorResult()
        }
    }

    override suspend fun supports(args: Any): Boolean =
        args is EcdhDeriveArgs &&
            args.privateKeyInfo != null &&
            args.publicKeyInfo != null
}

/**
 * Implementation of EcPointMultiplyCommand.
 * Exposes provider-backed raw-X point multiplication semantics.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class EcPointMultiplyCommandImpl(
    execution: SessionExecution,
    private val providerRegistry: KmsProviderRegistry,
) : TypedServiceCommandAdapter<EcPointMultiplyArgs, EcPointMultiplyResult, IdkError>(
        commandId = EcPointMultiplyCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<EcPointMultiplyArgs>(),
        outputTypeToken = typeToken<EcPointMultiplyResult>(),
    ),
    EcPointMultiplyCommand {
    override val commandId: String get() = EcPointMultiplyCommand.COMMAND_ID

    override suspend fun doExecute(
        args: EcPointMultiplyArgs,
        applyDuring: (EcPointMultiplyArgs) -> EcPointMultiplyArgs,
    ): IdkResult<EcPointMultiplyResult, IdkError> {
        val appliedArgs = applyDuring(args)
        val privateKeyInfo =
            appliedArgs.privateKeyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "privateKeyInfo is required").asErrorResult()
        val publicKeyInfo =
            appliedArgs.publicKeyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "publicKeyInfo is required").asErrorResult()

        return try {
            val provider = providerRegistry.getProvider(privateKeyInfo.providerId, privateKeyInfo.signatureAlgorithm)
            if (!provider.getCapabilities().supportsOperation(KmsProviderOperation.EC_POINT_MULTIPLY)) {
                return IdkError
                    .UNSUPPORTED_OPERATION_ERROR(
                        operation = KmsProviderOperation.EC_POINT_MULTIPLY.name,
                        reason = "Provider ${provider.id} does not advertise EC point multiplication",
                    ).asErrorResult()
            }
            provider
                .ecPointMultiply(
                    privateKeyInfo = privateKeyInfo,
                    publicKeyInfo = publicKeyInfo,
                    output = appliedArgs.output,
                ).asOkResult()
        } catch (expected: Exception) {
            log.warn("EC point multiplication failed: ${expected.message}")
            IdkError.fromString(message = "EC point multiplication failed: ${expected.message}", code = "CRYPTO_ERROR", exception = expected).asErrorResult()
        }
    }

    override suspend fun supports(args: Any): Boolean =
        args is EcPointMultiplyArgs &&
            args.privateKeyInfo != null &&
            args.publicKeyInfo != null
}
