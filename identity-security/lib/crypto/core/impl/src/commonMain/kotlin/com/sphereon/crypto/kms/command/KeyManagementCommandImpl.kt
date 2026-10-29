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
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.TypedServiceCommandAdapter
import com.sphereon.crypto.core.ManagedKeyReference
import com.sphereon.crypto.core.ManagedKeyReferenceFilter
import com.sphereon.crypto.core.kms.KmsProviderRegistry
import com.sphereon.crypto.core.kms.ManagedKeyStoreService
import com.sphereon.crypto.core.kms.command.DeleteKeyArgs
import com.sphereon.crypto.core.kms.command.DeleteKeyCommand
import com.sphereon.crypto.core.kms.command.DeleteKeyResult
import com.sphereon.crypto.core.kms.command.GenerateKeyArgs
import com.sphereon.crypto.core.kms.command.GenerateKeyCommand
import com.sphereon.crypto.core.kms.command.GenerateKeyResult
import com.sphereon.crypto.core.kms.command.GetKeyArgs
import com.sphereon.crypto.core.kms.command.GetKeyCommand
import com.sphereon.crypto.core.kms.command.GetKeyResult
import com.sphereon.crypto.core.kms.command.ListKeysArgs
import com.sphereon.crypto.core.kms.command.ListKeysCommand
import com.sphereon.crypto.core.kms.command.ListKeysResult
import com.sphereon.crypto.core.kms.command.StoreKeyArgs
import com.sphereon.crypto.core.kms.command.StoreKeyCommand
import com.sphereon.crypto.core.kms.command.StoreKeyResult
import com.sphereon.crypto.key.persistence.KeyReferenceRecord
import com.sphereon.crypto.key.persistence.KeyReferenceResolutionException
import com.sphereon.crypto.key.persistence.KeyReferenceStore
import com.sphereon.di.session.SessionContext
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn

import dev.zacsweers.metro.ExposeImplBinding
/**
 * Implementation of GenerateKeyCommand.
 * Generates a new cryptographic key pair and indexes it in the key reference store
 * if persistence is available.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class GenerateKeyCommandImpl(
    execution: SessionExecution,
    private val providerRegistry: KmsProviderRegistry,
    private val keyReferenceStore: KeyReferenceStore,
) : TypedServiceCommandAdapter<GenerateKeyArgs, GenerateKeyResult, IdkError>(
        commandId = GenerateKeyCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<GenerateKeyArgs>(),
        outputTypeToken = typeToken<GenerateKeyResult>(),
    ),
    GenerateKeyCommand {
    override val commandId: String get() = GenerateKeyCommand.COMMAND_ID

    override suspend fun doExecute(
        args: GenerateKeyArgs,
        applyDuring: (GenerateKeyArgs) -> GenerateKeyArgs,
    ): IdkResult<GenerateKeyResult, IdkError> {
        val appliedArgs = applyDuring(args)

        log.debug("Generating key with provider: ${appliedArgs.providerId ?: "default"}, alias: ${appliedArgs.alias ?: "none"}")

        return try {
            val provider = providerRegistry.getProvider(appliedArgs.providerId, appliedArgs.alg)
            val keyPair =
                provider.generateKeyAsync(
                    appliedArgs.alias,
                    appliedArgs.use,
                    appliedArgs.keyOperations,
                    appliedArgs.alg,
                )
            log.debug("Key generated successfully: ${keyPair.kid ?: keyPair.alias ?: "unknown"}")
            // A provider that wrote the authoritative index row itself is not indexed again here.
            // Repeating the write under the provider id the returned key reports is what produced a
            // second row for one key whenever that provider answers to more than one id.
            if (!provider.maintainsKeyReferenceIndex) {
                indexGeneratedKey(keyPair, appliedArgs.walletUnitId)
            }
            GenerateKeyResult(
                keyPair = keyPair,
                keyReference =
                    ManagedKeyReference(
                        alias = keyPair.alias,
                        kid = keyPair.kid,
                        providerId = keyPair.providerId,
                        signatureAlgorithm = appliedArgs.alg,
                        keyVisibility = appliedArgs.keyVisibility,
                        walletUnitId = appliedArgs.walletUnitId,
                    ),
            ).asOkResult()
        } catch (expected: Exception) {
            log.warn("Key generation failed: ${expected.message}")
            IdkError.fromString(message = "Key generation failed: ${expected.message}", code = "CRYPTO_ERROR", exception = expected).asErrorResult()
        }
    }

    override suspend fun supports(args: Any): Boolean = args is GenerateKeyArgs

    /** Index the generated key in the reference store. Silently skips if persistence is unavailable. */
    private suspend fun indexGeneratedKey(
        keyPair: com.sphereon.crypto.core.generic.ManagedKeyPair,
        walletUnitId: String?,
    ) {
        if (!keyReferenceStore.isAvailable) {
            return
        }
        try {
            val managedKeyInfo = keyPair.joseToManagedKeyInfo()
            val record =
                KeyReferenceRecord.fromManagedKey(
                    managedKeyInfo,
                    tenantId = execution.sessionContext.context.tenant.tenantId,
                    walletUnitId = walletUnitId,
                )
            keyReferenceStore.upsert(record)
        } catch (expected: Exception) {
            log.warn("Failed to index generated key in reference store: ${expected.message}")
        }
    }
}

/**
 * Implementation of ListKeysCommand.
 * Lists all keys in the key store.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class ListKeysCommandImpl(
    execution: SessionExecution,
    private val keyStore: ManagedKeyStoreService,
) : TypedServiceCommandAdapter<ListKeysArgs, ListKeysResult, IdkError>(
        commandId = ListKeysCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<ListKeysArgs>(),
        outputTypeToken = typeToken<ListKeysResult>(),
    ),
    ListKeysCommand {
    override val commandId: String get() = ListKeysCommand.COMMAND_ID

    override suspend fun doExecute(
        args: ListKeysArgs,
        applyDuring: (ListKeysArgs) -> ListKeysArgs,
    ): IdkResult<ListKeysResult, IdkError> {
        val appliedArgs = applyDuring(args)

        log.debug("Listing keys${appliedArgs.providerId?.let { " for provider: $it" } ?: ""}")

        return try {
            val filteredKeys =
                keyStore.listKeys(
                    ManagedKeyReferenceFilter(
                        providerId = appliedArgs.providerId,
                        alias = appliedArgs.alias,
                    ),
                )
            log.debug("Listed ${filteredKeys.size} keys")
            ListKeysResult(filteredKeys).asOkResult()
        } catch (expected: Exception) {
            log.warn("List keys failed: ${expected.message}")
            IdkError.UNKNOWN_ERROR(message = "Failed to list keys: ${expected.message}").asErrorResult()
        }
    }

    override suspend fun supports(args: Any): Boolean = args is ListKeysArgs
}

/**
 * Implementation of GetKeyCommand.
 * Retrieves a specific key from the key store.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class GetKeyCommandImpl(
    execution: SessionExecution,
    private val keyStore: ManagedKeyStoreService,
) : TypedServiceCommandAdapter<GetKeyArgs, GetKeyResult, IdkError>(
        commandId = GetKeyCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<GetKeyArgs>(),
        outputTypeToken = typeToken<GetKeyResult>(),
    ),
    GetKeyCommand {
    override val commandId: String get() = GetKeyCommand.COMMAND_ID

    override suspend fun doExecute(
        args: GetKeyArgs,
        applyDuring: (GetKeyArgs) -> GetKeyArgs,
    ): IdkResult<GetKeyResult, IdkError> {
        val appliedArgs = applyDuring(args)
        val keyInfo =
            appliedArgs.keyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "keyInfo is required").asErrorResult()

        log.debug("KMS_KEY_LOOKUP stage=begin kid_present=${keyInfo.kid != null} alias_present=${keyInfo.alias != null}")

        return try {
            val key = keyStore.getKey(keyInfo)
            log.debug("Key retrieved successfully")
            GetKeyResult(key).asOkResult()
        } catch (expected: Exception) {
            log.warn("KMS_KEY_LOOKUP_FAILED stage=key-store exception=${expected::class.simpleName}")
            IdkError
                .NOT_FOUND_ERROR(
                    resource = "Key",
                    message = "Key not found: ${expected.message}",
                ).asErrorResult()
        }
    }

    override suspend fun supports(args: Any): Boolean = args is GetKeyArgs && args.keyInfo != null
}

/**
 * Implementation of StoreKeyCommand.
 * Stores a key in the key store.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class StoreKeyCommandImpl(
    execution: SessionExecution,
    private val keyStore: ManagedKeyStoreService,
) : TypedServiceCommandAdapter<StoreKeyArgs, StoreKeyResult, IdkError>(
        commandId = StoreKeyCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<StoreKeyArgs>(),
        outputTypeToken = typeToken<StoreKeyResult>(),
    ),
    StoreKeyCommand {
    override val commandId: String get() = StoreKeyCommand.COMMAND_ID

    override suspend fun doExecute(
        args: StoreKeyArgs,
        applyDuring: (StoreKeyArgs) -> StoreKeyArgs,
    ): IdkResult<StoreKeyResult, IdkError> {
        val appliedArgs = applyDuring(args)
        val keyInfo =
            appliedArgs.keyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "keyInfo is required").asErrorResult()

        if (appliedArgs.providerId.isBlank()) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "providerId is required").asErrorResult()
        }
        if (appliedArgs.alias.isBlank()) {
            return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "alias is required").asErrorResult()
        }

        log.debug("Storing key with alias: ${appliedArgs.alias} in provider: ${appliedArgs.providerId}")

        return try {
            val storedKey =
                keyStore.storeKey(
                    keyInfo,
                    appliedArgs.providerId,
                    appliedArgs.alias,
                    appliedArgs.certChain,
                )
            log.debug("Key stored successfully")
            StoreKeyResult(storedKey).asOkResult()
        } catch (expected: Exception) {
            log.warn("Store key failed: ${expected.message}")
            IdkError.UNKNOWN_ERROR(message = "Failed to store key: ${expected.message}").asErrorResult()
        }
    }

    override suspend fun supports(args: Any): Boolean = args is StoreKeyArgs && args.keyInfo != null
}

/**
 * Implementation of DeleteKeyCommand.
 * Deletes a key from the key store.
 */
@Inject
@SingleIn(SessionScope::class)
@ExposeImplBinding
class DeleteKeyCommandImpl(
    execution: SessionExecution,
    private val keyStore: ManagedKeyStoreService,
) : TypedServiceCommandAdapter<DeleteKeyArgs, DeleteKeyResult, IdkError>(
        commandId = DeleteKeyCommand.COMMAND_ID,
        execution = execution,
        inputTypeToken = typeToken<DeleteKeyArgs>(),
        outputTypeToken = typeToken<DeleteKeyResult>(),
    ),
    DeleteKeyCommand {
    override val commandId: String get() = DeleteKeyCommand.COMMAND_ID

    override suspend fun doExecute(
        args: DeleteKeyArgs,
        applyDuring: (DeleteKeyArgs) -> DeleteKeyArgs,
    ): IdkResult<DeleteKeyResult, IdkError> {
        val appliedArgs = applyDuring(args)
        val keyInfo =
            appliedArgs.keyInfo
                ?: return IdkError.ILLEGAL_ARGUMENT_ERROR(message = "keyInfo is required").asErrorResult()

        log.debug("Deleting key: ${keyInfo.kid ?: keyInfo.alias ?: "unknown"}")

        return try {
            val deleted = keyStore.deleteKey(keyInfo)
            log.debug("Key deletion result: $deleted")
            DeleteKeyResult(deleted).asOkResult()
        } catch (expected: KeyReferenceResolutionException) {
            log.warn("Delete key rejected during reference resolution: ${expected.message}")
            IdkError.fromString(
                message = "Key deletion rejected: ${expected.message}",
                code = expected.code,
                exception = expected,
            ).asErrorResult()
        } catch (expected: Exception) {
            log.warn("Delete key failed: ${expected.message}")
            IdkError.UNKNOWN_ERROR(message = "Failed to delete key: ${expected.message}").asErrorResult()
        }
    }

    override suspend fun supports(args: Any): Boolean = args is DeleteKeyArgs && args.keyInfo != null
}
