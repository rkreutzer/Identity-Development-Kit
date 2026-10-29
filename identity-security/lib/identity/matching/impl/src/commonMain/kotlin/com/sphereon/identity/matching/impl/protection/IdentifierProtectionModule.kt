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

package com.sphereon.identity.matching.impl.protection

import com.sphereon.crypto.core.kms.command.DecryptCommand
import com.sphereon.crypto.core.kms.command.EncryptCommand
import com.sphereon.crypto.core.kms.command.GenerateKeyCommand
import com.sphereon.crypto.core.kms.command.GenerateMacCommand
import com.sphereon.crypto.core.kms.command.ListKeysCommand
import com.sphereon.core.api.conf.DEFAULT_APPLICATION_TENANT_ID
import com.sphereon.core.api.conf.KEY_APPLICATION_TENANT_ID
import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.SessionScopedCommandRegistry
import com.sphereon.di.session.SessionScope
import com.sphereon.identity.matching.protection.DefaultIdentifierProtectionPolicyService
import com.sphereon.identity.matching.protection.IdentifierProtectionPolicyService
import com.sphereon.identity.matching.protection.IdentifierProtectionKeyAccess
import com.sphereon.identity.matching.protection.IdentifierProtectionKeyProvisioner
import com.sphereon.identity.matching.protection.IdentifierProtector
import com.sphereon.identity.matching.protection.IdentifierValueEncryption
import dev.zacsweers.metro.ContributesTo
import dev.zacsweers.metro.Provides
import dev.zacsweers.metro.SingleIn

/**
 * Session-scoped DI module for identifier protection.
 *
 * Provides the KMS-backed [IdentifierProtector] and the built-in
 * [IdentifierProtectionPolicyService]. Mirrors the reconciliation crypto module so identifier
 * protection wires up automatically wherever the matching impl is on the classpath.
 */
@ContributesTo(SessionScope::class)
interface IdentifierProtectionModule {
    companion object {
        const val APPLICATION_IDENTIFIER_PROTECTION_PROVIDER_ID: String = "software"

        /**
         * Logical tenant provider resolved by the enterprise KMS typed-resource registry.
         *
         * Identifier protection must not use algorithm-only provider selection: a split tenant-KMS
         * also has a system-only bootstrap HMAC provider for token verification, and selecting by
         * HMAC capability would create tenant material in that transient provider. The logical
         * `default` id is resolved server-side through the tenant's opaque KMS resource binding.
         */
        const val TENANT_IDENTIFIER_PROTECTION_PROVIDER_ID: String = "default"
    }

    @Provides
    @SingleIn(SessionScope::class)
    fun provideIdentifierProtectionPolicyService(): IdentifierProtectionPolicyService = DefaultIdentifierProtectionPolicyService()

    @Provides
    @SingleIn(SessionScope::class)
    fun provideIdentifierProtector(
        commandRegistry: SessionScopedCommandRegistry,
        execution: SessionExecution,
        valueEncryption: IdentifierValueEncryption,
        keyAccess: IdentifierProtectionKeyAccess,
    ): IdentifierProtector {
        // Resolve each command from the session registry at construction time so config-based
        // LOCAL/SERVER selection is honored. This matters in wallet-unit: its WSCD still needs
        // private local KMS bindings, while identifier material for customer tenants must use the
        // routed tenant-KMS command adapters.
        val applicationTenantId =
            execution.conf.app
                .getPropertyAsString(KEY_APPLICATION_TENANT_ID, DEFAULT_APPLICATION_TENANT_ID)
                ?.trim()
                ?.takeIf(String::isNotEmpty)
                ?: DEFAULT_APPLICATION_TENANT_ID

        return KmsBackedIdentifierProtector(
            generateKeyCommand = requireIdentifierProtectionCommand(commandRegistry, GenerateKeyCommand.COMMAND_ID),
            listKeysCommand = requireIdentifierProtectionCommand(commandRegistry, ListKeysCommand.COMMAND_ID),
            generateMacCommand = requireIdentifierProtectionCommand(commandRegistry, GenerateMacCommand.COMMAND_ID),
            encryptCommand = requireIdentifierProtectionCommand(commandRegistry, EncryptCommand.COMMAND_ID),
            decryptCommand = requireIdentifierProtectionCommand(commandRegistry, DecryptCommand.COMMAND_ID),
            providerId = identifierProtectionProviderId(execution.tenantId, applicationTenantId),
            valueEncryption = valueEncryption,
            keyAccess = keyAccess,
        )
    }

    /**
     * The explicit creation point for identifier keys, backed by the same session protector so
     * provisioning and later resolution share one provider selection. A graph that binds an
     * [IdentifierProtector] without key lifecycle gets a provisioner that refuses.
     */
    @Provides
    @SingleIn(SessionScope::class)
    fun provideIdentifierProtectionKeyProvisioner(protector: IdentifierProtector): IdentifierProtectionKeyProvisioner =
        protector as? IdentifierProtectionKeyProvisioner ?: RefusingIdentifierProtectionKeyProvisioner
}

private object RefusingIdentifierProtectionKeyProvisioner : IdentifierProtectionKeyProvisioner {
    override suspend fun provisionKeys(tenantId: String): IdkResult<Unit, IdkError> =
        Err(IdkError.INVALID_STATE(message = "The bound identifier protector does not provision identifier keys"))
}

private inline fun <reified T : Any> requireIdentifierProtectionCommand(
    commandRegistry: SessionScopedCommandRegistry,
    commandId: String,
): T =
    commandRegistry.get(commandId) as? T
        ?: error("No routed identifier-protection command binding for $commandId")

/**
 * The application tenant owns a local persisted software provider. Customer tenants are routed to
 * tenant-KMS, where the server resolves the logical `default` id through the tenant's active typed
 * provider binding. Keeping this decision session-scoped prevents platform identities from being
 * written into a customer-provider namespace and prevents customer identifiers from falling into
 * a system-only bootstrap provider selected only because it supports the same algorithm.
 */
internal fun identifierProtectionProviderId(
    sessionTenantId: String,
    applicationTenantId: String,
): String =
    if (sessionTenantId == applicationTenantId) {
        IdentifierProtectionModule.APPLICATION_IDENTIFIER_PROTECTION_PROVIDER_ID
    } else {
        IdentifierProtectionModule.TENANT_IDENTIFIER_PROTECTION_PROVIDER_ID
    }
