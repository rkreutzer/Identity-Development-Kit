/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.identity.matching.impl.protection

import com.sphereon.core.api.Err
import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.SessionScopedCommandRegistry
import com.sphereon.crypto.core.kms.command.*
import com.sphereon.di.session.SessionScope
import com.sphereon.identity.matching.protection.IdentifierProtectionKeyAccess
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn

/** Standalone and distributed deployments preserve the configured KMS command route. */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class)
class DefaultIdentifierProtectionKeyAccess(
    private val execution: SessionExecution,
    private val commands: SessionScopedCommandRegistry,
) : IdentifierProtectionKeyAccess {
    override suspend fun listKeys(tenantId: String, args: ListKeysArgs): IdkResult<ListKeysResult, IdkError> {
        if (tenantId.isBlank() || tenantId != execution.tenantId) return refused("lookup-tenant")
        val command = commands.get(ListKeysCommand.COMMAND_ID) as? ListKeysCommand ?: return refused("lookup-command")
        return command.execute(args)
    }

    override suspend fun generateMac(tenantId: String, args: GenerateMacArgs): IdkResult<GenerateMacResult, IdkError> {
        if (tenantId.isBlank() || tenantId != execution.tenantId) return refused("mac-tenant")
        val command = commands.get(GenerateMacCommand.COMMAND_ID) as? GenerateMacCommand ?: return refused("mac-command")
        return command.execute(args)
    }

    private fun refused(stage: String): IdkResult<Nothing, IdkError> {
        execution.log.warn("IDENTIFIER_KEY_ACCESS_REFUSED stage=$stage")
        return Err(IdkError.FORBIDDEN_ERROR(message = "Identifier key access binding is unavailable"))
    }
}
