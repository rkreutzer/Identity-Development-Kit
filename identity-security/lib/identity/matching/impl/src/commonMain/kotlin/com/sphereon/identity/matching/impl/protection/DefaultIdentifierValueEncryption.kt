/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.identity.matching.impl.protection

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.Err
import com.sphereon.core.api.context.SessionExecution
import com.sphereon.core.api.error.IdkError
import com.sphereon.core.api.service.SessionScopedCommandRegistry
import com.sphereon.crypto.core.kms.command.*
import com.sphereon.di.session.SessionScope
import com.sphereon.identity.matching.protection.IdentifierValueEncryption
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn

/** Standalone and distributed deployments retain their configured command routing and policy. */
@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class)
class DefaultIdentifierValueEncryption(
    private val execution: SessionExecution,
    private val commands: SessionScopedCommandRegistry,
) : IdentifierValueEncryption {
    override suspend fun encrypt(tenantId: String, args: EncryptArgs): IdkResult<EncryptResult, IdkError> {
        if (tenantId.isBlank() || tenantId != execution.tenantId) return refused()
        val command = commands.get(EncryptCommand.COMMAND_ID) as? EncryptCommand ?: return refused()
        return command.execute(args)
    }
    override suspend fun decrypt(tenantId: String, args: DecryptArgs): IdkResult<DecryptResult, IdkError> {
        if (tenantId.isBlank() || tenantId != execution.tenantId) return refused()
        val command = commands.get(DecryptCommand.COMMAND_ID) as? DecryptCommand ?: return refused()
        return command.execute(args)
    }
    private fun refused(): IdkResult<Nothing, IdkError> {
        execution.log.warn("Identifier value encryption refused stage=tenant-or-command-binding")
        return Err(IdkError.FORBIDDEN_ERROR(message = "Identifier value encryption binding is unavailable"))
    }
}
