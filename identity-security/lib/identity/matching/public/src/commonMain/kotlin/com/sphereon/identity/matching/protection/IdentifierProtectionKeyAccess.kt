/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.identity.matching.protection

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.kms.command.GenerateMacArgs
import com.sphereon.crypto.core.kms.command.GenerateMacResult
import com.sphereon.crypto.core.kms.command.ListKeysArgs
import com.sphereon.crypto.core.kms.command.ListKeysResult

/** Tenant-bound identifier key discovery and blind indexing; implementations retain command policy. */
interface IdentifierProtectionKeyAccess {
    suspend fun listKeys(tenantId: String, args: ListKeysArgs): IdkResult<ListKeysResult, IdkError>
    suspend fun generateMac(tenantId: String, args: GenerateMacArgs): IdkResult<GenerateMacResult, IdkError>
}
