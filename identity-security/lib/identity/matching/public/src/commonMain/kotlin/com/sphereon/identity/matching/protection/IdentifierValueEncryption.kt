/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.identity.matching.protection

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.core.kms.command.EncryptArgs
import com.sphereon.crypto.core.kms.command.EncryptResult
import com.sphereon.crypto.core.kms.command.DecryptArgs
import com.sphereon.crypto.core.kms.command.DecryptResult

/** Internal identifier-value crypto boundary. Implementations retain owner and purpose binding. */
interface IdentifierValueEncryption {
    suspend fun encrypt(tenantId: String, args: EncryptArgs): IdkResult<EncryptResult, IdkError>
    suspend fun decrypt(tenantId: String, args: DecryptArgs): IdkResult<DecryptResult, IdkError>
}
