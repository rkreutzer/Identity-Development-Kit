/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.oauth2.server.authorization.signing

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.jose.jws.JwtCompactResult
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs

/**
 * Internal hosted-AS signing boundary after protocol validation and authoritative key selection.
 * Implementations must bind signing to the captured server and its own active key. This is not a
 * command or a caller-selectable signing endpoint. Deployments may execute backend signing under
 * their authenticated server workload without changing the requesting user's session.
 */
fun interface AsServerJwsSigner {
    suspend fun sign(captured: CapturedAsServerConfig, args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError>
}
