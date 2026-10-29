/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.oauth2.server.authorization.impl.signing

import com.sphereon.core.api.IdkResult
import com.sphereon.core.api.error.IdkError
import com.sphereon.crypto.jose.jws.JwtCompactResult
import com.sphereon.crypto.jose.jws.JwtService
import com.sphereon.crypto.jose.jws.command.CreateJwsArgs
import com.sphereon.di.session.SessionScope
import com.sphereon.oauth2.server.authorization.signing.AsServerJwsSigner
import com.sphereon.oauth2.server.authorization.signing.CapturedAsServerConfig
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<AsServerJwsSigner>())
class DefaultAsServerJwsSigner(private val jwtService: JwtService) : AsServerJwsSigner {
    override suspend fun sign(captured: CapturedAsServerConfig, args: CreateJwsArgs): IdkResult<JwtCompactResult, IdkError> =
        jwtService.createJwsCompact(args)
}
