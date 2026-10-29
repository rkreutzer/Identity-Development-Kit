/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.crypto.jose.jws.command

import com.sphereon.crypto.core.KeyInfoType
import com.sphereon.crypto.jose.jws.ManagedJwsSigningResultVerifier
import com.sphereon.di.session.SessionScope
import dev.zacsweers.metro.ContributesBinding
import dev.zacsweers.metro.Inject
import dev.zacsweers.metro.SingleIn
import dev.zacsweers.metro.binding

@Inject
@SingleIn(SessionScope::class)
@ContributesBinding(SessionScope::class, binding = binding<ManagedJwsSigningResultVerifier>())
class DefaultManagedJwsSigningResultVerifier : ManagedJwsSigningResultVerifier {
    override suspend fun matches(keyInfo: KeyInfoType<*>, headerAlg: String, input: ByteArray, signature: ByteArray): Boolean =
        verifyManagedJwsSigningResult(keyInfo, headerAlg, input, signature)
}
