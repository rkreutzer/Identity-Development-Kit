/* Copyright 2026 Sphereon International B.V. Licensed under the Apache License, Version 2.0. */
package com.sphereon.crypto.jose.jws

import com.sphereon.crypto.core.KeyInfoType

/** Post-sign consistency against captured public material; retains SIGN rather than requiring VERIFY. */
fun interface ManagedJwsSigningResultVerifier {
    suspend fun matches(keyInfo: KeyInfoType<*>, headerAlg: String, input: ByteArray, signature: ByteArray): Boolean
}
