/*
 * © 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

package com.sphereon.crypto.core.generic

import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Every signature algorithm the serializer writes must read back. A KMS provider reports raw RSA
 * (`RSA_RAW`) among its signing capabilities, and a receiver that cannot decode it rejects the whole
 * capability set.
 */
class SignatureAlgorithmSerializationTest {
    private val serializer = SetSerializer(SignatureAlgorithm.serializer())

    @Test
    fun everyDefinedAlgorithmRoundTrips() {
        for (algorithm in SignatureAlgorithm.serialized) {
            val encoded = Json.encodeToString(SignatureAlgorithm.serializer(), algorithm)
            assertEquals(algorithm, Json.decodeFromString(SignatureAlgorithm.serializer(), encoded), encoded)
        }
    }

    @Test
    fun providerCapabilitySetWithRawRsaReadsBack() {
        val capabilities = setOf(SignatureAlgorithm.RSA_SHA256, SignatureAlgorithm.RSA_RAW, SignatureAlgorithm.RSA_SSA_PSS_RAW_MGF1)
        val encoded = Json.encodeToString(serializer, capabilities)

        assertEquals("""["RSA_SHA256","RSA_RAW","RSA_SSA_PSS_RAW_MGF1"]""", encoded)
        assertEquals(capabilities, Json.decodeFromString(serializer, encoded))
    }

    @Test
    fun jwaLookupKeepsItsMappedAlgorithmsOnly() {
        assertEquals(null, SignatureAlgorithm.fromValue("RSA_RAW"))
        assertEquals(SignatureAlgorithm.ECDSA_SHA256, SignatureAlgorithm.fromValue("ECDSA_SHA256"))
    }
}
