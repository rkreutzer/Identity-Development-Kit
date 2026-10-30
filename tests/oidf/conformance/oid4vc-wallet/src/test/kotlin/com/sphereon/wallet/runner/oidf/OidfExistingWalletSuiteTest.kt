// Copyright 2026 Sphereon International B.V. Licensed under a commercial source-available license.
package com.sphereon.wallet.runner.oidf

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class OidfExistingWalletSuiteTest {
    @Test
    fun managementAndProtocolOriginsKeepTheirOwnHostAndPort() {
        assertEquals("https://localhost:18443", oidfExistingSuiteOrigin("https://localhost:18443/"))
        assertEquals("https://oidf-wallet.example.test", oidfExistingSuiteOrigin("https://oidf-wallet.example.test/"))
    }

    @Test
    fun refusesNonTlsCredentialsPathsAndAmbiguousOrigins() {
        for (
        value in
        listOf(
            "http://localhost:18443",
            "https://user:pass@example.test",
            "https://example.test/api",
            "https://example.test?x=1",
            "https://example.test#fragment",
            "https:///missing-host",
        )
        ) {
            assertFailsWith<IllegalArgumentException>(value) { oidfExistingSuiteOrigin(value) }
        }
    }
}
