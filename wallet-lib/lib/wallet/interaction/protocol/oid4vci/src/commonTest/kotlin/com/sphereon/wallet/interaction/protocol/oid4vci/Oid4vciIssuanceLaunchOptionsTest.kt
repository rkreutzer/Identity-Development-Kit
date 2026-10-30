/*
 * (c) 2026 Sphereon International B.V.
 * SPDX-License-Identifier: Apache-2.0
 */

package com.sphereon.wallet.interaction.protocol.oid4vci

import com.sphereon.oauth2.common.model.ClientAuthenticationMethod
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class Oid4vciIssuanceLaunchOptionsTest {
    @Test
    fun appliesPerInteractionProtocolOptionsWithoutReplacingKeyOwnership() {
        val baseline =
            Oid4vciHolderIssuanceOptions(
                signingKeyIds = listOf("wallet-unit-owned-key"),
                operationBinding = "attended-operation",
                clientId = "default-client",
            )

        val applied =
            baseline.withLaunchAttributes(
                mapOf(
                    Oid4vciInteractionLaunchAttributes.CLIENT_ID to "module-client",
                    Oid4vciInteractionLaunchAttributes.REDIRECT_URI to "https://suite.example/callback",
                    Oid4vciInteractionLaunchAttributes.CREDENTIAL_CONFIGURATION_ID to "pid",
                    Oid4vciInteractionLaunchAttributes.CREDENTIAL_BATCH_SIZE to "2",
                    Oid4vciInteractionLaunchAttributes.CLIENT_AUTHENTICATION_METHOD to "private_key_jwt",
                    Oid4vciInteractionLaunchAttributes.DPOP_ENABLED to "true",
                    Oid4vciInteractionLaunchAttributes.USE_PAR to "true",
                    Oid4vciInteractionLaunchAttributes.ENCRYPT_CREDENTIAL_REQUEST to "true",
                ),
            )

        assertEquals(listOf("wallet-unit-owned-key"), applied.signingKeyIds)
        assertEquals("attended-operation", applied.operationBinding)
        assertEquals("module-client", applied.clientId)
        assertEquals("https://suite.example/callback", applied.redirectUri)
        assertEquals("pid", applied.credentialConfigurationId)
        assertEquals(2, applied.batchSize)
        assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, applied.clientAuthenticationMethod)
        assertTrue(applied.dpopEnabled)
        assertEquals(true, applied.usePar)
        assertEquals(true, applied.encryptCredentialRequest)
    }

    @Test
    fun rejectsAmbiguousParAttribute() {
        assertFailsWith<IllegalArgumentException> {
            Oid4vciHolderIssuanceOptions(signingKeyIds = listOf("key")).withLaunchAttributes(
                mapOf(Oid4vciInteractionLaunchAttributes.USE_PAR to "sometimes"),
            )
        }
    }

    @Test
    fun rejectsNonPositiveOrNonNumericBatchSize() {
        listOf("0", "-1", "two").forEach { value ->
            assertFailsWith<IllegalArgumentException> {
                Oid4vciHolderIssuanceOptions(signingKeyIds = listOf("key")).withLaunchAttributes(
                    mapOf(Oid4vciInteractionLaunchAttributes.CREDENTIAL_BATCH_SIZE to value),
                )
            }
        }
    }
}
