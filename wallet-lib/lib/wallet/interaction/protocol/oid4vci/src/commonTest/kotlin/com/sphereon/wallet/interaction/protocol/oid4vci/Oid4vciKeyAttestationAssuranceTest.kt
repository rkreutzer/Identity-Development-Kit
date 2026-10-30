package com.sphereon.wallet.interaction.protocol.oid4vci

import com.sphereon.openid.oid4vci.common.model.KeyAttestationsRequired
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertTrue

class Oid4vciKeyAttestationAssuranceTest {
    @Test fun refusesUnevidencedIssuerAssuranceConstraintsBeforeKeyUse() = runTest {
        val provider = SecureComponentOid4vciKeyAttestationProvider { error("Unevidenced assurance must fail before key use") }
        for (required in listOf(KeyAttestationsRequired(keyStorage = listOf("iso_18045_high")),
            KeyAttestationsRequired(userAuthentication = listOf("iso_18045_moderate")))) {
            assertTrue(provider.attest(Oid4vciKeyAttestationRequest(
                walletUnitId = "unit-1", walletAccountId = "account-1", operationBinding = "attended-1",
                signingKeyId = "holder-key", signingAlgorithm = "ES256", audience = "https://issuer.example",
                nonce = "fresh-nonce", requirement = required,
            )).isErr)
        }
    }
}
