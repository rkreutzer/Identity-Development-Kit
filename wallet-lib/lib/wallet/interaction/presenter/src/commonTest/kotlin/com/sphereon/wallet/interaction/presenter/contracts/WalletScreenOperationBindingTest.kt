/*
 * Copyright 2026 Sphereon International B.V.
 * Licensed under the Apache License, Version 2.0.
 */
package com.sphereon.wallet.interaction.presenter.contracts

import com.sphereon.wallet.interaction.WalletApprovalOperation
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletInteractionState
import com.sphereon.wallet.interaction.WalletInteractionStatus
import com.sphereon.wallet.interaction.WalletSecurityAssurance
import com.sphereon.wallet.interaction.WalletSecurityChallenge
import com.sphereon.wallet.interaction.WalletSecurityChallengeKind
import com.sphereon.wallet.interaction.presenter.WalletScreenModelMapper
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class WalletScreenOperationBindingTest {
    private val json = Json { encodeDefaults = true }

    @Test
    fun attendedAuthorizationPreservesEverySignatureInOrderIncludingRepeatedKeys() {
        val operations = listOf(
            WalletApprovalOperation("holder-key", "first-digest"),
            WalletApprovalOperation("holder-key", "second-digest"),
        )
        assertEquals(
            json.parseToJsonElement("""[{"keyRef":"holder-key","operationHash":"first-digest"},{"keyRef":"holder-key","operationHash":"second-digest"}]"""),
            serializedAuthorization(operations)["operations"],
        )
    }

    @Test
    fun scalarAuthorizationKeepsAnEmptyOperationList() {
        assertEquals(json.parseToJsonElement("[]"), serializedAuthorization(emptyList())["operations"])
    }

    private fun serializedAuthorization(operations: List<WalletApprovalOperation>) =
        json.encodeToJsonElement(
            WalletAttendedAuthorizationPresentation.serializer(),
            assertIs<WalletInteractionScreenProjection.AttendedAuthorization>(
                WalletScreenModelMapper.map(
                    WalletInteractionState(
                        sessionId = WalletInteractionSessionId("interaction"),
                        walletUnitId = "wallet-unit",
                        status = WalletInteractionStatus.SecurityUnlockRequired,
                        securityChallenge = WalletSecurityChallenge(
                            challengeId = "challenge",
                            kind = WalletSecurityChallengeKind.PASSKEY,
                            reasonKey = "wallet.interaction.security.authorization_required",
                            requiredAssurance = WalletSecurityAssurance.PASSKEY,
                            operations = operations,
                        ),
                    ),
                ).projection,
            ).authorization,
        ).jsonObject
}
