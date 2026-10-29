// (c) 2026 Sphereon International B.V. SPDX-License-Identifier: AGPL-3.0-only
package com.sphereon.wallet.runner.oidf

import com.sphereon.wallet.interaction.WalletInteractionCompletionTransport
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OidfWalletCompletionHandoffTest {
    @Test
    fun browserCompletionPreservesExactUriAndFragmentInsteadOfParsingJson() =
        runTest {
            val uri = "https://verifier.example/cb#response_code=a+b%2Bc"
            val opened = mutableListOf<String>()
            val result =
                consumeOidfCompletionHandoff(
                    WalletInteractionCompletionTransport.BROWSER_REDIRECT,
                    consume = { uri },
                    openBrowser = {
                        opened += it
                        true
                    },
                )
            assertNull(result)
            assertEquals(listOf(uri), opened)
        }

    @Test
    fun privateUseAbsoluteCompletionUsesTheBrowserAdapter() =
        runTest {
            val uri = "verifier-app:/cb#response_code=secret"
            var opened: String? = null
            consumeOidfCompletionHandoff(
                WalletInteractionCompletionTransport.BROWSER_REDIRECT,
                consume = { uri },
                openBrowser = {
                    opened = it
                    true
                },
            )
            assertEquals(uri, opened)
        }

    @Test
    fun digitalCredentialsApiReturnsStructuredResponseWithoutBrowserNavigation() =
        runTest {
            val response = """{"protocol":"openid4vp-v1-signed","data":{"response":"opaque"}}"""
            var navigated = false
            val result =
                consumeOidfCompletionHandoff(
                    WalletInteractionCompletionTransport.DIGITAL_CREDENTIALS_API,
                    consume = { response },
                    openBrowser = {
                        navigated = true
                        true
                    },
                )
            assertEquals(Json.parseToJsonElement(response).jsonObject, result)
            assertTrue(!navigated)
        }

    @Test
    fun missingTransportDoesNotSpendTheCompletionReference() =
        runTest {
            var consumed = false
            val failure =
                runCatching {
                    consumeOidfCompletionHandoff(
                        null,
                        consume = {
                            consumed = true
                            "opaque"
                        },
                    )
                }.exceptionOrNull()
            assertTrue(failure is IllegalArgumentException)
            assertTrue(!consumed)
        }

    @Test
    fun unavailableBrowserFailsWithoutExposingCompletionSecret() =
        runTest {
            val secret = "private-completion-code"
            val failure =
                runCatching {
                    consumeOidfCompletionHandoff(
                        WalletInteractionCompletionTransport.BROWSER_REDIRECT,
                        consume = { "https://verifier.example/cb#response_code=$secret" },
                        openBrowser = { false },
                    )
                }.exceptionOrNull()
            assertTrue(failure is IllegalStateException)
            assertTrue(failure.message?.contains(secret) != true)
        }

    @Test
    fun executableAndRelativeTargetsCannotNavigate() =
        runTest {
            for (target in listOf("javascript:alert(1)", "/relative-callback")) {
                var navigated = false
                val failure =
                    runCatching {
                        consumeOidfCompletionHandoff(
                            WalletInteractionCompletionTransport.BROWSER_REDIRECT,
                            consume = { target },
                            openBrowser = {
                                navigated = true
                                true
                            },
                        )
                    }.exceptionOrNull()
                assertTrue(failure is IllegalArgumentException)
                assertTrue(!navigated)
            }
        }
}
