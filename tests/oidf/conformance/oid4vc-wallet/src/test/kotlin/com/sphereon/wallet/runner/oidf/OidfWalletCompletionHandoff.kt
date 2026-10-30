// (c) 2026 Sphereon International B.V. SPDX-License-Identifier: AGPL-3.0-only
package com.sphereon.wallet.runner.oidf

import com.sphereon.wallet.interaction.WalletInteractionCompletionTransport
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import java.awt.Desktop
import java.net.URI

/** OID4VP 8.2/8.3.1 browser navigation and Appendix A platform responses are different transports. */
internal suspend fun consumeOidfCompletionHandoff(
    transport: WalletInteractionCompletionTransport?,
    consume: suspend () -> String,
    openBrowser: (String) -> Boolean = ::openOidfCompletionBrowser,
): JsonObject? {
    requireNotNull(transport) { "OIDF completion transport is unavailable" }
    return when (transport) {
        WalletInteractionCompletionTransport.BROWSER_REDIRECT -> {
            val value = consume()
            val uri = runCatching { URI(value) }.getOrNull()
            require(
                uri != null && uri.isAbsolute &&
                    uri.scheme.lowercase() !in setOf("javascript", "vbscript", "data", "blob", "file"),
            ) {
                "OIDF browser completion target is invalid"
            }
            // A back-channel GET loses browser state and fragments and does not satisfy OID4VP 8.2.
            check(openBrowser(value)) { "OIDF completion requires an available user-agent browser" }
            null
        }

        WalletInteractionCompletionTransport.DIGITAL_CREDENTIALS_API -> {
            val value = consume()
            runCatching { Json.parseToJsonElement(value) as? JsonObject }.getOrNull()
                ?: error("OIDF DC API completion must contain a JSON object")
        }
    }
}

private fun openOidfCompletionBrowser(value: String): Boolean =
    runCatching {
        if (!Desktop.isDesktopSupported()) return false
        val desktop = Desktop.getDesktop()
        if (!desktop.isSupported(Desktop.Action.BROWSE)) return false
        desktop.browse(URI(value))
        true
    }.getOrDefault(false)
