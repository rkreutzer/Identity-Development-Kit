/*
 * Copyright 2026 Sphereon International B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

package com.sphereon.wallet.interaction

/**
 * Whether an issuer sign-in URL is safe to return from authorization-handoff consume, and therefore
 * safe to hand a host as a `window.open` target.
 *
 * MUST stay in agreement with the TypeScript `openableAuthorizationUri` in
 * `packages/enterprise-shared-ui/src/safety/renderableUri.ts`. Both admit `https:` and loopback
 * `http:` (host is `localhost`, `127.0.0.1`, `[::1]`, or `::1`). Both refuse everything else,
 * including `javascript:`, `data:`, `blob:`, remote `http:`, and any relative value. Loopback is
 * matched on the host, never as a substring.
 *
 * The TypeScript copy still runs in the browser as defense in depth. This copy runs first, at
 * consume, so an unopenable URL is never spent and never handed out. Agreement is
 * `authorization-handoff-uri-vectors.json` in the openapi checkout; [OpenableAuthorizationUriTest]
 * iterates that file.
 */
fun openableAuthorizationUri(value: String?): String? {
    if (value == null) return null
    val trimmed = value.trim()
    if (trimmed.isEmpty()) return null
    val schemeEnd = trimmed.indexOf(':')
    if (schemeEnd <= 0) return null
    val scheme = trimmed.substring(0, schemeEnd).lowercase()
    if (scheme == "https") return value
    if (scheme != "http") return null
    val host = hostOf(trimmed) ?: return null
    val loopback = host == "localhost" || host == "127.0.0.1" || host == "[::1]" || host == "::1"
    return if (loopback) value else null
}

/**
 * Validate-then-spend for an authorization handoff in its owning runtime. Local authorities peek
 * before spending; remote authorities execute their backend's typed command with the same rule.
 * Every consume path that can reach a holder-openable sink must go through this rather than
 * [WalletInteractionSensitiveInputAuthority.consume] directly.
 */
suspend fun WalletInteractionSensitiveInputAuthority.consumeOpenableAuthorizationHandoff(
    sessionId: WalletInteractionSessionId,
    ref: WalletInteractionSensitiveInputRef,
): String? {
    return consumeAuthorizationHandoff(sessionId, ref)
}

private fun hostOf(url: String): String? {
    val afterScheme = url.substringAfter("://", missingDelimiterValue = "")
    if (afterScheme.isEmpty()) return null
    if (afterScheme.startsWith("[")) {
        val end = afterScheme.indexOf(']')
        if (end < 0) return null
        return afterScheme.substring(0, end + 1).lowercase()
    }
    val hostPort = afterScheme.takeWhile { it != '/' && it != '?' && it != '#' }
    return hostPort.substringBefore(':').lowercase().trimEnd('.')
}
